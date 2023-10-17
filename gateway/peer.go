package gateway

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/internal/smux"
	"go.sia.tech/core/types"
	"go.sia.tech/mux"
)

// A Peer is a connected gateway peer.
type Peer struct {
	UniqueID UniqueID
	Version  string
	Addr     string
	ConnAddr string
	Inbound  bool
	smux     *smux.Session // for v1
	mux      *mux.Mux      // for v2
	mu       sync.Mutex
	err      error
}

// String implements fmt.Stringer.
func (p *Peer) String() string {
	if p.Inbound {
		return "<-" + p.ConnAddr
	}
	return "->" + p.ConnAddr
}

// SupportsV2 returns true if the peer supports v2 RPCs.
func (p *Peer) SupportsV2() bool { return p.mux != nil }

// Err returns the error that caused the peer to disconnect, if any.
func (p *Peer) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

// SetErr sets the peer's disconnection error.
func (p *Peer) SetErr(err error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err == nil {
		p.err = err
		if p.smux != nil {
			p.smux.Close()
		} else {
			p.mux.Close()
		}
	}
	return p.err
}

// Close closes the peer's connection.
func (p *Peer) Close() error {
	p.SetErr(errors.New("closing"))
	return nil
}

func (p *Peer) openStream() (net.Conn, error) {
	if p.smux != nil {
		return p.smux.OpenStream()
	}
	return p.mux.DialStream(), nil
}

func (p *Peer) acceptStream() (net.Conn, error) {
	if p.smux != nil {
		return p.smux.AcceptStream()
	}
	return p.mux.AcceptStream()
}

func (p *Peer) withEncoder(w io.Writer, fn func(*types.Encoder)) error {
	if p.smux != nil {
		return withV1Encoder(w, fn)
	}
	return withV2Encoder(w, fn)
}

func (p *Peer) withDecoder(r io.Reader, maxLen int, fn func(*types.Decoder)) error {
	if p.smux != nil {
		return withV1Decoder(r, maxLen, fn)
	}
	return withV2Decoder(r, maxLen, fn)
}

// An RPCHandler handles RPCs received from a peer.
type RPCHandler interface {
	// v1
	PeersForShare() []string
	Block(id types.BlockID) (types.Block, error)
	BlocksForHistory(history []types.BlockID, max uint64) ([]types.Block, uint64, error)
	RelayHeader(h BlockHeader, origin *Peer)
	RelayTransactionSet(txns []types.Transaction, origin *Peer)
	// v2
	Transactions(index types.ChainIndex, txns []types.Hash256) ([]types.Transaction, []types.V2Transaction, error)
	Checkpoint(index types.ChainIndex) (types.Block, consensus.State, error)
	RelayV2Header(h V2BlockHeader, origin *Peer)
	RelayV2BlockOutline(b V2BlockOutline, origin *Peer)
	RelayV2TransactionSet(txns []types.V2Transaction, origin *Peer)
}

// HandleRPC handles an RPC received from the peer.
func (p *Peer) HandleRPC(id types.Specifier, stream net.Conn, h RPCHandler) error {
	switch r := objectForID(id).(type) {
	case *RPCShareNodes:
		r.Peers = h.PeersForShare()
		if err := p.withEncoder(stream, r.encodeResponse); err != nil {
			return err
		}
		return nil
	case *RPCDiscoverIP:
		r.IP, _, _ = net.SplitHostPort(p.Addr)
		if err := p.withEncoder(stream, r.encodeResponse); err != nil {
			return err
		}
		return nil
	case *RPCRelayHeader:
		if err := p.withDecoder(stream, r.maxRequestLen(), r.decodeRequest); err != nil {
			return err
		}
		h.RelayHeader(r.Header, p)
		return nil
	case *RPCRelayTransactionSet:
		if err := p.withDecoder(stream, r.maxRequestLen(), r.decodeRequest); err != nil {
			return err
		}
		h.RelayTransactionSet(r.Transactions, p)
		return nil
	case *RPCSendBlk:
		err := p.withDecoder(stream, r.maxRequestLen(), r.decodeRequest)
		if err != nil {
			return err
		}
		r.Block, err = h.Block(r.ID)
		if err != nil {
			return err
		} else if err := p.withEncoder(stream, r.encodeResponse); err != nil {
			return err
		}
		return nil
	case *RPCSendBlocks:
		err := p.withDecoder(stream, r.maxRequestLen(), r.decodeRequest)
		if err != nil {
			return err
		}
		for {
			var rem uint64
			r.Blocks, rem, err = h.BlocksForHistory(r.History[:], 10)
			r.MoreAvailable = rem > 0
			if err != nil {
				return err
			} else if err := p.withEncoder(stream, r.encodeBlocksResponse); err != nil {
				return err
			} else if err := p.withEncoder(stream, r.encodeMoreAvailableResponse); err != nil {
				return err
			} else if !r.MoreAvailable {
				return nil
			}
			r.History[0] = r.Blocks[len(r.Blocks)-1].ID()
		}
	case *RPCSendTransactions:
		err := p.withDecoder(stream, r.maxRequestLen(), r.decodeRequest)
		if err != nil {
			return err
		}
		r.Transactions, r.V2Transactions, err = h.Transactions(r.Index, r.Hashes)
		if err != nil {
			return err
		} else if err := p.withEncoder(stream, r.encodeResponse); err != nil {
			return err
		}
		return nil
	case *RPCSendCheckpoint:
		err := p.withDecoder(stream, r.maxRequestLen(), r.decodeRequest)
		if err != nil {
			return err
		}
		r.Block, r.State, err = h.Checkpoint(r.Index)
		if err != nil {
			return err
		} else if err := p.withEncoder(stream, r.encodeResponse); err != nil {
			return err
		}
		return nil
	case *RPCRelayV2Header:
		if err := p.withDecoder(stream, r.maxRequestLen(), r.decodeRequest); err != nil {
			return err
		}
		h.RelayV2Header(r.Header, p)
		return nil
	case *RPCRelayV2BlockOutline:
		if err := p.withDecoder(stream, r.maxRequestLen(), r.decodeRequest); err != nil {
			return err
		}
		h.RelayV2BlockOutline(r.Block, p)
		return nil
	case *RPCRelayV2TransactionSet:
		if err := p.withDecoder(stream, r.maxRequestLen(), r.decodeRequest); err != nil {
			return err
		}
		h.RelayV2TransactionSet(r.Transactions, p)
		return nil
	case *RPCSendV2Blocks:
		err := p.withDecoder(stream, r.maxRequestLen(), r.decodeRequest)
		if err != nil {
			return err
		}
		if r.Max > 100 {
			r.Max = 100
		}
		r.Blocks, r.Remaining, err = h.BlocksForHistory(r.History, r.Max)
		if err != nil {
			return err
		} else if err := p.withEncoder(stream, r.encodeResponse); err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("unrecognized RPC: %q", id)
	}
}

func (p *Peer) callRPC(r object, timeout time.Duration) error {
	s, err := p.openStream()
	if err != nil {
		return fmt.Errorf("couldn't open stream: %w", err)
	}
	defer s.Close()
	s.SetDeadline(time.Now().Add(timeout))
	id := idForObject(r)
	if p.smux != nil {
		err = p.withEncoder(s, (*v1RPCID)(&id).encodeTo)
	} else {
		err = p.withEncoder(s, id.EncodeTo)
	}
	if err != nil {
		return fmt.Errorf("couldn't write RPC ID: %w", err)
	}
	if r.maxRequestLen() > 0 {
		if err := p.withEncoder(s, r.encodeRequest); err != nil {
			return fmt.Errorf("couldn't write request: %w", err)
		}
	}
	if r.maxResponseLen() > 0 {
		if err := p.withDecoder(s, r.maxResponseLen(), r.decodeResponse); err != nil {
			return fmt.Errorf("couldn't read response: %w", err)
		}
	}
	return nil
}

// ShareNodes requests a list of potential peers from the peer.
func (p *Peer) ShareNodes(timeout time.Duration) ([]string, error) {
	r := RPCShareNodes{}
	err := p.callRPC(&r, timeout)
	return r.Peers, err
}

// DiscoverIP requests our external IP as seen by the peer.
func (p *Peer) DiscoverIP(timeout time.Duration) (string, error) {
	r := RPCDiscoverIP{}
	err := p.callRPC(&r, timeout)
	return r.IP, err
}

// SendBlock requests a single block from the peer.
func (p *Peer) SendBlock(id types.BlockID, timeout time.Duration) (types.Block, error) {
	r := RPCSendBlk{ID: id}
	err := p.callRPC(&r, timeout)
	return r.Block, err
}

// RelayHeader relays a header to the peer.
func (p *Peer) RelayHeader(h BlockHeader, timeout time.Duration) error {
	return p.callRPC(&RPCRelayHeader{Header: h}, timeout)
}

// RelayTransactionSet relays a transaction set to the peer.
func (p *Peer) RelayTransactionSet(txns []types.Transaction, timeout time.Duration) error {
	return p.callRPC(&RPCRelayTransactionSet{Transactions: txns}, timeout)
}

// SendBlocks downloads blocks from p, starting from the most recent element of
// history known to p. The blocks are sent in batches, and fn is called on each
// batch.
func (p *Peer) SendBlocks(history [32]types.BlockID, timeout time.Duration, fn func([]types.Block) error) error {
	s, err := p.openStream()
	if err != nil {
		return fmt.Errorf("couldn't open stream: %w", err)
	}
	defer s.Close()

	s.SetDeadline(time.Now().Add(timeout))
	r := &RPCSendBlocks{History: history}
	id := v1RPCID(idForObject(r))
	if err := p.withEncoder(s, id.encodeTo); err != nil {
		return fmt.Errorf("couldn't write RPC ID: %w", err)
	} else if err := p.withEncoder(s, r.encodeRequest); err != nil {
		return fmt.Errorf("couldn't write request: %w", err)
	}

	r.MoreAvailable = true
	for r.MoreAvailable {
		s.SetDeadline(time.Now().Add(timeout))
		if err := p.withDecoder(s, r.maxBlocksResponseLen(), r.decodeBlocksResponse); err != nil {
			return fmt.Errorf("couldn't read response: %w", err)
		} else if err := p.withDecoder(s, r.maxMoreAvailableResponseLen(), r.decodeMoreAvailableResponse); err != nil {
			return fmt.Errorf("couldn't read response: %w", err)
		} else if err := fn(r.Blocks); err != nil {
			return err
		}
	}
	return nil
}

// SendTransactions requests a subset of a block's transactions from the peer.
func (p *Peer) SendTransactions(index types.ChainIndex, txnHashes []types.Hash256, timeout time.Duration) ([]types.Transaction, []types.V2Transaction, error) {
	r := RPCSendTransactions{Index: index, Hashes: txnHashes}
	err := p.callRPC(&r, timeout)
	return r.Transactions, r.V2Transactions, err
}

// SendCheckpoint requests a checkpoint from the peer. The checkpoint is
// validated.
func (p *Peer) SendCheckpoint(index types.ChainIndex, timeout time.Duration) (types.Block, consensus.State, error) {
	r := RPCSendCheckpoint{Index: index}
	err := p.callRPC(&r, timeout)
	if err == nil {
		if r.Block.V2 == nil || len(r.Block.MinerPayouts) != 1 {
			err = errors.New("checkpoint is not a v2 block")
		} else if (types.ChainIndex{ID: r.Block.ID()}) != index {
			err = errors.New("checkpoint has wrong index")
		} else if r.Block.V2.Commitment != r.State.Commitment(r.State.TransactionsCommitment(r.Block.Transactions, r.Block.V2Transactions()), r.Block.MinerPayouts[0].Address) {
			err = errors.New("checkpoint has wrong commitment")
		}
	}
	return r.Block, r.State, err
}

// RelayV2Header relays a v2 block header to the peer.
func (p *Peer) RelayV2Header(h V2BlockHeader, timeout time.Duration) error {
	return p.callRPC(&RPCRelayV2Header{Header: h}, timeout)
}

// RelayV2BlockOutline relays a v2 block outline to the peer.
func (p *Peer) RelayV2BlockOutline(b V2BlockOutline, timeout time.Duration) error {
	return p.callRPC(&RPCRelayV2BlockOutline{Block: b}, timeout)
}

// RelayV2TransactionSet relays a v2 transaction set to the peer.
func (p *Peer) RelayV2TransactionSet(txns []types.V2Transaction, timeout time.Duration) error {
	return p.callRPC(&RPCRelayV2TransactionSet{Transactions: txns}, timeout)
}

// SendV2Blocks requests up to n blocks from p, starting from the most recent
// element of history known to p. The peer also returns the number of remaining
// blocks left to sync.
func (p *Peer) SendV2Blocks(history []types.BlockID, max uint64, timeout time.Duration) ([]types.Block, uint64, error) {
	r := RPCSendV2Blocks{History: history, Max: max}
	err := p.callRPC(&r, timeout)
	return r.Blocks, r.Remaining, err
}

// AcceptRPC accepts an RPC initiated by the peer.
func (p *Peer) AcceptRPC() (types.Specifier, net.Conn, error) {
	s, err := p.acceptStream()
	if err != nil {
		return types.Specifier{}, nil, err
	}
	s.SetDeadline(time.Now().Add(5 * time.Second))
	var id types.Specifier
	if p.smux != nil {
		err = p.withDecoder(s, 8, (*v1RPCID)(&id).decodeFrom)
	} else {
		err = p.withDecoder(s, 16, id.DecodeFrom)
	}
	if err != nil {
		s.Close()
		return types.Specifier{}, nil, err
	}
	s.SetDeadline(time.Time{})
	return id, s, nil
}
