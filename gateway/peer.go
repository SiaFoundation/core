package gateway

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"go.sia.tech/core/internal/smux"
	"go.sia.tech/core/types"
	"lukechampine.com/frand"
)

// A UniqueID is a randomly-generated nonce that helps prevent self-connections
// and double-connections.
type UniqueID [8]byte

// GenerateUniqueID returns a random UniqueID.
func GenerateUniqueID() (id UniqueID) {
	frand.Read(id[:])
	return
}

// A Header contains various peer metadata which is exchanged during the gateway
// handshake.
type Header struct {
	GenesisID  types.BlockID
	UniqueID   UniqueID
	NetAddress string
}

func validateHeader(ours, theirs Header) error {
	if theirs.GenesisID != ours.GenesisID {
		return errors.New("peer has different genesis block")
	} else if theirs.UniqueID == ours.UniqueID {
		return errors.New("peer has same unique ID as us")
	}
	return nil
}

// A Peer is a connected gateway peer.
type Peer struct {
	Addr    string
	Inbound bool
	Version string
	mux     *smux.Session
	mu      sync.Mutex
	err     error
}

// String implements fmt.Stringer.
func (p *Peer) String() string {
	if p.Inbound {
		return "<-" + p.Addr
	}
	return "->" + p.Addr
}

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
		p.mux.Close()
	}
	return p.err
}

// An RPCHandler handles RPCs received from a peer.
type RPCHandler interface {
	PeersForShare() []string
	Block(id types.BlockID) (types.Block, error)
	BlocksForHistory(history [32]types.BlockID) ([]types.Block, bool, error)
	RelayHeader(h types.BlockHeader, origin *Peer)
	RelayTransactionSet(txns []types.Transaction, origin *Peer)
}

// HandleRPC handles an RPC received from the peer.
func (p *Peer) HandleRPC(id types.Specifier, stream net.Conn, h RPCHandler) error {
	switch r := objectForID(rpcID(id)).(type) {
	case *RPCShareNodes:
		r.Peers = h.PeersForShare()
		if err := withEncoder(stream, r.encodeResponse); err != nil {
			return err
		}
		return nil
	case *RPCDiscoverIP:
		r.IP, _, _ = net.SplitHostPort(p.Addr)
		if err := withEncoder(stream, r.encodeResponse); err != nil {
			return err
		}
		return nil
	case *RPCRelayHeader:
		if err := withDecoder(stream, r.maxRequestLen(), r.decodeRequest); err != nil {
			return err
		}
		h.RelayHeader(r.Header, p)
		return nil
	case *RPCRelayTransactionSet:
		if err := withDecoder(stream, r.maxRequestLen(), r.decodeRequest); err != nil {
			return err
		}
		h.RelayTransactionSet(r.Transactions, p)
		return nil
	case *RPCSendBlk:
		err := withDecoder(stream, r.maxRequestLen(), r.decodeRequest)
		if err != nil {
			return err
		}
		r.Block, err = h.Block(r.ID)
		if err != nil {
			return err
		} else if err := withEncoder(stream, r.encodeResponse); err != nil {
			return err
		}
		return nil
	case *RPCSendBlocks:
		err := withDecoder(stream, r.maxRequestLen(), r.decodeRequest)
		if err != nil {
			return err
		}
		for {
			r.Blocks, r.MoreAvailable, err = h.BlocksForHistory(r.History)
			if err != nil {
				return err
			} else if err := withEncoder(stream, r.encodeBlocksResponse); err != nil {
				return err
			} else if err := withEncoder(stream, r.encodeMoreAvailableResponse); err != nil {
				return err
			} else if !r.MoreAvailable {
				return nil
			}
			r.History[0] = r.Blocks[len(r.Blocks)-1].ID()
		}
	default:
		return fmt.Errorf("unrecognized RPC: %q", id)
	}
}

func (p *Peer) callRPC(r object, timeout time.Duration) error {
	s, err := p.mux.OpenStream()
	if err != nil {
		return fmt.Errorf("couldn't open stream: %w", err)
	}
	defer s.Close()
	s.SetDeadline(time.Now().Add(timeout))
	id := idForObject(r)
	if err := withEncoder(s, id.encodeTo); err != nil {
		return fmt.Errorf("couldn't write RPC ID: %w", err)
	}
	if r.maxRequestLen() > 0 {
		if err := withEncoder(s, r.encodeRequest); err != nil {
			return fmt.Errorf("couldn't write request: %w", err)
		}
	}
	if r.maxResponseLen() > 0 {
		if err := withDecoder(s, r.maxResponseLen(), r.decodeResponse); err != nil {
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
func (p *Peer) RelayHeader(h types.BlockHeader, timeout time.Duration) error {
	return p.callRPC(&RPCRelayHeader{Header: h}, timeout)
}

// RelayTransactionSet relays a transaction set to the peer.
func (p *Peer) RelayTransactionSet(txns []types.Transaction, timeout time.Duration) error {
	return p.callRPC(&RPCRelayTransactionSet{Transactions: txns}, timeout)
}

// SendBlocks downloads blocks from p, starting from the most recent element of
// history known to p. The blocks are sent in batches, and fn is called on each
// batch.
func (p *Peer) SendBlocks(history [32]types.BlockID, fn func([]types.Block) error) error {
	s, err := p.mux.OpenStream()
	if err != nil {
		return fmt.Errorf("couldn't open stream: %w", err)
	}
	defer s.Close()

	s.SetDeadline(time.Now().Add(10 * time.Second))
	r := &RPCSendBlocks{History: history}
	id := idForObject(r)
	if err := withEncoder(s, id.encodeTo); err != nil {
		return fmt.Errorf("couldn't write RPC ID: %w", err)
	} else if err := withEncoder(s, r.encodeRequest); err != nil {
		return fmt.Errorf("couldn't write request: %w", err)
	}

	r.MoreAvailable = true
	for r.MoreAvailable {
		s.SetDeadline(time.Now().Add(120 * time.Second))
		if err := withDecoder(s, r.maxBlocksResponseLen(), r.decodeBlocksResponse); err != nil {
			return fmt.Errorf("couldn't read response2: %w", err)
		} else if err := withDecoder(s, r.maxMoreAvailableResponseLen(), r.decodeMoreAvailableResponse); err != nil {
			return fmt.Errorf("couldn't read response1: %w", err)
		} else if err := fn(r.Blocks); err != nil {
			return err
		}
	}
	return nil
}

// AcceptRPC accepts an RPC initiated by the peer.
func (p *Peer) AcceptRPC() (types.Specifier, net.Conn, error) {
	s, err := p.mux.AcceptStream()
	if err != nil {
		return types.Specifier{}, nil, err
	}
	s.SetDeadline(time.Now().Add(5 * time.Second))
	var id types.Specifier
	if err := withDecoder(s, 8, (*rpcID)(&id).decodeFrom); err != nil {
		s.Close()
		return types.Specifier{}, nil, err
	}
	s.SetDeadline(time.Time{})
	return id, s, nil
}

// DialPeer initiates the gateway handshake with a peer.
func DialPeer(conn net.Conn, ourHeader Header) (_ *Peer, err error) {
	// exchange versions
	ourVersion := "1.5.5"
	var theirVersion string
	if err := withEncoder(conn, func(e *types.Encoder) { e.WriteString(ourVersion) }); err != nil {
		return nil, fmt.Errorf("could not write our version: %w", err)
	} else if err := withDecoder(conn, 128, func(d *types.Decoder) { theirVersion = d.ReadString() }); err != nil {
		return nil, fmt.Errorf("could not read peer version: %w", err)
	}
	// NOTE: we assume that the peer will be compatible, so we don't bother
	// validating the version

	// exchange headers
	var accept string
	var peerHeader Header
	if err := withEncoder(conn, ourHeader.encodeTo); err != nil {
		return nil, fmt.Errorf("could not write our header: %w", err)
	} else if err := withDecoder(conn, 128, func(d *types.Decoder) { accept = d.ReadString() }); err != nil {
		return nil, fmt.Errorf("could not read peer version: %w", err)
	} else if accept != "accept" {
		return nil, fmt.Errorf("peer rejected our header: %v", accept)
	} else if err := withDecoder(conn, 32+8+128, peerHeader.decodeFrom); err != nil {
		return nil, fmt.Errorf("could not read peer's header: %w", err)
	} else if err := validateHeader(ourHeader, peerHeader); err != nil {
		withEncoder(conn, func(e *types.Encoder) { e.WriteString(err.Error()) })
		return nil, fmt.Errorf("unacceptable header: %w", err)
	} else if err := withEncoder(conn, func(e *types.Encoder) { e.WriteString("accept") }); err != nil {
		return nil, fmt.Errorf("could not write accept: %w", err)
	}

	// establish mux session
	m, err := smux.Client(conn, nil)
	if err != nil {
		return nil, err
	}

	return &Peer{
		Addr:    conn.RemoteAddr().String(),
		Inbound: false,
		Version: theirVersion,
		mux:     m,
	}, nil
}

// AcceptPeer reciprocates the gateway handshake with a peer.
func AcceptPeer(conn net.Conn, ourHeader Header) (_ *Peer, err error) {
	// exchange versions
	ourVersion := "1.5.5"
	var theirVersion string
	if err := withDecoder(conn, 128, func(d *types.Decoder) { theirVersion = d.ReadString() }); err != nil {
		return nil, fmt.Errorf("could not read peer version: %w", err)
	} else if err := withEncoder(conn, func(e *types.Encoder) { e.WriteString(ourVersion) }); err != nil {
		return nil, fmt.Errorf("could not write our version: %w", err)
	}
	// NOTE: we assume that the peer will be compatible, so we don't bother
	// validating the version

	// exchange headers
	var accept string
	var peerHeader Header
	if err := withDecoder(conn, 32+8+128, peerHeader.decodeFrom); err != nil {
		return nil, fmt.Errorf("could not read peer's header: %w", err)
	} else if err := validateHeader(ourHeader, peerHeader); err != nil {
		withEncoder(conn, func(e *types.Encoder) { e.WriteString(err.Error()) })
		return nil, fmt.Errorf("unacceptable header: %w", err)
	} else if err := withEncoder(conn, func(e *types.Encoder) { e.WriteString("accept") }); err != nil {
		return nil, fmt.Errorf("could not write accept: %w", err)
	} else if err := withEncoder(conn, ourHeader.encodeTo); err != nil {
		return nil, fmt.Errorf("could not write our header: %w", err)
	} else if err := withDecoder(conn, 128, func(d *types.Decoder) { accept = d.ReadString() }); err != nil {
		return nil, fmt.Errorf("could not read peer version: %w", err)
	} else if accept != "accept" {
		return nil, fmt.Errorf("peer rejected our header: %v", accept)
	}

	// establish mux session
	m, err := smux.Server(conn, nil)
	if err != nil {
		return nil, err
	}

	return &Peer{
		Addr:    conn.RemoteAddr().String(),
		Inbound: true,
		Version: theirVersion,
		mux:     m,
	}, nil
}
