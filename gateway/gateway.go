package gateway

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/internal/blake2b"
	"go.sia.tech/core/internal/smux"
	"go.sia.tech/core/types"
	"go.sia.tech/mux"
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

func writeHeader(conn net.Conn, ourHeader Header) error {
	var accept string
	if err := withV1Encoder(conn, ourHeader.encodeTo); err != nil {
		return fmt.Errorf("could not write our header: %w", err)
	} else if err := withV1Decoder(conn, 128, func(d *types.Decoder) { accept = d.ReadString() }); err != nil {
		return fmt.Errorf("could not read peer header acceptance: %w", err)
	} else if accept != "accept" {
		return fmt.Errorf("peer rejected our header: %v", accept)
	}
	return nil
}

func readHeader(conn net.Conn, ourHeader Header, dialAddr *string) error {
	var peerHeader Header
	if err := withV1Decoder(conn, 32+8+128, peerHeader.decodeFrom); err != nil {
		return fmt.Errorf("could not read peer's header: %w", err)
	} else if err := validateHeader(ourHeader, peerHeader); err != nil {
		withV1Encoder(conn, func(e *types.Encoder) { e.WriteString(err.Error()) })
		return fmt.Errorf("unacceptable header: %w", err)
	} else if err := withV1Encoder(conn, func(e *types.Encoder) { e.WriteString("accept") }); err != nil {
		return fmt.Errorf("could not write accept: %w", err)
	} else if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err != nil {
		return fmt.Errorf("invalid remote addr (%q): %w", conn.RemoteAddr(), err)
	} else if _, port, err := net.SplitHostPort(peerHeader.NetAddress); err != nil {
		return fmt.Errorf("peer provided invalid net address (%q): %w", peerHeader.NetAddress, err)
	} else {
		*dialAddr = net.JoinHostPort(host, port)
	}
	return nil
}

// A BlockHeader contains a Block's non-transaction data.
type BlockHeader struct {
	ParentID   types.BlockID
	Nonce      uint64
	Timestamp  time.Time
	MerkleRoot types.Hash256
}

// ID returns a hash that uniquely identifies the block.
func (h BlockHeader) ID() types.BlockID {
	buf := make([]byte, 32+8+8+32)
	copy(buf[:32], h.ParentID[:])
	binary.LittleEndian.PutUint64(buf[32:], h.Nonce)
	binary.LittleEndian.PutUint64(buf[40:], uint64(h.Timestamp.Unix()))
	copy(buf[48:], h.MerkleRoot[:])
	return types.BlockID(types.HashBytes(buf))
}

// A V2BlockHeader contains a V2Block's non-transaction data.
type V2BlockHeader struct {
	Parent           types.ChainIndex
	Nonce            uint64
	Timestamp        time.Time
	TransactionsRoot types.Hash256
	MinerAddress     types.Address
}

// ID returns a hash that uniquely identifies the block.
func (h V2BlockHeader) ID(cs consensus.State) types.BlockID {
	return (&types.Block{
		Nonce:     h.Nonce,
		Timestamp: h.Timestamp,
		V2:        &types.V2BlockData{Commitment: cs.Commitment(h.TransactionsRoot, h.MinerAddress)},
	}).ID()
}

// An OutlineTransaction identifies a transaction by its full hash. The actual
// transaction data may or may not be present.
type OutlineTransaction struct {
	Hash          types.Hash256
	Transaction   *types.Transaction
	V2Transaction *types.V2Transaction
}

// A V2BlockOutline represents a Block with one or more transactions omitted.
// The original block can be reconstructed by matching the transaction hashes
// to transactions present in the txpool, or requesting them from peers.
type V2BlockOutline struct {
	Height       uint64
	ParentID     types.BlockID
	Nonce        uint64
	Timestamp    time.Time
	MinerAddress types.Address
	Transactions []OutlineTransaction
}

func (pb V2BlockOutline) commitment(cs consensus.State) types.Hash256 {
	var acc blake2b.Accumulator
	for _, txn := range pb.Transactions {
		acc.AddLeaf(txn.Hash)
	}
	return cs.Commitment(acc.Root(), pb.MinerAddress)
}

// ID returns a hash that uniquely identifies the block.
func (pb V2BlockOutline) ID(cs consensus.State) types.BlockID {
	return (&types.Block{
		Nonce:     pb.Nonce,
		Timestamp: pb.Timestamp,
		V2:        &types.V2BlockData{Commitment: pb.commitment(cs)},
	}).ID()
}

// Missing returns the hashes of transactions that are missing from the block.
func (pb V2BlockOutline) Missing() (missing []types.Hash256) {
	for _, txn := range pb.Transactions {
		if txn.Transaction == nil && txn.V2Transaction == nil {
			missing = append(missing, txn.Hash)
		}
	}
	return
}

// Complete attempts to reconstruct the original block using the supplied
// transactions. If the block cannot be fully reconstructed, it returns the
// hashes of the missing transactions.
func (pb *V2BlockOutline) Complete(cs consensus.State, txns []types.Transaction, v2txns []types.V2Transaction) (types.Block, []types.Hash256) {
	var v1hashes map[types.Hash256]types.Transaction
	var v2hashes map[types.Hash256]types.V2Transaction
	completeTxn := func(ptxn *OutlineTransaction) {
		if ptxn.Transaction != nil || ptxn.V2Transaction != nil {
			return
		}
		if v1hashes == nil {
			v1hashes = make(map[types.Hash256]types.Transaction, len(txns))
			for _, txn := range txns {
				v1hashes[txn.FullHash()] = txn
			}
		}
		if txn, ok := v1hashes[ptxn.Hash]; ok {
			ptxn.Transaction = &txn
			return
		}
		if v2hashes == nil {
			v2hashes = make(map[types.Hash256]types.V2Transaction, len(txns))
			for _, txn := range v2txns {
				v2hashes[txn.FullHash()] = txn
			}
		}
		if txn, ok := v2hashes[ptxn.Hash]; ok {
			ptxn.V2Transaction = &txn
			return
		}
	}

	b := types.Block{
		ParentID:     pb.ParentID,
		Nonce:        pb.Nonce,
		Timestamp:    pb.Timestamp,
		MinerPayouts: []types.SiacoinOutput{{Address: pb.MinerAddress, Value: cs.BlockReward()}},
		V2: &types.V2BlockData{
			Height:     pb.Height,
			Commitment: pb.commitment(cs),
		},
	}
	for i := range pb.Transactions {
		ptxn := &pb.Transactions[i]
		completeTxn(ptxn)
		if ptxn.Transaction != nil {
			b.Transactions = append(b.Transactions, *ptxn.Transaction)
			for _, fee := range ptxn.Transaction.MinerFees {
				b.MinerPayouts[0].Value = b.MinerPayouts[0].Value.Add(fee)
			}
		} else if ptxn.V2Transaction != nil {
			b.V2.Transactions = append(b.V2.Transactions, *ptxn.V2Transaction)
			b.MinerPayouts[0].Value = b.MinerPayouts[0].Value.Add(ptxn.V2Transaction.MinerFee)
		}
	}
	return b, pb.Missing()
}

// RemoveTransactions removes the specified transactions from the block.
func (pb *V2BlockOutline) RemoveTransactions(txns []types.Transaction, v2txns []types.V2Transaction) {
	remove := make(map[types.Hash256]bool)
	for _, txn := range txns {
		remove[txn.FullHash()] = true
	}
	for _, txn := range v2txns {
		remove[txn.FullHash()] = true
	}
	for i := range pb.Transactions {
		if remove[pb.Transactions[i].Hash] {
			pb.Transactions[i].Transaction = nil
			pb.Transactions[i].V2Transaction = nil
		}
	}
}

// Dial initiates the gateway handshake with a peer.
func Dial(conn net.Conn, ourHeader Header) (*Peer, error) {
	p := &Peer{
		ConnAddr: conn.RemoteAddr().String(),
		Inbound:  false,
	}

	// exchange versions
	const ourVersion = "2.0.0"
	if err := withV1Encoder(conn, func(e *types.Encoder) { e.WriteString(ourVersion) }); err != nil {
		return nil, fmt.Errorf("could not write our version: %w", err)
	} else if err := withV1Decoder(conn, 128, func(d *types.Decoder) { p.Version = d.ReadString() }); err != nil {
		return nil, fmt.Errorf("could not read peer version: %w", err)
	}
	// exchange headers
	if err := writeHeader(conn, ourHeader); err != nil {
		return nil, fmt.Errorf("could not write our header: %w", err)
	} else if err := readHeader(conn, ourHeader, &p.Addr); err != nil {
		return nil, fmt.Errorf("could not read peer's header: %w", err)
	}
	// establish mux
	var err error
	if strings.HasPrefix(p.Version, "1.") {
		p.smux, err = smux.Client(conn, nil)
	} else {
		p.mux, err = mux.DialAnonymous(conn)
	}
	return p, err
}

// Accept reciprocates the gateway handshake with a peer.
func Accept(conn net.Conn, ourHeader Header) (*Peer, error) {
	p := &Peer{
		ConnAddr: conn.RemoteAddr().String(),
		Inbound:  true,
	}

	// exchange versions
	const ourVersion = "2.0.0"
	if err := withV1Decoder(conn, 128, func(d *types.Decoder) { p.Version = d.ReadString() }); err != nil {
		return nil, fmt.Errorf("could not read peer version: %w", err)
	} else if err := withV1Encoder(conn, func(e *types.Encoder) { e.WriteString(ourVersion) }); err != nil {
		return nil, fmt.Errorf("could not write our version: %w", err)
	}
	// exchange headers
	if err := readHeader(conn, ourHeader, &p.Addr); err != nil {
		return nil, fmt.Errorf("could not read peer's header: %w", err)
	} else if err := writeHeader(conn, ourHeader); err != nil {
		return nil, fmt.Errorf("could not write our header: %w", err)
	}
	// establish mux
	var err error
	if strings.HasPrefix(p.Version, "1.") {
		p.smux, err = smux.Server(conn, nil)
	} else {
		p.mux, err = mux.AcceptAnonymous(conn)
	}
	return p, err
}
