package gateway

import (
	"encoding/binary"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/internal/blake2b"
	"go.sia.tech/core/types"
)

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

func (bo V2BlockOutline) commitment(cs consensus.State) types.Hash256 {
	var acc blake2b.Accumulator
	for _, txn := range bo.Transactions {
		acc.AddLeaf(txn.Hash)
	}
	return cs.Commitment(acc.Root(), bo.MinerAddress)
}

// ID returns a hash that uniquely identifies the block.
func (bo V2BlockOutline) ID(cs consensus.State) types.BlockID {
	return (&types.Block{
		Nonce:     bo.Nonce,
		Timestamp: bo.Timestamp,
		V2:        &types.V2BlockData{Commitment: bo.commitment(cs)},
	}).ID()
}

// Missing returns the hashes of transactions that are missing from the block.
func (bo V2BlockOutline) Missing() (missing []types.Hash256) {
	for _, txn := range bo.Transactions {
		if txn.Transaction == nil && txn.V2Transaction == nil {
			missing = append(missing, txn.Hash)
		}
	}
	return
}

// Complete attempts to reconstruct the original block using the supplied
// transactions. If the block cannot be fully reconstructed, it returns the
// hashes of the missing transactions.
func (bo *V2BlockOutline) Complete(cs consensus.State, txns []types.Transaction, v2txns []types.V2Transaction) (types.Block, []types.Hash256) {
	v1hashes := make(map[types.Hash256]*types.Transaction, len(txns))
	for i := range txns {
		v1hashes[txns[i].FullHash()] = &txns[i]
	}
	v2hashes := make(map[types.Hash256]*types.V2Transaction, len(v2txns))
	for i := range v2txns {
		v2hashes[v2txns[i].FullHash()] = &v2txns[i]
	}

	b := types.Block{
		ParentID:     bo.ParentID,
		Nonce:        bo.Nonce,
		Timestamp:    bo.Timestamp,
		MinerPayouts: []types.SiacoinOutput{{Address: bo.MinerAddress, Value: cs.BlockReward()}},
		V2: &types.V2BlockData{
			Height:     bo.Height,
			Commitment: bo.commitment(cs),
		},
	}
	for i := range bo.Transactions {
		ptxn := &bo.Transactions[i]
		if ptxn.Transaction == nil && ptxn.V2Transaction == nil {
			ptxn.Transaction, ptxn.V2Transaction = v1hashes[ptxn.Hash], v2hashes[ptxn.Hash]
		}
		if ptxn.Transaction != nil {
			b.Transactions = append(b.Transactions, *ptxn.Transaction)
			b.MinerPayouts[0].Value = b.MinerPayouts[0].Value.Add(ptxn.Transaction.TotalFees())
		} else if ptxn.V2Transaction != nil {
			b.V2.Transactions = append(b.V2.Transactions, *ptxn.V2Transaction)
			b.MinerPayouts[0].Value = b.MinerPayouts[0].Value.Add(ptxn.V2Transaction.MinerFee)
		}
	}
	return b, bo.Missing()
}

// RemoveTransactions removes the specified transactions from the block.
func (bo *V2BlockOutline) RemoveTransactions(txns []types.Transaction, v2txns []types.V2Transaction) {
	remove := make(map[types.Hash256]bool)
	for _, txn := range txns {
		remove[txn.FullHash()] = true
	}
	for _, txn := range v2txns {
		remove[txn.FullHash()] = true
	}
	for i := range bo.Transactions {
		if remove[bo.Transactions[i].Hash] {
			bo.Transactions[i].Transaction = nil
			bo.Transactions[i].V2Transaction = nil
		}
	}
}

// OutlineBlock returns a block outline for b that omits the specified
// transactions.
func OutlineBlock(b types.Block, txns []types.Transaction, v2txns []types.V2Transaction) V2BlockOutline {
	var otxns []OutlineTransaction
	for i := range b.Transactions {
		otxns = append(otxns, OutlineTransaction{
			Hash:        b.Transactions[i].FullHash(),
			Transaction: &b.Transactions[i],
		})
	}
	for i := range b.V2Transactions() {
		otxns = append(otxns, OutlineTransaction{
			Hash:          b.V2.Transactions[i].FullHash(),
			V2Transaction: &b.V2.Transactions[i],
		})
	}
	bo := V2BlockOutline{
		Height:       b.V2.Height,
		ParentID:     b.ParentID,
		Nonce:        b.Nonce,
		Timestamp:    b.Timestamp,
		MinerAddress: b.MinerPayouts[0].Address,
		Transactions: otxns,
	}
	bo.RemoveTransactions(txns, v2txns)
	return bo
}
