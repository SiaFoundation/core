package types

import (
	"encoding/binary"
	"errors"
	"math/bits"
	"sort"

	"go.sia.tech/core/internal/blake2b"
)

// copied from consensus/merkle.go

type elementLeaf struct {
	*StateElement
	ElementHash Hash256
}

func (l elementLeaf) hash() Hash256 {
	buf := make([]byte, 1+32+8+1)
	buf[0] = 0x00 // leafHashPrefix
	copy(buf[1:], l.ElementHash[:])
	binary.LittleEndian.PutUint64(buf[33:], l.LeafIndex)
	buf[41] = 0 // spent (always false for multiproofs)
	return HashBytes(buf)
}

func chainIndexLeaf(e *ChainIndexElement) elementLeaf {
	elemHash := hashAll("leaf/chainindex", e.ID, e.ChainIndex)
	return elementLeaf{&e.StateElement, elemHash}
}

func siacoinLeaf(e *SiacoinElement) elementLeaf {
	elemHash := hashAll("leaf/siacoin", e.ID, e.SiacoinOutput, e.MaturityHeight)
	return elementLeaf{&e.StateElement, elemHash}
}

func siafundLeaf(e *SiafundElement) elementLeaf {
	elemHash := hashAll("leaf/siafund", e.ID, e.SiafundOutput, e.ClaimStart)
	return elementLeaf{&e.StateElement, elemHash}
}

func v2FileContractLeaf(e *V2FileContractElement) elementLeaf {
	elemHash := hashAll("leaf/v2filecontract", e.ID, e.V2FileContract)
	return elementLeaf{&e.StateElement, elemHash}
}

func splitLeaves(ls []elementLeaf, mid uint64) (left, right []elementLeaf) {
	split := sort.Search(len(ls), func(i int) bool { return ls[i].LeafIndex >= mid })
	return ls[:split], ls[split:]
}

func forEachStateElement(txns []V2Transaction, fn func(*StateElement)) {
	for _, txn := range txns {
		for i := range txn.SiacoinInputs {
			fn(&txn.SiacoinInputs[i].Parent.StateElement)
		}
		for i := range txn.SiafundInputs {
			fn(&txn.SiafundInputs[i].Parent.StateElement)
		}
		for i := range txn.FileContractRevisions {
			fn(&txn.FileContractRevisions[i].Parent.StateElement)
		}
		for i := range txn.FileContractResolutions {
			fn(&txn.FileContractResolutions[i].Parent.StateElement)
			if sp, ok := txn.FileContractResolutions[i].Resolution.(*V2StorageProof); ok {
				fn(&sp.ProofIndex.StateElement)
			}
		}
	}
}

func forEachTree(txns []V2Transaction, fn func(i, j uint64, leaves []elementLeaf)) {
	clearBits := func(x uint64, n int) uint64 { return x &^ (1<<n - 1) }

	var trees [64][]elementLeaf
	addLeaf := func(l elementLeaf) {
		if l.LeafIndex != EphemeralLeafIndex {
			trees[len(l.MerkleProof)] = append(trees[len(l.MerkleProof)], l)
		}
	}
	for _, txn := range txns {
		for i := range txn.SiacoinInputs {
			addLeaf(siacoinLeaf(&txn.SiacoinInputs[i].Parent))
		}
		for i := range txn.SiafundInputs {
			addLeaf(siafundLeaf(&txn.SiafundInputs[i].Parent))
		}
		for i := range txn.FileContractRevisions {
			addLeaf(v2FileContractLeaf(&txn.FileContractRevisions[i].Parent))
		}
		for i := range txn.FileContractResolutions {
			addLeaf(v2FileContractLeaf(&txn.FileContractResolutions[i].Parent))
			if r, ok := txn.FileContractResolutions[i].Resolution.(*V2StorageProof); ok {
				addLeaf(chainIndexLeaf(&r.ProofIndex))
			}
		}
	}
	for height, leaves := range &trees {
		if len(leaves) == 0 {
			continue
		}
		sort.Slice(leaves, func(i, j int) bool {
			return leaves[i].LeafIndex < leaves[j].LeafIndex
		})
		start := clearBits(leaves[0].LeafIndex, height+1)
		end := start + 1<<height
		fn(start, end, leaves)
	}
}

// multiproofSize computes the size of a multiproof for the given transactions.
func multiproofSize(txns []V2Transaction) int {
	var proofSize func(i, j uint64, leaves []elementLeaf) int
	proofSize = func(i, j uint64, leaves []elementLeaf) int {
		height := bits.TrailingZeros64(j - i)
		if len(leaves) == 0 {
			return 1
		} else if height == 0 {
			return 0
		}
		mid := (i + j) / 2
		left, right := splitLeaves(leaves, mid)
		return proofSize(i, mid, left) + proofSize(mid, j, right)
	}

	size := 0
	forEachTree(txns, func(i, j uint64, leaves []elementLeaf) {
		size += proofSize(i, j, leaves)
	})
	return size
}

// computeMultiproof computes a single Merkle proof for all inputs in txns.
func computeMultiproof(txns []V2Transaction) (proof []Hash256) {
	var visit func(i, j uint64, leaves []elementLeaf)
	visit = func(i, j uint64, leaves []elementLeaf) {
		height := bits.TrailingZeros64(j - i)
		if height == 0 {
			return // fully consumed
		}
		mid := (i + j) / 2
		left, right := splitLeaves(leaves, mid)
		if len(left) == 0 {
			proof = append(proof, right[0].MerkleProof[height-1])
		} else {
			visit(i, mid, left)
		}
		if len(right) == 0 {
			proof = append(proof, left[0].MerkleProof[height-1])
		} else {
			visit(mid, j, right)
		}
	}

	forEachTree(txns, visit)
	return
}

// expandMultiproof restores all of the proofs with txns using the supplied
// multiproof, the length of which must equal multiproofSize(txns).
func expandMultiproof(txns []V2Transaction, proof []Hash256) {
	var visit func(i, j uint64, leaves []elementLeaf) Hash256
	visit = func(i, j uint64, leaves []elementLeaf) Hash256 {
		height := bits.TrailingZeros64(j - i)
		if len(leaves) == 0 {
			// no leaves in this subtree; must have a proof root
			h := proof[0]
			proof = proof[1:]
			return h
		} else if height == 0 {
			return leaves[0].hash()
		}
		mid := (i + j) / 2
		left, right := splitLeaves(leaves, mid)
		leftRoot := visit(i, mid, left)
		rightRoot := visit(mid, j, right)
		for i := range right {
			right[i].MerkleProof[height-1] = leftRoot
		}
		for i := range left {
			left[i].MerkleProof[height-1] = rightRoot
		}
		return blake2b.SumPair(leftRoot, rightRoot)
	}

	forEachTree(txns, func(i, j uint64, leaves []elementLeaf) {
		_ = visit(i, j, leaves)
	})
}

// V2TransactionsMultiproof is a slice of V2Transactions whose Merkle proofs are
// encoded as a single multiproof. This can significantly reduce the size of the
// encoded transactions. However, multiproofs may only be used for transaction
// sets whose Merkle proofs are all valid for the same consensus state.
type V2TransactionsMultiproof []V2Transaction

// EncodeTo implements types.EncoderTo.
func (txns V2TransactionsMultiproof) EncodeTo(e *Encoder) {
	var proofs [][]Hash256
	forEachStateElement(txns, func(se *StateElement) {
		proofs = append(proofs, se.MerkleProof)
		se.MerkleProof = nil
	})
	e.WritePrefix(len(txns))
	for i := range txns {
		txns[i].EncodeTo(e)
	}
	forEachStateElement(txns, func(se *StateElement) {
		se.MerkleProof = proofs[0]
		proofs = proofs[1:]
		e.WriteUint8(uint8(len(se.MerkleProof)))
	})
	multiproof := computeMultiproof(txns)
	for _, p := range multiproof {
		p.EncodeTo(e)
	}
}

// DecodeFrom implements types.DecoderFrom.
func (txns *V2TransactionsMultiproof) DecodeFrom(d *Decoder) {
	*txns = make(V2TransactionsMultiproof, d.ReadPrefix())
	for i := range *txns {
		(*txns)[i].DecodeFrom(d)
	}
	forEachStateElement(*txns, func(se *StateElement) {
		se.MerkleProof = make([]Hash256, d.ReadUint8())
		if len(se.MerkleProof) >= 64 {
			d.SetErr(errors.New("invalid Merkle proof size"))
		}
	})
	// multiproofSize and/or expandMultiproof will panic if the the transactions
	// are invalid, so bail out early if we've encountered an error
	if d.Err() != nil {
		return
	}
	multiproof := make([]Hash256, multiproofSize(*txns))
	for i := range multiproof {
		multiproof[i].DecodeFrom(d)
	}
	expandMultiproof(*txns, multiproof)
}
