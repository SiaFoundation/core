package types

import (
	"testing"

	"go.sia.tech/core/blake2b"
	"lukechampine.com/frand"
)

// TestStratumBlockMerkleRoot tests the merkle root logic for
// stratum miners to ensure it is compatible with existing
// hardware.
func TestStratumBlockMerkleRoot(t *testing.T) {
	minerPayouts := make([]SiacoinOutput, frand.Intn(100))
	txns := make([]Transaction, frand.Intn(100))
	for i := range minerPayouts {
		minerPayouts[i].Address = frand.Entropy256()
		minerPayouts[i].Value = NewCurrency64(frand.Uint64n(100))
	}
	for i := range txns {
		txns[i].ArbitraryData = [][]byte{frand.Bytes(32)}
	}

	h := hasherPool.Get().(*Hasher)
	defer hasherPool.Put(h)
	var acc blake2b.Accumulator
	for _, mp := range minerPayouts {
		h.Reset()
		h.E.WriteUint8(leafHashPrefix)
		V1SiacoinOutput(mp).EncodeTo(h.E)
		acc.AddLeaf(h.Sum())
	}
	for _, txn := range txns {
		h.Reset()
		h.E.WriteUint8(leafHashPrefix)
		txn.EncodeTo(h.E)
		acc.AddLeaf(h.Sum())
	}

	var trees []Hash256
	for i, root := range acc.Trees {
		if acc.NumLeaves&(1<<i) != 0 {
			trees = append(trees, root)
		}
	}

	coinbaseTxn := Transaction{
		ArbitraryData: [][]byte{[]byte("hello, world!")},
	}
	h.Reset()
	h.E.WriteUint8(0x00)
	coinbaseTxn.EncodeTo(h.E)
	root := h.Sum()

	for _, tree := range trees {
		root = blake2b.SumPair(tree, root)
	}

	expectedRoot := blockMerkleRoot(minerPayouts, append(txns, coinbaseTxn))
	if root != expectedRoot {
		t.Fatalf("expected %x, got %x", expectedRoot, root)
	}
}
