package merkle

import (
	"reflect"
	"testing"

	"go.sia.tech/core/types"
	"lukechampine.com/frand"
)

func TestUpdateLeaves(t *testing.T) {
	outputs := make([]types.SiacoinElement, 8)
	leaves := make([]ElementLeaf, len(outputs))
	for i := range outputs {
		leaves[i] = SiacoinLeaf(outputs[i], false)
	}
	var acc ElementAccumulator
	acc.addLeaves(leaves)
	for i := range outputs {
		outputs[i].StateElement = leaves[i].StateElement
	}

	updated := []ElementLeaf{
		SiacoinLeaf(outputs[0], true),
		SiacoinLeaf(outputs[2], true),
		SiacoinLeaf(outputs[3], true),
		SiacoinLeaf(outputs[5], true),
		SiacoinLeaf(outputs[6], true),
	}

	acc.updateLeaves(updated)

	var acc2 Accumulator
	addOutput := func(o types.SiacoinElement, spent bool) {
		// seek to first open slot, merging nodes as we go
		root := SiacoinLeaf(o, spent).Hash()
		i := 0
		for ; acc2.hasTreeAtHeight(i); i++ {
			root = NodeHash(acc2.Trees[i], root)
		}
		acc2.Trees[i] = root
		acc2.NumLeaves++
	}
	for i, o := range outputs {
		switch i {
		case 0, 2, 3, 5, 6:
			addOutput(o, true)
		default:
			addOutput(o, false)
		}
	}
	for i := range acc2.Trees {
		if acc2.hasTreeAtHeight(i) {
			if !acc2.hasTreeAtHeight(i) {
				t.Fatal("mismatch")
			}
			if acc2.Trees[i] != acc.Trees[i] {
				t.Fatal("mismatch")
			}
		}
	}
}

func TestMultiproof(t *testing.T) {
	outputs := make([]types.SiacoinElement, 8)
	leaves := make([]types.Hash256, len(outputs))
	for i := range outputs {
		outputs[i].LeafIndex = uint64(i)
		outputs[i].ID.Index = uint64(i)
		leaves[i] = SiacoinLeaf(outputs[i], false).Hash()
	}
	node01 := NodeHash(leaves[0], leaves[1])
	node23 := NodeHash(leaves[2], leaves[3])
	node45 := NodeHash(leaves[4], leaves[5])
	node67 := NodeHash(leaves[6], leaves[7])
	node03 := NodeHash(node01, node23)
	node47 := NodeHash(node45, node67)
	outputs[0].MerkleProof = []types.Hash256{leaves[1], node23, node47}
	outputs[1].MerkleProof = []types.Hash256{leaves[0], node23, node47}
	outputs[2].MerkleProof = []types.Hash256{leaves[3], node01, node47}
	outputs[3].MerkleProof = []types.Hash256{leaves[2], node01, node47}
	outputs[4].MerkleProof = []types.Hash256{leaves[5], node67, node03}
	outputs[5].MerkleProof = []types.Hash256{leaves[4], node67, node03}
	outputs[6].MerkleProof = []types.Hash256{leaves[7], node45, node03}
	outputs[7].MerkleProof = []types.Hash256{leaves[6], node45, node03}

	tests := []struct {
		inputs []int
		proof  []types.Hash256
	}{
		{
			inputs: []int{0},
			proof:  []types.Hash256{leaves[1], node23, node47},
		},
		{
			inputs: []int{1, 2, 3},
			proof:  []types.Hash256{leaves[0], node47},
		},
		{
			inputs: []int{7, 6, 0, 2, 3},
			proof:  []types.Hash256{leaves[1], node45},
		},
		{
			inputs: []int{7, 6, 5, 4, 3, 2, 1, 0},
			proof:  nil,
		},
	}
	for _, test := range tests {
		txns := []types.Transaction{{SiacoinInputs: make([]types.SiacoinInput, len(test.inputs))}}
		for i, j := range test.inputs {
			txns[0].SiacoinInputs[i].Parent = outputs[j]
		}

		old := txns[0].DeepCopy()
		// compute multiproof
		proof := ComputeMultiproof(txns)
		if !reflect.DeepEqual(proof, test.proof) {
			t.Error("wrong proof generated")
		}
		for _, txn := range txns {
			for i := range txn.SiacoinInputs {
				txn.SiacoinInputs[i].Parent.MerkleProof = make([]types.Hash256, len(txn.SiacoinInputs[i].Parent.MerkleProof))
			}
		}
		// expand multiproof and check roundtrip
		ExpandMultiproof(txns, proof)
		if !reflect.DeepEqual(txns[0], old) {
			t.Fatal("\n", txns[0], "\n", old)
		}
	}
}

func BenchmarkSiacoinLeafHash(b *testing.B) {
	var o types.SiacoinElement
	for i := 0; i < b.N; i++ {
		SiacoinLeaf(o, false).Hash()
	}
}

func BenchmarkUpdateExistingObjects(b *testing.B) {
	outputs := make([]types.SiacoinElement, 1000)
	leaves := make([]ElementLeaf, len(outputs))
	for i := range outputs {
		leaves[i] = SiacoinLeaf(outputs[i], false)
	}
	var acc ElementAccumulator
	acc.addLeaves(leaves)
	for i := range outputs {
		outputs[i].StateElement = leaves[i].StateElement
	}

	proofs := make([][]types.Hash256, len(outputs))
	for i := range proofs {
		proofs[i] = append([]types.Hash256(nil), outputs[i].MerkleProof...)
	}
	indices := frand.Perm(len(outputs))[:len(outputs)/2]
	updated := make([]ElementLeaf, len(indices))
	for i, j := range indices {
		updated[i] = SiacoinLeaf(outputs[j], true)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// reset everything
		b.StopTimer()
		acc2 := acc
		for i, j := range indices {
			copy(updated[i].MerkleProof, proofs[j])
		}
		b.StartTimer()

		acc2.updateLeaves(updated)
	}
}
