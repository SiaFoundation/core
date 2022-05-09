package merkle

import (
	"reflect"
	"testing"

	"go.sia.tech/core/types"

	"lukechampine.com/frand"
)

func TestUpdateLeavesSiacoin(t *testing.T) {
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
	for _, leaf := range leaves {
		if !acc.containsLeaf(leaf) {
			t.Fatal("accumulator missing leaf that was added to it")
		}
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
			if !acc.ContainsSpentSiacoinElement(o) {
				t.Fatal("accumulator missing spent siacoin element")
			}
		default:
			addOutput(o, false)
			if acc.ContainsSpentSiacoinElement(o) {
				t.Fatal("accumulator missing unspent siacoin element")
			}
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

func TestUpdateLeavesSiafund(t *testing.T) {
	outputs := make([]types.SiafundElement, 8)
	leaves := make([]ElementLeaf, len(outputs))
	for i := range outputs {
		leaves[i] = SiafundLeaf(outputs[i], false)
	}
	var acc ElementAccumulator
	acc.addLeaves(leaves)
	for i := range outputs {
		outputs[i].StateElement = leaves[i].StateElement
	}
	for _, leaf := range leaves {
		if !acc.containsLeaf(leaf) {
			t.Fatal("accumulator missing leaf that was added to it")
		}
	}

	updated := []ElementLeaf{
		SiafundLeaf(outputs[0], true),
		SiafundLeaf(outputs[2], true),
		SiafundLeaf(outputs[3], true),
		SiafundLeaf(outputs[5], true),
		SiafundLeaf(outputs[6], true),
	}

	acc.updateLeaves(updated)

	var acc2 Accumulator
	addOutput := func(o types.SiafundElement, spent bool) {
		// seek to first open slot, merging nodes as we go
		root := SiafundLeaf(o, spent).Hash()
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
			if !acc.ContainsSpentSiafundElement(o) {
				t.Fatal("accumulator missing spent siafund element")
			}
		default:
			addOutput(o, false)
			if acc.ContainsSpentSiafundElement(o) {
				t.Fatal("accumulator missing unspent siafund element")
			}
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

func TestApplyBlock(t *testing.T) {
	// create some elements and add them to the initial accumulator
	sces := make([]types.SiacoinElement, 7)
	sfes := make([]types.SiafundElement, 7)
	fces := make([]types.FileContractElement, 7)
	leaves := make([]ElementLeaf, 0, len(sces)+len(sfes)+len(fces))
	for i := range sces {
		sces[i].ID.Index = uint64(len(leaves))
		leaves = append(leaves, SiacoinLeaf(sces[i], false))
	}
	for i := range sfes {
		sfes[i].ID.Index = uint64(len(leaves))
		leaves = append(leaves, SiafundLeaf(sfes[i], false))
	}
	for i := range fces {
		fces[i].ID.Index = uint64(len(leaves))
		leaves = append(leaves, FileContractLeaf(fces[i], false))
	}
	var acc ElementAccumulator
	acc.NumLeaves = 6
	acc.ApplyBlock(nil, leaves)
	for i := range sces {
		sces[i].StateElement = leaves[i].StateElement
	}
	for i := range sfes {
		sfes[i].StateElement = leaves[len(sces)+i].StateElement
	}
	for i := range fces {
		fces[i].StateElement = leaves[len(sces)+len(sfes)+i].StateElement
	}
	// all leaves should be present in the accumulator
	for _, sce := range sces {
		if !acc.ContainsUnspentSiacoinElement(sce) || acc.ContainsSpentSiacoinElement(sce) {
			t.Fatal("unspent siacoin element should be reflected in accumulator")
		}
	}
	for _, sfe := range sfes {
		if !acc.ContainsUnspentSiafundElement(sfe) || acc.ContainsSpentSiafundElement(sfe) {
			t.Fatal("unspent siafund element should be reflected in accumulator")
		}
	}
	for _, fce := range fces {
		if !acc.ContainsUnresolvedFileContractElement(fce) || acc.ContainsResolvedFileContractElement(fce) {
			t.Fatal("unresolved file contract should be reflected in accumulator")
		}
	}

	// mark some of the leaves as spent
	spent := []ElementLeaf{
		SiacoinLeaf(sces[0], true),
		SiafundLeaf(sfes[0], true),
		FileContractLeaf(fces[0], true),
	}
	// acc and elements will be modified; save copies for later
	oldAcc := acc
	oldSpent := append([]ElementLeaf(nil), spent...)
	for i := range oldSpent {
		oldSpent[i].MerkleProof = append([]types.Hash256(nil), oldSpent[i].MerkleProof...)
	}
	eau := acc.ApplyBlock(spent, nil)
	// update proofs
	for i := range sces {
		eau.UpdateElementProof(&sces[i].StateElement)
	}
	for i := range sfes {
		eau.UpdateElementProof(&sfes[i].StateElement)
	}
	for i := range fces {
		eau.UpdateElementProof(&fces[i].StateElement)
	}
	// the spent leaves should be marked as such in the accumulator
	if !acc.ContainsSpentSiacoinElement(sces[0]) || acc.ContainsUnspentSiacoinElement(sces[0]) {
		t.Fatal("spent siacoin element should be reflected in accumulator")
	}
	if !acc.ContainsSpentSiafundElement(sfes[0]) || acc.ContainsUnspentSiafundElement(sfes[0]) {
		t.Fatal("spent siafund element should be reflected in accumulator")
	}
	if !acc.ContainsResolvedFileContractElement(fces[0]) || acc.ContainsUnresolvedFileContractElement(fces[0]) {
		t.Fatal("resolved file contract should be reflected in accumulator")
	}
	// other leaves should still be unspent
	for _, sce := range sces[1:] {
		if !acc.ContainsUnspentSiacoinElement(sce) || acc.ContainsSpentSiacoinElement(sce) {
			t.Fatal("unspent siacoin element should be reflected in accumulator")
		}
	}
	for _, sfe := range sfes[1:] {
		if !acc.ContainsUnspentSiafundElement(sfe) || acc.ContainsSpentSiafundElement(sfe) {
			t.Fatal("unspent siafund element should be reflected in accumulator")
		}
	}
	for _, fce := range fces[1:] {
		if !acc.ContainsUnresolvedFileContractElement(fce) || acc.ContainsResolvedFileContractElement(fce) {
			t.Fatal("unresolved file contract should be reflected in accumulator")
		}
	}

	// restore old copies and revert the block
	acc = oldAcc
	spent = oldSpent
	for i := range spent {
		spent[i].Spent = false
	}
	eru := acc.RevertBlock(spent)
	// update proofs
	for i := range sces {
		eru.UpdateElementProof(&sces[i].StateElement)
	}
	for i := range sfes {
		eru.UpdateElementProof(&sfes[i].StateElement)
	}
	for i := range fces {
		eru.UpdateElementProof(&fces[i].StateElement)
	}

	// all leaves should be unspent again
	for _, sce := range sces {
		if !acc.ContainsUnspentSiacoinElement(sce) || acc.ContainsSpentSiacoinElement(sce) {
			t.Fatal("unspent siacoin element should be reflected in accumulator")
		}
	}
	for _, sfe := range sfes {
		if !acc.ContainsUnspentSiafundElement(sfe) || acc.ContainsSpentSiafundElement(sfe) {
			t.Fatal("unspent siafund element should be reflected in accumulator")
		}
	}
	for _, fce := range fces {
		if !acc.ContainsUnresolvedFileContractElement(fce) || acc.ContainsResolvedFileContractElement(fce) {
			t.Fatal("unresolved file contract should be reflected in accumulator")
		}
	}
}

func TestHistoryAccumulator(t *testing.T) {
	blocks := make([]types.ChainIndex, 16)
	for i := range blocks {
		blocks[i].Height = uint64(i)
		frand.Read(blocks[i].ID[:])
	}

	// test every subset of blocks 0..n
	for n := 1; n < len(blocks); n++ {
		// insert blocks into accumulator
		var acc HistoryAccumulator
		var accs []HistoryAccumulator
		proofs := make([][]types.Hash256, n)
		for i, index := range blocks[:n] {
			accs = append(accs, acc)
			hau := acc.ApplyBlock(index)
			proofs[i] = hau.HistoryProof()
			for j := 0; j < i; j++ {
				hau.UpdateProof(&proofs[j])
			}
		}
		// check that all blocks are present
		for i, index := range blocks[:n] {
			if !acc.Contains(index, proofs[i]) {
				t.Fatal("history accumulator missing block")
			}
		}
		// check that using the wrong proof doesn't work
		for _, proof := range proofs[1:] {
			if acc.Contains(blocks[0], proof) {
				t.Fatal("history accumulator claims to contain block with wrong proof")
			}
		}

		// revert each block
		for i := n - 1; i >= 0; i-- {
			// revert latest block
			acc := accs[i]
			eru := acc.RevertBlock(blocks[i])
			// update proofs of remaining blocks
			for j := 0; j < i; j++ {
				eru.UpdateProof(uint64(j), &proofs[j])
			}
			// check that blocks < i are still present, and blocks >= i are not
			for j, index := range blocks[:n] {
				if j < i && !acc.Contains(index, proofs[j]) {
					t.Fatal("history accumulator missing block")
				} else if acc.Contains(index, proofs[i]) {
					t.Fatal("history accumulator contains reverted block")
				}
			}
		}
	}
}

func TestMarshalJSON(t *testing.T) {
	eq := func(a, b HistoryAccumulator) bool {
		if a.NumLeaves != b.NumLeaves {
			return false
		}
		for i := range a.Trees {
			if a.hasTreeAtHeight(i) && a.Trees[i] != b.Trees[i] {
				return false
			}
		}
		return true
	}
	var ha HistoryAccumulator
	for i := 0; i < 16; i++ {
		ha.ApplyBlock(types.ChainIndex{Height: uint64(i)})
		js, _ := ha.MarshalJSON()
		var ha2 HistoryAccumulator
		if err := ha2.UnmarshalJSON(js); err != nil {
			t.Fatal(err)
		} else if !eq(ha, ha2) {
			t.Fatal("accumulator marshal/unmarshal failed")
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
