package consensus

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/bits"
	"math/rand/v2"
	"slices"
	"testing"

	"go.sia.tech/core/blake2b"
	"go.sia.tech/core/types"
)

func testElementLeaves(n int) []elementLeaf {
	leaves := make([]elementLeaf, n)
	for i := range leaves {
		leaves[i] = elementLeaf{
			StateElement: &types.StateElement{LeafIndex: uint64(i)},
			elementHash:  types.Hash256{byte(i), byte(i >> 8), 0xA5},
		}
	}
	return leaves
}

// referenceElementAccumulator constructs every node of the forest, bottom-up,
// without using the accumulator's insertion or proof-update algorithms.
func referenceElementAccumulator(leaves []elementLeaf) (ElementAccumulator, [][]types.Hash256) {
	acc := ElementAccumulator{NumLeaves: uint64(len(leaves))}
	proofs := make([][]types.Hash256, len(leaves))
	for start := 0; start < len(leaves); {
		height := bits.Len(uint(len(leaves)-start)) - 1
		size := 1 << height
		nodes := make([]types.Hash256, size)
		for i := range nodes {
			nodes[i] = leaves[start+i].hash()
		}
		for level := 0; len(nodes) > 1; level++ {
			for i := range size {
				proofs[start+i] = append(proofs[start+i], nodes[(i>>level)^1])
			}
			parents := make([]types.Hash256, len(nodes)/2)
			for i := range parents {
				parents[i] = blake2b.SumPair(nodes[2*i], nodes[2*i+1])
			}
			nodes = parents
		}
		acc.Trees[height] = nodes[0]
		start += size
	}
	return acc, proofs
}

func checkElementAccumulator(t *testing.T, acc, expected ElementAccumulator, leaves []elementLeaf, proofs [][]types.Hash256) {
	t.Helper()
	if acc.NumLeaves != expected.NumLeaves {
		t.Fatalf("expected %v leaves, got %v", expected.NumLeaves, acc.NumLeaves)
	}
	for height := range acc.Trees {
		if acc.hasTreeAtHeight(height) && acc.Trees[height] != expected.Trees[height] {
			t.Fatalf("incorrect root at height %v", height)
		}
	}
	// A synthetic large forest may have reference proofs only for its suffix.
	firstIndex := expected.NumLeaves - uint64(len(proofs))
	for _, leaf := range leaves {
		index := leaf.LeafIndex - firstIndex
		if index >= uint64(len(proofs)) || !slices.Equal(leaf.MerkleProof, proofs[index]) {
			t.Fatalf("incorrect proof for leaf %v", leaf.LeafIndex)
		}
	}
}

func TestElementAccumulatorAddLeaves(t *testing.T) {
	for initial := 0; initial <= 64; initial++ {
		for _, added := range []int{0, 1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 64, 65} {
			t.Run(fmt.Sprintf("%v+%v", initial, added), func(t *testing.T) {
				leaves := testElementLeaves(initial + added)
				acc, oldProofs := referenceElementAccumulator(leaves[:initial])
				expected, proofs := referenceElementAccumulator(leaves)
				for i := range initial {
					leaves[i].MerkleProof = oldProofs[i]
				}
				for _, leaf := range leaves[initial:] {
					leaf.LeafIndex = types.UnassignedLeafIndex
				}
				growth := acc.addLeaves(leaves[initial:])
				for _, leaf := range leaves[:initial] {
					leaf.MerkleProof = append(leaf.MerkleProof, growth[len(leaf.MerkleProof)]...)
				}
				for i, leaf := range leaves {
					if leaf.LeafIndex != uint64(i) {
						t.Fatalf("expected leaf index %v, got %v", i, leaf.LeafIndex)
					}
				}
				checkElementAccumulator(t, acc, expected, leaves, proofs)
			})
		}
	}
}

func TestElementAccumulatorApplyRevert(t *testing.T) {
	for _, initial := range []int{0, 1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65} {
		for _, added := range []int{0, 1, 3, 8, 17, 64} {
			for _, mode := range []string{"none", "single", "sparse", "all"} {
				t.Run(fmt.Sprintf("%v+%v/%v", initial, added, mode), func(t *testing.T) {
					leaves := testElementLeaves(initial + added)
					before, oldProofs := referenceElementAccumulator(leaves[:initial])
					var updated, reverted []elementLeaf
					// Descending indices exercise unsorted input, including updates
					// in different trees and sibling subtrees.
					for i := initial - 1; i >= 0; i-- {
						leaves[i].MerkleProof = slices.Clone(oldProofs[i])
						if mode == "all" || mode == "single" && i == initial/2 || mode == "sparse" && i%3 == 0 {
							old := leaves[i]
							se := old.StateElement.Copy()
							old.StateElement = &se
							reverted = append(reverted, old)
							leaves[i].spent = true
							leaves[i].elementHash[2]++
							updated = append(updated, leaves[i])
						}
					}
					expected, proofs := referenceElementAccumulator(leaves)
					acc := before
					au := acc.applyBlock(updated, leaves[initial:])
					checkElementAccumulator(t, acc, expected, updated, proofs)
					checkElementAccumulator(t, acc, expected, leaves[initial:], proofs)
					// Independently held proofs must update for both changed and
					// unchanged leaves, then return exactly to their original state.
					tracked := testElementLeaves(initial)
					for i := range tracked {
						tracked[i].MerkleProof = slices.Clone(oldProofs[i])
						au.updateElementProof(tracked[i].StateElement)
					}
					checkElementAccumulator(t, acc, expected, tracked, proofs)
					ru := before.revertBlock(reverted, nil)
					for _, leaf := range tracked {
						ru.updateElementProof(leaf.StateElement)
					}
					checkElementAccumulator(t, before, before, tracked, oldProofs)
				})
			}
		}
	}
}

func TestUpdateLeavesDuplicateIndex(t *testing.T) {
	leaves := testElementLeaves(8)
	_, proofs := referenceElementAccumulator(leaves)
	leaves[3].MerkleProof = proofs[3]
	duplicate := leaves[3]
	se := duplicate.StateElement.Copy()
	duplicate.StateElement = &se
	defer func() {
		if r := recover(); r != "consensus: multiple leaves with same accumulator index" {
			t.Fatalf("expected duplicate leaf panic, got %v", r)
		}
	}()
	updateLeaves([]elementLeaf{leaves[3], duplicate})
}

func TestUpdateProofPermutations(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for trial := range 20 {
		leaves := testElementLeaves(129)
		_, oldProofs := referenceElementAccumulator(leaves)
		var updated []elementLeaf
		for _, i := range rng.Perm(len(leaves))[:1+rng.IntN(len(leaves))] {
			leaves[i].MerkleProof = slices.Clone(oldProofs[i])
			leaves[i].spent = true
			updated = append(updated, leaves[i])
		}
		_, proofs := referenceElementAccumulator(leaves)
		trees := updateLeaves(updated)
		for _, group := range trees {
			for i := 1; i < len(group); i++ {
				if group[i-1].LeafIndex >= group[i].LeafIndex {
					t.Fatal("updated leaves are not sorted")
				}
			}
		}
		for i := range leaves {
			e := types.StateElement{LeafIndex: uint64(i), MerkleProof: slices.Clone(oldProofs[i])}
			updateProof(&e, &trees)
			if !slices.Equal(e.MerkleProof, proofs[i]) {
				t.Fatalf("trial %v: incorrect proof for leaf %v", trial, i)
			}
		}
	}
}

func TestUpdateJSONLeafOrder(t *testing.T) {
	leaves := testElementLeaves(8)
	_, proofs := referenceElementAccumulator(leaves)
	for i := range leaves {
		leaves[i].MerkleProof = proofs[i]
	}
	slices.Reverse(leaves)
	b, err := json.Marshal(applyUpdateJSON{UpdatedLeaves: map[int][]elementLeaf{3: leaves}})
	if err != nil {
		t.Fatal(err)
	}
	var au ApplyUpdate
	var ru RevertUpdate
	if err := au.UnmarshalJSON(b); err != nil {
		t.Fatal(err)
	} else if err := ru.UnmarshalJSON(b); err != nil {
		t.Fatal(err)
	}
	for _, updated := range []*[64][]elementLeaf{&au.eau.updated, &ru.eru.updated} {
		for i, leaf := range updated[3] {
			if leaf.LeafIndex != uint64(i) {
				t.Fatal("decoded updated leaves are not sorted")
			}
			e := types.StateElement{LeafIndex: uint64(i), MerkleProof: make([]types.Hash256, 3)}
			updateProof(&e, updated)
			if !slices.Equal(e.MerkleProof, proofs[i]) {
				t.Fatalf("incorrect proof for decoded leaf %v", i)
			}
		}
	}
}

func TestElementAccumulatorHighIndices(t *testing.T) {
	t.Run("above 2^63", func(t *testing.T) {
		const offset = uint64(1 << 63)
		leaves, tracked := testElementLeaves(17), testElementLeaves(13)
		for _, set := range [][]elementLeaf{leaves, tracked} {
			for _, leaf := range set {
				leaf.LeafIndex += offset
			}
		}
		before, oldProofs := referenceElementAccumulator(leaves[:13])
		before.NumLeaves += offset
		before.Trees[63] = types.Hash256{0xFF} // untouched tree below the offset
		for i := range tracked {
			leaves[i].MerkleProof = slices.Clone(oldProofs[i])
			tracked[i].MerkleProof = slices.Clone(oldProofs[i])
		}
		var updated, reverted []elementLeaf
		for _, i := range []int{12, 10, 7, 1} {
			old := tracked[i]
			se := old.StateElement.Copy()
			old.StateElement = &se
			reverted = append(reverted, old)
			leaves[i].spent = true
			updated = append(updated, leaves[i])
		}
		expected, proofs := referenceElementAccumulator(leaves)
		expected.NumLeaves += offset
		expected.Trees[63] = before.Trees[63]
		acc := before
		au := acc.applyBlock(updated, leaves[13:])
		checkElementAccumulator(t, acc, expected, updated, proofs)
		checkElementAccumulator(t, acc, expected, leaves[13:], proofs)
		for _, leaf := range tracked {
			au.updateElementProof(leaf.StateElement)
		}
		checkElementAccumulator(t, acc, expected, tracked, proofs)
		ru := before.revertBlock(reverted, nil)
		for _, leaf := range tracked {
			ru.updateElementProof(leaf.StateElement)
		}
		checkElementAccumulator(t, before, before, tracked, oldProofs)
	})
	t.Run("height 63 carry", func(t *testing.T) {
		acc := ElementAccumulator{NumLeaves: 1<<63 - 1}
		for height := range 63 {
			acc.Trees[height] = types.Hash256{byte(height), 0xA5}
		}
		leaves := testElementLeaves(1)
		leaves[0].LeafIndex = acc.NumLeaves
		proof := slices.Clone(acc.Trees[:63])
		root := leaves[0].hash()
		for _, sibling := range proof {
			root = blake2b.SumPair(sibling, root)
		}
		growth := acc.addLeaves(leaves)
		if acc.NumLeaves != 1<<63 || acc.Trees[63] != root || !slices.Equal(leaves[0].MerkleProof, proof) {
			t.Fatal("incorrect accumulator or proof after height 63 carry")
		}
		for height, sibling := range proof {
			// Treat each original tree as a leaf in the tree above it.
			index := (leaves[0].LeafIndex >> height) &^ 1
			if len(growth[height]) != 63-height || proofRoot(sibling, index, growth[height]) != root {
				t.Fatalf("incorrect growth at height %v", height)
			}
		}
		if len(growth[63]) != 0 {
			t.Fatal("unexpected growth of previously absent height 63 tree")
		}
	})
}

func TestElementAccumulatorEncoding(t *testing.T) {
	for _, test := range []struct {
		numLeaves uint64
		exp       string
	}{
		{0, `{"numLeaves":0,"trees":[]}`},
		{1, `{"numLeaves":1,"trees":["0000000000000000000000000000000000000000000000000000000000000000"]}`},
		{2, `{"numLeaves":2,"trees":["0100000000000000000000000000000000000000000000000000000000000000"]}`},
		{3, `{"numLeaves":3,"trees":["0000000000000000000000000000000000000000000000000000000000000000","0100000000000000000000000000000000000000000000000000000000000000"]}`},
		{10, `{"numLeaves":10,"trees":["0100000000000000000000000000000000000000000000000000000000000000","0300000000000000000000000000000000000000000000000000000000000000"]}`},
		{1 << 16, `{"numLeaves":65536,"trees":["1000000000000000000000000000000000000000000000000000000000000000"]}`},
		{1 << 32, `{"numLeaves":4294967296,"trees":["2000000000000000000000000000000000000000000000000000000000000000"]}`},
	} {
		acc := ElementAccumulator{NumLeaves: test.numLeaves}
		for i := range acc.Trees {
			if acc.hasTreeAtHeight(i) {
				acc.Trees[i][0] = byte(i)
			}
		}
		js, err := acc.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		if string(js) != test.exp {
			t.Errorf("expected %s, got %s", test.exp, js)
		}
		var acc2 ElementAccumulator
		if err := acc2.UnmarshalJSON(js); err != nil {
			t.Fatal(err)
		}
		if acc2 != acc {
			t.Fatal("round trip failed: expected", acc, "got", acc2)
		}
	}
}

func TestElementAccumulatorRoundTrip(t *testing.T) {
	leafData := []byte{0x01, 0x02, 0x03, 0x0A, 0x0B, 0x0C}
	leafHash := types.HashBytes(leafData)

	for _, numLeaves := range []uint64{0, 1, 2, 3, 10, 1 << 16, 1 << 32, 1 << 63} {
		acc := ElementAccumulator{NumLeaves: numLeaves}

		for i := 0; i < 64; i++ {
			if acc.hasTreeAtHeight(i) {
				acc.Trees[i] = leafHash
			}
		}

		var buf bytes.Buffer
		e := types.NewEncoder(&buf)
		acc.EncodeTo(e)
		if err := e.Flush(); err != nil {
			t.Fatalf("Unexpected error during encoding: %v", err)
		}

		encodedData := buf.Bytes()

		d := types.NewBufDecoder(encodedData)
		var decodedAcc ElementAccumulator
		decodedAcc.DecodeFrom(d)

		if decodedAcc.NumLeaves != acc.NumLeaves {
			t.Errorf("NumLeaves mismatch: got %d, expected %d", decodedAcc.NumLeaves, acc.NumLeaves)
		}

		for i, tree := range decodedAcc.Trees {
			if tree != acc.Trees[i] {
				t.Errorf("Tree mismatch at %d: got %v, expected %v", i, tree, acc.Trees[i])
			}
		}
	}
}

func TestUpdateElementProof(t *testing.T) {
	tests := []struct {
		name           string
		leafIndex      uint64
		numLeaves      uint64
		expectPanic    bool
		expectProofLen int
	}{
		{
			name:        "UnassignedLeafIndexPanic",
			leafIndex:   types.UnassignedLeafIndex,
			numLeaves:   5,
			expectPanic: true,
		},
		{
			name:        "LeafIndexOutOfRangePanic",
			leafIndex:   10,
			numLeaves:   5,
			expectPanic: true,
		},
		{
			name:           "ValidUpdate",
			leafIndex:      3,
			numLeaves:      5,
			expectPanic:    false,
			expectProofLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &types.StateElement{
				LeafIndex:   tt.leafIndex,
				MerkleProof: make([]types.Hash256, 3),
			}
			eru := &elementRevertUpdate{
				numLeaves: tt.numLeaves,
				updated:   [64][]elementLeaf{},
			}

			var didPanic bool
			func() {
				defer func() { didPanic = recover() != nil }()
				eru.updateElementProof(e)
			}()

			if didPanic != tt.expectPanic {
				t.Errorf("updateElementProof() didPanic = %v, want %v for %s", didPanic, tt.expectPanic, tt.name)
			}

			if !tt.expectPanic {
				if len(e.MerkleProof) != tt.expectProofLen {
					t.Errorf("%s: expected MerkleProof length %d, got %d", tt.name, tt.expectProofLen, len(e.MerkleProof))
				}
			}
		})
	}
}
