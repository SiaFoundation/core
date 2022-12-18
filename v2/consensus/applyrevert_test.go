package consensus_test

import (
	"sort"
	"testing"

	"go.sia.tech/core/v2/consensus"
	"go.sia.tech/core/v2/internal/chainutil"
	"go.sia.tech/core/v2/types"
)

func TestApplyRevertBlock(t *testing.T) {
	// mine 100 blocks, then apply/revert them in a random walk, ensuring that
	// the results remain consistent

	sim := chainutil.NewChainSim()

	s := sim.State
	sau := consensus.GenesisUpdate(sim.Genesis.Block, s.Difficulty)
	var elems []types.StateElement
	for _, sce := range sau.NewSiacoinElements {
		elems = append(elems, sce.StateElement)
	}
	sort.Slice(elems, func(i, j int) bool {
		return elems[i].LeafIndex < elems[j].LeafIndex
	})
	for i := 0; i < 100; i++ {
		b := sim.MineBlock()
		sau = consensus.ApplyBlock(s, b)

		// create new accumulator tree, using new + updated elements
		newElems := append([]types.StateElement(nil), elems...)
		for i := range newElems {
			newElems[i].MerkleProof = append([]types.Hash256(nil), newElems[i].MerkleProof...)
			sau.UpdateElementProof(&newElems[i])
		}
		for _, sce := range sau.NewSiacoinElements {
			e := sce.StateElement
			e.MerkleProof = append([]types.Hash256(nil), e.MerkleProof...)
			newElems = append(newElems, e)
		}
		if len(newElems) != int(sau.State.Elements.NumLeaves) {
			t.Fatal("accumulator size does not match", len(newElems), sau.State.Elements.NumLeaves)
		}
		sort.Slice(newElems, func(i, j int) bool {
			return newElems[i].LeafIndex < newElems[j].LeafIndex
		})

		// revert the block
		sru := consensus.RevertBlock(s, b)
		var relems []types.StateElement
		for _, e := range newElems {
			if e.LeafIndex < sru.State.Elements.NumLeaves {
				e.MerkleProof = append([]types.Hash256(nil), e.MerkleProof...)
				sru.UpdateElementProof(&e)
				relems = append(relems, e)
			}
		}
		if len(relems) != len(elems) {
			t.Fatal("tree does not match after revert:", len(relems), len(elems))
		}

		// check equality
		for i := range relems {
			a, b := relems[i], elems[i]
			eq := a.ID == b.ID && a.LeafIndex == b.LeafIndex && len(a.MerkleProof) == len(b.MerkleProof)
			if eq {
				for i := range a.MerkleProof {
					eq = eq && a.MerkleProof[i] == b.MerkleProof[i]
				}
			}
			if !eq {
				t.Error("reverted element does not match previous accumulator:", "\n", a, "\n\n", b)
			}
		}

		s = sau.State
		elems = newElems
	}
}
