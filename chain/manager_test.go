package chain_test

import (
	"reflect"
	"testing"

	"go.sia.tech/core/chain"
	"go.sia.tech/core/consensus"
	"go.sia.tech/core/internal/chainutil"
	"go.sia.tech/core/types"
)

func newTestStore(tb testing.TB, checkpoint consensus.Checkpoint) *chainutil.FlatStore {
	fs, _, err := chainutil.NewFlatStore(tb.TempDir(), checkpoint)
	if err != nil {
		tb.Fatal(err)
	}
	return fs
}

type historySubscriber struct {
	revertHistory []uint64
	applyHistory  []uint64
}

func (hs *historySubscriber) ProcessChainApplyUpdate(cau *chain.ApplyUpdate, _ bool) error {
	hs.applyHistory = append(hs.applyHistory, cau.Block.Header.Height)
	return nil
}

func (hs *historySubscriber) ProcessChainRevertUpdate(cru *chain.RevertUpdate) error {
	hs.revertHistory = append(hs.revertHistory, cru.Block.Header.Height)
	return nil
}

func TestManager(t *testing.T) {
	sim := chainutil.NewChainSim()

	store := newTestStore(t, sim.Genesis)
	cm := chain.NewManager(store, sim.State)
	defer cm.Close()

	var hs historySubscriber
	cm.AddSubscriber(&hs, cm.Tip())

	// mine 5 blocks, fork, then mine 5 more blocks
	sim.MineBlocks(5)
	fork := sim.Fork()
	sim.MineBlocks(5)

	// give the blocks to the manager
	for _, b := range sim.Chain {
		if err := cm.AddTipBlock(b); err != nil {
			t.Fatal(err)
		}
	}

	// all blocks should have been applied
	if !reflect.DeepEqual(hs.revertHistory, []uint64(nil)) {
		t.Fatal("no blocks should have been reverted:", hs.revertHistory)
	} else if !reflect.DeepEqual(hs.applyHistory, []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
		t.Fatal("10 blocks should have been applied:", hs.applyHistory)
	}

	// mine 10 blocks on the fork, ensuring that it has more total work, and give them to the manager
	betterChain := fork.MineBlocks(10)
	chainutil.FindBlockNonce(&betterChain[9].Header, types.HashRequiringWork(sim.State.TotalWork))
	hs.revertHistory = nil
	hs.applyHistory = nil
	if _, err := cm.AddHeaders(chainutil.JustHeaders(betterChain)); err != nil {
		t.Fatal(err)
	} else if _, err := cm.AddBlocks(betterChain); err != nil {
		t.Fatal(err)
	}

	// check that we reorged to the better chain
	if !reflect.DeepEqual(hs.revertHistory, []uint64{10, 9, 8, 7, 6}) {
		t.Fatal("5 blocks should have been reverted:", hs.revertHistory)
	} else if !reflect.DeepEqual(hs.applyHistory, []uint64{6, 7, 8, 9, 10, 11, 12, 13, 14, 15}) {
		t.Fatal("10 blocks should have been applied:", hs.applyHistory)
	}
	if cm.Tip() != betterChain[len(betterChain)-1].Index() {
		t.Fatal("didn't reorg to better chain")
	}
	for _, b := range betterChain {
		index, err := store.BestIndex(b.Header.Height)
		if err != nil {
			t.Fatal(err)
		} else if index != b.Index() {
			t.Error("store does not contain better chain:", index, b.Index())
		}
	}

	// add a subscriber whose tip is in the middle of the old chain
	subTip := sim.Chain[7].Index()
	var hs2 historySubscriber
	if err := cm.AddSubscriber(&hs2, subTip); err != nil {
		t.Fatal(err)
	}
	// check that the subscriber was properly synced
	if !reflect.DeepEqual(hs2.revertHistory, []uint64{8, 7, 6}) {
		t.Fatal("3 blocks should have been reverted:", hs2.revertHistory)
	} else if !reflect.DeepEqual(hs2.applyHistory, []uint64{6, 7, 8, 9, 10, 11, 12, 13, 14, 15}) {
		t.Fatal("10 blocks should have been applied:", hs2.applyHistory)
	}
}
