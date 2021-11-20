package chainutil

import (
	"io"
	"os"
	"testing"

	"go.sia.tech/core/chain"
	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

func TestFlatStoreRecovery(t *testing.T) {
	dir, err := os.MkdirTemp(os.TempDir(), t.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	sim := NewChainSim()
	fs, _, err := NewFlatStore(dir, sim.Genesis)
	if err != nil {
		t.Fatal(err)
	}

	invalidIndex := types.ChainIndex{Height: 9999}
	if _, err := fs.Checkpoint(invalidIndex); err != chain.ErrUnknownIndex {
		t.Fatal("Checkpoint returned no error for an invalid index")
	}
	if _, err := fs.BestIndex(invalidIndex.Height); err != chain.ErrUnknownIndex {
		t.Fatal("BestIndex returned no error for an invalid block height")
	}

	// add some blocks and flush meta
	blocks := sim.MineBlocks(5)
	for _, block := range blocks {
		if err := fs.AddCheckpoint(consensus.Checkpoint{
			Block:   block,
			Context: sim.Context,
		}); err != nil {
			t.Fatal(err)
		} else if err := fs.ExtendBest(sim.Context.Index); err != nil {
			t.Fatal(err)
		}
	}
	if fs.Flush(); err != nil {
		t.Fatal(err)
	}

	// compare tips
	if fs.meta.tip != sim.Context.Index {
		t.Fatal("meta tip mismatch", fs.meta.tip, sim.Context.Index)
	} else if index, err := fs.BestIndex(fs.meta.tip.Height); err != nil || index != fs.meta.tip {
		t.Fatal("tip mismatch", index, fs.meta.tip)
	}
	goodTip := fs.meta.tip

	// add more blocks, then close without flushing
	blocks = sim.MineBlocks(5)
	for _, block := range blocks {
		if err := fs.AddCheckpoint(consensus.Checkpoint{
			Block:   block,
			Context: sim.Context,
		}); err != nil {
			t.Fatal(err)
		} else if err := fs.ExtendBest(sim.Context.Index); err != nil {
			t.Fatal(err)
		}
	}

	// simulate write failure by corrupting index, entry, and best files
	for _, f := range []*os.File{fs.indexFile, fs.entryFile, fs.bestFile} {
		f.Seek(-10, io.SeekEnd)
		f.WriteString("garbagegarbage")
	}
	if index, err := fs.BestIndex(fs.meta.tip.Height); err != nil {
		t.Fatal(err)
	} else if index == fs.meta.tip {
		t.Fatal("tip should not match after corruption")
	}

	// reload fs; should recover to last good state
	fs.indexFile.Close()
	fs.entryFile.Close()
	fs.bestFile.Close()
	fs, tip, err := NewFlatStore(dir, sim.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	if tip.Context.Index != goodTip || fs.meta.tip != goodTip {
		t.Fatal("tip mismatch", tip.Context.Index, fs.meta.tip, goodTip)
	} else if index, err := fs.BestIndex(goodTip.Height); err != nil || index != goodTip {
		t.Fatal("tip mismatch", index, goodTip)
	}
	fs.Close()
}

func TestEphemeralStore(t *testing.T) {
	dir, err := os.MkdirTemp(os.TempDir(), t.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	sim := NewChainSim()
	es := NewEphemeralStore(sim.Genesis)
	if err != nil {
		t.Fatal(err)
	}

	// add some blocks
	blocks := sim.MineBlocks(5)
	for _, block := range blocks {
		if err := es.AddCheckpoint(consensus.Checkpoint{
			Block:   block,
			Context: sim.Context,
		}); err != nil {
			t.Fatal(err)
		} else if err := es.ExtendBest(sim.Context.Index); err != nil {
			t.Fatal(err)
		}
	}
	// ephemeral store flush should always return nil
	if err := es.Flush(); err != nil {
		t.Fatal(err)
	}

	tip, err := es.Header(sim.Context.Index)
	if err != nil {
		t.Fatal(err)
	}
	// compare tips
	if tip.Index() != sim.Context.Index {
		t.Fatal("tip mismatch", tip.Index(), sim.Context.Index)
	} else if index, err := es.BestIndex(tip.Height); err != nil || index != tip.Index() {
		t.Fatal("tip mismatch", index, tip)
	}

	invalidIndex := types.ChainIndex{Height: 9999}
	if _, err := es.Checkpoint(invalidIndex); err != chain.ErrUnknownIndex {
		t.Fatal("Checkpoint returned no error for an invalid index")
	}
	if _, err := es.BestIndex(invalidIndex.Height); err != chain.ErrUnknownIndex {
		t.Fatal("BestIndex returned no error for an invalid block height")
	}
}

func BenchmarkFlatStore(b *testing.B) {
	dir, err := os.MkdirTemp(os.TempDir(), b.Name())
	if err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(dir)
	fs, _, err := NewFlatStore(dir, consensus.Checkpoint{})
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()

	cp := consensus.Checkpoint{
		Block: types.Block{
			Transactions: make([]types.Transaction, 10),
		},
	}

	for i := 0; i < b.N; i++ {
		if err := fs.AddCheckpoint(cp); err != nil {
			b.Fatal(err)
		}
	}
}
