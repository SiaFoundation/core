package blake2b

import (
	"testing"
	"unsafe"

	"lukechampine.com/frand"
)

func TestBLAKE2b(t *testing.T) {
	var leaves [4][64]byte
	for i := range leaves {
		for j := range leaves[i] {
			leaves[i][j] = byte(i*64 + j + 7)
		}
	}
	var refs [4][32]byte
	hashBlocksGeneric(&refs, &leaves, 0)
	var outs [4][32]byte
	SumLeaves(&outs, &leaves)
	for i := range outs {
		if outs[i] != refs[i] {
			t.Fatalf("mismatch %v:\nasm: %x\nref: %x", i, outs[i], refs[i])
		}
	}

	parents := (*[8][32]byte)(unsafe.Pointer(&leaves))
	hashBlocksGeneric(&refs, &leaves, 1)
	SumNodes(&outs, parents)
	for i := range outs {
		if outs[i] != refs[i] {
			t.Fatalf("mismatch %v:\nasm: %x\nref: %x", i, outs[i], refs[i])
		}
	}
}

// TestHashBlocks checks hashBlocks against the generic implementation on random
// and extremal inputs.
func TestHashBlocks(t *testing.T) {
	var msgs [4][64]byte
	check := func(prefix uint64) {
		t.Helper()
		var want, got [4][32]byte
		hashBlocksGeneric(&want, &msgs, prefix)
		hashBlocks(&got, &msgs, prefix)
		if got != want {
			t.Fatalf("mismatch for prefix %v, msgs %x:\ngot:  %x\nwant: %x", prefix, msgs, got, want)
		}
	}
	for _, prefix := range []uint64{leafHashPrefix, nodeHashPrefix} {
		for range 1000 {
			for i := range msgs {
				frand.Read(msgs[i][:])
			}
			check(prefix)
		}
		// every byte zero, then every byte set
		for _, fill := range []byte{0x00, 0xff} {
			for i := range msgs {
				for j := range msgs[i] {
					msgs[i][j] = fill
				}
			}
			check(prefix)
		}
	}
}

// TestHashBlock checks hashBlock against the generic implementation on random
// and extremal inputs.
func TestHashBlock(t *testing.T) {
	var msg [64]byte
	check := func(prefix uint64) {
		t.Helper()
		want := hashBlockGeneric(&msg, prefix)
		got := hashBlock(&msg, prefix)
		if got != want {
			t.Fatalf("mismatch for prefix %v, msg %x:\ngot:  %x\nwant: %x", prefix, msg, got, want)
		}
	}
	for _, prefix := range []uint64{leafHashPrefix, nodeHashPrefix} {
		for range 1000 {
			frand.Read(msg[:])
			check(prefix)
		}
		// every byte zero, then every byte set
		for _, fill := range []byte{0x00, 0xff} {
			for i := range msg {
				msg[i] = fill
			}
			check(prefix)
		}
		// walk a single set bit through the message; a word wired to the wrong
		// slot of the schedule shows up as a run of failures pointing at it
		for i := range msg {
			for bit := range 8 {
				clear(msg[:])
				msg[i] = 1 << bit
				check(prefix)
			}
		}
	}
}

func BenchmarkBLAKE2b(b *testing.B) {
	var leaves [4][64]byte
	var nodes [8][32]byte
	var outs [4][32]byte
	b.Run("SumLeaves", func(b *testing.B) {
		b.SetBytes(4 * 64)
		for i := 0; i < b.N; i++ {
			SumLeaves(&outs, &leaves)
		}
	})
	b.Run("SumNodes", func(b *testing.B) {
		b.SetBytes(8 * 32)
		for i := 0; i < b.N; i++ {
			SumNodes(&outs, &nodes)
		}
	})
	b.Run("SumLeaf", func(b *testing.B) {
		b.SetBytes(64)
		for i := 0; i < b.N; i++ {
			SumLeaf(&leaves[0])
		}
	})
	b.Run("SumPair", func(b *testing.B) {
		b.SetBytes(64)
		for i := 0; i < b.N; i++ {
			SumPair(outs[0], outs[1])
		}
	})
	b.Run("hashBlockGeneric", func(b *testing.B) {
		b.SetBytes(64)
		for i := 0; i < b.N; i++ {
			hashBlockGeneric(&leaves[0], 0)
		}
	})
	b.Run("hashBlocksGeneric", func(b *testing.B) {
		b.SetBytes(4 * 64)
		for i := 0; i < b.N; i++ {
			hashBlocksGeneric(&outs, &leaves, 0)
		}
	})
}
