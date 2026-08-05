package blake2b

import (
	"testing"
	"unsafe"
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

// TestBLAKE2bVectors checks the optimized implementation against the generic
// one across many inputs. hashBlocksGeneric defers to x/crypto/blake2b, so this
// is a comparison against an independent implementation.
func TestBLAKE2bVectors(t *testing.T) {
	// splitmix64, so that any failure is reproducible
	state := uint64(0x9E3779B97F4A7C15)
	next := func() byte {
		state += 0x9E3779B97F4A7C15
		z := state
		z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
		z = (z ^ (z >> 27)) * 0x94D049BB133111EB
		return byte(z ^ (z >> 31))
	}

	check := func(t *testing.T, msgs *[4][64]byte) {
		t.Helper()
		for _, prefix := range []uint64{leafHashPrefix, nodeHashPrefix} {
			var refs, outs [4][32]byte
			hashBlocksGeneric(&refs, msgs, prefix)
			hashBlocks(&outs, msgs, prefix)
			if outs != refs {
				t.Fatalf("mismatch (prefix %v)\nmsgs: %x\nasm:  %x\nref:  %x", prefix, msgs, outs, refs)
			}
		}
	}

	t.Run("edge cases", func(t *testing.T) {
		var zero, ones [4][64]byte
		for i := range ones {
			for j := range ones[i] {
				ones[i][j] = 0xFF
			}
		}
		check(t, &zero)
		check(t, &ones)
	})

	t.Run("random", func(t *testing.T) {
		for i := 0; i < 500; i++ {
			var msgs [4][64]byte
			for j := range msgs {
				for k := range msgs[j] {
					msgs[j][k] = next()
				}
			}
			check(t, &msgs)
		}
	})

	// Set one bit at a time, so that a message word or lane that the
	// transposition drops, duplicates or misplaces cannot go unnoticed.
	t.Run("single bits", func(t *testing.T) {
		for lane := 0; lane < 4; lane++ {
			for pos := 0; pos < 64; pos++ {
				for _, bit := range []uint{0, 7} {
					var msgs [4][64]byte
					msgs[lane][pos] = 1 << bit
					check(t, &msgs)
				}
			}
		}
	})
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
	b.Run("hashBlocksGeneric", func(b *testing.B) {
		b.SetBytes(4 * 64)
		for i := 0; i < b.N; i++ {
			hashBlocksGeneric(&outs, &leaves, 0)
		}
	})
}
