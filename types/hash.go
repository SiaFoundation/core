package types

import (
	"hash"
	"math/bits"
	"sync"

	"go.sia.tech/core/internal/blake2b"
)

// HashBytes computes the hash of b using Sia's hash function.
func HashBytes(b []byte) Hash256 {
	return blake2b.Sum256(b)
}

// A Hasher streams objects into an instance of Sia's hash function.
type Hasher struct {
	h hash.Hash
	E *Encoder
}

// Reset resets the underlying hash digest state.
func (h *Hasher) Reset() { h.h.Reset() }

// Sum returns the digest of the objects written to the Hasher.
func (h *Hasher) Sum() (sum Hash256) {
	_ = h.E.Flush() // no error possible
	h.h.Sum(sum[:0])
	return
}

// NewHasher returns a new Hasher instance.
func NewHasher() *Hasher {
	h := blake2b.New256()
	e := NewEncoder(h)
	return &Hasher{h, e}
}

// Pool for reducing heap allocations when hashing. This is only necessary
// because blake2b.New256 returns a hash.Hash interface, which prevents the
// compiler from doing escape analysis. Can be removed if we switch to an
// implementation whose constructor returns a concrete type.
var hasherPool = &sync.Pool{New: func() interface{} { return NewHasher() }}

const leafHashPrefix = 0 // from RFC 6962

type merkleAccumulator struct {
	trees     [64]Hash256
	numLeaves uint64
}

func (acc *merkleAccumulator) hasTreeAtHeight(height int) bool {
	return acc.numLeaves&(1<<height) != 0
}

func (acc *merkleAccumulator) addLeaf(h Hash256) {
	i := 0
	for ; acc.hasTreeAtHeight(i); i++ {
		h = blake2b.SumPair(acc.trees[i], h)
	}
	acc.trees[i] = h
	acc.numLeaves++
}

func (acc *merkleAccumulator) root() Hash256 {
	i := bits.TrailingZeros64(acc.numLeaves)
	if i == 64 {
		return Hash256{}
	}
	root := acc.trees[i]
	for i++; i < 64; i++ {
		if acc.hasTreeAtHeight(i) {
			root = blake2b.SumPair(acc.trees[i], root)
		}
	}
	return root
}
