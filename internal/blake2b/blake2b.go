// Package blake2b implements the BLAKE2b cryptographic hash function,
// with optimized variants for hashing Merkle tree inputs.
package blake2b

import (
	"hash"
	"math/bits"
	"unsafe"

	"golang.org/x/crypto/blake2b"
)

// re-export from crypto/blake2b

// Sum256 returns the BLAKE2b-256 checksum of the data.
func Sum256(data []byte) [32]byte {
	return blake2b.Sum256(data)
}

// New256 returns a new hash.Hash computing the BLAKE2b-256 checksum.
func New256() hash.Hash {
	h, _ := blake2b.New256(nil)
	return h
}

// from RFC 6962
const leafHashPrefix = 0
const nodeHashPrefix = 1

// SumLeaf computes the Merkle tree leaf hash of a single leaf.
func SumLeaf(leaf *[64]byte) [32]byte {
	return hashBlock(leaf, leafHashPrefix)
}

// SumPair computes the Merkle root of a pair of node hashes.
func SumPair(left, right [32]byte) [32]byte {
	return hashBlock((*[64]byte)(unsafe.Pointer(&[2][32]byte{left, right})), nodeHashPrefix)
}

// SumLeaves computes the Merkle tree leaf hash of four leaves, storing the
// results in outs.
func SumLeaves(outs *[4][32]byte, leaves *[4][64]byte) {
	hashBlocks(outs, leaves, leafHashPrefix)
}

// SumNodes computes the Merkle roots of four pairs of node hashes, storing the
// results in outs.
func SumNodes(outs *[4][32]byte, nodes *[8][32]byte) {
	hashBlocks(outs, (*[4][64]byte)(unsafe.Pointer(nodes)), nodeHashPrefix)
}

func hashBlockGeneric(msg *[64]byte, prefix uint64) [32]byte {
	var buf [65]byte
	buf[0] = byte(prefix)
	copy(buf[1:], msg[:])
	return blake2b.Sum256(buf[:])
}

func hashBlocksGeneric(outs *[4][32]byte, msgs *[4][64]byte, prefix uint64) {
	for i := range msgs {
		outs[i] = hashBlockGeneric(&msgs[i], prefix)
	}
}

// An Accumulator is a generic Merkle tree accumulator.
type Accumulator struct {
	Trees     [64][32]byte
	NumLeaves uint64
}

func (acc *Accumulator) hasTreeAtHeight(height int) bool {
	return acc.NumLeaves&(1<<height) != 0
}

// AddLeaf incorporates a leaf into the accumulator.
func (acc *Accumulator) AddLeaf(h [32]byte) {
	i := 0
	for ; acc.hasTreeAtHeight(i); i++ {
		h = SumPair(acc.Trees[i], h)
	}
	acc.Trees[i] = h
	acc.NumLeaves++
}

// Root returns the Merkle root of the accumulator's leaves.
func (acc *Accumulator) Root() [32]byte {
	i := bits.TrailingZeros64(acc.NumLeaves)
	if i == 64 {
		return [32]byte{}
	}
	root := acc.Trees[i]
	for i++; i < 64; i++ {
		if acc.hasTreeAtHeight(i) {
			root = SumPair(acc.Trees[i], root)
		}
	}
	return root
}
