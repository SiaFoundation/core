package merkle

import (
	"math/bits"

	"go.sia.tech/core/types"
)

// from RFC 6961
const leafHashPrefix = 0x00
const nodeHashPrefix = 0x01

// mergeHeight returns the height at which the proof paths of x and y merge.
func mergeHeight(x, y uint64) int { return bits.Len64(x ^ y) }

// clearBits clears the n least significant bits of x.
func clearBits(x uint64, n int) uint64 { return x &^ (1<<n - 1) }

// trailingOnes returns the number of trailing one bits in x.
func trailingOnes(x uint64) int { return bits.TrailingZeros64(x + 1) }

// NodeHash computes the Merkle root of a pair of node hashes.
func NodeHash(left, right types.Hash256) types.Hash256 {
	buf := make([]byte, 65)
	buf[0] = nodeHashPrefix
	copy(buf[1:], left[:])
	copy(buf[33:], right[:])
	return types.HashBytes(buf)
}

// ProofRoot returns the Merkle root derived from the supplied leaf hash and
// Merkle proof.
func ProofRoot(leafHash types.Hash256, leafIndex uint64, proof []types.Hash256) types.Hash256 {
	root := leafHash
	for i, h := range proof {
		if leafIndex&(1<<i) == 0 {
			root = NodeHash(root, h)
		} else {
			root = NodeHash(h, root)
		}
	}
	return root
}

// StorageProofLeafHash computes the leaf hash of a file contract data segment.
func StorageProofLeafHash(segment []byte) types.Hash256 {
	const segSize = len(types.StorageProof{}.DataSegment)
	buf := make([]byte, 1+segSize)
	buf[0] = leafHashPrefix
	copy(buf[1:], segment)
	return types.HashBytes(buf)
}

// StorageProofRoot returns the Merkle root derived from the supplied storage
// proof.
func StorageProofRoot(sp types.StorageProof, segmentIndex uint64) types.Hash256 {
	return ProofRoot(StorageProofLeafHash(sp.DataSegment[:]), segmentIndex, sp.SegmentProof)
}
