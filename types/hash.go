package types

import (
	"encoding/binary"
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

func standardUnlockHash(pk PublicKey) Address {
	// An Address is the Merkle root of UnlockConditions. Since the standard
	// UnlockConditions use a single public key, the Merkle tree is:
	//
	//           ┌─────────┴──────────┐
	//     ┌─────┴─────┐              │
	//  timelock     pubkey     sigsrequired
	//
	// This implies a total of 5 BLAKE2b hashes: 3 leaves and 2 nodes. However,
	// in standard UnlockConditions, the timelock and sigsrequired are always
	// the same (0 and 1, respectively), so we can precompute these hashes,
	// bringing the total down to 3 BLAKE2b hashes.

	// calculate the leaf hash for the pubkey.
	buf := make([]byte, 1+16+8+32)
	buf[0] = leafHashPrefix
	copy(buf[1:], SpecifierEd25519[:])
	binary.LittleEndian.PutUint64(buf[17:], 32)
	copy(buf[25:], pk[:])
	pubkeyHash := blake2b.Sum256(buf)

	// BLAKE2b(0x00 | uint64(0))
	timelockHash := Hash256{
		0x51, 0x87, 0xb7, 0xa8, 0x02, 0x1b, 0xf4, 0xf2,
		0xc0, 0x04, 0xea, 0x3a, 0x54, 0xcf, 0xec, 0xe1,
		0x75, 0x4f, 0x11, 0xc7, 0x62, 0x4d, 0x23, 0x63,
		0xc7, 0xf4, 0xcf, 0x4f, 0xdd, 0xd1, 0x44, 0x1e,
	}
	// BLAKE2b(0x00 | uint64(1))
	sigsrequiredHash := Hash256{
		0xb3, 0x60, 0x10, 0xeb, 0x28, 0x5c, 0x15, 0x4a,
		0x8c, 0xd6, 0x30, 0x84, 0xac, 0xbe, 0x7e, 0xac,
		0x0c, 0x4d, 0x62, 0x5a, 0xb4, 0xe1, 0xa7, 0x6e,
		0x62, 0x4a, 0x87, 0x98, 0xcb, 0x63, 0x49, 0x7b,
	}

	return Address(blake2b.SumPair(blake2b.SumPair(timelockHash, pubkeyHash), sigsrequiredHash))
}
