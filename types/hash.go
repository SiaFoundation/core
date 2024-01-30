package types

import (
	"encoding/binary"
	"hash"
	"sync"

	"go.sia.tech/core/internal/blake2b"
)

// HashBytes computes the hash of b using Sia's hash function.
func HashBytes(b []byte) Hash256 {
	return blake2b.Sum256(b)
}

// A Hasher streams objects into an instance of Sia's hash function.
type Hasher struct {
	h   hash.Hash
	sum Hash256 // prevent Sum from allocating
	E   *Encoder
}

// Reset resets the underlying hash and encoder state.
func (h *Hasher) Reset() {
	h.E.n = 0
	h.h.Reset()
}

// WriteDistinguisher writes a distinguisher prefix to the encoder.
func (h *Hasher) WriteDistinguisher(p string) {
	h.E.Write([]byte("sia/" + p + "|"))
}

// Sum returns the digest of the objects written to the Hasher.
func (h *Hasher) Sum() (sum Hash256) {
	_ = h.E.Flush() // no error possible
	h.h.Sum(h.sum[:0])
	return h.sum
}

// NewHasher returns a new Hasher instance.
func NewHasher() *Hasher {
	h := blake2b.New256()
	e := NewEncoder(h)
	return &Hasher{h: h, E: e}
}

// Pool for reducing heap allocations when hashing. This is only necessary
// because blake2b.New256 returns a hash.Hash interface, which prevents the
// compiler from doing escape analysis. Can be removed if we switch to an
// implementation whose constructor returns a concrete type.
var hasherPool = &sync.Pool{New: func() interface{} { return NewHasher() }}

func hashAll(elems ...interface{}) [32]byte {
	h := hasherPool.Get().(*Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	for _, e := range elems {
		if et, ok := e.(EncoderTo); ok {
			et.EncodeTo(h.E)
		} else {
			switch e := e.(type) {
			case string:
				h.WriteDistinguisher(e)
			case int:
				h.E.WriteUint64(uint64(e))
			case uint64:
				h.E.WriteUint64(e)
			case bool:
				h.E.WriteBool(e)
			default:
				panic("unhandled type")
			}
		}
	}
	return h.Sum()
}

const leafHashPrefix = 0 // from RFC 6962

// StandardAddress returns the standard v2 Address derived from pk. It is
// equivalent to PolicyPublicKey(pk).Address().
func StandardAddress(pk PublicKey) Address {
	buf := make([]byte, 12+1+1+len(pk))
	copy(buf, "sia/address|")
	buf[12] = 1 // version
	buf[13] = 3 // opPublicKey
	copy(buf[14:], pk[:])
	return Address(blake2b.Sum256(buf))
}

// StandardUnlockHash returns the standard UnlockHash derived from pk. It is equivalent to
// SpendPolicy{PolicyUnlockConditions(StandardUnlockConditions(pk))}.Address().
func StandardUnlockHash(pk PublicKey) Address {
	// An UnlockHash is the Merkle root of UnlockConditions. Since the standard
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

func unlockConditionsRoot(uc UnlockConditions) Address {
	h := hasherPool.Get().(*Hasher)
	defer hasherPool.Put(h)
	var acc blake2b.Accumulator
	h.Reset()
	h.E.WriteUint8(leafHashPrefix)
	h.E.WriteUint64(uc.Timelock)
	acc.AddLeaf(h.Sum())
	for _, key := range uc.PublicKeys {
		h.Reset()
		h.E.WriteUint8(leafHashPrefix)
		key.EncodeTo(h.E)
		acc.AddLeaf(h.Sum())
	}
	h.Reset()
	h.E.WriteUint8(leafHashPrefix)
	h.E.WriteUint64(uc.SignaturesRequired)
	acc.AddLeaf(h.Sum())
	return acc.Root()
}

func blockMerkleRoot(minerPayouts []SiacoinOutput, txns []Transaction) Hash256 {
	h := hasherPool.Get().(*Hasher)
	defer hasherPool.Put(h)
	var acc blake2b.Accumulator
	for _, mp := range minerPayouts {
		h.Reset()
		h.E.WriteUint8(leafHashPrefix)
		V1SiacoinOutput(mp).EncodeTo(h.E)
		acc.AddLeaf(h.Sum())
	}
	for _, txn := range txns {
		h.Reset()
		h.E.WriteUint8(leafHashPrefix)
		txn.EncodeTo(h.E)
		acc.AddLeaf(h.Sum())
	}
	return acc.Root()
}
