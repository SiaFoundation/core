package rhp

import (
	"math/bits"
	"testing"

	"go.sia.tech/core/types"
	"golang.org/x/crypto/blake2b"
	"lukechampine.com/frand"
)

func leafHash(seg []byte) types.Hash256 {
	return blake2b.Sum256(append([]byte{0}, seg...))
}

func nodeHash(left, right types.Hash256) types.Hash256 {
	return blake2b.Sum256(append([]byte{1}, append(left[:], right[:]...)...))
}

func refSectorRoot(sector *[SectorSize]byte) types.Hash256 {
	roots := make([]types.Hash256, LeavesPerSector)
	for i := range roots {
		roots[i] = leafHash(sector[i*LeafSize:][:LeafSize])
	}
	return recNodeRoot(roots)
}

func recNodeRoot(roots []types.Hash256) types.Hash256 {
	switch len(roots) {
	case 0:
		return types.Hash256{}
	case 1:
		return roots[0]
	default:
		// split at largest power of two
		split := 1 << (bits.Len(uint(len(roots)-1)) - 1)
		return nodeHash(
			recNodeRoot(roots[:split]),
			recNodeRoot(roots[split:]),
		)
	}
}

func TestSectorRoot(t *testing.T) {
	// test some known roots
	var sector [SectorSize]byte
	if SectorRoot(&sector).String() != "50ed59cecd5ed3ca9e65cec0797202091dbba45272dafa3faa4e27064eedd52c" {
		t.Error("wrong Merkle root for empty sector")
	}
	sector[0] = 1
	if SectorRoot(&sector).String() != "8c20a2c90a733a5139cc57e45755322e304451c3434b0c0a0aad87f2f89a44ab" {
		t.Error("wrong Merkle root for sector[0] = 1")
	}
	sector[0] = 0
	sector[SectorSize-1] = 1
	if SectorRoot(&sector).String() != "d0ab6691d76750618452e920386e5f6f98fdd1219a70a06f06ef622ac6c6373c" {
		t.Error("wrong Merkle root for sector[SectorSize-1] = 1")
	}

	// test some random roots against a reference implementation
	for i := 0; i < 5; i++ {
		frand.Read(sector[:])
		if SectorRoot(&sector) != refSectorRoot(&sector) {
			t.Error("SectorRoot does not match reference implementation")
		}
	}

	// SectorRoot should not allocate
	allocs := testing.AllocsPerRun(5, func() {
		_ = SectorRoot(&sector)
	})
	if allocs > 0 {
		t.Error("expected SectorRoot to allocate 0 times, got", allocs)
	}
}

func BenchmarkSectorRoot(b *testing.B) {
	b.ReportAllocs()
	var sector [SectorSize]byte
	b.SetBytes(SectorSize)
	for i := 0; i < b.N; i++ {
		_ = SectorRoot(&sector)
	}
}
