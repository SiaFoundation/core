package rhp

import (
	"bytes"
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
	assertRoot := func(sector *[SectorSize]byte, expected string) {
		t.Helper()
		if root := SectorRoot(sector).String(); root != expected {
			t.Errorf("wrong Merkle root: got %s, want %s", root, expected)
		} else if root, err := ReaderRoot(bytes.NewReader(sector[:])); err != nil || root.String() != expected {
			t.Errorf("ReaderRoot does not match SectorRoot: got %s, want %s", root.String(), expected)
		} else if root, err := ReadSectorRoot(bytes.NewReader(sector[:])); err != nil || root.String() != expected {
			t.Errorf("ReadSectorRoot does not match SectorRoot: got %s, want %s", root.String(), expected)
		}
	}
	var sector [SectorSize]byte
	assertRoot(&sector, "50ed59cecd5ed3ca9e65cec0797202091dbba45272dafa3faa4e27064eedd52c")

	sector[0] = 1
	assertRoot(&sector, "8c20a2c90a733a5139cc57e45755322e304451c3434b0c0a0aad87f2f89a44ab")

	sector[0] = 0
	sector[SectorSize-1] = 1
	assertRoot(&sector, "d0ab6691d76750618452e920386e5f6f98fdd1219a70a06f06ef622ac6c6373c")

	// test some random roots against a reference implementation
	for range 5 {
		frand.Read(sector[:])
		assertRoot(&sector, refSectorRoot(&sector).String())
	}
}

func TestPartialReadSectorRoot(t *testing.T) {
	var sector [SectorSize]byte
	for i := range LeafSize {
		sector[0] = byte(i)
	}

	expected := refSectorRoot(&sector)
	got, err := ReadSectorRoot(bytes.NewReader(sector[:LeafSize]))
	if err != nil {
		t.Fatal(err)
	} else if got != expected {
		t.Fatalf("partial ReadSectorRoot does not match reference implementation: got %s, want %s", got.String(), expected.String())
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
