package rhp

import (
	"bytes"
	"math/bits"
	"slices"
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
}

func BenchmarkSectorRoot(b *testing.B) {
	b.Run("serial", func(b *testing.B) {
		b.ReportAllocs()
		var sector [SectorSize]byte
		b.SetBytes(SectorSize)
		for i := 0; i < b.N; i++ {
			var sa sectorAccumulator
			sa.appendLeaves(sector[:])
			_ = sa.root()
		}
	})
	b.Run("parallel", func(b *testing.B) {
		b.ReportAllocs()
		var sector [SectorSize]byte
		b.SetBytes(SectorSize)
		for i := 0; i < b.N; i++ {
			_ = SectorRoot(&sector)
		}
	})
}

func TestMetaRoot(t *testing.T) {
	// test some known roots
	if MetaRoot(nil) != (types.Hash256{}) {
		t.Error("wrong Merkle root for empty tree")
	}
	roots := make([]types.Hash256, 1)
	roots[0] = frand.Entropy256()
	if MetaRoot(roots) != roots[0] {
		t.Error("wrong Merkle root for single root")
	}
	roots = make([]types.Hash256, 32)
	if MetaRoot(roots).String() != "1c23727030051d1bba1c887273addac2054afbd6926daddef6740f4f8bf1fb7f" {
		t.Error("wrong Merkle root for 32 empty roots")
	}
	roots[0][0] = 1
	if MetaRoot(roots).String() != "c5da05749139505704ea18a5d92d46427f652ac79c5f5712e4aefb68e20dffb8" {
		t.Error("wrong Merkle root for roots[0][0] = 1")
	}

	// test some random roots against a reference implementation
	for i := 0; i < 5; i++ {
		for j := range roots {
			roots[j] = frand.Entropy256()
		}
		if MetaRoot(roots) != recNodeRoot(roots) {
			t.Error("MetaRoot does not match reference implementation")
		}
	}
	// test some random tree sizes
	for i := 0; i < 10; i++ {
		roots := make([]types.Hash256, frand.Intn(LeavesPerSector))
		if MetaRoot(roots) != recNodeRoot(roots) {
			t.Error("MetaRoot does not match reference implementation")
		}
	}

	roots = roots[:5]
	if MetaRoot(roots) != recNodeRoot(roots) {
		t.Error("MetaRoot does not match reference implementation")
	}

	allocs := testing.AllocsPerRun(10, func() {
		_ = MetaRoot(roots)
	})
	if allocs > 0 {
		t.Error("expected MetaRoot to allocate 0 times, got", allocs)
	}

	// test a massive number of roots, larger than a single stack can store
	const sectorsPerTerabyte = 262145
	roots = make([]types.Hash256, sectorsPerTerabyte)
	if MetaRoot(roots) != recNodeRoot(roots) {
		t.Error("MetaRoot does not match reference implementation")
	}
}

func BenchmarkMetaRoot1TB(b *testing.B) {
	const sectorsPerTerabyte = 262144
	roots := make([]types.Hash256, sectorsPerTerabyte)
	b.SetBytes(sectorsPerTerabyte * 32)
	for i := 0; i < b.N; i++ {
		_ = MetaRoot(roots)
	}
}

func TestProofAccumulator(t *testing.T) {
	var pa proofAccumulator

	// test some known roots
	if pa.root() != (types.Hash256{}) {
		t.Error("wrong root for empty accumulator")
	}

	roots := make([]types.Hash256, 32)
	for _, root := range roots {
		pa.insertNode(root, 0)
	}
	if pa.root().String() != "1c23727030051d1bba1c887273addac2054afbd6926daddef6740f4f8bf1fb7f" {
		t.Error("wrong root for 32 empty roots")
	}

	pa = proofAccumulator{}
	roots[0][0] = 1
	for _, root := range roots {
		pa.insertNode(root, 0)
	}
	if pa.root().String() != "c5da05749139505704ea18a5d92d46427f652ac79c5f5712e4aefb68e20dffb8" {
		t.Error("wrong root for roots[0][0] = 1")
	}

	// test some random roots against a reference implementation
	for i := 0; i < 5; i++ {
		var pa proofAccumulator
		for j := range roots {
			roots[j] = frand.Entropy256()
			pa.insertNode(roots[j], 0)
		}
		if pa.root() != recNodeRoot(roots) {
			t.Error("root does not match reference implementation")
		}
	}

	// test an odd number of roots
	pa = proofAccumulator{}
	roots = roots[:5]
	for _, root := range roots {
		pa.insertNode(root, 0)
	}
	refRoot := recNodeRoot([]types.Hash256{recNodeRoot(roots[:4]), roots[4]})
	if pa.root() != refRoot {
		t.Error("root does not match reference implementation")
	}
}

func TestReadSector(t *testing.T) {
	var expected [SectorSize]byte
	frand.Read(expected[:256])
	buf := bytes.NewBuffer(nil)
	buf.Write(expected[:])

	expectedRoot := refSectorRoot(&expected)
	root, sector, err := ReadSector(buf)
	if err != nil {
		t.Fatal(err)
	} else if expectedRoot != root {
		t.Fatalf("incorrect root: expected %s, got %s", expected, root)
	} else if !bytes.Equal(sector[:], expected[:]) {
		t.Fatalf("incorrect data: expected %v, got %v", expected, sector)
	}

	buf.Reset()
	buf.Write(expected[:len(expected)-100])
	_, _, err = ReadSector(buf)
	if err == nil {
		t.Fatal("expected read error")
	}
}

func TestRangeProofVerifierReadFrom(t *testing.T) {
	tests := []struct {
		name            string
		start, end      uint64
		availableLeaves uint64
	}{
		{"full data, single subtree", 0, 8, 8},
		{"short reader, single subtree", 0, 8, 4},
		{"full data, multiple subtrees", 0, 10, 10},
		{"short reader, multiple subtrees", 0, 10, 9},
		{"empty reader", 0, 8, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := frand.Bytes(int(tt.availableLeaves) * LeafSize)
			rpv := NewRangeProofVerifier(tt.start, tt.end)
			n, err := rpv.ReadFrom(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			if n != int64(len(data)) {
				t.Fatalf("expected %d bytes read, got %d", len(data), n)
			}
		})
	}
}

func TestDiffProof(t *testing.T) {
	appendSector := RPCWriteAction{Type: RPCWriteActionAppend}
	trim := func(n uint64) RPCWriteAction { return RPCWriteAction{Type: RPCWriteActionTrim, A: n} }
	swap := func(i, j uint64) RPCWriteAction { return RPCWriteAction{Type: RPCWriteActionSwap, A: i, B: j} }
	for _, test := range []struct {
		name    string
		initial int
		actions []RPCWriteAction
	}{
		{"empty", 0, nil},
		{"unchanged", 7, nil},
		{"append", 7, []RPCWriteAction{appendSector, appendSector, appendSector}},
		{"swap repeatedly", 8, []RPCWriteAction{swap(2, 6), swap(2, 3), swap(2, 6), swap(1, 1)}},
		{"trim all", 8, []RPCWriteAction{trim(8)}},
		{"reuse trimmed indices", 8, []RPCWriteAction{trim(3), appendSector, appendSector, swap(2, 6), appendSector, trim(5), appendSector, swap(1, 3)}},
		{"swap appended sectors", 5, []RPCWriteAction{appendSector, appendSector, swap(0, 6), trim(3), appendSector, swap(1, 4)}},
		{"empty and refill", 3, []RPCWriteAction{swap(0, 2), trim(3), appendSector, appendSector, swap(0, 1), trim(2), appendSector}},
	} {
		t.Run(test.name, func(t *testing.T) {
			roots := make([]types.Hash256, test.initial)
			for i := range roots {
				roots[i] = types.Hash256{byte(i), 0xA5}
			}
			// Apply actions directly to the complete sector list, independently
			// of the compressed proof's index mapping.
			expected := slices.Clone(roots)
			var appendRoots []types.Hash256
			for _, action := range test.actions {
				switch action.Type {
				case RPCWriteActionAppend:
					root := types.Hash256{byte(len(appendRoots)), 0xFF}
					appendRoots = append(appendRoots, root)
					expected = append(expected, root)
				case RPCWriteActionTrim:
					expected = expected[:uint64(len(expected))-action.A]
				case RPCWriteActionSwap:
					expected[action.A], expected[action.B] = expected[action.B], expected[action.A]
				}
			}
			treeHashes, leafHashes := BuildDiffProof(test.actions, roots)
			originalLeaves := slices.Clone(leafHashes)
			oldRoot, newRoot := recNodeRoot(roots), recNodeRoot(expected)
			if !VerifyDiffProof(test.actions, uint64(len(roots)), treeHashes, leafHashes, oldRoot, newRoot, appendRoots) {
				t.Fatal("valid diff proof rejected")
			} else if !slices.Equal(leafHashes, originalLeaves) {
				t.Fatal("verification modified the supplied leaf hashes")
			}
			for _, hashes := range [][]types.Hash256{treeHashes, leafHashes} {
				if len(hashes) != 0 {
					hashes[0][0] ^= 1
					if VerifyDiffProof(test.actions, uint64(len(roots)), treeHashes, leafHashes, oldRoot, newRoot, appendRoots) {
						t.Fatal("corrupt diff proof accepted")
					}
					hashes[0][0] ^= 1
				}
			}
		})
	}
}

func BenchmarkReadSector(b *testing.B) {
	buf := bytes.NewBuffer(nil)
	buf.Grow(SectorSize)

	sector := make([]byte, SectorSize)
	frand.Read(sector[:256])

	b.SetBytes(SectorSize)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		buf.Write(sector)
		_, _, err := ReadSector(buf)
		if err != nil {
			b.Fatal(err)
		}
	}
}
