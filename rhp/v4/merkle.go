package rhp

import (
	"fmt"
	"io"
	"math/bits"
	"sync"
	"unsafe"

	"go.sia.tech/core/blake2b"
	rhp2 "go.sia.tech/core/rhp/v2"
	"go.sia.tech/core/types"
)

const (
	// sectorSubtreeLeaves is the number of leaves per cached subtree
	sectorSubtreeLeaves = 64

	// LeafSize is the size of one leaf in bytes.
	LeafSize = rhp2.LeafSize

	// LeavesPerSector is the number of leaves in one sector.
	LeavesPerSector = rhp2.LeavesPerSector
)

// sectorAccumulator is a specialized accumulator for computing the total root
// of a sector.
type sectorAccumulator struct {
	// Unlike proofAccumulator, the subtree roots are ordered largest-to-
	// smallest, and we store four roots per height. This ordering allows us to
	// cast two adjacent elements into a single [8][32]byte, which reduces
	// copying when hashing.
	trees [15][4][32]byte
	// Since we operate on 8 nodes at a time, we need a buffer to hold nodes
	// until we have enough. And since the buffer is adjacent to the trees in
	// memory, we can again avoid some copying.
	nodeBuf [4][32]byte
	// Like proofAccumulator, 'numLeaves' is both the number of subtree roots
	// appended and a bit vector that indicates which elements are active. We
	// also use it to determine how many nodes are in the buffer.
	numLeaves uint32
}

// We rely on the nodeBuf field immediately following the last element of the
// trees field. This should always be true -- there's no reason for a compiler
// to insert padding between them -- but it doesn't hurt to check.
var _ [unsafe.Offsetof(sectorAccumulator{}.nodeBuf)]struct{} = [unsafe.Sizeof(sectorAccumulator{}.trees)]struct{}{}

func (sa *sectorAccumulator) reset() {
	sa.numLeaves = 0
}

func (sa *sectorAccumulator) hasNodeAtHeight(i int) bool {
	// not as simple as in proofAccumulator; order is reversed, and sa.numLeaves
	// is "off" by a factor of 4
	return (sa.numLeaves>>2)&(1<<(len(sa.trees)-i-1)) != 0
}

func (sa *sectorAccumulator) appendNode(h types.Hash256) {
	sa.nodeBuf[sa.numLeaves%4] = h
	sa.numLeaves++
	if sa.numLeaves%4 == 0 {
		sa.numLeaves -= 4 // hack: offset mergeNodeBuf adding 4
		sa.mergeNodeBuf()
	}
}

func (sa *sectorAccumulator) appendLeaves(leaves []byte) {
	if len(leaves)%LeafSize != 0 {
		panic("appendLeaves: illegal input size")
	}
	rem := len(leaves) % (LeafSize * 4)
	for i := 0; i < len(leaves)-rem; i += LeafSize * 4 {
		blake2b.SumLeaves(&sa.nodeBuf, (*[4][64]byte)(unsafe.Pointer(&leaves[i])))
		sa.mergeNodeBuf()
	}
	for i := len(leaves) - rem; i < len(leaves); i += LeafSize {
		sa.appendNode(blake2b.SumLeaf((*[64]byte)(unsafe.Pointer(&leaves[i]))))
	}
}

func (sa *sectorAccumulator) mergeNodeBuf() {
	// same as in proofAccumulator, except that we operate on 8 nodes at a time,
	// exploiting the fact that the two groups of 4 are contiguous in memory
	nodes := &sa.nodeBuf
	i := len(sa.trees) - 1
	for ; sa.hasNodeAtHeight(i); i-- {
		blake2b.SumNodes(&sa.trees[i], (*[8][32]byte)(unsafe.Pointer(&sa.trees[i])))
		nodes = &sa.trees[i]
	}
	sa.trees[i] = *nodes
	sa.numLeaves += 4
}

func (sa *sectorAccumulator) root() types.Hash256 {
	if sa.numLeaves == 0 {
		return types.Hash256{}
	}

	// helper function for computing the root of four subtrees
	root4 := func(nodes [4][32]byte) types.Hash256 {
		// NOTE: it would be more efficient to mutate sa.trees directly, but
		// that would make root non-idempotent
		in := (*[8][32]byte)(unsafe.Pointer(&[2][4][32]byte{0: nodes}))
		out := (*[4][32]byte)(unsafe.Pointer(in))
		blake2b.SumNodes(out, in)
		blake2b.SumNodes(out, in)
		return out[0]
	}

	i := len(sa.trees) - 1 - bits.TrailingZeros32(sa.numLeaves>>2)
	var root types.Hash256
	switch sa.numLeaves % 4 {
	case 0:
		root = root4(sa.trees[i])
		i--
	case 1:
		root = sa.nodeBuf[0]
	case 2:
		root = blake2b.SumPair(sa.nodeBuf[0], sa.nodeBuf[1])
	case 3:
		root = blake2b.SumPair(blake2b.SumPair(sa.nodeBuf[0], sa.nodeBuf[1]), sa.nodeBuf[2])
	}
	for ; i >= 0; i-- {
		if sa.hasNodeAtHeight(i) {
			root = blake2b.SumPair(root4(sa.trees[i]), root)
		}
	}
	return root
}

// A RangeProofVerifier allows range proofs to be verified in streaming fashion.
type RangeProofVerifier = rhp2.RangeProofVerifier

// NewRangeProofVerifier returns a RangeProofVerifier for the sector range
// [start, end).
func NewRangeProofVerifier(start, end uint64) *RangeProofVerifier {
	return rhp2.NewRangeProofVerifier(start, end)
}

func sectorProofSize(n, i uint64) uint64 {
	return rhp2.RangeProofSize(n, i, i+1)
}

// SectorRoot computes the Merkle root of a sector.
func SectorRoot(sector *[SectorSize]byte) types.Hash256 {
	return rhp2.SectorRoot(sector)
}

// ReaderRoot returns the Merkle root of the supplied stream, which must contain
// an integer multiple of leaves.
func ReaderRoot(r io.Reader) (types.Hash256, error) {
	return rhp2.ReaderRoot(r)
}

// ReadSectorRoot computes the merkle root of a sector read from a reader.
func ReadSectorRoot(r io.Reader) (types.Hash256, error) {
	return rhp2.ReadSectorRoot(r)
}

// ReadSector reads a single sector from r and calculates its root.
func ReadSector(r io.Reader) (types.Hash256, *[SectorSize]byte, error) {
	return rhp2.ReadSector(r)
}

// MetaRoot calculates the root of a set of existing Merkle roots.
func MetaRoot(roots []types.Hash256) types.Hash256 {
	return rhp2.MetaRoot(roots)
}

// SectorSubtreeRange computes the leaves required to construct a
// proof for the leaf range [start, end). It assumes that the cached
// subtrees are 64 leaves (4 KiB) in size, and returns the aligned
// start and end offsets that cover the requested range.
func SectorSubtreeRange(start, end uint64) (rangeStart, rangeEnd uint64) {
	switch {
	case end > LeavesPerSector:
		panic("end exceeds number of leaves")
	case start > end:
		panic("start exceeds end")
	case start == end:
		panic("start equals end")
	}

	return (start / sectorSubtreeLeaves) * sectorSubtreeLeaves, ((end + sectorSubtreeLeaves - 1) / sectorSubtreeLeaves) * sectorSubtreeLeaves
}

// CachedSectorSubtrees computes and returns the cached subtree roots for a sector.
// Each root corresponds to a subtree of 64 leaves or 4 KiB of data.
func CachedSectorSubtrees(sector *[SectorSize]byte) []types.Hash256 {
	per := LeafSize * sectorSubtreeLeaves
	n := LeavesPerSector / sectorSubtreeLeaves
	roots := make([]types.Hash256, n)
	var wg sync.WaitGroup
	for i := range roots {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var sa sectorAccumulator
			sa.appendLeaves(sector[i*per:][:per])
			roots[i] = sa.root()
		}(i)
	}
	wg.Wait()
	return roots
}

// BuildSectorProof constructs a proof for the segment range [start, end).
//
// `segment` must contain a 64-leaf-aligned segment of the
// sector data containing all leaves in the range [start, end).
//
// `cache` must contain the 64-leaf subtree roots for the sector.
func BuildSectorProof(segment []byte, start, end uint64, cache []types.Hash256) []types.Hash256 {
	switch {
	case end > LeavesPerSector:
		panic("end exceeds number of leaves")
	case start > end:
		panic("start exceeds end")
	case start == end:
		panic("start equals end")
	case len(cache) != LeavesPerSector/sectorSubtreeLeaves:
		panic("cache has incorrect size")
	}

	segmentStart, segmentEnd := SectorSubtreeRange(start, end)

	if uint64(len(segment)) != (segmentEnd-segmentStart)*LeafSize {
		panic("segment has incorrect size")
	}

	// hash any subtree fully inside segment
	var s sectorAccumulator
	subtreeRoot := func(i, j uint64) types.Hash256 {
		s.reset()
		s.appendLeaves(segment[(i-segmentStart)*LeafSize : (j-segmentStart)*LeafSize])
		return s.root()
	}

	// supply a root from cache when the subtree is aligned to 64-leaf chunks
	precalc := func(i, j uint64) types.Hash256 {
		if i >= segmentStart && j <= segmentEnd {
			return subtreeRoot(i, j)
		}
		// use cached roots for aligned ranges
		if i%sectorSubtreeLeaves == 0 && j%sectorSubtreeLeaves == 0 {
			return MetaRoot(cache[i/sectorSubtreeLeaves : j/sectorSubtreeLeaves])
		}
		panic(fmt.Errorf("no precalculated root for subtree [%d, %d)", i, j))
	}

	// we build the proof by recursively enumerating subtrees, left to right.
	// If a subtree is inside the segment range, we can skip it (because the
	// verifier has the segments); otherwise, we use the precalculated root for
	// the subtree. If a subtree partially overlaps the segment range, we split
	// it and recurse.
	proof := make([]types.Hash256, 0, sectorProofSize(LeavesPerSector, start))
	var rec func(uint64, uint64)
	rec = func(i, j uint64) {
		if i >= start && j <= end {
			// this subtree contains only data segments; skip it
			return
		} else if j <= start || i >= end {
			proof = append(proof, precalc(i, j))
			return
		}
		// this subtree partially overlaps the data segments; split it
		// into two subtrees and recurse on each
		mid := (i + j) / 2
		rec(i, mid)
		rec(mid, j)
	}
	rec(0, LeavesPerSector)
	return proof
}

// VerifyLeafProof verifies the Merkle proof for a given leaf within a sector.
func VerifyLeafProof(proof []types.Hash256, leaf [64]byte, leafIndex uint64, root types.Hash256) bool {
	return rhp2.VerifySectorRangeProof(proof, []types.Hash256{blake2b.SumLeaf(&leaf)}, leafIndex, leafIndex+1, LeavesPerSector, root)
}

// BuildAppendProof builds a Merkle proof for appending a set of sectors to a
// contract.
func BuildAppendProof(sectorRoots, appended []types.Hash256) ([]types.Hash256, types.Hash256) {
	var acc blake2b.Accumulator
	for _, h := range sectorRoots {
		acc.AddLeaf(h)
	}
	var subtreeRoots []types.Hash256
	for i, h := range acc.Trees {
		if acc.NumLeaves&(1<<i) != 0 {
			subtreeRoots = append(subtreeRoots, h)
		}
	}
	for _, h := range appended {
		acc.AddLeaf(h)
	}
	return subtreeRoots, acc.Root()
}

// VerifyAppendSectorsProof verifies a Merkle proof produced by BuildAppendProof.
func VerifyAppendSectorsProof(numSectors uint64, subtreeRoots []types.Hash256, appended []types.Hash256, oldRoot, newRoot types.Hash256) bool {
	acc := blake2b.Accumulator{NumLeaves: numSectors}
	for i := 0; i < bits.Len64(numSectors); i++ {
		if numSectors&(1<<i) != 0 && len(subtreeRoots) > 0 {
			acc.Trees[i] = subtreeRoots[0]
			subtreeRoots = subtreeRoots[1:]
		}
	}
	if acc.Root() != oldRoot {
		return false
	}
	for _, h := range appended {
		acc.AddLeaf(h)
	}
	return acc.Root() == newRoot
}

// BuildSectorRootsProof builds a Merkle proof for a range of sectors within a
// contract.
func BuildSectorRootsProof(sectorRoots []types.Hash256, start, end uint64) []types.Hash256 {
	return rhp2.BuildSectorRangeProof(sectorRoots, start, end)
}

// VerifySectorRootsProof verifies a Merkle proof produced by
// BuildSectorRootsProof.
func VerifySectorRootsProof(proof, sectorRoots []types.Hash256, numSectors, start, end uint64, root types.Hash256) bool {
	return rhp2.VerifySectorRangeProof(proof, sectorRoots, start, end, numSectors, root)
}

func convertFreeActions(freed []uint64, numSectors uint64) []rhp2.RPCWriteAction {
	as := make([]rhp2.RPCWriteAction, 0, len(freed)+1)
	// swap
	for i, n := range freed {
		as = append(as, rhp2.RPCWriteAction{
			Type: rhp2.RPCWriteActionSwap,
			A:    n,
			B:    numSectors - uint64(i) - 1,
		})
	}
	// trim
	return append(as, rhp2.RPCWriteAction{
		Type: rhp2.RPCWriteActionTrim,
		A:    uint64(len(freed)),
	})
}

// BuildFreeSectorsProof builds a Merkle proof for freeing a set of sectors.
func BuildFreeSectorsProof(sectorRoots []types.Hash256, freed []uint64) (treeHashes, leafHashes []types.Hash256) {
	return rhp2.BuildDiffProof(convertFreeActions(freed, uint64(len(sectorRoots))), sectorRoots)
}

// VerifyFreeSectorsProof verifies a Merkle proof produced by
// BuildFreeSectorsProof.
func VerifyFreeSectorsProof(treeHashes, leafHashes []types.Hash256, freed []uint64, numSectors uint64, oldRoot types.Hash256, newRoot types.Hash256) bool {
	return rhp2.VerifyDiffProof(convertFreeActions(freed, numSectors), numSectors, treeHashes, leafHashes, oldRoot, newRoot, nil)
}
