package rhp

import (
	"bytes"
	"errors"
	"io"
	"math"
	"math/bits"
	"unsafe"

	"go.sia.tech/core/internal/blake2b"
	"go.sia.tech/core/types"
)

// Most of these algorithms are derived from "Streaming Merkle Proofs within
// Binary Numeral Trees", available at https://eprint.iacr.org/2021/038

const (
	// SectorSize is the size of one sector in bytes.
	SectorSize = 1 << 22 // 4 MiB

	// LeafSize is the size of one leaf in bytes.
	LeafSize = 64

	// LeavesPerSector is the number of leaves in one sector.
	LeavesPerSector = SectorSize / LeafSize
)

// Check that LeafSize == len(types.StorageProof{}.Leaf). We *could* define
// LeafSize = len(types.StorageProof{}.Leaf), but then it would be an int
// instead of a an untyped constant.
var _ [LeafSize]byte = [len(types.StorageProof{}.Leaf)]byte{}

// A proofAccumulator is a specialized accumulator for building and verifying
// Merkle proofs.
type proofAccumulator struct {
	trees     [64]types.Hash256
	numLeaves uint64
}

func (pa *proofAccumulator) hasNodeAtHeight(height int) bool {
	return pa.numLeaves&(1<<height) != 0
}

func (pa *proofAccumulator) insertNode(h types.Hash256, height int) {
	i := height
	for ; pa.hasNodeAtHeight(i); i++ {
		h = blake2b.SumPair(pa.trees[i], h)
	}
	pa.trees[i] = h
	pa.numLeaves += 1 << height
}

func (pa *proofAccumulator) root() types.Hash256 {
	i := bits.TrailingZeros64(pa.numLeaves)
	if i == 64 {
		return types.Hash256{}
	}
	root := pa.trees[i]
	for i++; i < len(pa.trees); i++ {
		if pa.hasNodeAtHeight(i) {
			root = blake2b.SumPair(pa.trees[i], root)
		}
	}
	return root
}

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

// SectorRoot computes the Merkle root of a sector.
func SectorRoot(sector *[SectorSize]byte) types.Hash256 {
	var sa sectorAccumulator
	sa.appendLeaves(sector[:])
	return sa.root()
}

// ReaderRoot returns the Merkle root of the supplied stream, which must contain
// an integer multiple of leaves.
func ReaderRoot(r io.Reader) (types.Hash256, error) {
	var s sectorAccumulator
	leafBatch := make([]byte, LeafSize*16)
	for {
		n, err := io.ReadFull(r, leafBatch)
		if err == io.EOF {
			break
		} else if err == io.ErrUnexpectedEOF {
			if n%LeafSize != 0 {
				return types.Hash256{}, errors.New("stream does not contain integer multiple of leaves")
			}
		} else if err != nil {
			return types.Hash256{}, err
		}
		s.appendLeaves(leafBatch[:n])
	}
	return s.root(), nil
}

// ReadSector reads a single sector from r and calculates its root.
func ReadSector(r io.Reader) (types.Hash256, *[SectorSize]byte, error) {
	var sector [SectorSize]byte
	buf := bytes.NewBuffer(sector[:0])
	root, err := ReaderRoot(io.TeeReader(io.LimitReader(r, SectorSize), buf))
	if buf.Len() != SectorSize {
		return types.Hash256{}, nil, io.ErrUnexpectedEOF
	}
	return root, &sector, err
}

// MetaRoot calculates the root of a set of existing Merkle roots.
func MetaRoot(roots []types.Hash256) types.Hash256 {
	// sectorAccumulator is only designed to store one sector's worth of leaves,
	// so we'll panic if we insert more than leavesPerSector leaves. To
	// compensate, call MetaRoot recursively.
	if len(roots) <= LeavesPerSector {
		var sa sectorAccumulator
		for _, r := range roots {
			sa.appendNode(r)
		}
		return sa.root()
	}
	// split at largest power of two
	split := 1 << (bits.Len(uint(len(roots)-1)) - 1)
	return blake2b.SumPair(MetaRoot(roots[:split]), MetaRoot(roots[split:]))
}

// ProofSize returns the size of a Merkle proof for the leaf i within a tree
// containing n leaves.
func ProofSize(n, i uint64) uint64 {
	leftHashes := bits.OnesCount64(i)
	pathMask := 1<<bits.Len64(n-1) - 1
	rightHashes := bits.OnesCount64(^(n - 1)) & pathMask
	return uint64(leftHashes + rightHashes)
}

// RangeProofSize returns the size of a Merkle proof for the leaf range [start,
// end) within a tree containing n leaves.
func RangeProofSize(n, start, end uint64) uint64 {
	leftHashes := bits.OnesCount64(start)
	pathMask := 1<<bits.Len64((end-1)^(n-1)) - 1
	rightHashes := bits.OnesCount64(^(end - 1)) & pathMask
	return uint64(leftHashes + rightHashes)
}

// DiffProofSize returns the size of a Merkle diff proof for the specified
// actions within a tree containing n leaves.
func DiffProofSize(n int, actions []RPCWriteAction) int {
	return 128 // TODO
}

// nextSubtreeSize returns the size of the subtree adjacent to start that does
// not overlap end.
func nextSubtreeSize(start, end uint64) uint64 {
	ideal := bits.TrailingZeros64(start)
	max := bits.Len64(end-start) - 1
	if ideal > max {
		return 1 << max
	}
	return 1 << ideal
}

// BuildProof constructs a proof for the segment range [start, end). If a non-
// nil precalc function is provided, it will be used to supply precalculated
// subtree Merkle roots. For example, if the root of the left half of the
// Merkle tree is precomputed, precalc should return it for i == 0 and j ==
// SegmentsPerSector/2. If a precalculated root is not available, precalc
// should return the zero hash.
func BuildProof(sector *[SectorSize]byte, start, end uint64, precalc func(i, j uint64) types.Hash256) []types.Hash256 {
	if end > LeavesPerSector || start > end || start == end {
		panic("BuildProof: illegal proof range")
	}
	if precalc == nil {
		precalc = func(i, j uint64) (h types.Hash256) { return }
	}

	// define a helper function for later
	var s sectorAccumulator
	subtreeRoot := func(i, j uint64) types.Hash256 {
		s.reset()
		s.appendLeaves(sector[i*LeafSize : j*LeafSize])
		return s.root()
	}

	// we build the proof by recursively enumerating subtrees, left to right.
	// If a subtree is inside the segment range, we can skip it (because the
	// verifier has the segments); otherwise, we add its Merkle root to the
	// proof.
	//
	// NOTE: this operation might be a little tricky to understand because
	// it's a recursive function with side effects (appending to proof), but
	// this is the simplest way I was able to implement it. Namely, it has the
	// important advantage of being symmetrical to the Verify operation.
	proof := make([]types.Hash256, 0, ProofSize(LeavesPerSector, start))
	var rec func(uint64, uint64)
	rec = func(i, j uint64) {
		if i >= start && j <= end {
			// this subtree contains only data segments; skip it
		} else if j <= start || i >= end {
			// this subtree does not contain any data segments; add its Merkle
			// root to the proof. If we have a precalculated root, use that;
			// otherwise, calculate it from scratch.
			if h := precalc(i, j); h != (types.Hash256{}) {
				proof = append(proof, h)
			} else {
				proof = append(proof, subtreeRoot(i, j))
			}
		} else {
			// this subtree partially overlaps the data segments; split it
			// into two subtrees and recurse on each
			mid := (i + j) / 2
			rec(i, mid)
			rec(mid, j)
		}
	}
	rec(0, LeavesPerSector)
	return proof
}

// BuildSectorRangeProof constructs a proof for the sector range [start, end).
func BuildSectorRangeProof(sectorRoots []types.Hash256, start, end uint64) []types.Hash256 {
	numLeaves := uint64(len(sectorRoots))
	if numLeaves == 0 {
		return nil
	} else if end > numLeaves || start > end || start == end {
		panic("BuildSectorRangeProof: illegal proof range")
	}

	proof := make([]types.Hash256, 0, ProofSize(numLeaves, start))
	buildRange := func(i, j uint64) {
		for i < j && i < numLeaves {
			subtreeSize := nextSubtreeSize(i, j)
			if i+subtreeSize > numLeaves {
				subtreeSize = numLeaves - i
			}
			proof = append(proof, MetaRoot(sectorRoots[i:][:subtreeSize]))
			i += subtreeSize
		}
	}
	buildRange(0, start)
	buildRange(end, math.MaxInt32)
	return proof
}

// A RangeProofVerifier allows range proofs to be verified in streaming fashion.
type RangeProofVerifier struct {
	start, end uint64
	roots      []types.Hash256
}

// ReadFrom implements io.ReaderFrom.
func (rpv *RangeProofVerifier) ReadFrom(r io.Reader) (int64, error) {
	var total int64
	i, j := rpv.start, rpv.end
	for i < j {
		subtreeSize := nextSubtreeSize(i, j)
		n := int64(subtreeSize * LeafSize)
		root, err := ReaderRoot(io.LimitReader(r, n))
		if err != nil {
			return total, err
		}
		total += n
		rpv.roots = append(rpv.roots, root)
		i += subtreeSize
	}
	return total, nil
}

// Verify verifies the supplied proof, using the data ingested from ReadFrom.
func (rpv *RangeProofVerifier) Verify(proof []types.Hash256, root types.Hash256) bool {
	if uint64(len(proof)) != RangeProofSize(LeavesPerSector, rpv.start, rpv.end) {
		return false
	}
	var acc proofAccumulator
	consume := func(roots *[]types.Hash256, i, j uint64) {
		for i < j && len(*roots) > 0 {
			subtreeSize := nextSubtreeSize(i, j)
			height := bits.TrailingZeros(uint(subtreeSize)) // log2
			acc.insertNode((*roots)[0], height)
			*roots = (*roots)[1:]
			i += subtreeSize
		}
	}
	consume(&proof, 0, rpv.start)
	consume(&rpv.roots, rpv.start, rpv.end)
	consume(&proof, rpv.end, LeavesPerSector)
	return acc.root() == root
}

// NewRangeProofVerifier returns a RangeProofVerifier for the sector range
// [start, end).
func NewRangeProofVerifier(start, end uint64) *RangeProofVerifier {
	return &RangeProofVerifier{
		start: start,
		end:   end,
	}
}

// VerifyAppendProof verifies a proof produced by BuildAppendProof.
func VerifyAppendProof(numLeaves uint64, treeHashes []types.Hash256, sectorRoot, oldRoot, newRoot types.Hash256) bool {
	acc := proofAccumulator{numLeaves: numLeaves}
	for i := range acc.trees {
		if acc.hasNodeAtHeight(i) && len(treeHashes) > 0 {
			acc.trees[i] = treeHashes[0]
			treeHashes = treeHashes[1:]
		}
	}
	if acc.root() != oldRoot {
		return false
	}
	acc.insertNode(sectorRoot, 0)
	return acc.root() == newRoot
}
