package rhp

import (
	"bytes"
	"errors"
	"io"
	"math/bits"
	"runtime"
	"sync"
	"unsafe"

	"go.sia.tech/core/blake2b"
	rhp2 "go.sia.tech/core/rhp/v2"
	"go.sia.tech/core/types"
)

const (
	// LeafSize is the size of one leaf in bytes.
	LeafSize = rhp2.LeafSize

	// LeavesPerSector is the number of leaves in one sector.
	LeavesPerSector = rhp2.LeavesPerSector
)

var (
	sectorAccumulatorPool = sync.Pool{
		New: func() any {
			return new(sectorAccumulator)
		},
	}

	proofAccumulatorPool = sync.Pool{
		New: func() any {
			return new(proofAccumulator)
		},
	}
)

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

func (pa *proofAccumulator) reset() {
	pa.numLeaves = 0
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
func SectorRoot(sector []byte) types.Hash256 {
	if len(sector) == 0 || len(sector)%LeafSize != 0 {
		panic("SectorRoot: illegal input size")
	}
	leaves := len(sector) / LeafSize
	// assign one subtree to each of 2^n goroutines, then merge
	p := min(1<<bits.Len(uint(runtime.NumCPU())), max(1, leaves/4))
	per := len(sector) / p
	roots := make([]types.Hash256, p)
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
	var sa sectorAccumulator
	for _, r := range roots {
		sa.appendNode(r)
	}
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

// ReadVariableSector reads a variably sized sector from r and calculates its root.
// sectorSize must be a multiple of LeafSize. Returns an error if the stream
// does not contain exactly sectorSize bytes.
func ReadVariableSector(r io.Reader, sectorSize uint64) (types.Hash256, []byte, error) {
	if sectorSize%LeafSize != 0 {
		return types.Hash256{}, nil, errors.New("sector length must be multiple of leaf size")
	}

	s := sectorAccumulatorPool.Get().(*sectorAccumulator)
	defer sectorAccumulatorPool.Put(s)
	s.reset()

	sector := make([]byte, 0, sectorSize)
	r = io.TeeReader(io.LimitReader(r, int64(sectorSize)), bytes.NewBuffer(sector))

	leafBatch := make([]byte, LeafSize*16)
	for {
		n, err := io.ReadFull(r, leafBatch)
		if err == io.EOF {
			break
		} else if err == io.ErrUnexpectedEOF {
			if n%LeafSize != 0 {
				return types.Hash256{}, nil, errors.New("stream does not contain integer multiple of leaves")
			}
		} else if err != nil {
			return types.Hash256{}, nil, err
		}
		sector = append(sector, leafBatch[:n]...)
		s.appendLeaves(leafBatch[:n])
	}
	if uint64(len(sector)) != sectorSize {
		return types.Hash256{}, nil, io.ErrUnexpectedEOF
	}
	return s.root(), sector, nil
}

// MetaRoot calculates the root of a set of existing Merkle roots.
func MetaRoot(roots []types.Hash256) types.Hash256 {
	return rhp2.MetaRoot(roots)
}

// proofSize returns the size of a Merkle proof for the leaf i within a tree
// containing n leaves.
func proofSize(n, i uint64) uint64 {
	return rhp2.RangeProofSize(n, i, i+1)
}

// BuildSectorProof builds a Merkle proof for a given range within a sector.
func BuildSectorProof(data []byte, start, end uint64) []types.Hash256 {
	if len(data)%LeafSize != 0 {
		panic("BuildProof: illegal data size")
	}
	leaves := uint64(len(data) / LeafSize)

	if end > leaves || start > end || start == end {
		panic("BuildProof: illegal proof range")
	}

	// define a helper function for later
	s := sectorAccumulatorPool.Get().(*sectorAccumulator)
	defer sectorAccumulatorPool.Put(s)
	subtreeRoot := func(i, j uint64) types.Hash256 {
		s.reset()
		s.appendLeaves(data[i*LeafSize : j*LeafSize])
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
	proof := make([]types.Hash256, 0, proofSize(leaves, start))
	var rec func(uint64, uint64)
	rec = func(i, j uint64) {
		if i >= start && j <= end {
			// this subtree contains only data segments; skip it
		} else if j <= start || i >= end {
			// this subtree does not contain any data segments; add its Merkle
			// root to the proof. If we have a precalculated root, use that;
			// otherwise, calculate it from scratch.
			proof = append(proof, subtreeRoot(i, j))
		} else {
			// this subtree partially overlaps the data segments; split it
			// into two subtrees and recurse on each
			mid := (i + j) / 2
			rec(i, mid)
			rec(mid, j)
		}
	}
	rec(0, leaves)
	return proof
}

// nextSubtreeSize returns the size of the subtree adjacent to start that does
// not overlap end.
func nextSubtreeSize(start, end uint64) uint64 {
	ideal := bits.TrailingZeros64(start)
	maxSize := bits.Len64(end-start) - 1
	if ideal > maxSize {
		return 1 << maxSize
	}
	return 1 << ideal
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
		root, err := rhp2.ReaderRoot(io.LimitReader(r, n))
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
func (rpv *RangeProofVerifier) Verify(proof []types.Hash256, root types.Hash256, leaves uint64) bool {
	if uint64(len(proof)) != rhp2.RangeProofSize(leaves, rpv.start, rpv.end) {
		return false
	}
	acc := proofAccumulatorPool.Get().(*proofAccumulator)
	defer proofAccumulatorPool.Put(acc)
	acc.reset()

	// helper function to consume subtrees from the proof or the data roots
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
	consume(&proof, rpv.end, leaves)
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

// VerifyLeafProof verifies the Merkle proof for a given leaf within a sector.
func VerifyLeafProof(proof []types.Hash256, leaf [64]byte, leaves, leafIndex uint64, root types.Hash256) bool {
	return rhp2.VerifySectorRangeProof(proof, []types.Hash256{blake2b.SumLeaf(&leaf)}, leafIndex, leafIndex+1, leaves, root)
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
