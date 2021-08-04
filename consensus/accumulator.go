package consensus

import (
	"encoding/binary"
	"math/bits"
	"sort"

	"go.sia.tech/core/types"
)

// from RFC 6961
const leafHashPrefix = 0x00
const nodeHashPrefix = 0x01

// flags for state objects
const (
	flagSpent = 1 << iota
	flagExpired
)

// mergeHeight returns the height at which the proof paths of x and y merge.
func mergeHeight(x, y uint64) int { return bits.Len64(x ^ y) }

// clearBits clears the n least significant bits of x.
func clearBits(x uint64, n int) uint64 { return x &^ (1<<n - 1) }

// trailingOnes returns the number of trailing one bits in x.
func trailingOnes(x uint64) int { return bits.TrailingZeros64(x + 1) }

func merkleNodeHash(left, right types.Hash256) types.Hash256 {
	buf := make([]byte, 65)
	buf[0] = nodeHashPrefix
	copy(buf[1:], left[:])
	copy(buf[33:], right[:])
	return types.HashBytes(buf)
}

func merkleProofRoot(leafHash types.Hash256, leafIndex uint64, proof []types.Hash256) types.Hash256 {
	root := leafHash
	for i, h := range proof {
		if leafIndex&(1<<i) == 0 {
			root = merkleNodeHash(root, h)
		} else {
			root = merkleNodeHash(h, root)
		}
	}
	return root
}

type stateObject struct {
	objHash   types.Hash256
	leafIndex uint64
	flags     uint64
	proof     []types.Hash256
}

func (so stateObject) leafHash() types.Hash256 {
	buf := make([]byte, 1+32+8+8)
	buf[0] = leafHashPrefix
	copy(buf[1:], so.objHash[:])
	binary.LittleEndian.PutUint64(buf[33:], so.leafIndex)
	binary.LittleEndian.PutUint64(buf[41:], so.flags)
	return types.HashBytes(buf)
}

func (so stateObject) proofRoot() types.Hash256 {
	return merkleProofRoot(so.leafHash(), so.leafIndex, so.proof)
}

func (so stateObject) truncatedProofRoot(n int) types.Hash256 {
	return merkleProofRoot(so.leafHash(), so.leafIndex, so.proof[:n])
}

func siacoinOutputStateObject(o types.SiacoinOutput, flags uint64) stateObject {
	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	h.Reset()

	h.WriteOutputID(o.ID)
	h.WriteCurrency(o.Value)
	h.WriteHash(o.Address)
	h.WriteUint64(o.Timelock)

	return stateObject{
		objHash:   h.Sum(),
		leafIndex: o.LeafIndex,
		flags:     flags,
		proof:     o.MerkleProof,
	}
}

func siafundOutputStateObject(o types.SiafundOutput, flags uint64) stateObject {
	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	h.Reset()

	h.WriteOutputID(o.ID)
	h.WriteCurrency(o.Value)
	h.WriteHash(o.Address)

	return stateObject{
		objHash:   h.Sum(),
		leafIndex: o.LeafIndex,
		flags:     flags,
		proof:     o.MerkleProof,
	}
}

func fileContractStateObject(fc types.FileContract, flags uint64) stateObject {
	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	h.WriteOutputID(fc.ID)
	h.WriteFileContractRevision(fc.Revision)
	return stateObject{
		objHash:   h.Sum(),
		leafIndex: fc.LeafIndex,
		flags:     flags,
		proof:     fc.MerkleProof,
	}
}

func splitObjects(os []stateObject, mid uint64) (left, right []stateObject) {
	split := sort.Search(len(os), func(i int) bool { return os[i].leafIndex >= mid })
	return os[:split], os[split:]
}

func objectsByTree(txns []types.Transaction) [64][]stateObject {
	var trees [64][]stateObject
	addObject := func(so stateObject) {
		trees[len(so.proof)] = append(trees[len(so.proof)], so)
	}
	for _, txn := range txns {
		for _, in := range txn.SiacoinInputs {
			if in.Parent.LeafIndex != types.EphemeralLeafIndex {
				addObject(siacoinOutputStateObject(in.Parent, 0))
			}
		}
		for _, in := range txn.SiafundInputs {
			addObject(siafundOutputStateObject(in.Parent, 0))
		}
	}
	for _, objects := range trees {
		sort.Slice(objects, func(i, j int) bool {
			return objects[i].leafIndex < objects[j].leafIndex
		})
	}
	return trees
}

func updateProof(proof []types.Hash256, leafIndex uint64, updated *[64][]stateObject) {
	// find the "closest" updated object (the one with the lowest mergeHeight)
	updatedInTree := updated[len(proof)]
	if len(updatedInTree) == 0 {
		return
	}
	best := updatedInTree[0]
	for _, so := range updatedInTree[1:] {
		if mergeHeight(leafIndex, so.leafIndex) < mergeHeight(leafIndex, best.leafIndex) {
			best = so
		}
	}

	if best.leafIndex == leafIndex {
		// copy over the updated proof in its entirety
		copy(proof, best.proof)
	} else {
		// copy over the updated proof above the mergeHeight
		mh := mergeHeight(leafIndex, best.leafIndex)
		copy(proof[mh:], best.proof[mh:])
		// at the merge point itself, compute the updated sibling hash
		proof[mh-1] = best.truncatedProofRoot(mh - 1)
	}
}

// A StateAccumulator tracks the state of all objects.
type StateAccumulator struct {
	// A set of perfect Merkle trees, containing at most one tree at each
	// height. Only the root of each tree is stored.
	Trees     [64]types.Hash256
	NumLeaves uint64
}

// HasTreeAtHeight returns true if the StateAccumulator contains a tree root at
// the specified height.
func (sa *StateAccumulator) HasTreeAtHeight(height int) bool {
	return sa.NumLeaves&(1<<height) != 0
}

func (sa *StateAccumulator) containsObject(so stateObject) bool {
	root := so.proofRoot()
	start, end := bits.TrailingZeros64(sa.NumLeaves), bits.Len64(sa.NumLeaves)
	for i := start; i < end; i++ {
		if sa.HasTreeAtHeight(i) && sa.Trees[i] == root {
			return true
		}
	}
	return false
}

// ContainsUnspentSiacoinOutput returns true if o is a valid unspent output in
// the accumulator.
func (sa *StateAccumulator) ContainsUnspentSiacoinOutput(o types.SiacoinOutput) bool {
	return sa.containsObject(siacoinOutputStateObject(o, 0))
}

// ContainsUnspentSiafundOutput returns true if o is a valid unspent output in
// the accumulator.
func (sa *StateAccumulator) ContainsUnspentSiafundOutput(o types.SiafundOutput) bool {
	return sa.containsObject(siafundOutputStateObject(o, 0))
}

// ContainsUnresolvedFileContract returns true if fc is a valid unresolved file
// contract in the accumulator.
func (sa *StateAccumulator) ContainsUnresolvedFileContract(fc types.FileContract) bool {
	return sa.containsObject(fileContractStateObject(fc, 0))
}

// addNewObjects adds the supplied objects to the accumulator, filling in their
// Merkle proofs and returning the new node hashes that extend each existing
// tree.
func (sa *StateAccumulator) addNewObjects(objects []stateObject) [64][]types.Hash256 {
	initialLeaves := sa.NumLeaves
	var treeGrowth [64][]types.Hash256
	for i := range objects {
		objects[i].leafIndex = sa.NumLeaves
		// TODO: preallocate this more accurately
		objects[i].proof = make([]types.Hash256, 0, trailingOnes(sa.NumLeaves))

		// Walk "up" the Forest, merging trees of the same height, but before
		// merging two trees, append each of their roots to the proofs under the
		// opposite tree.
		h := objects[i].leafHash()
		for height := range &sa.Trees {
			if !sa.HasTreeAtHeight(height) {
				// no tree at this height; insert the new tree
				sa.Trees[height] = h
				sa.NumLeaves++
				break
			}
			// Another tree exists at this height. We need to append the root of
			// the "old" (left-hand) tree to the proofs under the "new"
			// (right-hand) tree, and vice versa. To do this, we seek backwards
			// through the proofs, starting from i, such that the first 2^height
			// proofs we encounter will be under to the right-hand tree, and the
			// next 2^height proofs will be under to the left-hand tree.
			oldRoot := sa.Trees[height]
			startOfNewTree := i - 1<<height
			startOfOldTree := i - 1<<(height+1)
			j := i
			for ; j > startOfNewTree && j >= 0; j-- {
				objects[j].proof = append(objects[j].proof, oldRoot)
			}
			for ; j > startOfOldTree && j >= 0; j-- {
				objects[j].proof = append(objects[j].proof, h)
			}
			// Record the left- and right-hand roots in treeGrowth, where
			// applicable.
			curTreeIndex := (sa.NumLeaves + 1) - 1<<height
			prevTreeIndex := (sa.NumLeaves + 1) - 1<<(height+1)
			for bit := range treeGrowth {
				if initialLeaves&(1<<bit) == 0 {
					continue
				}
				treeStartIndex := clearBits(initialLeaves, bit+1)
				if treeStartIndex >= curTreeIndex {
					treeGrowth[bit] = append(treeGrowth[bit], oldRoot)
				} else if treeStartIndex >= prevTreeIndex {
					treeGrowth[bit] = append(treeGrowth[bit], h)
				}
			}
			// Merge with the existing tree at this height. Since we're always
			// adding leaves on the right-hand side of the tree, the existing
			// root is always the left-hand sibling.
			h = merkleNodeHash(oldRoot, h)
		}
	}
	return treeGrowth
}

// updateExistingObjects overwrites the specified objects in the accumulator
// with their new leaf hashes. It updates the Merkle proofs of each object, and
// returns the objects (grouped by tree) for later use.
func (sa *StateAccumulator) updateExistingObjects(objects []stateObject) [64][]stateObject {
	var recompute func(i, j uint64, objects []stateObject) types.Hash256
	recompute = func(i, j uint64, objects []stateObject) types.Hash256 {
		height := bits.TrailingZeros64(j - i) // equivalent to log2(j-i), as j-i is always a power of two
		if len(objects) == 1 && height == 0 {
			return objects[0].leafHash()
		}
		mid := (i + j) / 2
		left, right := splitObjects(objects, mid)
		var leftRoot, rightRoot types.Hash256
		if len(left) == 0 {
			leftRoot = right[0].proof[height-1]
		} else {
			leftRoot = recompute(i, mid, left)
			for i := range right {
				right[i].proof[height-1] = leftRoot
			}
		}
		if len(right) == 0 {
			rightRoot = left[0].proof[height-1]
		} else {
			rightRoot = recompute(mid, j, right)
			for i := range left {
				left[i].proof[height-1] = rightRoot
			}
		}
		return merkleNodeHash(leftRoot, rightRoot)
	}

	// Group objects by tree, and sort them by leaf index.
	var trees [64][]stateObject
	sort.Slice(objects, func(i, j int) bool {
		if len(objects[i].proof) != len(objects[j].proof) {
			return len(objects[i].proof) < len(objects[j].proof)
		}
		return objects[i].leafIndex < objects[j].leafIndex
	})
	for len(objects) > 0 {
		i := 0
		for i < len(objects) && len(objects[i].proof) == len(objects[0].proof) {
			i++
		}
		trees[len(objects[0].proof)] = objects[:i]
		objects = objects[i:]
	}

	// Recompute the root of each tree with updated objects, and fill in the
	// proofs of each object.
	for height, objects := range &trees {
		if len(objects) == 0 {
			continue
		}
		// Determine the range of leaf indices that comprise this tree. We can
		// compute this efficiently by zeroing the least-significant bits of
		// NumLeaves. (Zeroing these bits is equivalent to subtracting the
		// number of leaves in all trees smaller than this one.)
		start := clearBits(sa.NumLeaves, height+1)
		end := start + 1<<height
		sa.Trees[height] = recompute(start, end, objects)
	}
	return trees
}

// MultiproofSize computes the size of a multiproof for the given txns.
func MultiproofSize(txns []types.Transaction) int {
	var proofSize func(i, j uint64, objects []stateObject) int
	proofSize = func(i, j uint64, objects []stateObject) int {
		height := bits.TrailingZeros64(j - i)
		if len(objects) == 0 {
			return 1
		} else if height == 0 {
			return 0
		}
		mid := (i + j) / 2
		left, right := splitObjects(objects, mid)
		return proofSize(i, mid, left) + proofSize(mid, j, right)
	}

	size := 0
	for height, objects := range objectsByTree(txns) {
		if len(objects) == 0 {
			continue
		}
		start := clearBits(objects[0].leafIndex, height+1)
		end := start + 1<<height
		size += proofSize(start, end, objects)
	}
	return size
}

// ComputeMultiproof computes a single Merkle proof for all inputs in txns.
func ComputeMultiproof(txns []types.Transaction) (proof []types.Hash256) {
	var visit func(i, j uint64, objects []stateObject)
	visit = func(i, j uint64, objects []stateObject) {
		height := bits.TrailingZeros64(j - i)
		if height == 0 {
			return // fully consumed
		}
		mid := (i + j) / 2
		left, right := splitObjects(objects, mid)
		if len(left) == 0 {
			proof = append(proof, right[0].proof[height-1])
		} else {
			visit(i, mid, left)
		}
		if len(right) == 0 {
			proof = append(proof, left[0].proof[height-1])
		} else {
			visit(mid, j, right)
		}
	}

	for height, objects := range objectsByTree(txns) {
		if len(objects) == 0 {
			continue
		}
		start := clearBits(objects[0].leafIndex, height+1)
		end := start + 1<<height
		visit(start, end, objects)
	}
	return
}

// ExpandMultiproof restores all of the input proofs in txns using the supplied
// multiproof, which must be valid. The len of each input proof must be the
// correct size.
func ExpandMultiproof(txns []types.Transaction, proof []types.Hash256) {
	var expand func(i, j uint64, objects []stateObject) types.Hash256
	expand = func(i, j uint64, objects []stateObject) types.Hash256 {
		height := bits.TrailingZeros64(j - i)
		if len(objects) == 0 {
			// no objects in this subtree; must have a proof root
			h := proof[0]
			proof = proof[1:]
			return h
		} else if height == 0 {
			return objects[0].leafHash()
		}
		mid := (i + j) / 2
		left, right := splitObjects(objects, mid)
		leftRoot := expand(i, mid, left)
		rightRoot := expand(mid, j, right)
		for i := range right {
			right[i].proof[height-1] = leftRoot
		}
		for i := range left {
			left[i].proof[height-1] = rightRoot
		}
		return merkleNodeHash(leftRoot, rightRoot)
	}

	for height, objects := range objectsByTree(txns) {
		if len(objects) == 0 {
			continue
		}
		start := clearBits(objects[0].leafIndex, height+1)
		end := start + 1<<height
		expand(start, end, objects)
	}
}

func merkleHistoryLeafHash(index types.ChainIndex) types.Hash256 {
	buf := make([]byte, 1+8+32)
	buf[0] = leafHashPrefix
	binary.LittleEndian.PutUint64(buf[1:], index.Height)
	copy(buf[9:], index.ID[:])
	return types.HashBytes(buf)
}

// A HistoryAccumulator is a Merkle tree of sequential ChainIndexes.
type HistoryAccumulator struct {
	// same design as StateAccumulator
	Trees     [64]types.Hash256
	NumLeaves uint64
}

// HasTreeAtHeight returns true if the HistoryAccumulator contains a tree root at
// the specified height.
func (ha *HistoryAccumulator) HasTreeAtHeight(height int) bool {
	return ha.NumLeaves&(1<<height) != 0
}

// AppendLeaf appends an index to the accumulator. It returns the "growth" of
// the accumulator, which can be used to update history proofs.
func (ha *HistoryAccumulator) AppendLeaf(index types.ChainIndex) (growth []types.Hash256) {
	h := merkleHistoryLeafHash(index)
	i := 0
	for ; ha.HasTreeAtHeight(i); i++ {
		h = merkleNodeHash(ha.Trees[i], h)
		growth = append(growth, ha.Trees[i])
	}
	ha.Trees[i] = h
	growth = append(growth, ha.Trees[i])
	ha.NumLeaves++
	return
}

// Contains returns true if the accumulator contains the given index.
func (ha *HistoryAccumulator) Contains(index types.ChainIndex, proof []types.Hash256) bool {
	root := merkleProofRoot(merkleHistoryLeafHash(index), index.Height, proof)
	start, end := bits.TrailingZeros64(ha.NumLeaves), bits.Len64(ha.NumLeaves)
	for i := start; i < end; i++ {
		if ha.HasTreeAtHeight(i) && ha.Trees[i] == root {
			return true
		}
	}
	return false
}

func storageProofRoot(sp types.StorageProof, segmentIndex uint64) types.Hash256 {
	buf := make([]byte, 65)
	buf[0] = leafHashPrefix
	copy(buf[1:], sp.DataSegment[:])
	return merkleProofRoot(types.HashBytes(buf), segmentIndex, sp.SegmentProof)
}
