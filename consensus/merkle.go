package consensus

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/bits"
	"sort"

	"go.sia.tech/core/internal/blake2b"
	"go.sia.tech/core/types"
)

// from RFC 6961
const leafHashPrefix = 0x00

// mergeHeight returns the height at which the proof paths of x and y merge.
func mergeHeight(x, y uint64) int { return bits.Len64(x ^ y) }

// clearBits clears the n least significant bits of x.
func clearBits(x uint64, n int) uint64 { return x &^ (1<<n - 1) }

func proofRoot(leafHash types.Hash256, leafIndex uint64, proof []types.Hash256) types.Hash256 {
	root := leafHash
	for i, h := range proof {
		if leafIndex&(1<<i) == 0 {
			root = blake2b.SumPair(root, h)
		} else {
			root = blake2b.SumPair(h, root)
		}
	}
	return root
}

func storageProofRoot(leafHash types.Hash256, leafIndex uint64, filesize uint64, proof []types.Hash256) types.Hash256 {
	const leafSize = uint64(len(types.V2StorageProof{}.Leaf))
	lastLeafIndex := filesize / leafSize
	if filesize%leafSize == 0 {
		lastLeafIndex--
	}
	subtreeHeight := bits.Len64(leafIndex ^ lastLeafIndex)
	if len(proof) < subtreeHeight {
		return types.Hash256{} // invalid proof
	}
	root := proofRoot(leafHash, leafIndex, proof[:subtreeHeight])
	for _, h := range proof[subtreeHeight:] {
		root = blake2b.SumPair(root, h)
	}
	return root
}

// An ElementLeaf represents a leaf in the ElementAccumulator Merkle tree.
type ElementLeaf struct {
	*types.StateElement
	ElementHash types.Hash256
	Spent       bool
}

// Hash returns the leaf's hash, for direct use in the Merkle tree.
func (l ElementLeaf) Hash() types.Hash256 {
	buf := make([]byte, 1+32+8+1)
	buf[0] = leafHashPrefix
	copy(buf[1:], l.ElementHash[:])
	binary.LittleEndian.PutUint64(buf[33:], l.LeafIndex)
	if l.Spent {
		buf[41] = 1
	}
	return types.HashBytes(buf)
}

// ProofRoot returns the root obtained from the leaf and its proof..
func (l ElementLeaf) ProofRoot() types.Hash256 {
	return proofRoot(l.Hash(), l.LeafIndex, l.MerkleProof)
}

// SiacoinLeaf returns the ElementLeaf for a SiacoinElement.
func SiacoinLeaf(e *types.SiacoinElement, spent bool) ElementLeaf {
	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	h.E.WriteString("sia/leaf/siacoin|")
	e.ID.EncodeTo(h.E)
	e.SiacoinOutput.EncodeTo(h.E)
	h.E.WriteUint64(e.MaturityHeight)
	return ElementLeaf{
		StateElement: &e.StateElement,
		ElementHash:  h.Sum(),
		Spent:        spent,
	}
}

// SiafundLeaf returns the ElementLeaf for a SiafundElement.
func SiafundLeaf(e *types.SiafundElement, spent bool) ElementLeaf {
	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	h.E.WriteString("sia/leaf/siafund|")
	e.ID.EncodeTo(h.E)
	e.SiafundOutput.EncodeTo(h.E)
	e.ClaimStart.EncodeTo(h.E)
	return ElementLeaf{
		StateElement: &e.StateElement,
		ElementHash:  h.Sum(),
		Spent:        spent,
	}
}

// FileContractLeaf returns the ElementLeaf for a FileContractElement.
func FileContractLeaf(e *types.FileContractElement, spent bool) ElementLeaf {
	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	h.E.WriteString("sia/leaf/filecontract|")
	e.ID.EncodeTo(h.E)
	e.FileContract.EncodeTo(h.E)
	return ElementLeaf{
		StateElement: &e.StateElement,
		ElementHash:  h.Sum(),
		Spent:        spent,
	}
}

// V2FileContractLeaf returns the ElementLeaf for a V2FileContractElement.
func V2FileContractLeaf(e *types.V2FileContractElement, spent bool) ElementLeaf {
	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	h.E.WriteString("sia/leaf/v2filecontract|")
	e.ID.EncodeTo(h.E)
	e.V2FileContract.EncodeTo(h.E)
	return ElementLeaf{
		StateElement: &e.StateElement,
		ElementHash:  h.Sum(),
		Spent:        spent,
	}
}

type accumulator struct {
	Trees     [64]types.Hash256
	NumLeaves uint64
}

func (acc *accumulator) hasTreeAtHeight(height int) bool {
	return acc.NumLeaves&(1<<height) != 0
}

// EncodeTo implements types.EncoderTo.
func (acc accumulator) EncodeTo(e *types.Encoder) {
	e.WriteUint64(acc.NumLeaves)
	for i, root := range acc.Trees {
		if acc.hasTreeAtHeight(i) {
			types.Hash256(root).EncodeTo(e)
		}
	}
}

// DecodeFrom implements types.DecoderFrom.
func (acc *accumulator) DecodeFrom(d *types.Decoder) {
	acc.NumLeaves = d.ReadUint64()
	for i := range acc.Trees {
		if acc.hasTreeAtHeight(i) {
			(*types.Hash256)(&acc.Trees[i]).DecodeFrom(d)
		}
	}
}

// MarshalJSON implements json.Marshaler.
func (acc accumulator) MarshalJSON() ([]byte, error) {
	v := struct {
		NumLeaves uint64          `json:"numLeaves"`
		Trees     []types.Hash256 `json:"trees"`
	}{acc.NumLeaves, []types.Hash256{}}
	for i, root := range acc.Trees {
		if acc.hasTreeAtHeight(i) {
			v.Trees = append(v.Trees, root)
		}
	}
	return json.Marshal(v)
}

// UnmarshalJSON implements json.Unmarshaler.
func (acc *accumulator) UnmarshalJSON(b []byte) error {
	var v struct {
		NumLeaves uint64
		Trees     []types.Hash256
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	} else if len(v.Trees) != bits.OnesCount64(v.NumLeaves) {
		return errors.New("invalid accumulator encoding")
	}
	acc.NumLeaves = v.NumLeaves
	for i := range acc.Trees {
		if acc.hasTreeAtHeight(i) {
			acc.Trees[i] = v.Trees[0]
			v.Trees = v.Trees[1:]
		}
	}
	return nil
}

// An ElementAccumulator tracks the state of an unbounded number of elements
// without storing the elements themselves.
type ElementAccumulator struct {
	accumulator
}

func (acc *ElementAccumulator) containsLeaf(l ElementLeaf) bool {
	return acc.hasTreeAtHeight(len(l.MerkleProof)) && acc.Trees[len(l.MerkleProof)] == l.ProofRoot()
}

// ContainsUnspentSiacoinElement returns true if the accumulator contains sce as an
// unspent output.
func (acc *ElementAccumulator) ContainsUnspentSiacoinElement(sce types.SiacoinElement) bool {
	return acc.containsLeaf(SiacoinLeaf(&sce, false))
}

// ContainsSpentSiacoinElement returns true if the accumulator contains sce as a
// spent output.
func (acc *ElementAccumulator) ContainsSpentSiacoinElement(sce types.SiacoinElement) bool {
	return acc.containsLeaf(SiacoinLeaf(&sce, true))
}

// ContainsUnspentSiafundElement returns true if the accumulator contains e as an
// unspent output.
func (acc *ElementAccumulator) ContainsUnspentSiafundElement(sfe types.SiafundElement) bool {
	return acc.containsLeaf(SiafundLeaf(&sfe, false))
}

// ContainsSpentSiafundElement returns true if the accumulator contains o as a
// spent output.
func (acc *ElementAccumulator) ContainsSpentSiafundElement(sfe types.SiafundElement) bool {
	return acc.containsLeaf(SiafundLeaf(&sfe, true))
}

// ContainsUnresolvedV2FileContractElement returns true if the accumulator
// contains fce as an unresolved file contract.
func (acc *ElementAccumulator) ContainsUnresolvedV2FileContractElement(fce types.V2FileContractElement) bool {
	return acc.containsLeaf(V2FileContractLeaf(&fce, false))
}

// ContainsResolvedV2FileContractElement returns true if the accumulator contains
// fce as a resolved file contract.
func (acc *ElementAccumulator) ContainsResolvedV2FileContractElement(fce types.V2FileContractElement) bool {
	return acc.containsLeaf(V2FileContractLeaf(&fce, true))
}

// addLeaves adds the supplied leaves to the accumulator, filling in their
// Merkle proofs and returning the new node hashes that extend each existing
// tree.
func (acc *ElementAccumulator) addLeaves(leaves []ElementLeaf) [64][]types.Hash256 {
	initialLeaves := acc.NumLeaves
	var treeGrowth [64][]types.Hash256
	for i, el := range leaves {
		el.LeafIndex = acc.NumLeaves

		// Walk "up" the Forest, merging trees of the same height, but before
		// merging two trees, append each of their roots to the proofs under the
		// opposite tree.
		h := el.Hash()
		for height := range &acc.Trees {
			if !acc.hasTreeAtHeight(height) {
				// no tree at this height; insert the new tree
				acc.Trees[height] = h
				acc.NumLeaves++
				break
			}
			// Another tree exists at this height. We need to append the root of
			// the "old" (left-hand) tree to the proofs under the "new"
			// (right-hand) tree, and vice versa. To do this, we seek backwards
			// through the proofs, starting from i, such that the first 2^height
			// proofs we encounter will be under to the right-hand tree, and the
			// next 2^height proofs will be under to the left-hand tree.
			oldRoot := acc.Trees[height]
			startOfNewTree := i - 1<<height
			startOfOldTree := i - 1<<(height+1)
			j := i
			for ; j > startOfNewTree && j >= 0; j-- {
				leaves[j].MerkleProof = append(leaves[j].MerkleProof, oldRoot)
			}
			for ; j > startOfOldTree && j >= 0; j-- {
				leaves[j].MerkleProof = append(leaves[j].MerkleProof, h)
			}
			// Record the left- and right-hand roots in treeGrowth, where
			// applicable.
			curTreeIndex := (acc.NumLeaves + 1) - 1<<height
			prevTreeIndex := (acc.NumLeaves + 1) - 1<<(height+1)
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
			h = blake2b.SumPair(oldRoot, h)
		}
	}
	return treeGrowth
}

// updateLeaves updates the Merkle proofs of each leaf to reflect the changes in
// all other leaves, and returns the leaves (grouped by tree) for later use.
func updateLeaves(leaves []ElementLeaf) [64][]ElementLeaf {
	splitLeaves := func(ls []ElementLeaf, mid uint64) (left, right []ElementLeaf) {
		split := sort.Search(len(ls), func(i int) bool { return ls[i].LeafIndex >= mid })
		return ls[:split], ls[split:]
	}

	var recompute func(i, j uint64, leaves []ElementLeaf) types.Hash256
	recompute = func(i, j uint64, leaves []ElementLeaf) types.Hash256 {
		height := bits.TrailingZeros64(j - i) // equivalent to log2(j-i), as j-i is always a power of two
		if len(leaves) == 1 && height == 0 {
			return leaves[0].Hash()
		}
		mid := (i + j) / 2
		left, right := splitLeaves(leaves, mid)
		var leftRoot, rightRoot types.Hash256
		if len(left) == 0 {
			leftRoot = right[0].MerkleProof[height-1]
		} else {
			leftRoot = recompute(i, mid, left)
			for _, e := range right {
				e.MerkleProof[height-1] = leftRoot
			}
		}
		if len(right) == 0 {
			rightRoot = left[0].MerkleProof[height-1]
		} else {
			rightRoot = recompute(mid, j, right)
			for _, e := range left {
				e.MerkleProof[height-1] = rightRoot
			}
		}
		return blake2b.SumPair(leftRoot, rightRoot)
	}

	// Group leaves by tree, and sort them by leaf index.
	var trees [64][]ElementLeaf
	sort.Slice(leaves, func(i, j int) bool {
		if len(leaves[i].MerkleProof) != len(leaves[j].MerkleProof) {
			return len(leaves[i].MerkleProof) < len(leaves[j].MerkleProof)
		}
		return leaves[i].LeafIndex < leaves[j].LeafIndex
	})
	for len(leaves) > 0 {
		i := 0
		for i < len(leaves) && len(leaves[i].MerkleProof) == len(leaves[0].MerkleProof) {
			i++
		}
		trees[len(leaves[0].MerkleProof)] = leaves[:i]
		leaves = leaves[i:]
	}

	// Update the proofs within each tree by recursively recomputing the total
	// root.
	for height, leaves := range &trees {
		if len(leaves) == 0 {
			continue
		}
		// Determine the range of leaf indices that comprise this tree. We can
		// compute this efficiently by zeroing the least-significant bits of the
		// leaf index.
		start := clearBits(leaves[0].LeafIndex, height)
		end := start + 1<<height
		_ = recompute(start, end, leaves)
	}
	return trees
}

// ApplyBlock applies the supplied leaves to the accumulator, modifying it and
// producing an update.
func (acc *ElementAccumulator) ApplyBlock(updated, added []ElementLeaf) (eau ElementApplyUpdate) {
	eau.updated = updateLeaves(updated)
	for height, es := range eau.updated {
		if len(es) > 0 {
			acc.Trees[height] = es[0].ProofRoot()
		}
	}
	eau.treeGrowth = acc.addLeaves(added)
	for _, e := range updated {
		e.MerkleProof = append(e.MerkleProof, eau.treeGrowth[len(e.MerkleProof)]...)
	}
	return eau
}

// RevertBlock modifies the proofs of supplied elements such that they validate
// under acc, which must be the accumulator prior to the application of those
// elements. The accumulator itself is not modified.
func (acc *ElementAccumulator) RevertBlock(updated []ElementLeaf) (eru ElementRevertUpdate) {
	eru.updated = updateLeaves(updated)
	eru.numLeaves = acc.NumLeaves
	return
}

func updateProof(e *types.StateElement, updated *[64][]ElementLeaf) {
	// find the "closest" updated object (the one with the lowest mergeHeight)
	updatedInTree := updated[len(e.MerkleProof)]
	if len(updatedInTree) == 0 {
		return
	}
	best := updatedInTree[0]
	for _, ul := range updatedInTree[1:] {
		if mergeHeight(e.LeafIndex, ul.LeafIndex) < mergeHeight(e.LeafIndex, best.LeafIndex) {
			best = ul
		}
	}

	if best.LeafIndex == e.LeafIndex {
		// copy over the updated proof in its entirety
		copy(e.MerkleProof, best.MerkleProof)
	} else {
		// copy over the updated proof above the mergeHeight
		mh := mergeHeight(e.LeafIndex, best.LeafIndex)
		copy(e.MerkleProof[mh:], best.MerkleProof[mh:])
		// at the merge point itself, compute the updated sibling hash
		e.MerkleProof[mh-1] = proofRoot(best.Hash(), best.LeafIndex, best.MerkleProof[:mh-1])
	}
}

// An ElementApplyUpdate reflects the changes to an ElementAccumulator resulting
// from the application of a block.
type ElementApplyUpdate struct {
	updated    [64][]ElementLeaf
	treeGrowth [64][]types.Hash256
}

// UpdateElementProof updates the Merkle proof of the supplied element to
// incorporate the changes made to the accumulator. The element's proof must be
// up-to-date; if it is not, UpdateElementProof may panic.
func (eau *ElementApplyUpdate) UpdateElementProof(e *types.StateElement) {
	if e.LeafIndex == types.EphemeralLeafIndex {
		panic("cannot update an ephemeral element")
	}
	updateProof(e, &eau.updated)
	e.MerkleProof = append(e.MerkleProof, eau.treeGrowth[len(e.MerkleProof)]...)
}

// An ElementRevertUpdate reflects the changes to an ElementAccumulator
// resulting from the removal of a block.
type ElementRevertUpdate struct {
	updated   [64][]ElementLeaf
	numLeaves uint64
}

// UpdateElementProof updates the Merkle proof of the supplied element to
// incorporate the changes made to the accumulator. The element's proof must be
// up-to-date; if it is not, UpdateElementProof may panic.
func (eru *ElementRevertUpdate) UpdateElementProof(e *types.StateElement) {
	if e.LeafIndex == types.EphemeralLeafIndex {
		panic("cannot update an ephemeral element")
	} else if e.LeafIndex >= eru.numLeaves {
		panic("cannot update an element that is not present in the accumulator")
	}
	if mh := mergeHeight(eru.numLeaves, e.LeafIndex); mh <= len(e.MerkleProof) {
		e.MerkleProof = e.MerkleProof[:mh-1]
	}
	updateProof(e, &eru.updated)
}

func historyLeafHash(index types.ChainIndex) types.Hash256 {
	buf := make([]byte, 1+8+32)
	buf[0] = leafHashPrefix
	binary.LittleEndian.PutUint64(buf[1:], index.Height)
	copy(buf[9:], index.ID[:])
	return types.HashBytes(buf)
}

func historyProofRoot(index types.ChainIndex, proof []types.Hash256) types.Hash256 {
	return proofRoot(historyLeafHash(index), index.Height, proof)
}

// A HistoryAccumulator tracks the state of all ChainIndexs in a chain without
// storing the full sequence of indexes itself.
type HistoryAccumulator struct {
	accumulator
}

// Contains returns true if the accumulator contains the given index.
func (acc *HistoryAccumulator) Contains(index types.ChainIndex, proof []types.Hash256) bool {
	return acc.hasTreeAtHeight(len(proof)) && acc.Trees[len(proof)] == historyProofRoot(index, proof)
}

// ApplyBlock integrates a ChainIndex into the accumulator, producing a
// HistoryApplyUpdate.
func (acc *HistoryAccumulator) ApplyBlock(index types.ChainIndex) (hau HistoryApplyUpdate) {
	h := historyLeafHash(index)
	i := 0
	for ; acc.hasTreeAtHeight(i); i++ {
		hau.proof = append(hau.proof, acc.Trees[i])
		hau.growth = append(hau.growth, h)
		h = blake2b.SumPair(acc.Trees[i], h)
	}
	acc.Trees[i] = h
	acc.NumLeaves++
	return
}

// RevertBlock produces a HistoryRevertUpdate from a ChainIndex.
func (acc *HistoryAccumulator) RevertBlock(index types.ChainIndex) HistoryRevertUpdate {
	return HistoryRevertUpdate{index}
}

// A HistoryApplyUpdate reflects the changes to a HistoryAccumulator resulting
// from the application of a block.
type HistoryApplyUpdate struct {
	proof  []types.Hash256
	growth []types.Hash256
}

// HistoryProof returns a history proof for the applied block. To prevent
// aliasing, it always returns new memory.
func (hau *HistoryApplyUpdate) HistoryProof() []types.Hash256 {
	return append([]types.Hash256(nil), hau.proof...)
}

// UpdateProof updates the supplied history proof to incorporate changes made to
// the chain history. The proof must be up-to-date; if it is not, UpdateProof
// may panic.
func (hau *HistoryApplyUpdate) UpdateProof(proof *[]types.Hash256) {
	if len(hau.growth) > len(*proof) {
		*proof = append(*proof, hau.growth[len(*proof)])
		*proof = append(*proof, hau.proof[len(*proof):]...)
	}
}

// UpdateHistoryProof updates the supplied storage proof to incorporate changes
// made to the chain history. The proof must be up-to-date; if it is not,
// UpdateHistoryProof may panic.
func (hau *HistoryApplyUpdate) UpdateHistoryProof(sp *types.V2StorageProof) {
	hau.UpdateProof(&sp.HistoryProof)
}

// A HistoryRevertUpdate reflects the changes to a HistoryAccumulator resulting
// from the removal of a block.
type HistoryRevertUpdate struct {
	index types.ChainIndex
}

// UpdateProof updates the supplied history proof to incorporate the changes
// made to the chain history. The proof must be up-to-date; if it is not,
// UpdateHistoryProof may panic.
func (hru *HistoryRevertUpdate) UpdateProof(height uint64, proof *[]types.Hash256) {
	if mh := mergeHeight(hru.index.Height, height); mh <= len(*proof) {
		*proof = (*proof)[:mh-1]
	}
}

// UpdateHistoryProof updates the supplied storage proof to incorporate the
// changes made to the chain history. The proof must be up-to-date; if it is
// not, UpdateHistoryProof may panic.
func (hru *HistoryRevertUpdate) UpdateHistoryProof(sp *types.V2StorageProof) {
	hru.UpdateProof(sp.ProofStart.Height, &sp.HistoryProof)
}
