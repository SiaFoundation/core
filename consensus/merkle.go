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

// An elementLeaf represents a leaf in the ElementAccumulator Merkle tree.
type elementLeaf struct {
	*types.StateElement
	ElementHash types.Hash256
	Spent       bool
}

// hash returns the leaf's hash, for direct use in the Merkle tree.
func (l elementLeaf) hash() types.Hash256 {
	buf := make([]byte, 1+32+8+1)
	buf[0] = leafHashPrefix
	copy(buf[1:], l.ElementHash[:])
	binary.LittleEndian.PutUint64(buf[33:], l.LeafIndex)
	if l.Spent {
		buf[41] = 1
	}
	return types.HashBytes(buf)
}

// proofRoot returns the root obtained from the leaf and its proof..
func (l elementLeaf) proofRoot() types.Hash256 {
	return proofRoot(l.hash(), l.LeafIndex, l.MerkleProof)
}

// chainIndexLeaf returns the elementLeaf for a ChainIndexElement.
func chainIndexLeaf(e *types.ChainIndexElement) elementLeaf {
	elemHash := hashAll("leaf/chainindex", e.ID, e.ChainIndex)
	return elementLeaf{&e.StateElement, elemHash, false}
}

// siacoinLeaf returns the elementLeaf for a SiacoinElement.
func siacoinLeaf(e *types.SiacoinElement, spent bool) elementLeaf {
	elemHash := hashAll("leaf/siacoin", e.ID, types.V2SiacoinOutput(e.SiacoinOutput), e.MaturityHeight)
	return elementLeaf{&e.StateElement, elemHash, spent}
}

// siafundLeaf returns the elementLeaf for a SiafundElement.
func siafundLeaf(e *types.SiafundElement, spent bool) elementLeaf {
	elemHash := hashAll("leaf/siafund", e.ID, types.V2SiafundOutput(e.SiafundOutput), types.V2Currency(e.ClaimStart))
	return elementLeaf{&e.StateElement, elemHash, spent}
}

// fileContractLeaf returns the elementLeaf for a FileContractElement.
func fileContractLeaf(e *types.FileContractElement, spent bool) elementLeaf {
	elemHash := hashAll("leaf/filecontract", e.ID, e.FileContract)
	return elementLeaf{&e.StateElement, elemHash, spent}
}

// v2FileContractLeaf returns the elementLeaf for a V2FileContractElement.
func v2FileContractLeaf(e *types.V2FileContractElement, spent bool) elementLeaf {
	elemHash := hashAll("leaf/v2filecontract", e.ID, e.V2FileContract)
	return elementLeaf{&e.StateElement, elemHash, spent}
}

// attestationLeaf returns the elementLeaf for an AttestationElement.
func attestationLeaf(e *types.AttestationElement) elementLeaf {
	elemHash := hashAll("leaf/attestation", e.ID, e.Attestation)
	return elementLeaf{&e.StateElement, elemHash, false}
}

// An ElementAccumulator tracks the state of an unbounded number of elements
// without storing the elements themselves.
type ElementAccumulator struct {
	Trees     [64]types.Hash256
	NumLeaves uint64
}

// EncodeTo implements types.EncoderTo.
func (acc ElementAccumulator) EncodeTo(e *types.Encoder) {
	e.WriteUint64(acc.NumLeaves)
	for i, root := range acc.Trees {
		if acc.hasTreeAtHeight(i) {
			types.Hash256(root).EncodeTo(e)
		}
	}
}

// DecodeFrom implements types.DecoderFrom.
func (acc *ElementAccumulator) DecodeFrom(d *types.Decoder) {
	acc.NumLeaves = d.ReadUint64()
	for i := range acc.Trees {
		if acc.hasTreeAtHeight(i) {
			(*types.Hash256)(&acc.Trees[i]).DecodeFrom(d)
		}
	}
}

// MarshalJSON implements json.Marshaler.
func (acc ElementAccumulator) MarshalJSON() ([]byte, error) {
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
func (acc *ElementAccumulator) UnmarshalJSON(b []byte) error {
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

func (acc *ElementAccumulator) hasTreeAtHeight(height int) bool {
	return acc.NumLeaves&(1<<height) != 0
}

func (acc *ElementAccumulator) containsLeaf(l elementLeaf) bool {
	return acc.hasTreeAtHeight(len(l.MerkleProof)) && acc.Trees[len(l.MerkleProof)] == l.proofRoot()
}

func (acc *ElementAccumulator) containsChainIndex(cie types.ChainIndexElement) bool {
	return acc.containsLeaf(chainIndexLeaf(&cie))
}

func (acc *ElementAccumulator) containsUnspentSiacoinElement(sce types.SiacoinElement) bool {
	return acc.containsLeaf(siacoinLeaf(&sce, false))
}

func (acc *ElementAccumulator) containsSpentSiacoinElement(sce types.SiacoinElement) bool {
	return acc.containsLeaf(siacoinLeaf(&sce, true))
}

func (acc *ElementAccumulator) containsUnspentSiafundElement(sfe types.SiafundElement) bool {
	return acc.containsLeaf(siafundLeaf(&sfe, false))
}

func (acc *ElementAccumulator) containsSpentSiafundElement(sfe types.SiafundElement) bool {
	return acc.containsLeaf(siafundLeaf(&sfe, true))
}

func (acc *ElementAccumulator) containsUnresolvedV2FileContractElement(fce types.V2FileContractElement) bool {
	return acc.containsLeaf(v2FileContractLeaf(&fce, false))
}

func (acc *ElementAccumulator) containsResolvedV2FileContractElement(fce types.V2FileContractElement) bool {
	return acc.containsLeaf(v2FileContractLeaf(&fce, true))
}

// addLeaves adds the supplied leaves to the accumulator, filling in their
// Merkle proofs and returning the new node hashes that extend each existing
// tree.
func (acc *ElementAccumulator) addLeaves(leaves []elementLeaf) [64][]types.Hash256 {
	initialLeaves := acc.NumLeaves
	var treeGrowth [64][]types.Hash256
	for i, el := range leaves {
		el.LeafIndex = acc.NumLeaves

		// Walk "up" the Forest, merging trees of the same height, but before
		// merging two trees, append each of their roots to the proofs under the
		// opposite tree.
		h := el.hash()
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
func updateLeaves(leaves []elementLeaf) [64][]elementLeaf {
	splitLeaves := func(ls []elementLeaf, mid uint64) (left, right []elementLeaf) {
		split := sort.Search(len(ls), func(i int) bool { return ls[i].LeafIndex >= mid })
		return ls[:split], ls[split:]
	}

	var recompute func(i, j uint64, leaves []elementLeaf) types.Hash256
	recompute = func(i, j uint64, leaves []elementLeaf) types.Hash256 {
		height := bits.TrailingZeros64(j - i) // equivalent to log2(j-i), as j-i is always a power of two
		if len(leaves) == 1 && height == 0 {
			return leaves[0].hash()
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
	var trees [64][]elementLeaf
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

// applyBlock applies the supplied leaves to the accumulator, modifying it and
// producing an update.
func (acc *ElementAccumulator) applyBlock(updated, added []elementLeaf) (eau elementApplyUpdate) {
	eau.updated = updateLeaves(updated)
	for height, es := range eau.updated {
		if len(es) > 0 {
			acc.Trees[height] = es[0].proofRoot()
		}
	}
	eau.oldNumLeaves = acc.NumLeaves
	eau.treeGrowth = acc.addLeaves(added)
	for _, e := range updated {
		e.MerkleProof = append(e.MerkleProof, eau.treeGrowth[len(e.MerkleProof)]...)
	}
	eau.numLeaves = acc.NumLeaves
	return eau
}

// revertBlock modifies the proofs of supplied elements such that they validate
// under acc, which must be the accumulator prior to the application of those
// elements. All of the elements will be marked unspent. The accumulator itself
// is not modified.
func (acc *ElementAccumulator) revertBlock(updated, added []elementLeaf) (eru elementRevertUpdate) {
	eru.updated = updateLeaves(updated)
	eru.numLeaves = acc.NumLeaves
	for i := range added {
		added[i].LeafIndex = acc.NumLeaves + uint64(i)
	}
	return
}

func updateProof(e *types.StateElement, updated *[64][]elementLeaf) {
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
		e.MerkleProof[mh-1] = proofRoot(best.hash(), best.LeafIndex, best.MerkleProof[:mh-1])
	}
}

type elementApplyUpdate struct {
	updated      [64][]elementLeaf
	treeGrowth   [64][]types.Hash256
	oldNumLeaves uint64
	numLeaves    uint64
}

func (eau *elementApplyUpdate) updateElementProof(e *types.StateElement) {
	if e.LeafIndex == types.EphemeralLeafIndex {
		panic("cannot update an ephemeral element")
	} else if e.LeafIndex >= eau.oldNumLeaves {
		return // newly-added element
	}
	updateProof(e, &eau.updated)
	if mh := mergeHeight(eau.numLeaves, e.LeafIndex); mh != len(e.MerkleProof) {
		e.MerkleProof = append(e.MerkleProof, eau.treeGrowth[len(e.MerkleProof)]...)
	}
}

type elementRevertUpdate struct {
	updated   [64][]elementLeaf
	numLeaves uint64
}

func (eru *elementRevertUpdate) updateElementProof(e *types.StateElement) {
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
