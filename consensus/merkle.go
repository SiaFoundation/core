package consensus

import (
	"cmp"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/bits"
	"slices"
	"sort"

	"go.sia.tech/core/blake2b"
	"go.sia.tech/core/types"
)

// from RFC 6962, Section 2.1
const leafHashPrefix uint8 = 0x00

// mergeHeight returns the height at which the proof paths of x and y merge.
func mergeHeight(x, y uint64) int { return bits.Len64(x ^ y) }

// clearBits clears the n least significant bits of x.
func clearBits(x uint64, n int) uint64 { return x &^ (1<<n - 1) }

func sortLeaves(leaves []elementLeaf) {
	slices.SortFunc(leaves, func(a, b elementLeaf) int {
		return cmp.Compare(a.LeafIndex, b.LeafIndex)
	})
}

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
		root = blake2b.SumPair(h, root)
	}
	return root
}

// An elementLeaf represents a leaf in the ElementAccumulator Merkle tree.
type elementLeaf struct {
	*types.StateElement
	elementHash types.Hash256
	spent       bool
}

// hash returns the leaf's hash, for direct use in the Merkle tree.
func (l elementLeaf) hash() types.Hash256 {
	buf := make([]byte, 1+32+8+1)
	buf[0] = leafHashPrefix
	copy(buf[1:], l.elementHash[:])
	binary.LittleEndian.PutUint64(buf[33:], l.LeafIndex)
	if l.spent {
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
func fileContractLeaf(e *types.FileContractElement, rev *types.FileContract, spent bool) elementLeaf {
	fc := e.FileContract
	if rev != nil {
		fc = *rev
	}
	elemHash := hashAll("leaf/filecontract", e.ID, fc)
	return elementLeaf{&e.StateElement, elemHash, spent}
}

// v2FileContractLeaf returns the elementLeaf for a V2FileContractElement.
func v2FileContractLeaf(e *types.V2FileContractElement, rev *types.V2FileContract, spent bool) elementLeaf {
	fc := e.V2FileContract
	if rev != nil {
		fc = *rev
	}
	elemHash := hashAll("leaf/v2filecontract", e.ID, fc)
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

func (acc *ElementAccumulator) containsUnresolvedFileContractElement(fce types.FileContractElement) bool {
	return acc.containsLeaf(fileContractLeaf(&fce, nil, false))
}

func (acc *ElementAccumulator) containsUnresolvedV2FileContractElement(fce types.V2FileContractElement) bool {
	return acc.containsLeaf(v2FileContractLeaf(&fce, nil, false))
}

func (acc *ElementAccumulator) containsResolvedV2FileContractElement(fce types.V2FileContractElement) bool {
	return acc.containsLeaf(v2FileContractLeaf(&fce, nil, true))
}

// ValidateTransactionElements validates the Merkle proofs of all elements in the
// supplied transaction.
func (acc *ElementAccumulator) ValidateTransactionElements(txn types.V2Transaction) (err error) {
	check := func(typ string, l elementLeaf) {
		if err == nil && l.LeafIndex != types.UnassignedLeafIndex {
			if !acc.containsLeaf(l) {
				err = errors.New(typ + " parent has invalid Merkle proof")
			}
		}
	}
	for i := range txn.SiacoinInputs {
		check("siacoin input", siacoinLeaf(&txn.SiacoinInputs[i].Parent, false))
	}
	for i := range txn.SiafundInputs {
		check("siafund input", siafundLeaf(&txn.SiafundInputs[i].Parent, false))
	}
	for i := range txn.FileContractRevisions {
		check("file contract revision", v2FileContractLeaf(&txn.FileContractRevisions[i].Parent, nil, false))
	}
	for i := range txn.FileContractResolutions {
		check("file contract resolution", v2FileContractLeaf(&txn.FileContractResolutions[i].Parent, nil, false))
		if r, ok := txn.FileContractResolutions[i].Resolution.(*types.V2StorageProof); ok {
			check("storage proof", chainIndexLeaf(&r.ProofIndex))
		}
	}
	return
}

// addLeaves adds the supplied leaves to the accumulator, filling in their
// Merkle proofs and returning the new node hashes that extend each existing
// tree.
func (acc *ElementAccumulator) addLeaves(leaves []elementLeaf) [64][]types.Hash256 {
	var treeGrowth [64][]types.Hash256
	if len(leaves) == 0 {
		return treeGrowth
	}
	initialLeaves := acc.NumLeaves
	for i, el := range leaves {
		el.LeafIndex = acc.NumLeaves
		el.MerkleProof = nil

		// Merge trees of equal height, appending each root to the proofs in
		// the opposite tree.
		h := el.hash()
		for height := range &acc.Trees {
			if !acc.hasTreeAtHeight(height) {
				// no tree at this height; insert the new tree
				acc.Trees[height] = h
				acc.NumLeaves++
				break
			}
			// The two trees cover adjacent ranges of 2^height leaves. Clip
			// those ranges to the leaves added in this call.
			oldRoot := acc.Trees[height]
			start := max(clearBits(el.LeafIndex, height+1), initialLeaves) - initialLeaves
			mid := max(clearBits(el.LeafIndex, height), initialLeaves) - initialLeaves
			for _, l := range leaves[start:mid] {
				l.MerkleProof = append(l.MerkleProof, h)
			}
			for _, l := range leaves[mid : i+1] {
				l.MerkleProof = append(l.MerkleProof, oldRoot)
			}
			// If the left tree contains no added leaves, it is an original
			// tree. Save its new sibling to begin its proof extension.
			if mid == 0 {
				treeGrowth[height] = []types.Hash256{h}
			}
			h = blake2b.SumPair(oldRoot, h)
		}
	}

	// Every original tree that grew is a left sibling on the first added
	// leaf's proof path. Above their merge point, they share the same proof.
	for height, growth := range treeGrowth[:len(leaves[0].MerkleProof)] {
		if len(growth) > 0 {
			treeGrowth[height] = append(growth, leaves[0].MerkleProof[height+1:]...)
		}
	}
	return treeGrowth
}

// updateLeaves updates the Merkle proofs of each leaf to reflect the changes in
// all other leaves, and returns the leaves (grouped by tree) for later use.
func updateLeaves(leaves []elementLeaf) (trees [64][]elementLeaf) {
	var recompute func(height int, leaves []elementLeaf) types.Hash256
	recompute = func(height int, leaves []elementLeaf) types.Hash256 {
		first := leaves[0]
		if len(leaves) == 1 {
			return proofRoot(first.hash(), first.LeafIndex, first.MerkleProof[:height])
		}

		// Split at the highest bit where the leaf indices differ. Above
		// this point, all updated leaves share the same proof path.
		mh := mergeHeight(first.LeafIndex, leaves[len(leaves)-1].LeafIndex)
		if mh == 0 {
			panic("consensus: multiple leaves with same accumulator index")
		}
		split := sort.Search(len(leaves), func(i int) bool { return leaves[i].LeafIndex&(1<<(mh-1)) != 0 })
		left, right := leaves[:split], leaves[split:]
		leftRoot, rightRoot := recompute(mh-1, left), recompute(mh-1, right)
		for _, e := range left {
			e.MerkleProof[mh-1] = rightRoot
		}
		for _, e := range right {
			e.MerkleProof[mh-1] = leftRoot
		}
		root := blake2b.SumPair(leftRoot, rightRoot)
		if mh == height {
			return root
		}
		// Fold in the unchanged siblings above the branching subtree.
		return proofRoot(root, first.LeafIndex>>mh, first.MerkleProof[mh:height])
	}

	// Trees occupy disjoint ranges, so sorting by leaf index also groups the
	// leaves by tree.
	sortLeaves(leaves)
	for len(leaves) > 0 {
		height := len(leaves[0].MerkleProof)
		i := 1
		for i < len(leaves) && len(leaves[i].MerkleProof) == height {
			i++
		}
		trees[height] = leaves[:i]
		if i > 1 {
			recompute(mergeHeight(leaves[0].LeafIndex, leaves[i-1].LeafIndex), leaves[:i])
		}
		leaves = leaves[i:]
	}
	return trees
}

// applyBlock applies the supplied leaves to the accumulator, modifying it and
// producing an update.
func (acc *ElementAccumulator) applyBlock(updated, added []elementLeaf) (eau elementApplyUpdate) {
	for _, el := range updated {
		_ = el.Move() // panics if element is shared
	}
	for _, el := range added {
		_ = el.Move() // panics if element is shared
	}

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
// elements. The accumulator itself is not modified.
func (acc *ElementAccumulator) revertBlock(updated, added []elementLeaf) (eru elementRevertUpdate) {
	for _, el := range updated {
		_ = el.Move() // panics if element is shared
	}
	for _, el := range added {
		_ = el.Move() // panics if element is shared
	}

	eru.updated = updateLeaves(updated)
	eru.numLeaves = acc.NumLeaves
	for i := range added {
		added[i].LeafIndex = acc.NumLeaves + uint64(i)
	}
	return
}

func updateProof(e *types.StateElement, updated *[64][]elementLeaf) {
	updatedInTree := updated[len(e.MerkleProof)]
	if len(updatedInTree) == 0 {
		return
	}
	// The closest updated leaf (lowest mergeHeight) is either the predecessor
	// or successor of e in leaf-index order.
	i := sort.Search(len(updatedInTree), func(i int) bool { return updatedInTree[i].LeafIndex >= e.LeafIndex })
	if i == len(updatedInTree) || i > 0 && mergeHeight(e.LeafIndex, updatedInTree[i-1].LeafIndex) < mergeHeight(e.LeafIndex, updatedInTree[i].LeafIndex) {
		i--
	}
	best := updatedInTree[i]

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
	_ = e.Move() // panics if element is shared
	if e.LeafIndex == types.UnassignedLeafIndex {
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
	_ = e.Move() // panics if element is shared
	if e.LeafIndex == types.UnassignedLeafIndex {
		panic("cannot update an ephemeral element")
	} else if e.LeafIndex >= eru.numLeaves {
		panic("cannot update an element that is not present in the accumulator")
	}
	if mh := mergeHeight(eru.numLeaves, e.LeafIndex); mh <= len(e.MerkleProof) {
		e.MerkleProof = e.MerkleProof[:mh-1]
	}
	updateProof(e, &eru.updated)
}
