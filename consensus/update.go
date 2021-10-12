package consensus

import (
	"time"

	"go.sia.tech/core/types"
)

// SiafundCount is the number of siafunds in existence.
const SiafundCount = 10000

// BlockInterval is the expected wall clock time between consecutive blocks.
const BlockInterval = 10 * time.Minute

func updateOakTotals(oakTime, newTime time.Duration, oakWork, newWork types.Work) (time.Duration, types.Work) {
	// decay totals by 0.5% before adding the new values
	decayedTime := oakTime - (oakTime / 200) + newTime
	decayedWork := oakWork.Sub(oakWork.Div64(200)).Add(newWork)
	return decayedTime, decayedWork
}

func adjustDifficulty(difficulty types.Work, height uint64, actualTime time.Duration, oakTime time.Duration, oakWork types.Work) types.Work {
	// NOTE: To avoid overflow/underflow issues, this function operates on
	// integer seconds (rather than time.Duration, which uses nanoseconds). This
	// shouldn't appreciably affect the precision of the algorithm.

	const blockInterval = BlockInterval / time.Second
	expectedTime := blockInterval * time.Duration(height)
	delta := (expectedTime - actualTime) / time.Second
	// square the delta and preserve its sign
	shift := delta * delta
	if delta < 0 {
		shift = -shift
	}
	// scale such that a delta of 10,000 produces a shift of 10 seconds
	shift *= 10
	shift /= 10000 * 10000

	// calculate the new target block time, clamped to a factor of 3
	targetBlockTime := blockInterval + shift
	if min := blockInterval / 3; targetBlockTime < min {
		targetBlockTime = min
	} else if max := blockInterval * 3; targetBlockTime > max {
		targetBlockTime = max
	}

	// estimate the hashrate from the (decayed) total work and the (decayed,
	// clamped) total time
	if oakTime <= time.Second {
		oakTime = time.Second
	}
	estimatedHashrate := oakWork.Div64(uint64(oakTime / time.Second))

	// multiply the estimated hashrate by the target block time; this is the
	// expected number of hashes required to produce the next block, i.e. the
	// new difficulty
	newDifficulty := estimatedHashrate.Mul64(uint64(targetBlockTime))

	// clamp the adjustment to 0.4%
	maxAdjust := difficulty.Div64(250)
	if min := difficulty.Sub(maxAdjust); newDifficulty.Cmp(min) < 0 {
		newDifficulty = min
	} else if max := difficulty.Add(maxAdjust); newDifficulty.Cmp(max) > 0 {
		newDifficulty = max
	}
	return newDifficulty
}

func applyHeader(vc ValidationContext, h types.BlockHeader) ValidationContext {
	if h.Height == 0 {
		// special handling for GenesisUpdate
		vc.PrevTimestamps[0] = h.Timestamp
		vc.Index = h.Index()
		return vc
	}
	blockWork := types.WorkRequiredForHash(h.ID())
	vc.TotalWork = vc.TotalWork.Add(blockWork)
	parentTimestamp := vc.PrevTimestamps[vc.numTimestamps()-1]
	vc.OakTime, vc.OakWork = updateOakTotals(vc.OakTime, h.Timestamp.Sub(parentTimestamp), vc.OakWork, blockWork)
	vc.Difficulty = adjustDifficulty(vc.Difficulty, h.Height, h.Timestamp.Sub(vc.GenesisTimestamp), vc.OakTime, vc.OakWork)
	if vc.numTimestamps() < len(vc.PrevTimestamps) {
		vc.PrevTimestamps[vc.numTimestamps()] = h.Timestamp
	} else {
		copy(vc.PrevTimestamps[:], vc.PrevTimestamps[1:])
		vc.PrevTimestamps[len(vc.PrevTimestamps)-1] = h.Timestamp
	}
	vc.Index = h.Index()
	return vc
}

func updatedInBlock(vc ValidationContext, b types.Block) (scos []types.SiacoinElement, sfos []types.SiafundElement, fcs []types.FileContractElement, objects []stateObject) {
	addObject := func(so stateObject) {
		// copy proofs so we don't mutate transaction data
		so.MerkleProof = append([]types.Hash256(nil), so.MerkleProof...)
		objects = append(objects, so)
	}

	for _, txn := range b.Transactions {
		for _, in := range txn.SiacoinInputs {
			scos = append(scos, in.Parent)
			if in.Parent.LeafIndex != types.EphemeralLeafIndex {
				addObject(siacoinElementStateObject(in.Parent, true))
			}
		}
		for _, in := range txn.SiafundInputs {
			sfos = append(sfos, in.Parent)
			addObject(siafundElementStateObject(in.Parent, true))
		}
		for _, fcr := range txn.FileContractRevisions {
			fc := fcr.Parent
			fc.FileContract = fcr.Revision
			fcs = append(fcs, fc)
			addObject(fileContractElementStateObject(fc, false))
		}
		for _, fcr := range txn.FileContractResolutions {
			addObject(fileContractElementStateObject(fcr.Parent, true))
		}
	}

	return
}

func createdInBlock(vc ValidationContext, b types.Block) (sces []types.SiacoinElement, sfes []types.SiafundElement, fces []types.FileContractElement, objects []stateObject) {
	spent := make(map[types.ElementID]bool)
	for _, txn := range b.Transactions {
		for _, in := range txn.SiacoinInputs {
			if in.Parent.LeafIndex == types.EphemeralLeafIndex {
				spent[in.Parent.ID] = true
			}
		}
	}
	addSiacoinElement := func(sce types.SiacoinElement) {
		sces = append(sces, sce)
		objects = append(objects, siacoinElementStateObject(sce, spent[sce.ID]))
	}
	addSiafundElement := func(sfe types.SiafundElement) {
		sfes = append(sfes, sfe)
		objects = append(objects, siafundElementStateObject(sfe, spent[sfe.ID]))
	}
	addFileContract := func(fce types.FileContractElement) {
		fces = append(fces, fce)
		objects = append(objects, fileContractElementStateObject(fce, spent[fce.ID]))
	}

	addSiacoinElement(types.SiacoinElement{
		StateElement: types.StateElement{
			ID: types.ElementID{
				Source: types.Hash256(b.ID()),
				Index:  0,
			},
		},
		SiacoinOutput: types.SiacoinOutput{
			Value:   vc.BlockReward(),
			Address: b.Header.MinerAddress,
		},
		Timelock: vc.BlockRewardTimelock(),
	})
	if subsidy := vc.FoundationSubsidy(); !subsidy.IsZero() {
		addSiacoinElement(types.SiacoinElement{
			StateElement: types.StateElement{
				ID: types.ElementID{
					Source: types.Hash256(b.ID()),
					Index:  1,
				},
			},
			SiacoinOutput: types.SiacoinOutput{
				Value:   subsidy,
				Address: vc.FoundationAddress,
			},
			Timelock: vc.BlockRewardTimelock(),
		})
	}
	for _, txn := range b.Transactions {
		txid := txn.ID()
		var index uint64
		nextElement := func() types.StateElement {
			index++
			return types.StateElement{
				ID: types.ElementID{
					Source: types.Hash256(txid),
					Index:  index - 1,
				},
			}
		}

		for _, out := range txn.SiacoinOutputs {
			addSiacoinElement(types.SiacoinElement{
				StateElement:  nextElement(),
				SiacoinOutput: out,
			})
		}
		for _, in := range txn.SiafundInputs {
			// TODO: don't create zero-valued claim outputs?
			addSiacoinElement(types.SiacoinElement{
				StateElement: nextElement(),
				SiacoinOutput: types.SiacoinOutput{
					Value:   vc.SiafundPool.Sub(in.Parent.ClaimStart).Div64(SiafundCount).Mul64(in.Parent.Value),
					Address: in.ClaimAddress,
				},
				Timelock: vc.BlockRewardTimelock(), // TODO: define a separate method for this?
			})
		}
		for _, out := range txn.SiafundOutputs {
			addSiafundElement(types.SiafundElement{
				StateElement:  nextElement(),
				SiafundOutput: out,
				ClaimStart:    vc.SiafundPool,
			})
		}
		for _, fc := range txn.FileContracts {
			addFileContract(types.FileContractElement{
				StateElement: nextElement(),
				FileContract: fc,
			})
		}
		for _, fcr := range txn.FileContractResolutions {
			fce := fcr.Parent
			renter, host := fce.ValidRenterOutput, fce.ValidRenterOutput
			if fcr.HasStorageProof() {
				renter, host = fce.MissedRenterOutput, fce.MissedRenterOutput
			}
			addSiacoinElement(types.SiacoinElement{
				StateElement:  nextElement(),
				SiacoinOutput: renter,
			})
			addSiacoinElement(types.SiacoinElement{
				StateElement:  nextElement(),
				SiacoinOutput: host,
			})
		}
	}

	return
}

// A StateApplyUpdate reflects the changes to consensus state resulting from the
// application of a block.
type StateApplyUpdate struct {
	Context              ValidationContext
	SpentSiacoinElements []types.SiacoinElement
	NewSiacoinElements   []types.SiacoinElement
	SpentSiafundElements []types.SiafundElement
	NewSiafundElements   []types.SiafundElement
	RevisedFileContracts []types.FileContractElement
	NewFileContracts     []types.FileContractElement
	updatedElements      [64][]stateObject
	treeGrowth           [64][]types.Hash256
	historyProof         []types.Hash256
	historyGrowth        []types.Hash256
}

// SiacoinElementWasSpent returns true if the given SiacoinElement was spent.
func (sau *StateApplyUpdate) SiacoinElementWasSpent(sce types.SiacoinElement) bool {
	for i := range sau.SpentSiacoinElements {
		if sau.SpentSiacoinElements[i].LeafIndex == sce.LeafIndex {
			return true
		}
	}
	return false
}

// SiafundElementWasSpent returns true if the given SiafundElement was spent.
func (sau *StateApplyUpdate) SiafundElementWasSpent(sfe types.SiafundElement) bool {
	for i := range sau.SpentSiafundElements {
		if sau.SpentSiafundElements[i].LeafIndex == sfe.LeafIndex {
			return true
		}
	}
	return false
}

// UpdateElementProof updates the Merkle proof of the supplied element to
// incorporate the changes made to the state tree. The element's proof must be
// up-to-date; if it is not, UpdateElementProof may panic.
func (sau *StateApplyUpdate) UpdateElementProof(se *types.StateElement) {
	updateProof(se.MerkleProof, se.LeafIndex, &sau.updatedElements)
	se.MerkleProof = append(se.MerkleProof, sau.treeGrowth[len(se.MerkleProof)]...)
}

func (sau *StateApplyUpdate) updateHistoryProof(proof []types.Hash256, leafIndex uint64) []types.Hash256 {
	if len(sau.historyGrowth) > len(proof) {
		proof = append(proof, sau.historyGrowth[len(proof)])
		proof = append(proof, sau.historyProof[len(proof):]...)
	}
	return proof
}

// UpdateWindowProof updates the history proof of the supplied storage proof
// contract to incorporate the changes made to the state tree. The contract's
// proof must be up-to-date; if it is not, UpdateWindowProof may panic.
func (sau *StateApplyUpdate) UpdateWindowProof(sp *types.StorageProof) {
	sp.WindowProof = sau.updateHistoryProof(sp.WindowProof, sp.WindowStart.Height)
}

// HistoryProof returns a history proof for the current block.
func (sau *StateApplyUpdate) HistoryProof() []types.Hash256 {
	return append([]types.Hash256(nil), sau.historyProof...)
}

// ApplyBlock integrates a block into the current consensus state, producing
// a StateApplyUpdate detailing the resulting changes. The block is assumed to
// be fully validated.
func ApplyBlock(vc ValidationContext, b types.Block) (sau StateApplyUpdate) {
	sau.Context = applyHeader(vc, b.Header)

	var updated, created []stateObject
	sau.SpentSiacoinElements, sau.SpentSiafundElements, sau.RevisedFileContracts, updated = updatedInBlock(vc, b)
	sau.NewSiacoinElements, sau.NewSiafundElements, sau.NewFileContracts, created = createdInBlock(vc, b)

	sau.updatedElements = sau.Context.State.updateExistingObjects(updated)
	sau.treeGrowth = sau.Context.State.addNewObjects(created)
	for i := range sau.NewSiacoinElements {
		sau.NewSiacoinElements[i].StateElement = created[0].StateElement
		created = created[1:]
	}
	for i := range sau.NewSiafundElements {
		sau.NewSiafundElements[i].StateElement = created[0].StateElement
		created = created[1:]
	}
	for i := range sau.NewFileContracts {
		sau.NewFileContracts[i].StateElement = created[0].StateElement
		created = created[1:]
	}

	sau.historyProof = sau.Context.History.appendLeaf(b.Index())
	sau.historyGrowth = historyGrowth(b.Index(), sau.historyProof)

	for _, txn := range b.Transactions {
		// update SiafundPool
		for _, fc := range txn.FileContracts {
			sau.Context.SiafundPool = sau.Context.SiafundPool.Add(sau.Context.FileContractTax(fc))
		}
		// update Foundation address
		if txn.NewFoundationAddress != types.VoidAddress {
			sau.Context.FoundationAddress = txn.NewFoundationAddress
		}
	}

	return
}

// GenesisUpdate returns the StateApplyUpdate for the genesis block b.
func GenesisUpdate(b types.Block, initialDifficulty types.Work) StateApplyUpdate {
	return ApplyBlock(ValidationContext{
		Difficulty:       initialDifficulty,
		GenesisTimestamp: b.Header.Timestamp,
	}, b)
}

// A StateRevertUpdate reflects the changes to consensus state resulting from the
// removal of a block.
type StateRevertUpdate struct {
	Context              ValidationContext
	SpentSiacoinElements []types.SiacoinElement
	NewSiacoinElements   []types.SiacoinElement
	SpentSiafundElements []types.SiafundElement
	NewSiafundElements   []types.SiafundElement
	RevisedFileContracts []types.FileContractElement
	NewFileContracts     []types.FileContractElement
	updatedElements      [64][]stateObject
}

// SiacoinElementWasRemoved returns true if the specified SiacoinElement was
// reverted.
func (sru *StateRevertUpdate) SiacoinElementWasRemoved(o types.SiacoinElement) bool {
	return o.LeafIndex >= sru.Context.State.NumLeaves
}

// SiafundElementWasRemoved returns true if the specified SiafundElement was
// reverted.
func (sru *StateRevertUpdate) SiafundElementWasRemoved(o types.SiafundElement) bool {
	return o.LeafIndex >= sru.Context.State.NumLeaves
}

// UpdateElementProof updates the Merkle proof of the supplied element to
// incorporate the changes made to the state tree. The element's proof must be
// up-to-date; if it is not, UpdateElementProof may panic.
func (sru *StateRevertUpdate) UpdateElementProof(se *types.StateElement) {
	if mh := mergeHeight(sru.Context.State.NumLeaves, se.LeafIndex); mh <= len(se.MerkleProof) {
		se.MerkleProof = se.MerkleProof[:mh-1]
	}
	updateProof(se.MerkleProof, se.LeafIndex, &sru.updatedElements)
}

func (sru *StateRevertUpdate) updateHistoryProof(proof []types.Hash256, leafIndex uint64) []types.Hash256 {
	if mh := mergeHeight(sru.Context.Index.Height, leafIndex); mh <= len(proof) {
		proof = proof[:mh-1]
	}
	return proof
}

// UpdateWindowProof updates the history proof of the supplied storage proof
// contract to incorporate the changes made to the state tree. The contract's
// proof must be up-to-date; if it is not, UpdateWindowProof may panic.
func (sru *StateRevertUpdate) UpdateWindowProof(sp *types.StorageProof) {
	sp.WindowProof = sru.updateHistoryProof(sp.WindowProof, sp.WindowStart.Height)
}

// RevertBlock produces a StateRevertUpdate from a block and the
// ValidationContext prior to that block.
func RevertBlock(vc ValidationContext, b types.Block) (sru StateRevertUpdate) {
	sru.Context = vc
	sru.SpentSiacoinElements, sru.SpentSiafundElements, sru.RevisedFileContracts, _ = updatedInBlock(vc, b)
	sru.NewSiacoinElements, sru.NewSiafundElements, sru.NewFileContracts, _ = createdInBlock(vc, b)
	sru.updatedElements = objectsByTree(b.Transactions)
	return
}
