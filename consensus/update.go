package consensus

import (
	"time"

	"go.sia.tech/core/merkle"
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

func applyHeader(vc *ValidationContext, h types.BlockHeader) {
	if h.Height == 0 {
		// special handling for GenesisUpdate
		vc.PrevTimestamps[0] = h.Timestamp
		vc.Index = h.Index()
		return
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
}

func updatedInBlock(vc ValidationContext, b types.Block) (scos []types.SiacoinElement, sfos []types.SiafundElement, revised, resolved []types.FileContractElement, leaves []merkle.ElementLeaf) {
	addLeaf := func(l merkle.ElementLeaf) {
		// copy proofs so we don't mutate transaction data
		l.MerkleProof = append([]types.Hash256(nil), l.MerkleProof...)
		leaves = append(leaves, l)
	}

	for _, txn := range b.Transactions {
		for _, in := range txn.SiacoinInputs {
			if in.Parent.LeafIndex != types.EphemeralLeafIndex {
				scos = append(scos, in.Parent)
				addLeaf(merkle.SiacoinLeaf(in.Parent, true))
			}
		}
		for _, in := range txn.SiafundInputs {
			sfos = append(sfos, in.Parent)
			addLeaf(merkle.SiafundLeaf(in.Parent, true))
		}
		for _, fcr := range txn.FileContractRevisions {
			fce := fcr.Parent
			fce.FileContract = fcr.Revision
			if fcr.Revision.CanResolveEarly() {
				resolved = append(resolved, fce)
			} else {
				revised = append(revised, fce)
			}
			addLeaf(merkle.FileContractLeaf(fce, false))
		}
		for _, fcr := range txn.FileContractResolutions {
			fce := fcr.Parent
			resolved = append(resolved, fce)
			addLeaf(merkle.FileContractLeaf(fce, true))
		}
	}

	return
}

func createdInBlock(vc ValidationContext, b types.Block) (sces []types.SiacoinElement, sfes []types.SiafundElement, fces []types.FileContractElement, leaves []merkle.ElementLeaf) {
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
		leaves = append(leaves, merkle.SiacoinLeaf(sce, spent[sce.ID]))
	}
	addSiafundElement := func(sfe types.SiafundElement) {
		sfes = append(sfes, sfe)
		leaves = append(leaves, merkle.SiafundLeaf(sfe, spent[sfe.ID]))
	}
	addFileContract := func(fce types.FileContractElement) {
		fces = append(fces, fce)
		leaves = append(leaves, merkle.FileContractLeaf(fce, spent[fce.ID]))
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
		for _, fcr := range txn.FileContractRevisions {
			if fc := fcr.Revision; fc.CanResolveEarly() {
				renter, host := fc.ValidRenterOutput, fc.ValidHostOutput
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
		for _, fcr := range txn.FileContractResolutions {
			fce := fcr.Parent
			renter, host := fce.ValidRenterOutput, fce.ValidHostOutput
			if !fcr.HasStorageProof() {
				renter, host = fce.MissedRenterOutput, fce.MissedHostOutput
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

// A ApplyUpdate reflects the changes to consensus state resulting from the
// application of a block.
type ApplyUpdate struct {
	merkle.ElementApplyUpdate
	merkle.HistoryApplyUpdate

	Context               ValidationContext
	SpentSiacoins         []types.SiacoinElement
	SpentSiafunds         []types.SiafundElement
	RevisedFileContracts  []types.FileContractElement
	ResolvedFileContracts []types.FileContractElement
	NewSiacoinElements    []types.SiacoinElement
	NewSiafundElements    []types.SiafundElement
	NewFileContracts      []types.FileContractElement
}

// SiacoinElementWasSpent returns true if the given SiacoinElement was spent.
func (au *ApplyUpdate) SiacoinElementWasSpent(sce types.SiacoinElement) bool {
	for i := range au.SpentSiacoins {
		if au.SpentSiacoins[i].LeafIndex == sce.LeafIndex {
			return true
		}
	}
	return false
}

// SiafundElementWasSpent returns true if the given SiafundElement was spent.
func (au *ApplyUpdate) SiafundElementWasSpent(sfe types.SiafundElement) bool {
	for i := range au.SpentSiafunds {
		if au.SpentSiafunds[i].LeafIndex == sfe.LeafIndex {
			return true
		}
	}
	return false
}

// FileContractElementWasResolved returns true if the given FileContractElement was resolved.
func (au *ApplyUpdate) FileContractElementWasResolved(fce types.FileContractElement) bool {
	for i := range au.ResolvedFileContracts {
		if au.ResolvedFileContracts[i].LeafIndex == fce.LeafIndex {
			return true
		}
	}
	return false
}

// ApplyBlock integrates a block into the current consensus state, producing an
// ApplyUpdate detailing the resulting changes. The block is assumed to be fully
// validated.
func ApplyBlock(vc ValidationContext, b types.Block) (au ApplyUpdate) {
	// update elements
	var updated, created []merkle.ElementLeaf
	au.SpentSiacoins, au.SpentSiafunds, au.RevisedFileContracts, au.ResolvedFileContracts, updated = updatedInBlock(vc, b)
	au.NewSiacoinElements, au.NewSiafundElements, au.NewFileContracts, created = createdInBlock(vc, b)
	au.ElementApplyUpdate = vc.State.ApplyBlock(updated, created)
	for i := range au.NewSiacoinElements {
		au.NewSiacoinElements[i].StateElement = created[0].StateElement
		created = created[1:]
	}
	for i := range au.NewSiafundElements {
		au.NewSiafundElements[i].StateElement = created[0].StateElement
		created = created[1:]
	}
	for i := range au.NewFileContracts {
		au.NewFileContracts[i].StateElement = created[0].StateElement
		created = created[1:]
	}

	// update history
	au.HistoryApplyUpdate = vc.History.ApplyBlock(b.Index())

	// update context
	applyHeader(&vc, b.Header)
	for _, txn := range b.Transactions {
		for _, fc := range txn.FileContracts {
			vc.SiafundPool = vc.SiafundPool.Add(vc.FileContractTax(fc))
		}
		if txn.NewFoundationAddress != types.VoidAddress {
			vc.FoundationAddress = txn.NewFoundationAddress
		}
	}
	au.Context = vc

	return
}

// GenesisUpdate returns the ApplyUpdate for the genesis block b.
func GenesisUpdate(b types.Block, initialDifficulty types.Work) ApplyUpdate {
	return ApplyBlock(ValidationContext{
		Difficulty:       initialDifficulty,
		GenesisTimestamp: b.Header.Timestamp,
	}, b)
}

// A RevertUpdate reflects the changes to consensus state resulting from the
// removal of a block.
type RevertUpdate struct {
	merkle.ElementRevertUpdate
	merkle.HistoryRevertUpdate

	Context               ValidationContext
	SpentSiacoins         []types.SiacoinElement
	SpentSiafunds         []types.SiafundElement
	RevisedFileContracts  []types.FileContractElement
	ResolvedFileContracts []types.FileContractElement
	NewSiacoinElements    []types.SiacoinElement
	NewSiafundElements    []types.SiafundElement
	NewFileContracts      []types.FileContractElement
}

// SiacoinElementWasRemoved returns true if the specified SiacoinElement was
// reverted.
func (ru *RevertUpdate) SiacoinElementWasRemoved(sce types.SiacoinElement) bool {
	return sce.LeafIndex >= ru.Context.State.NumLeaves
}

// SiafundElementWasRemoved returns true if the specified SiafundElement was
// reverted.
func (ru *RevertUpdate) SiafundElementWasRemoved(sfe types.SiafundElement) bool {
	return sfe.LeafIndex >= ru.Context.State.NumLeaves
}

// FileContractElementWasRemoved returns true if the specified
// FileContractElement was reverted.
func (ru *RevertUpdate) FileContractElementWasRemoved(o types.FileContractElement) bool {
	return o.LeafIndex >= ru.Context.State.NumLeaves
}

// RevertBlock produces a RevertUpdate from a block and the ValidationContext
// prior to that block.
func RevertBlock(vc ValidationContext, b types.Block) (ru RevertUpdate) {
	ru.Context = vc
	ru.HistoryRevertUpdate = ru.Context.History.RevertBlock(b.Index())
	var updated []merkle.ElementLeaf
	ru.SpentSiacoins, ru.SpentSiafunds, ru.RevisedFileContracts, ru.ResolvedFileContracts, updated = updatedInBlock(vc, b)
	ru.NewSiacoinElements, ru.NewSiafundElements, ru.NewFileContracts, _ = createdInBlock(vc, b)
	ru.ElementRevertUpdate = ru.Context.State.RevertBlock(updated)
	return
}
