package consensus

import (
	"time"

	"go.sia.tech/core/v2/merkle"
	"go.sia.tech/core/v2/types"
)

func updateOakTotals(s *State, h types.BlockHeader) (time.Duration, types.Work) {
	parentTimestamp := s.PrevTimestamps[s.numTimestamps()-1]
	blockTime := h.Timestamp.Sub(parentTimestamp)
	blockWork := s.Difficulty

	// decay totals by 0.5% before adding the new values
	decayedTime := s.OakTime - (s.OakTime / 200) + blockTime
	decayedWork := s.OakWork.Sub(s.OakWork.Div64(200)).Add(blockWork)
	return decayedTime, decayedWork
}

func adjustDifficulty(s *State, h types.BlockHeader) types.Work {
	// NOTE: To avoid overflow/underflow issues, this function operates on
	// integer seconds (rather than time.Duration, which uses nanoseconds). This
	// shouldn't appreciably affect the precision of the algorithm.

	blockInterval := s.BlockInterval() / time.Second
	expectedTime := s.BlockInterval() * time.Duration(h.Height)
	actualTime := h.Timestamp.Sub(s.GenesisTimestamp) / time.Second
	delta := expectedTime - actualTime
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
	if s.OakTime <= time.Second {
		s.OakTime = time.Second
	}
	estimatedHashrate := s.OakWork.Div64(uint64(s.OakTime / time.Second))

	// multiply the estimated hashrate by the target block time; this is the
	// expected number of hashes required to produce the next block, i.e. the
	// new difficulty
	newDifficulty := estimatedHashrate.Mul64(uint64(targetBlockTime))

	// clamp the adjustment to 0.4%
	maxAdjust := s.Difficulty.Div64(250)
	if min := s.Difficulty.Sub(maxAdjust); newDifficulty.Cmp(min) < 0 {
		newDifficulty = min
	} else if max := s.Difficulty.Add(maxAdjust); newDifficulty.Cmp(max) > 0 {
		newDifficulty = max
	}
	return newDifficulty
}

func applyHeader(s *State, h types.BlockHeader) {
	if h.Height == 0 {
		// special handling for GenesisUpdate
		s.PrevTimestamps[0] = h.Timestamp
		s.Index = h.Index()
		return
	}
	s.TotalWork = s.TotalWork.Add(s.Difficulty)
	s.OakTime, s.OakWork = updateOakTotals(s, h)
	s.Difficulty = adjustDifficulty(s, h)
	if s.numTimestamps() < len(s.PrevTimestamps) {
		s.PrevTimestamps[s.numTimestamps()] = h.Timestamp
	} else {
		copy(s.PrevTimestamps[:], s.PrevTimestamps[1:])
		s.PrevTimestamps[len(s.PrevTimestamps)-1] = h.Timestamp
	}
	s.Index = h.Index()
}

func updatedInBlock(s State, b types.Block, apply bool) (scos []types.SiacoinElement, sfos []types.SiafundElement, revised, resolved []types.FileContractElement, leaves []merkle.ElementLeaf) {
	addLeaf := func(l merkle.ElementLeaf) {
		// copy proofs so we don't mutate transaction data
		l.MerkleProof = append([]types.Hash256(nil), l.MerkleProof...)
		leaves = append(leaves, l)
	}

	for _, txn := range b.Transactions {
		for _, in := range txn.SiacoinInputs {
			if in.Parent.LeafIndex != types.EphemeralLeafIndex {
				scos = append(scos, in.Parent)
				addLeaf(merkle.SiacoinLeaf(in.Parent, apply))
			}
		}
		for _, in := range txn.SiafundInputs {
			sfos = append(sfos, in.Parent)
			addLeaf(merkle.SiafundLeaf(in.Parent, apply))
		}
		for _, fcr := range txn.FileContractRevisions {
			fce := fcr.Parent
			if apply {
				fce.FileContract = fcr.Revision
			}
			revised = append(revised, fce)
			addLeaf(merkle.FileContractLeaf(fce, false))
		}
		for _, fcr := range txn.FileContractResolutions {
			fce := fcr.Parent
			if apply {
				if fcr.HasRenewal() {
					fce.FileContract = fcr.Renewal.FinalRevision
				} else if fcr.HasFinalization() {
					fce.FileContract = fcr.Finalization
				}
			}
			resolved = append(resolved, fce)
			addLeaf(merkle.FileContractLeaf(fce, apply))
		}
	}

	return
}

func createdInBlock(s State, b types.Block) (sces []types.SiacoinElement, sfes []types.SiafundElement, fces []types.FileContractElement) {
	sces = append(sces, types.SiacoinElement{
		StateElement: types.StateElement{
			ID: b.MinerOutputID(),
		},
		SiacoinOutput: types.SiacoinOutput{
			Value:   s.BlockReward(),
			Address: b.Header.MinerAddress,
		},
		MaturityHeight: s.MaturityHeight(),
	})
	if subsidy := s.FoundationSubsidy(); !subsidy.IsZero() {
		sces = append(sces, types.SiacoinElement{
			StateElement: types.StateElement{
				ID: b.FoundationOutputID(),
			},
			SiacoinOutput: types.SiacoinOutput{
				Value:   subsidy,
				Address: s.FoundationAddress,
			},
			MaturityHeight: s.MaturityHeight(),
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
			sces = append(sces, types.SiacoinElement{
				StateElement:  nextElement(),
				SiacoinOutput: out,
			})
		}
		for _, in := range txn.SiafundInputs {
			sces = append(sces, types.SiacoinElement{
				StateElement: nextElement(),
				SiacoinOutput: types.SiacoinOutput{
					Value:   s.SiafundPool.Sub(in.Parent.ClaimStart).Div64(s.SiafundCount()).Mul64(in.Parent.Value),
					Address: in.ClaimAddress,
				},
				MaturityHeight: s.MaturityHeight(),
			})
		}
		for _, out := range txn.SiafundOutputs {
			sfes = append(sfes, types.SiafundElement{
				StateElement:  nextElement(),
				SiafundOutput: out,
				ClaimStart:    s.SiafundPool,
			})
		}
		for _, fc := range txn.FileContracts {
			fces = append(fces, types.FileContractElement{
				StateElement: nextElement(),
				FileContract: fc,
			})
		}
		for _, fcr := range txn.FileContractResolutions {
			fce := fcr.Parent
			var renter, host types.SiacoinOutput
			if fcr.HasRenewal() {
				renter, host = fcr.Renewal.FinalRevision.RenterOutput, fcr.Renewal.FinalRevision.HostOutput
				renter.Value = renter.Value.Sub(fcr.Renewal.RenterRollover)
				host.Value = host.Value.Sub(fcr.Renewal.HostRollover)
				fces = append(fces, types.FileContractElement{
					StateElement: nextElement(),
					FileContract: fcr.Renewal.InitialRevision,
				})
			} else if fcr.HasStorageProof() {
				renter, host = fce.RenterOutput, fce.HostOutput
			} else if fcr.HasFinalization() {
				renter, host = fcr.Finalization.RenterOutput, fcr.Finalization.HostOutput
			} else if fce.Filesize == 0 {
				renter, host = fce.RenterOutput, fce.HostOutput
			} else {
				renter, host = fce.RenterOutput, fce.MissedHostOutput()
			}
			sces = append(sces, types.SiacoinElement{
				StateElement:   nextElement(),
				SiacoinOutput:  renter,
				MaturityHeight: s.MaturityHeight(),
			})
			sces = append(sces, types.SiacoinElement{
				StateElement:   nextElement(),
				SiacoinOutput:  host,
				MaturityHeight: s.MaturityHeight(),
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

	State                 State
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

// UpdateTransactionProofs updates the element proofs and window proofs of a
// transaction.
func (au *ApplyUpdate) UpdateTransactionProofs(txn *types.Transaction) {
	for i := range txn.SiacoinInputs {
		if txn.SiacoinInputs[i].Parent.LeafIndex != types.EphemeralLeafIndex {
			au.UpdateElementProof(&txn.SiacoinInputs[i].Parent.StateElement)
		}
	}
	for i := range txn.SiafundInputs {
		if txn.SiafundInputs[i].Parent.LeafIndex != types.EphemeralLeafIndex {
			au.UpdateElementProof(&txn.SiafundInputs[i].Parent.StateElement)
		}
	}
	for i := range txn.FileContractRevisions {
		au.UpdateElementProof(&txn.FileContractRevisions[i].Parent.StateElement)
	}
	for i := range txn.FileContractResolutions {
		au.UpdateElementProof(&txn.FileContractResolutions[i].Parent.StateElement)
		au.UpdateWindowProof(&txn.FileContractResolutions[i].StorageProof)
	}
}

// ApplyBlock integrates a block into the current consensus state, producing an
// ApplyUpdate detailing the resulting changes. The block is assumed to be fully
// validated.
func ApplyBlock(s State, b types.Block) (au ApplyUpdate) {
	if s.Index.Height > 0 && s.Index != b.Header.ParentIndex() {
		panic("consensus: cannot apply non-child block")
	}

	// update elements
	var updated, created []merkle.ElementLeaf
	au.SpentSiacoins, au.SpentSiafunds, au.RevisedFileContracts, au.ResolvedFileContracts, updated = updatedInBlock(s, b, true)
	au.NewSiacoinElements, au.NewSiafundElements, au.NewFileContracts = createdInBlock(s, b)
	spent := make(map[types.ElementID]bool)
	for _, txn := range b.Transactions {
		for _, in := range txn.SiacoinInputs {
			if in.Parent.LeafIndex == types.EphemeralLeafIndex {
				spent[in.Parent.ID] = true
			}
		}
	}
	for _, sce := range au.NewSiacoinElements {
		created = append(created, merkle.SiacoinLeaf(sce, spent[sce.ID]))
	}
	for _, sfe := range au.NewSiafundElements {
		created = append(created, merkle.SiafundLeaf(sfe, spent[sfe.ID]))
	}
	for _, fce := range au.NewFileContracts {
		created = append(created, merkle.FileContractLeaf(fce, spent[fce.ID]))
	}
	au.ElementApplyUpdate = s.Elements.ApplyBlock(updated, created)
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
	au.HistoryApplyUpdate = s.History.ApplyBlock(b.Index())

	// update state
	applyHeader(&s, b.Header)
	for _, txn := range b.Transactions {
		for _, fc := range txn.FileContracts {
			s.SiafundPool = s.SiafundPool.Add(s.FileContractTax(fc))
		}
		if txn.NewFoundationAddress != types.VoidAddress {
			s.FoundationAddress = txn.NewFoundationAddress
		}
	}
	au.State = s

	return
}

// GenesisUpdate returns the ApplyUpdate for the genesis block b.
func GenesisUpdate(b types.Block, initialDifficulty types.Work) ApplyUpdate {
	return ApplyBlock(State{
		Difficulty:       initialDifficulty,
		GenesisTimestamp: b.Header.Timestamp,
	}, b)
}

// A RevertUpdate reflects the changes to consensus state resulting from the
// removal of a block.
type RevertUpdate struct {
	merkle.ElementRevertUpdate
	merkle.HistoryRevertUpdate

	State                 State
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
	return sce.LeafIndex != types.EphemeralLeafIndex && sce.LeafIndex >= ru.State.Elements.NumLeaves
}

// SiafundElementWasRemoved returns true if the specified SiafundElement was
// reverted.
func (ru *RevertUpdate) SiafundElementWasRemoved(sfe types.SiafundElement) bool {
	return sfe.LeafIndex != types.EphemeralLeafIndex && sfe.LeafIndex >= ru.State.Elements.NumLeaves
}

// FileContractElementWasRemoved returns true if the specified
// FileContractElement was reverted.
func (ru *RevertUpdate) FileContractElementWasRemoved(fce types.FileContractElement) bool {
	return fce.LeafIndex != types.EphemeralLeafIndex && fce.LeafIndex >= ru.State.Elements.NumLeaves
}

// UpdateTransactionProofs updates the element proofs and window proofs of a
// transaction.
func (ru *RevertUpdate) UpdateTransactionProofs(txn *types.Transaction) {
	for i := range txn.SiacoinInputs {
		if txn.SiacoinInputs[i].Parent.LeafIndex != types.EphemeralLeafIndex {
			ru.UpdateElementProof(&txn.SiacoinInputs[i].Parent.StateElement)
		}
	}
	for i := range txn.SiafundInputs {
		if txn.SiafundInputs[i].Parent.LeafIndex != types.EphemeralLeafIndex {
			ru.UpdateElementProof(&txn.SiafundInputs[i].Parent.StateElement)
		}
	}
	for i := range txn.FileContractRevisions {
		ru.UpdateElementProof(&txn.FileContractRevisions[i].Parent.StateElement)
	}
	for i := range txn.FileContractResolutions {
		ru.UpdateElementProof(&txn.FileContractResolutions[i].Parent.StateElement)
		ru.UpdateWindowProof(&txn.FileContractResolutions[i].StorageProof)
	}
}

// RevertBlock produces a RevertUpdate from a block and the State
// prior to that block.
func RevertBlock(s State, b types.Block) (ru RevertUpdate) {
	if b.Header.Height == 0 {
		panic("consensus: cannot revert genesis block")
	} else if s.Index != b.Header.ParentIndex() {
		panic("consensus: cannot revert non-child block")
	}

	ru.State = s
	ru.HistoryRevertUpdate = ru.State.History.RevertBlock(b.Index())
	var updated []merkle.ElementLeaf
	ru.SpentSiacoins, ru.SpentSiafunds, ru.RevisedFileContracts, ru.ResolvedFileContracts, updated = updatedInBlock(s, b, false)
	ru.NewSiacoinElements, ru.NewSiafundElements, ru.NewFileContracts = createdInBlock(s, b)
	ru.ElementRevertUpdate = ru.State.Elements.RevertBlock(updated)
	return
}
