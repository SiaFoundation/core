package consensus

import (
	"bytes"
	"math/big"
	"time"

	"go.sia.tech/core/types"
)

var maxTarget = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

func intToTarget(i *big.Int) (t types.BlockID) {
	if i.BitLen() >= 256 {
		i = maxTarget
	}
	i.FillBytes(t[:])
	return
}

// s = 1/(1/x + 1/y) = x*y/(x+y)
func addTarget(x, y types.BlockID) types.BlockID {
	xi := new(big.Int).SetBytes(x[:])
	yi := new(big.Int).SetBytes(y[:])
	return intToTarget(yi.Div(
		new(big.Int).Mul(xi, yi),
		new(big.Int).Add(xi, yi),
	))
}

// m = x*n/d
func mulTargetFrac(x types.BlockID, n, d int64) (m types.BlockID) {
	i := new(big.Int).SetBytes(x[:])
	i.Mul(i, big.NewInt(n))
	i.Div(i, big.NewInt(d))
	return intToTarget(i)
}

func updateOakTime(s State, blockTimestamp, parentTimestamp time.Time) time.Duration {
	if s.childHeight() == s.Network.HardforkASIC.Height-1 {
		return s.Network.HardforkASIC.OakTime
	}
	prevTotalTime := s.OakTime
	if s.childHeight() == s.Network.HardforkOak.Height-1 {
		prevTotalTime = s.BlockInterval() * time.Duration(s.childHeight())
	}
	decayedTime := (((prevTotalTime / time.Second) * 995) / 1000) * time.Second
	return decayedTime + blockTimestamp.Sub(parentTimestamp)
}

func updateOakTarget(s State) types.BlockID {
	if s.childHeight() == s.Network.HardforkASIC.Height-1 {
		return s.Network.HardforkASIC.OakTarget
	}
	return addTarget(mulTargetFrac(s.OakTarget, 1000, 995), s.ChildTarget)
}

func adjustTarget(s State, blockTimestamp time.Time, targetTimestamp time.Time) types.BlockID {
	blockInterval := int64(s.BlockInterval() / time.Second)

	// pre-Oak algorithm
	if s.childHeight() <= s.Network.HardforkOak.Height {
		windowSize := uint64(1000)
		if s.childHeight()%(windowSize/2) != 0 {
			return s.ChildTarget // no change
		}
		ancestorDepth := windowSize
		if windowSize > s.childHeight() {
			ancestorDepth = s.childHeight()
		}
		elapsed := int64(blockTimestamp.Sub(targetTimestamp) / time.Second)
		expected := blockInterval * int64(ancestorDepth)
		// clamp
		if r := float64(expected) / float64(elapsed); r > 25.0/10.0 {
			expected, elapsed = 25, 10
		} else if r < 10.0/25.0 {
			expected, elapsed = 10, 25
		}
		// multiply
		return mulTargetFrac(s.ChildTarget, elapsed, expected)
	}

	oakTotalTime := int64(s.OakTime / time.Second)

	var delta int64
	if s.Index.Height < s.Network.HardforkOak.FixHeight {
		delta = (blockInterval * int64(s.Index.Height)) - oakTotalTime
	} else {
		parentTimestamp := s.PrevTimestamps[0]
		delta = (blockInterval * int64(s.Index.Height)) - (parentTimestamp.Unix() - s.Network.HardforkOak.GenesisTimestamp.Unix())
	}

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

	// calculate the new target
	//
	// NOTE: this *should* be as simple as:
	//
	//   newTarget := mulTargetFrac(s.OakTarget, oakTotalTime, targetBlockTime)
	//
	// However, the siad consensus code includes maxTarget divisions, resulting
	// in slightly different rounding, which we must preserve here. First, we
	// calculate the estimated hashrate from the (decayed) total work and the
	// (decayed, clamped) total time. We then multiply by the target block time
	// to get the expected number of hashes required to produce the next block,
	// i.e. the new difficulty. Finally, we divide maxTarget by the difficulty
	// to get the new target.
	if oakTotalTime <= 0 {
		oakTotalTime = 1
	}
	if targetBlockTime == 0 {
		targetBlockTime = 1
	}
	estimatedHashrate := new(big.Int).Div(maxTarget, new(big.Int).SetBytes(s.OakTarget[:]))
	estimatedHashrate.Div(estimatedHashrate, big.NewInt(oakTotalTime))
	estimatedHashrate.Mul(estimatedHashrate, big.NewInt(targetBlockTime))
	if estimatedHashrate.BitLen() == 0 {
		estimatedHashrate = big.NewInt(1)
	}
	newTarget := intToTarget(new(big.Int).Div(maxTarget, estimatedHashrate))

	// clamp the adjustment to 0.4%, except for ASIC hardfork block
	//
	// NOTE: the multiplications are flipped re: siad because we are comparing
	// work, not targets
	if s.childHeight() == s.Network.HardforkASIC.Height {
		return newTarget
	}
	min := mulTargetFrac(s.ChildTarget, 1004, 1000)
	max := mulTargetFrac(s.ChildTarget, 1000, 1004)
	if newTarget.CmpWork(min) < 0 {
		newTarget = min
	} else if newTarget.CmpWork(max) > 0 {
		newTarget = max
	}
	return newTarget
}

// ApplyOrphan applies the work of b to s, returning the resulting state. Only
// the PoW-related fields are updated.
func ApplyOrphan(s State, b types.Block, targetTimestamp time.Time) State {
	if s.Index.Height > 0 && s.Index.ID != b.ParentID {
		panic("consensus: cannot apply non-child block")
	}

	if b.ParentID == (types.BlockID{}) {
		// special handling for genesis block
		s.OakTime = updateOakTime(s, b.Timestamp, b.Timestamp)
		s.OakTarget = updateOakTarget(s)
		s.Index = types.ChainIndex{Height: 0, ID: b.ID()}
	} else {
		s.Depth = addTarget(s.Depth, s.ChildTarget)
		s.ChildTarget = adjustTarget(s, b.Timestamp, targetTimestamp)
		s.OakTime = updateOakTime(s, b.Timestamp, s.PrevTimestamps[0])
		s.OakTarget = updateOakTarget(s)
		s.Index = types.ChainIndex{Height: s.Index.Height + 1, ID: b.ID()}
	}
	copy(s.PrevTimestamps[1:], s.PrevTimestamps[:])
	s.PrevTimestamps[0] = b.Timestamp
	return s

}

func (ms *MidState) addedLeaf(id types.Hash256) *elementLeaf {
	for i := range ms.added {
		if ms.added[i].ID == id {
			return &ms.added[i]
		}
	}
	return nil
}

func (ms *MidState) addSiacoinElement(sce types.SiacoinElement) {
	ms.sces = append(ms.sces, sce)
	ms.added = append(ms.added, siacoinLeaf(&ms.sces[len(ms.sces)-1], false))
	ms.ephemeral[ms.sces[len(ms.sces)-1].ID] = len(ms.sces) - 1
}

func (ms *MidState) spendSiacoinElement(sce types.SiacoinElement, txid types.TransactionID) {
	ms.spends[sce.ID] = txid
	if _, ok := ms.ephemeral[sce.ID]; ok {
		ms.addedLeaf(sce.ID).Spent = true
	} else {
		sce.MerkleProof = append([]types.Hash256(nil), sce.MerkleProof...)
		ms.sces = append(ms.sces, sce)
		ms.updated = append(ms.updated, siacoinLeaf(&ms.sces[len(ms.sces)-1], true))
	}
}

func (ms *MidState) addSiafundElement(sfe types.SiafundElement) {
	ms.sfes = append(ms.sfes, sfe)
	ms.added = append(ms.added, siafundLeaf(&ms.sfes[len(ms.sfes)-1], false))
	ms.ephemeral[ms.sfes[len(ms.sfes)-1].ID] = len(ms.sfes) - 1
}

func (ms *MidState) spendSiafundElement(sfe types.SiafundElement, txid types.TransactionID) {
	ms.spends[sfe.ID] = txid
	if _, ok := ms.ephemeral[sfe.ID]; ok {
		ms.addedLeaf(sfe.ID).Spent = true
	} else {
		sfe.MerkleProof = append([]types.Hash256(nil), sfe.MerkleProof...)
		ms.sfes = append(ms.sfes, sfe)
		ms.updated = append(ms.updated, siafundLeaf(&ms.sfes[len(ms.sfes)-1], true))
	}
}

func (ms *MidState) addFileContractElement(fce types.FileContractElement) {
	ms.fces = append(ms.fces, fce)
	ms.added = append(ms.added, fileContractLeaf(&ms.fces[len(ms.fces)-1], false))
	ms.ephemeral[ms.fces[len(ms.fces)-1].ID] = len(ms.fces) - 1
	ms.siafundPool = ms.siafundPool.Add(ms.base.FileContractTax(fce.FileContract))
}

func (ms *MidState) reviseFileContractElement(fce types.FileContractElement, rev types.FileContract) {
	rev.Payout = fce.FileContract.Payout
	if i, ok := ms.ephemeral[fce.ID]; ok {
		ms.fces[i].FileContract = rev
		*ms.addedLeaf(fce.ID) = fileContractLeaf(&ms.fces[i], false)
	} else {
		if r, ok := ms.revs[fce.ID]; ok {
			r.FileContract = rev
			for i := range ms.updated {
				if ms.updated[i].ID == fce.ID {
					ms.updated[i] = fileContractLeaf(r, false)
					break
				}
			}
		} else {
			// store the original
			fce.MerkleProof = append([]types.Hash256(nil), fce.MerkleProof...)
			ms.fces = append(ms.fces, fce)
			// store the revision
			fce.MerkleProof = append([]types.Hash256(nil), fce.MerkleProof...)
			fce.FileContract = rev
			ms.revs[fce.ID] = &fce
			ms.updated = append(ms.updated, fileContractLeaf(&fce, false))
		}
	}
}

func (ms *MidState) resolveFileContractElement(fce types.FileContractElement, txid types.TransactionID) {
	ms.spends[fce.ID] = txid
	fce.MerkleProof = append([]types.Hash256(nil), fce.MerkleProof...)
	ms.fces = append(ms.fces, fce)
	ms.updated = append(ms.updated, fileContractLeaf(&ms.fces[len(ms.fces)-1], true))
}

func (ms *MidState) addV2FileContractElement(fce types.V2FileContractElement) {
	ms.v2fces = append(ms.v2fces, fce)
	ms.added = append(ms.added, v2FileContractLeaf(&ms.v2fces[len(ms.v2fces)-1], false))
	ms.ephemeral[ms.v2fces[len(ms.v2fces)-1].ID] = len(ms.v2fces) - 1
	ms.siafundPool = ms.siafundPool.Add(ms.base.V2FileContractTax(fce.V2FileContract))
}

func (ms *MidState) reviseV2FileContractElement(fce types.V2FileContractElement, rev types.V2FileContract) {
	fce.MerkleProof = append([]types.Hash256(nil), fce.MerkleProof...)
	ms.v2fces = append(ms.v2fces, fce)
	ms.updated = append(ms.updated, fileContractLeaf(&ms.fces[len(ms.fces)-1], false))
}

func (ms *MidState) resolveV2FileContractElement(fce types.V2FileContractElement, txid types.TransactionID) {
	ms.spends[fce.ID] = txid
	fce.MerkleProof = append([]types.Hash256(nil), fce.MerkleProof...)
	ms.v2fces = append(ms.v2fces, fce)
	ms.updated = append(ms.updated, v2FileContractLeaf(&ms.v2fces[len(ms.v2fces)-1], true))
}

// ApplyTransaction applies a transaction to the MidState.
func (ms *MidState) ApplyTransaction(txn types.Transaction, ts V1TransactionSupplement) {
	txid := txn.ID()
	for _, sci := range txn.SiacoinInputs {
		ms.spendSiacoinElement(ms.mustSiacoinElement(ts, sci.ParentID), txid)
	}
	for i, sco := range txn.SiacoinOutputs {
		ms.addSiacoinElement(types.SiacoinElement{
			StateElement:  types.StateElement{ID: types.Hash256(txn.SiacoinOutputID(i))},
			SiacoinOutput: sco,
		})
	}
	for _, sfi := range txn.SiafundInputs {
		sfe := ms.mustSiafundElement(ts, sfi.ParentID)
		claimPortion := ms.siafundPool.Sub(sfe.ClaimStart).Div64(ms.base.SiafundCount()).Mul64(sfe.Value)
		ms.spendSiafundElement(sfe, txid)
		ms.addSiacoinElement(types.SiacoinElement{
			StateElement:   types.StateElement{ID: types.Hash256(sfi.ParentID.ClaimOutputID())},
			SiacoinOutput:  types.SiacoinOutput{Value: claimPortion, Address: sfi.ClaimAddress},
			MaturityHeight: ms.base.MaturityHeight(),
		})
	}
	for i, sfo := range txn.SiafundOutputs {
		ms.addSiafundElement(types.SiafundElement{
			StateElement:  types.StateElement{ID: types.Hash256(txn.SiafundOutputID(i))},
			SiafundOutput: sfo,
			ClaimStart:    ms.siafundPool,
		})
	}
	for i, fc := range txn.FileContracts {
		ms.addFileContractElement(types.FileContractElement{
			StateElement: types.StateElement{ID: types.Hash256(txn.FileContractID(i))},
			FileContract: fc,
		})
	}
	for _, fcr := range txn.FileContractRevisions {
		ms.reviseFileContractElement(ms.mustFileContractElement(ts, fcr.ParentID), fcr.FileContract)
	}
	for _, sp := range txn.StorageProofs {
		fce := ms.mustFileContractElement(ts, sp.ParentID)
		ms.resolveFileContractElement(fce, txid)
		for i, sco := range fce.ValidProofOutputs {
			ms.addSiacoinElement(types.SiacoinElement{
				StateElement:   types.StateElement{ID: types.Hash256(sp.ParentID.ValidOutputID(i))},
				SiacoinOutput:  sco,
				MaturityHeight: ms.base.MaturityHeight(),
			})
		}
	}
	if ms.base.Index.Height >= ms.base.Network.HardforkFoundation.Height {
		for _, arb := range txn.ArbitraryData {
			if bytes.HasPrefix(arb, types.SpecifierFoundation[:]) {
				var update types.FoundationAddressUpdate
				update.DecodeFrom(types.NewBufDecoder(arb[len(types.SpecifierFoundation):]))
				ms.foundationPrimary = update.NewPrimary
				ms.foundationFailsafe = update.NewFailsafe
			}
		}
	}
}

// ApplyV2Transaction applies a v2 transaction to the MidState.
func (ms *MidState) ApplyV2Transaction(txn types.V2Transaction) {
	txid := txn.ID()
	var elems uint64
	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	nextElement := func() types.StateElement {
		h.Reset()
		types.SpecifierElementID.EncodeTo(h.E)
		txid.EncodeTo(h.E)
		h.E.WriteUint64(elems)
		elems++
		return types.StateElement{ID: h.Sum()}
	}

	for _, sci := range txn.SiacoinInputs {
		ms.spendSiacoinElement(sci.Parent, txid)
	}
	for _, sco := range txn.SiacoinOutputs {
		ms.addSiacoinElement(types.SiacoinElement{
			StateElement:  nextElement(),
			SiacoinOutput: sco,
		})
	}
	for _, sfi := range txn.SiafundInputs {
		ms.spendSiafundElement(sfi.Parent, txid)
		claimPortion := ms.siafundPool.Sub(sfi.Parent.ClaimStart).Div64(ms.base.SiafundCount()).Mul64(sfi.Parent.Value)
		ms.addSiacoinElement(types.SiacoinElement{
			StateElement:   nextElement(),
			SiacoinOutput:  types.SiacoinOutput{Value: claimPortion, Address: sfi.ClaimAddress},
			MaturityHeight: ms.base.MaturityHeight(),
		})
	}
	for _, sfo := range txn.SiafundOutputs {
		ms.addSiafundElement(types.SiafundElement{
			StateElement:  nextElement(),
			SiafundOutput: sfo,
			ClaimStart:    ms.siafundPool,
		})
	}
	for _, fc := range txn.FileContracts {
		ms.addV2FileContractElement(types.V2FileContractElement{
			StateElement:   nextElement(),
			V2FileContract: fc,
		})
	}
	for _, fcr := range txn.FileContractRevisions {
		ms.reviseV2FileContractElement(fcr.Parent, fcr.Revision)
	}
	for _, fcr := range txn.FileContractResolutions {
		ms.resolveV2FileContractElement(fcr.Parent, txid)

		fce := fcr.Parent
		var renter, host types.SiacoinOutput
		switch r := fcr.Resolution.(type) {
		case types.V2FileContractRenewal:
			renter, host = r.FinalRevision.RenterOutput, r.FinalRevision.HostOutput
			renter.Value = renter.Value.Sub(r.RenterRollover)
			host.Value = host.Value.Sub(r.HostRollover)
			ms.addV2FileContractElement(types.V2FileContractElement{
				StateElement:   nextElement(),
				V2FileContract: r.InitialRevision,
			})
		case types.V2StorageProof:
			renter, host = fce.RenterOutput, fce.HostOutput
		case types.V2FileContract: // finalization
			renter, host = r.RenterOutput, r.HostOutput
		case types.V2FileContractExpiration:
			renter, host = fce.RenterOutput, fce.MissedHostOutput()
		}
		ms.addSiacoinElement(types.SiacoinElement{
			StateElement:   nextElement(),
			SiacoinOutput:  renter,
			MaturityHeight: ms.base.MaturityHeight(),
		})
		ms.addSiacoinElement(types.SiacoinElement{
			StateElement:   nextElement(),
			SiacoinOutput:  host,
			MaturityHeight: ms.base.MaturityHeight(),
		})
	}
	if txn.NewFoundationAddress != nil {
		ms.foundationPrimary = *txn.NewFoundationAddress
		ms.foundationFailsafe = *txn.NewFoundationAddress
	}
}

// ApplyBlock applies a block to the MidState.
func (ms *MidState) ApplyBlock(b types.Block, bs V1BlockSupplement) {
	for i, txn := range b.Transactions {
		ms.ApplyTransaction(txn, bs.Transactions[i])
	}
	if b.V2 != nil {
		for _, txn := range b.V2.Transactions {
			ms.ApplyV2Transaction(txn)
		}
	}
	bid := b.ID()
	for i, sco := range b.MinerPayouts {
		ms.addSiacoinElement(types.SiacoinElement{
			StateElement:   types.StateElement{ID: types.Hash256(bid.MinerOutputID(i))},
			SiacoinOutput:  sco,
			MaturityHeight: ms.base.MaturityHeight(),
		})
	}
	if subsidy := ms.base.FoundationSubsidy(); !subsidy.Value.IsZero() {
		ms.addSiacoinElement(types.SiacoinElement{
			StateElement:   types.StateElement{ID: types.Hash256(bid.FoundationOutputID())},
			SiacoinOutput:  subsidy,
			MaturityHeight: ms.base.MaturityHeight(),
		})
	}
	for _, fce := range bs.ExpiringFileContracts {
		if ms.isSpent(fce.ID) {
			continue
		}
		ms.resolveFileContractElement(fce, types.TransactionID(bid))
		for i, sco := range fce.MissedProofOutputs {
			ms.addSiacoinElement(types.SiacoinElement{
				StateElement:   types.StateElement{ID: types.Hash256(types.FileContractID(fce.ID).MissedOutputID(i))},
				SiacoinOutput:  sco,
				MaturityHeight: ms.base.MaturityHeight(),
			})
		}
	}

	ms.cie = types.ChainIndexElement{
		StateElement: types.StateElement{ID: types.Hash256(bid)},
		ChainIndex:   types.ChainIndex{Height: ms.base.childHeight(), ID: bid},
	}
	ms.added = append(ms.added, chainIndexLeaf(&ms.cie))
}

// An ApplyUpdate represents the effects of applying a block to a state.
type ApplyUpdate struct {
	ElementApplyUpdate
	ms *MidState
}

// ForEachSiacoinElement calls fn on each siacoin element related to au.
func (au ApplyUpdate) ForEachSiacoinElement(fn func(sce types.SiacoinElement, spent bool)) {
	for _, sce := range au.ms.sces {
		fn(sce, au.ms.isSpent(sce.ID))
	}
}

// ForEachSiafundElement calls fn on each siafund element related to au.
func (au ApplyUpdate) ForEachSiafundElement(fn func(sfe types.SiafundElement, spent bool)) {
	for _, sfe := range au.ms.sfes {
		fn(sfe, au.ms.isSpent(sfe.ID))
	}
}

// ForEachFileContractElement calls fn on each file contract element related to
// au. If the contract was revised, rev is non-nil.
func (au ApplyUpdate) ForEachFileContractElement(fn func(fce types.FileContractElement, rev *types.FileContractElement, resolved bool)) {
	for _, fce := range au.ms.fces {
		fn(fce, au.ms.revision(fce.ID), au.ms.isSpent(fce.ID))
	}
}

// ChainIndexElement returns the chain index element for the applied block.
func (au ApplyUpdate) ChainIndexElement() types.ChainIndexElement {
	cie := au.ms.cie
	cie.MerkleProof = append([]types.Hash256(nil), cie.MerkleProof...)
	return cie
}

// ApplyBlock applies b to s, producing a new state and a set of effects.
func ApplyBlock(s State, b types.Block, bs V1BlockSupplement, targetTimestamp time.Time) (State, ApplyUpdate) {
	if s.Index.Height > 0 && s.Index.ID != b.ParentID {
		panic("consensus: cannot apply non-child block")
	}

	ms := NewMidState(s)
	ms.ApplyBlock(b, bs)
	s.SiafundPool = ms.siafundPool
	s.FoundationPrimaryAddress = ms.foundationPrimary
	s.FoundationFailsafeAddress = ms.foundationFailsafe
	eau := s.Elements.ApplyBlock(ms.updated, ms.added)
	s = ApplyOrphan(s, b, targetTimestamp)
	return s, ApplyUpdate{eau, ms}
}

// A RevertUpdate represents the effects of reverting to a prior state.
type RevertUpdate struct {
	ElementRevertUpdate
	ms *MidState
}

// ForEachSiacoinElement calls fn on each siacoin element related to ru.
func (ru RevertUpdate) ForEachSiacoinElement(fn func(sce types.SiacoinElement, spent bool)) {
	for i := range ru.ms.sces {
		sce := ru.ms.sces[len(ru.ms.sces)-i-1]
		fn(sce, ru.ms.isSpent(sce.ID))
	}
}

// ForEachSiafundElement calls fn on each siafund element related to ru.
func (ru RevertUpdate) ForEachSiafundElement(fn func(sfe types.SiafundElement, spent bool)) {
	for i := range ru.ms.sfes {
		sfe := ru.ms.sfes[len(ru.ms.sfes)-i-1]
		fn(sfe, ru.ms.isSpent(sfe.ID))
	}
}

// ForEachFileContractElement calls fn on each file contract element related to
// ru. If the contract was revised, rev is non-nil.
func (ru RevertUpdate) ForEachFileContractElement(fn func(fce types.FileContractElement, rev *types.FileContractElement, resolved bool)) {
	for i := range ru.ms.fces {
		fce := ru.ms.fces[len(ru.ms.fces)-i-1]
		fn(fce, ru.ms.revision(fce.ID), ru.ms.isSpent(fce.ID))
	}
}

// RevertBlock reverts b, producing the effects undone by the block.
func RevertBlock(s State, b types.Block, bs V1BlockSupplement) RevertUpdate {
	if s.Index.ID != b.ParentID {
		panic("consensus: cannot revert non-child block")
	}
	ms := NewMidState(s)
	ms.ApplyBlock(b, bs)
	// invert spends
	//
	// TODO: this might be horribly inadequate
	for i := range ms.updated {
		_, spent := ms.spends[ms.updated[i].ID]
		ms.updated[i].Spent = !spent
	}

	eru := s.Elements.RevertBlock(ms.updated)
	return RevertUpdate{eru, ms}
}
