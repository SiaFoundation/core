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

func adjustTarget(s State, blockTimestamp time.Time, store Store) types.BlockID {
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
		targetTimestamp := store.AncestorTimestamp(s.Index.ID, ancestorDepth)
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

// ApplyState applies b to s, returning the resulting state.
func ApplyState(s State, store Store, b types.Block) State {
	if s.Index.Height > 0 && s.Index.ID != b.ParentID {
		panic("consensus: cannot apply non-child block")
	}

	siafundPool := s.SiafundPool
	for _, txn := range b.Transactions {
		for _, fc := range txn.FileContracts {
			siafundPool = siafundPool.Add(s.FileContractTax(fc))
		}
	}
	if b.V2 != nil {
		for _, txn := range b.V2.Transactions {
			for _, fc := range txn.FileContracts {
				siafundPool = siafundPool.Add(s.V2FileContractTax(fc))
			}
		}
	}

	// update state
	newFoundationPrimaryAddress := s.FoundationPrimaryAddress
	newFoundationFailsafeAddress := s.FoundationFailsafeAddress
	if s.Index.Height >= s.Network.HardforkFoundation.Height {
	outer:
		for _, txn := range b.Transactions {
			for _, arb := range txn.ArbitraryData {
				if bytes.HasPrefix(arb, types.SpecifierFoundation[:]) {
					var update types.FoundationAddressUpdate
					update.DecodeFrom(types.NewBufDecoder(arb[len(types.SpecifierFoundation):]))
					newFoundationPrimaryAddress = update.NewPrimary
					newFoundationFailsafeAddress = update.NewFailsafe
					break outer // Foundation addresses can only be updated once per block
				}
			}
		}
	}
	if b.V2 != nil {
		for _, txn := range b.V2.Transactions {
			if txn.NewFoundationAddress != nil {
				newFoundationPrimaryAddress = *txn.NewFoundationAddress
				newFoundationFailsafeAddress = *txn.NewFoundationAddress
			}
		}
	}

	if b.ParentID == (types.BlockID{}) {
		// special handling for genesis block
		return State{
			Network: s.Network,

			Index:          types.ChainIndex{Height: 0, ID: b.ID()},
			PrevTimestamps: [11]time.Time{0: b.Timestamp},
			Depth:          s.Depth,
			ChildTarget:    s.ChildTarget,
			SiafundPool:    siafundPool,

			OakTime:                   updateOakTime(s, b.Timestamp, b.Timestamp),
			OakTarget:                 updateOakTarget(s),
			FoundationPrimaryAddress:  newFoundationPrimaryAddress,
			FoundationFailsafeAddress: newFoundationFailsafeAddress,

			History:  s.History,
			Elements: s.Elements,
		}
	}

	prevTimestamps := s.PrevTimestamps
	copy(prevTimestamps[1:], s.PrevTimestamps[:])
	prevTimestamps[0] = b.Timestamp
	return State{
		Network: s.Network,

		Index:          types.ChainIndex{Height: s.Index.Height + 1, ID: b.ID()},
		PrevTimestamps: prevTimestamps,
		Depth:          addTarget(s.Depth, s.ChildTarget),
		ChildTarget:    adjustTarget(s, b.Timestamp, store),
		SiafundPool:    siafundPool,

		OakTime:                   updateOakTime(s, b.Timestamp, s.PrevTimestamps[0]),
		OakTarget:                 updateOakTarget(s),
		FoundationPrimaryAddress:  newFoundationPrimaryAddress,
		FoundationFailsafeAddress: newFoundationFailsafeAddress,

		History:  s.History,
		Elements: s.Elements,
	}
}

// v2SiacoinOutputID returns the ID of the i'th siacoin output created by the
// transaction.
func v2SiacoinOutputID(txid types.TransactionID, i int) types.SiacoinOutputID {
	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	types.SpecifierSiacoinOutput.EncodeTo(h.E)
	txid.EncodeTo(h.E)
	h.E.WriteUint64(uint64(i))
	return types.SiacoinOutputID(h.Sum())
}

// v2SiafundOutputID returns the ID of the i'th siafund output created by the
// transaction.
func v2SiafundOutputID(txid types.TransactionID, i int) types.SiafundOutputID {
	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	types.SpecifierSiafundOutput.EncodeTo(h.E)
	txid.EncodeTo(h.E)
	h.E.WriteUint64(uint64(i))
	return types.SiafundOutputID(h.Sum())
}

// v2FileContractID returns the ID of the i'th file contract created by the
// transaction.
func v2FileContractID(txid types.TransactionID, i int) types.FileContractID {
	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	types.SpecifierFileContract.EncodeTo(h.E)
	txid.EncodeTo(h.E)
	h.E.WriteUint64(uint64(i))
	return types.FileContractID(h.Sum())
}

// A TransactionDiff represents the changes to an ElementStore resulting from
// the application of a transaction.
type TransactionDiff struct {
	CreatedSiacoinElements []types.SiacoinElement      `json:"createdSiacoinElements,omitempty"`
	CreatedSiafundElements []types.SiafundElement      `json:"createdSiafundElements,omitempty"`
	CreatedFileContracts   []types.FileContractElement `json:"createdFileContracts,omitempty"`

	SpentSiacoinElements []types.SiacoinElement              `json:"spentSiacoinElements,omitempty"`
	SpentSiafundElements []types.SiafundElement              `json:"spentSiafundElements,omitempty"`
	RevisedFileContracts []types.FileContractElementRevision `json:"revisedFileContracts,omitempty"`
	ValidFileContracts   []types.FileContractElement         `json:"validFileContracts,omitempty"`
}

// EncodeTo implements types.EncoderTo.
func (td TransactionDiff) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(td.CreatedSiacoinElements))
	for i := range td.CreatedSiacoinElements {
		td.CreatedSiacoinElements[i].EncodeTo(e)
	}
	e.WritePrefix(len(td.CreatedSiafundElements))
	for i := range td.CreatedSiafundElements {
		td.CreatedSiafundElements[i].EncodeTo(e)
	}
	e.WritePrefix(len(td.CreatedFileContracts))
	for i := range td.CreatedFileContracts {
		td.CreatedFileContracts[i].EncodeTo(e)
	}
	e.WritePrefix(len(td.SpentSiacoinElements))
	for i := range td.SpentSiacoinElements {
		td.SpentSiacoinElements[i].EncodeTo(e)
	}
	e.WritePrefix(len(td.SpentSiafundElements))
	for i := range td.SpentSiafundElements {
		td.SpentSiafundElements[i].EncodeTo(e)
	}
	e.WritePrefix(len(td.RevisedFileContracts))
	for i := range td.RevisedFileContracts {
		td.RevisedFileContracts[i].EncodeTo(e)
	}
	e.WritePrefix(len(td.ValidFileContracts))
	for i := range td.ValidFileContracts {
		td.ValidFileContracts[i].EncodeTo(e)
	}
}

// DecodeFrom implements types.DecoderFrom.
func (td *TransactionDiff) DecodeFrom(d *types.Decoder) {
	td.CreatedSiacoinElements = make([]types.SiacoinElement, d.ReadPrefix())
	for i := range td.CreatedSiacoinElements {
		td.CreatedSiacoinElements[i].DecodeFrom(d)
	}
	td.CreatedSiafundElements = make([]types.SiafundElement, d.ReadPrefix())
	for i := range td.CreatedSiafundElements {
		td.CreatedSiafundElements[i].DecodeFrom(d)
	}
	td.CreatedFileContracts = make([]types.FileContractElement, d.ReadPrefix())
	for i := range td.CreatedFileContracts {
		td.CreatedFileContracts[i].DecodeFrom(d)
	}
	td.SpentSiacoinElements = make([]types.SiacoinElement, d.ReadPrefix())
	for i := range td.SpentSiacoinElements {
		td.SpentSiacoinElements[i].DecodeFrom(d)
	}
	td.SpentSiafundElements = make([]types.SiafundElement, d.ReadPrefix())
	for i := range td.SpentSiafundElements {
		td.SpentSiafundElements[i].DecodeFrom(d)
	}
	td.RevisedFileContracts = make([]types.FileContractElementRevision, d.ReadPrefix())
	for i := range td.RevisedFileContracts {
		td.RevisedFileContracts[i].DecodeFrom(d)
	}
	td.ValidFileContracts = make([]types.FileContractElement, d.ReadPrefix())
	for i := range td.ValidFileContracts {
		td.ValidFileContracts[i].DecodeFrom(d)
	}
}

// A V2TransactionDiff contains the elements added to the state accumulator by a
// v2 transaction.
type V2TransactionDiff struct {
	CreatedSiacoinElements []types.SiacoinElement        `json:"createdSiacoinElements,omitempty"`
	CreatedSiafundElements []types.SiafundElement        `json:"createdSiafundElements,omitempty"`
	CreatedFileContracts   []types.V2FileContractElement `json:"createdFileContracts,omitempty"`

	// NOTE: these fields are all easily derived from the block itself; we
	// include them for convenience
	SpentSiacoinElements  []types.SiacoinElement           `json:"spentSiacoinElements,omitempty"`
	SpentSiafundElements  []types.SiafundElement           `json:"spentSiafundElements,omitempty"`
	RevisedFileContracts  []types.V2FileContractRevision   `json:"revisedFileContracts,omitempty"`
	ResolvedFileContracts []types.V2FileContractResolution `json:"resolvedFileContracts,omitempty"`
}

// EncodeTo implements types.EncoderTo.
func (td V2TransactionDiff) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(td.CreatedSiacoinElements))
	for i := range td.CreatedSiacoinElements {
		td.CreatedSiacoinElements[i].EncodeTo(e)
	}
	e.WritePrefix(len(td.CreatedSiafundElements))
	for i := range td.CreatedSiafundElements {
		td.CreatedSiafundElements[i].EncodeTo(e)
	}
	e.WritePrefix(len(td.CreatedFileContracts))
	for i := range td.CreatedFileContracts {
		td.CreatedFileContracts[i].EncodeTo(e)
	}
}

// DecodeFrom implements types.DecoderFrom.
func (td *V2TransactionDiff) DecodeFrom(d *types.Decoder) {
	td.CreatedSiacoinElements = make([]types.SiacoinElement, d.ReadPrefix())
	for i := range td.CreatedSiacoinElements {
		td.CreatedSiacoinElements[i].DecodeFrom(d)
	}
	td.CreatedSiafundElements = make([]types.SiafundElement, d.ReadPrefix())
	for i := range td.CreatedSiafundElements {
		td.CreatedSiafundElements[i].DecodeFrom(d)
	}
	td.CreatedFileContracts = make([]types.V2FileContractElement, d.ReadPrefix())
	for i := range td.CreatedFileContracts {
		td.CreatedFileContracts[i].DecodeFrom(d)
	}
}

// A BlockDiff represents the changes to blockchain state resulting from the
// application of a block.
type BlockDiff struct {
	Transactions           []TransactionDiff           `json:"transactions,omitempty"`
	V2Transactions         []V2TransactionDiff         `json:"v2Transactions,omitempty"`
	CreatedSiacoinElements []types.SiacoinElement      `json:"createdSiacoinElements,omitempty"`
	MissedFileContracts    []types.FileContractElement `json:"missedFileContracts,omitempty"`
	ElementApplyUpdate     ElementApplyUpdate          `json:"-"`
	HistoryApplyUpdate     HistoryApplyUpdate          `json:"-"`
}

// EncodeTo implements types.EncoderTo.
func (bd BlockDiff) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(bd.Transactions))
	for i := range bd.Transactions {
		bd.Transactions[i].EncodeTo(e)
	}
	e.WritePrefix(len(bd.V2Transactions))
	for i := range bd.V2Transactions {
		bd.V2Transactions[i].EncodeTo(e)
	}
	e.WritePrefix(len(bd.CreatedSiacoinElements))
	for i := range bd.CreatedSiacoinElements {
		bd.CreatedSiacoinElements[i].EncodeTo(e)
	}
	e.WritePrefix(len(bd.MissedFileContracts))
	for i := range bd.MissedFileContracts {
		bd.MissedFileContracts[i].EncodeTo(e)
	}
}

// DecodeFrom implements types.DecoderFrom.
func (bd *BlockDiff) DecodeFrom(d *types.Decoder) {
	bd.Transactions = make([]TransactionDiff, d.ReadPrefix())
	for i := range bd.Transactions {
		bd.Transactions[i].DecodeFrom(d)
	}
	bd.V2Transactions = make([]V2TransactionDiff, d.ReadPrefix())
	for i := range bd.V2Transactions {
		bd.V2Transactions[i].DecodeFrom(d)
	}
	bd.CreatedSiacoinElements = make([]types.SiacoinElement, d.ReadPrefix())
	for i := range bd.CreatedSiacoinElements {
		bd.CreatedSiacoinElements[i].DecodeFrom(d)
	}
	bd.MissedFileContracts = make([]types.FileContractElement, d.ReadPrefix())
	for i := range bd.MissedFileContracts {
		bd.MissedFileContracts[i].DecodeFrom(d)
	}
}

// ApplyTransaction applies a transaction to the MidState.
func (ms *MidState) ApplyTransaction(store Store, txn types.Transaction) {
	txid := txn.ID()
	for _, sci := range txn.SiacoinInputs {
		ms.spends[types.Hash256(sci.ParentID)] = txid
	}
	for i, sco := range txn.SiacoinOutputs {
		scoid := txn.SiacoinOutputID(i)
		ms.sces[scoid] = types.SiacoinElement{
			StateElement:   types.StateElement{ID: types.Hash256(scoid)},
			SiacoinOutput:  sco,
			MaturityHeight: 0,
		}
	}
	for _, sfi := range txn.SiafundInputs {
		ms.spends[types.Hash256(sfi.ParentID)] = txid
	}
	for i, sfo := range txn.SiafundOutputs {
		sfoid := txn.SiafundOutputID(i)
		ms.sfes[sfoid] = types.SiafundElement{
			StateElement:  types.StateElement{ID: types.Hash256(sfoid)},
			SiafundOutput: sfo,
			ClaimStart:    ms.siafundPool,
		}
	}
	for i, fc := range txn.FileContracts {
		fcid := txn.FileContractID(i)
		ms.fces[fcid] = types.FileContractElement{
			StateElement: types.StateElement{ID: types.Hash256(fcid)},
			FileContract: fc,
		}
		ms.siafundPool = ms.siafundPool.Add(ms.base.FileContractTax(fc))
	}
	for _, fcr := range txn.FileContractRevisions {
		fce := ms.mustFileContractElement(store, fcr.ParentID)
		ms.fces[contractRevisionID(fcr.ParentID, fcr.RevisionNumber)] = fce // store previous revision for Diff later
		fcr.FileContract.Payout = fce.Payout
		fce.FileContract = fcr.FileContract
		ms.fces[fcr.ParentID] = fce
	}
	for _, sp := range txn.StorageProofs {
		ms.spends[types.Hash256(sp.ParentID)] = txid
	}
}

// ApplyV2Transaction applies a v2 transaction to the MidState.
func (ms *MidState) ApplyV2Transaction(txn types.V2Transaction) {
	txid := txn.ID()
	for _, sci := range txn.SiacoinInputs {
		ms.spends[sci.Parent.ID] = txid
	}
	for i, sco := range txn.SiacoinOutputs {
		scoid := v2SiacoinOutputID(txid, i)
		ms.sces[scoid] = types.SiacoinElement{
			StateElement:   types.StateElement{ID: types.Hash256(scoid)},
			SiacoinOutput:  sco,
			MaturityHeight: 0,
		}
	}
	for _, sfi := range txn.SiafundInputs {
		ms.spends[sfi.Parent.ID] = txid
	}
	for i, sfo := range txn.SiafundOutputs {
		sfoid := v2SiafundOutputID(txid, i)
		ms.sfes[sfoid] = types.SiafundElement{
			StateElement:  types.StateElement{ID: types.Hash256(sfoid)},
			SiafundOutput: sfo,
			ClaimStart:    ms.siafundPool,
		}
	}
	for i, fc := range txn.FileContracts {
		fcid := v2FileContractID(txid, i)
		ms.v2fces[fcid] = types.V2FileContractElement{
			StateElement:   types.StateElement{ID: types.Hash256(fcid)},
			V2FileContract: fc,
		}
		ms.siafundPool = ms.siafundPool.Add(ms.base.V2FileContractTax(fc))
	}
	for _, fcr := range txn.FileContractRevisions {
		fce := fcr.Parent
		fce.V2FileContract = fcr.Revision
		ms.v2fces[types.FileContractID(fcr.Parent.ID)] = fce
	}
	for _, res := range txn.FileContractResolutions {
		ms.spends[res.Parent.ID] = txid
	}
}

// ApplyDiff applies b to s, returning the resulting effects.
func ApplyDiff(s State, store Store, b types.Block) BlockDiff {
	if s.Index.Height > 0 && s.Index.ID != b.ParentID {
		panic("consensus: cannot apply non-child block")
	}

	ms := NewMidState(s)

	var diff BlockDiff
	for _, txn := range b.Transactions {
		var tdiff TransactionDiff
		for _, sci := range txn.SiacoinInputs {
			tdiff.SpentSiacoinElements = append(tdiff.SpentSiacoinElements, ms.mustSiacoinElement(store, sci.ParentID))
		}
		for i, sco := range txn.SiacoinOutputs {
			scoid := txn.SiacoinOutputID(i)
			tdiff.CreatedSiacoinElements = append(tdiff.CreatedSiacoinElements, types.SiacoinElement{
				StateElement:  types.StateElement{ID: types.Hash256(scoid)},
				SiacoinOutput: sco,
			})
		}
		for i, fc := range txn.FileContracts {
			fcid := txn.FileContractID(i)
			tdiff.CreatedFileContracts = append(tdiff.CreatedFileContracts, types.FileContractElement{
				StateElement: types.StateElement{ID: types.Hash256(fcid)},
				FileContract: fc,
			})
		}
		for _, sfi := range txn.SiafundInputs {
			sfe, claimPortion := ms.mustSiafundElement(store, sfi.ParentID)
			tdiff.SpentSiafundElements = append(tdiff.SpentSiafundElements, sfe)
			tdiff.CreatedSiacoinElements = append(tdiff.CreatedSiacoinElements, types.SiacoinElement{
				StateElement:   types.StateElement{ID: types.Hash256(sfi.ParentID.ClaimOutputID())},
				SiacoinOutput:  types.SiacoinOutput{Value: claimPortion, Address: sfi.ClaimAddress},
				MaturityHeight: s.MaturityHeight(),
			})
		}
		for i, sfo := range txn.SiafundOutputs {
			sfoid := txn.SiafundOutputID(i)
			tdiff.CreatedSiafundElements = append(tdiff.CreatedSiafundElements, types.SiafundElement{
				StateElement:  types.StateElement{ID: types.Hash256(sfoid)},
				SiafundOutput: sfo,
				ClaimStart:    ms.siafundPool,
			})
		}
		for _, fcr := range txn.FileContractRevisions {
			fce := ms.mustFileContractParentRevision(store, fcr.ParentID, fcr.RevisionNumber)
			tdiff.RevisedFileContracts = append(tdiff.RevisedFileContracts, types.FileContractElementRevision{
				Parent:   fce,
				Revision: fcr.FileContract,
			})
		}
		for _, sp := range txn.StorageProofs {
			fce := ms.mustFileContractElement(store, sp.ParentID)
			tdiff.ValidFileContracts = append(tdiff.ValidFileContracts, fce)
			for i, sco := range fce.ValidProofOutputs {
				scoid := sp.ParentID.ValidOutputID(i)
				tdiff.CreatedSiacoinElements = append(tdiff.CreatedSiacoinElements, types.SiacoinElement{
					StateElement:   types.StateElement{ID: types.Hash256(scoid)},
					SiacoinOutput:  sco,
					MaturityHeight: s.MaturityHeight(),
				})
			}
		}

		diff.Transactions = append(diff.Transactions, tdiff)
		ms.ApplyTransaction(store, txn)
	}

	if b.V2 != nil {
		for _, txn := range b.V2.Transactions {
			var tdiff V2TransactionDiff
			txid := txn.ID()

			for _, sci := range txn.SiacoinInputs {
				tdiff.SpentSiacoinElements = append(tdiff.SpentSiacoinElements, sci.Parent)
			}
			for _, sco := range txn.SiacoinOutputs {
				scoid := v2SiacoinOutputID(txid, len(tdiff.CreatedSiacoinElements))
				tdiff.CreatedSiacoinElements = append(tdiff.CreatedSiacoinElements, types.SiacoinElement{
					StateElement:  types.StateElement{ID: types.Hash256(scoid)},
					SiacoinOutput: sco,
				})
			}
			for _, fc := range txn.FileContracts {
				tdiff.CreatedFileContracts = append(tdiff.CreatedFileContracts, types.V2FileContractElement{
					StateElement:   types.StateElement{ID: types.Hash256(v2FileContractID(txid, len(tdiff.CreatedFileContracts)))},
					V2FileContract: fc,
				})
			}
			for _, sfi := range txn.SiafundInputs {
				tdiff.SpentSiafundElements = append(tdiff.SpentSiafundElements, sfi.Parent)
				scoid := v2SiacoinOutputID(txid, len(tdiff.CreatedSiacoinElements))
				claimPortion := ms.siafundPool.Sub(sfi.Parent.ClaimStart).Div64(ms.base.SiafundCount()).Mul64(sfi.Parent.Value)
				tdiff.CreatedSiacoinElements = append(tdiff.CreatedSiacoinElements, types.SiacoinElement{
					StateElement:   types.StateElement{ID: types.Hash256(scoid)},
					SiacoinOutput:  types.SiacoinOutput{Value: claimPortion, Address: sfi.ClaimAddress},
					MaturityHeight: s.MaturityHeight(),
				})
			}
			for _, sfo := range txn.SiafundOutputs {
				sfoid := v2SiafundOutputID(txid, len(tdiff.CreatedSiafundElements))
				tdiff.CreatedSiafundElements = append(tdiff.CreatedSiafundElements, types.SiafundElement{
					StateElement:  types.StateElement{ID: types.Hash256(sfoid)},
					SiafundOutput: sfo,
					ClaimStart:    ms.siafundPool,
				})
			}
			tdiff.RevisedFileContracts = append(tdiff.RevisedFileContracts, txn.FileContractRevisions...)
			tdiff.ResolvedFileContracts = append(tdiff.ResolvedFileContracts, txn.FileContractResolutions...)
			for _, res := range txn.FileContractResolutions {
				if r, ok := res.Resolution.(types.V2FileContractRenewal); ok {
					fcid := v2FileContractID(txid, len(tdiff.CreatedFileContracts))
					tdiff.CreatedFileContracts = append(tdiff.CreatedFileContracts, types.V2FileContractElement{
						StateElement:   types.StateElement{ID: types.Hash256(fcid)},
						V2FileContract: r.InitialRevision,
					})
				}
			}
			diff.V2Transactions = append(diff.V2Transactions, tdiff)
			ms.ApplyV2Transaction(txn)
		}
	}

	bid := b.ID()
	for i, sco := range b.MinerPayouts {
		scoid := bid.MinerOutputID(i)
		diff.CreatedSiacoinElements = append(diff.CreatedSiacoinElements, types.SiacoinElement{
			StateElement:   types.StateElement{ID: types.Hash256(scoid)},
			SiacoinOutput:  sco,
			MaturityHeight: s.MaturityHeight(),
		})
	}
	for _, fcid := range store.MissedFileContracts(s.childHeight()) {
		if _, ok := ms.spent(types.Hash256(fcid)); ok {
			continue
		}
		fce := ms.mustFileContractElement(store, fcid)
		diff.MissedFileContracts = append(diff.MissedFileContracts, fce)
		for i, sco := range fce.MissedProofOutputs {
			scoid := fcid.MissedOutputID(i)
			diff.CreatedSiacoinElements = append(diff.CreatedSiacoinElements, types.SiacoinElement{
				StateElement:   types.StateElement{ID: types.Hash256(scoid)},
				SiacoinOutput:  sco,
				MaturityHeight: s.MaturityHeight(),
			})
		}
	}
	if subsidy := s.FoundationSubsidy(); !subsidy.Value.IsZero() {
		scoid := bid.FoundationOutputID()
		diff.CreatedSiacoinElements = append(diff.CreatedSiacoinElements, types.SiacoinElement{
			StateElement:   types.StateElement{ID: types.Hash256(scoid)},
			SiacoinOutput:  subsidy,
			MaturityHeight: s.MaturityHeight(),
		})
	}

	diff.ElementApplyUpdate = s.Elements.ApplyBlock(&diff) // fills in leaf index + proofs for all elements
	diff.HistoryApplyUpdate = s.History.ApplyBlock(types.ChainIndex{Height: s.Index.Height + 1, ID: bid})
	return diff
}
