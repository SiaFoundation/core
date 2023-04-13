package consensus

import (
	"bytes"
	"fmt"
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
	}
}

// A SiacoinOutputDiff records the creation, deletion, or spending of a
// SiacoinOutput.
type SiacoinOutputDiff struct {
	ID     types.SiacoinOutputID
	Output types.SiacoinOutput
}

// EncodeTo implements types.EncoderTo.
func (scod SiacoinOutputDiff) EncodeTo(e *types.Encoder) {
	scod.ID.EncodeTo(e)
	scod.Output.EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (scod *SiacoinOutputDiff) DecodeFrom(d *types.Decoder) {
	scod.ID.DecodeFrom(d)
	scod.Output.DecodeFrom(d)
}

// A DelayedOutputSource identifies the source (miner payout, contract, etc.) of
// a delayed SiacoinOutput.
type DelayedOutputSource uint8

// Possible sources of a delayed SiacoinOutput.
const (
	OutputSourceMiner DelayedOutputSource = iota + 1
	OutputSourceValidContract
	OutputSourceMissedContract
	OutputSourceSiafundClaim
	OutputSourceFoundation
)

// String implements fmt.Stringer.
func (d DelayedOutputSource) String() string {
	if d == 0 || d > OutputSourceFoundation {
		return fmt.Sprintf("DelayedOutputSource(%d)", d)
	}
	return [...]string{
		OutputSourceMiner:          "miner payout",
		OutputSourceValidContract:  "valid contract",
		OutputSourceMissedContract: "missed contract",
		OutputSourceSiafundClaim:   "siafund claim",
		OutputSourceFoundation:     "foundation subsidy",
	}[d]
}

// MarshalText implements encoding.TextMarshaler.
func (d DelayedOutputSource) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *DelayedOutputSource) UnmarshalText(b []byte) error {
	switch string(b) {
	case OutputSourceMiner.String():
		*d = OutputSourceMiner
	case OutputSourceValidContract.String():
		*d = OutputSourceValidContract
	case OutputSourceMissedContract.String():
		*d = OutputSourceMissedContract
	case OutputSourceSiafundClaim.String():
		*d = OutputSourceSiafundClaim
	case OutputSourceFoundation.String():
		*d = OutputSourceFoundation
	default:
		return fmt.Errorf("unrecognized DelayedOutputSource %q", b)
	}
	return nil
}

// A DelayedSiacoinOutputDiff records the creation, deletion, or maturation of a
// delayed SiacoinOutput. "Delayed" means that the output is immature when
// created; it may only be spent when the "MaturityHeight" is reached.
type DelayedSiacoinOutputDiff struct {
	ID             types.SiacoinOutputID `json:"ID"`
	Output         types.SiacoinOutput   `json:"output"`
	Source         DelayedOutputSource   `json:"source"`
	MaturityHeight uint64                `json:"maturityHeight"`
}

// EncodeTo implements types.EncoderTo.
func (dscod DelayedSiacoinOutputDiff) EncodeTo(e *types.Encoder) {
	dscod.ID.EncodeTo(e)
	dscod.Output.EncodeTo(e)
	e.WriteUint8(uint8(dscod.Source))
	e.WriteUint64(dscod.MaturityHeight)
}

// DecodeFrom implements types.DecoderFrom.
func (dscod *DelayedSiacoinOutputDiff) DecodeFrom(d *types.Decoder) {
	dscod.ID.DecodeFrom(d)
	dscod.Output.DecodeFrom(d)
	dscod.Source = DelayedOutputSource(d.ReadUint8())
	dscod.MaturityHeight = d.ReadUint64()
}

// A SiafundOutputDiff records the creation, deletion, or spending of a
// SiafundOutput.
type SiafundOutputDiff struct {
	ID         types.SiafundOutputID `json:"ID"`
	Output     types.SiafundOutput   `json:"output"`
	ClaimStart types.Currency        `json:"claimStart"`
}

// EncodeTo implements types.EncoderTo.
func (sfod SiafundOutputDiff) EncodeTo(e *types.Encoder) {
	sfod.ID.EncodeTo(e)
	sfod.Output.EncodeTo(e)
	sfod.ClaimStart.EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (sfod *SiafundOutputDiff) DecodeFrom(d *types.Decoder) {
	sfod.ID.DecodeFrom(d)
	sfod.Output.DecodeFrom(d)
	sfod.ClaimStart.DecodeFrom(d)
}

// A FileContractDiff records the creation, deletion, or resolution of a
// FileContract.
type FileContractDiff struct {
	ID       types.FileContractID `json:"ID"`
	Contract types.FileContract   `json:"contract"`
}

// EncodeTo implements types.EncoderTo.
func (fcd FileContractDiff) EncodeTo(e *types.Encoder) {
	fcd.ID.EncodeTo(e)
	fcd.Contract.EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (fcd *FileContractDiff) DecodeFrom(d *types.Decoder) {
	fcd.ID.DecodeFrom(d)
	fcd.Contract.DecodeFrom(d)
}

// A FileContractRevisionDiff records the revision of a FileContract.
type FileContractRevisionDiff struct {
	ID          types.FileContractID `json:"ID"`
	OldContract types.FileContract   `json:"oldContract"`
	NewContract types.FileContract   `json:"newContract"`
}

// EncodeTo implements types.EncoderTo.
func (fcrd FileContractRevisionDiff) EncodeTo(e *types.Encoder) {
	fcrd.ID.EncodeTo(e)
	fcrd.OldContract.EncodeTo(e)
	fcrd.NewContract.EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (fcrd *FileContractRevisionDiff) DecodeFrom(d *types.Decoder) {
	fcrd.ID.DecodeFrom(d)
	fcrd.OldContract.DecodeFrom(d)
	fcrd.NewContract.DecodeFrom(d)
}

// A TransactionDiff represents the changes to an ElementStore resulting from
// the application of a transaction.
type TransactionDiff struct {
	CreatedSiacoinOutputs  []SiacoinOutputDiff        `json:"createdSiacoinOutputs"`
	ImmatureSiacoinOutputs []DelayedSiacoinOutputDiff `json:"immatureSiacoinOutputs"`
	CreatedSiafundOutputs  []SiafundOutputDiff        `json:"createdSiafundOutputs"`
	CreatedFileContracts   []FileContractDiff         `json:"createdFileContracts"`

	SpentSiacoinOutputs  []SiacoinOutputDiff        `json:"spentSiacoinOutputs"`
	SpentSiafundOutputs  []SiafundOutputDiff        `json:"spentSiafundOutputs"`
	RevisedFileContracts []FileContractRevisionDiff `json:"revisedFileContracts"`
	ValidFileContracts   []FileContractDiff         `json:"validFileContracts"`
}

// EncodeTo implements types.EncoderTo.
func (td TransactionDiff) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(td.CreatedSiacoinOutputs))
	for i := range td.CreatedSiacoinOutputs {
		td.CreatedSiacoinOutputs[i].EncodeTo(e)
	}
	e.WritePrefix(len(td.ImmatureSiacoinOutputs))
	for i := range td.ImmatureSiacoinOutputs {
		td.ImmatureSiacoinOutputs[i].EncodeTo(e)
	}
	e.WritePrefix(len(td.CreatedSiafundOutputs))
	for i := range td.CreatedSiafundOutputs {
		td.CreatedSiafundOutputs[i].EncodeTo(e)
	}
	e.WritePrefix(len(td.CreatedFileContracts))
	for i := range td.CreatedFileContracts {
		td.CreatedFileContracts[i].EncodeTo(e)
	}
	e.WritePrefix(len(td.SpentSiacoinOutputs))
	for i := range td.SpentSiacoinOutputs {
		td.SpentSiacoinOutputs[i].EncodeTo(e)
	}
	e.WritePrefix(len(td.SpentSiafundOutputs))
	for i := range td.SpentSiafundOutputs {
		td.SpentSiafundOutputs[i].EncodeTo(e)
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
	td.CreatedSiacoinOutputs = make([]SiacoinOutputDiff, d.ReadPrefix())
	for i := range td.CreatedSiacoinOutputs {
		td.CreatedSiacoinOutputs[i].DecodeFrom(d)
	}
	td.ImmatureSiacoinOutputs = make([]DelayedSiacoinOutputDiff, d.ReadPrefix())
	for i := range td.ImmatureSiacoinOutputs {
		td.ImmatureSiacoinOutputs[i].DecodeFrom(d)
	}
	td.CreatedSiafundOutputs = make([]SiafundOutputDiff, d.ReadPrefix())
	for i := range td.CreatedSiafundOutputs {
		td.CreatedSiafundOutputs[i].DecodeFrom(d)
	}
	td.CreatedFileContracts = make([]FileContractDiff, d.ReadPrefix())
	for i := range td.CreatedFileContracts {
		td.CreatedFileContracts[i].DecodeFrom(d)
	}
	td.SpentSiacoinOutputs = make([]SiacoinOutputDiff, d.ReadPrefix())
	for i := range td.SpentSiacoinOutputs {
		td.SpentSiacoinOutputs[i].DecodeFrom(d)
	}
	td.SpentSiafundOutputs = make([]SiafundOutputDiff, d.ReadPrefix())
	for i := range td.SpentSiafundOutputs {
		td.SpentSiafundOutputs[i].DecodeFrom(d)
	}
	td.RevisedFileContracts = make([]FileContractRevisionDiff, d.ReadPrefix())
	for i := range td.RevisedFileContracts {
		td.RevisedFileContracts[i].DecodeFrom(d)
	}
	td.ValidFileContracts = make([]FileContractDiff, d.ReadPrefix())
	for i := range td.ValidFileContracts {
		td.ValidFileContracts[i].DecodeFrom(d)
	}
}

// A BlockDiff represents the changes to a Store resulting from the application
// of a block.
type BlockDiff struct {
	Transactions           []TransactionDiff          `json:"transactions"`
	MaturedSiacoinOutputs  []DelayedSiacoinOutputDiff `json:"maturedSiacoinOutputs"`
	ImmatureSiacoinOutputs []DelayedSiacoinOutputDiff `json:"immatureSiacoinOutputs"`
	MissedFileContracts    []FileContractDiff         `json:"missedFileContracts"`
}

// EncodeTo implements types.EncoderTo.
func (bd BlockDiff) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(bd.Transactions))
	for i := range bd.Transactions {
		bd.Transactions[i].EncodeTo(e)
	}
	e.WritePrefix(len(bd.ImmatureSiacoinOutputs))
	for i := range bd.ImmatureSiacoinOutputs {
		bd.ImmatureSiacoinOutputs[i].EncodeTo(e)
	}
	e.WritePrefix(len(bd.MaturedSiacoinOutputs))
	for i := range bd.MaturedSiacoinOutputs {
		bd.MaturedSiacoinOutputs[i].EncodeTo(e)
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
	bd.ImmatureSiacoinOutputs = make([]DelayedSiacoinOutputDiff, d.ReadPrefix())
	for i := range bd.ImmatureSiacoinOutputs {
		bd.ImmatureSiacoinOutputs[i].DecodeFrom(d)
	}
	bd.MaturedSiacoinOutputs = make([]DelayedSiacoinOutputDiff, d.ReadPrefix())
	for i := range bd.MaturedSiacoinOutputs {
		bd.MaturedSiacoinOutputs[i].DecodeFrom(d)
	}
	bd.MissedFileContracts = make([]FileContractDiff, d.ReadPrefix())
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
		ms.scos[txn.SiacoinOutputID(i)] = sco
	}
	for _, sfi := range txn.SiafundInputs {
		ms.spends[types.Hash256(sfi.ParentID)] = txid
	}
	for i, sfo := range txn.SiafundOutputs {
		sfoid := txn.SiafundOutputID(i)
		ms.sfos[sfoid] = sfo
		ms.claims[sfoid] = ms.siafundPool
	}
	for i, fc := range txn.FileContracts {
		ms.fcs[txn.FileContractID(i)] = fc
		ms.siafundPool = ms.siafundPool.Add(ms.base.FileContractTax(fc))
	}
	for _, fcr := range txn.FileContractRevisions {
		fc := ms.mustFileContract(store, fcr.ParentID)
		newContract := fcr.FileContract
		newContract.Payout = fc.Payout // see types.FileContractRevision docstring
		ms.fcs[fcr.ParentID] = newContract
	}
	for _, sp := range txn.StorageProofs {
		ms.spends[types.Hash256(sp.ParentID)] = txid
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
			tdiff.SpentSiacoinOutputs = append(tdiff.SpentSiacoinOutputs, SiacoinOutputDiff{
				ID:     sci.ParentID,
				Output: ms.mustSiacoinOutput(store, sci.ParentID),
			})
		}
		for i, sco := range txn.SiacoinOutputs {
			scoid := txn.SiacoinOutputID(i)
			tdiff.CreatedSiacoinOutputs = append(tdiff.CreatedSiacoinOutputs, SiacoinOutputDiff{
				ID:     scoid,
				Output: sco,
			})
		}
		for i, fc := range txn.FileContracts {
			fcid := txn.FileContractID(i)
			tdiff.CreatedFileContracts = append(tdiff.CreatedFileContracts, FileContractDiff{
				ID:       fcid,
				Contract: fc,
			})
		}
		for _, sfi := range txn.SiafundInputs {
			sfo, claimStart, claimPortion := ms.mustSiafundOutput(store, sfi.ParentID)
			tdiff.SpentSiafundOutputs = append(tdiff.SpentSiafundOutputs, SiafundOutputDiff{
				ID:         sfi.ParentID,
				Output:     sfo,
				ClaimStart: claimStart,
			})
			tdiff.ImmatureSiacoinOutputs = append(tdiff.ImmatureSiacoinOutputs, DelayedSiacoinOutputDiff{
				ID:             sfi.ParentID.ClaimOutputID(),
				Output:         types.SiacoinOutput{Value: claimPortion, Address: sfi.ClaimAddress},
				Source:         OutputSourceSiafundClaim,
				MaturityHeight: s.MaturityHeight(),
			})
		}
		for i, sfo := range txn.SiafundOutputs {
			sfoid := txn.SiafundOutputID(i)
			tdiff.CreatedSiafundOutputs = append(tdiff.CreatedSiafundOutputs, SiafundOutputDiff{
				ID:         sfoid,
				Output:     sfo,
				ClaimStart: ms.siafundPool,
			})
		}
		for _, fcr := range txn.FileContractRevisions {
			fc := ms.mustFileContract(store, fcr.ParentID)
			newContract := fcr.FileContract
			newContract.Payout = fc.Payout // see types.FileContractRevision docstring
			tdiff.RevisedFileContracts = append(tdiff.RevisedFileContracts, FileContractRevisionDiff{
				ID:          fcr.ParentID,
				OldContract: fc,
				NewContract: newContract,
			})
		}
		for _, sp := range txn.StorageProofs {
			fc := ms.mustFileContract(store, sp.ParentID)
			tdiff.ValidFileContracts = append(tdiff.ValidFileContracts, FileContractDiff{
				ID:       sp.ParentID,
				Contract: fc,
			})
			for i, sco := range fc.ValidProofOutputs {
				tdiff.ImmatureSiacoinOutputs = append(tdiff.ImmatureSiacoinOutputs, DelayedSiacoinOutputDiff{
					ID:             sp.ParentID.ValidOutputID(i),
					Output:         sco,
					Source:         OutputSourceValidContract,
					MaturityHeight: s.MaturityHeight(),
				})
			}
		}
		diff.Transactions = append(diff.Transactions, tdiff)
		ms.ApplyTransaction(store, txn)
	}

	bid := b.ID()
	diff.MaturedSiacoinOutputs = store.MaturedSiacoinOutputs(s.childHeight())
	for i, sco := range b.MinerPayouts {
		diff.ImmatureSiacoinOutputs = append(diff.ImmatureSiacoinOutputs, DelayedSiacoinOutputDiff{
			ID:             bid.MinerOutputID(i),
			Output:         sco,
			Source:         OutputSourceMiner,
			MaturityHeight: s.MaturityHeight(),
		})
	}
	for _, fcid := range store.MissedFileContracts(s.childHeight()) {
		if _, ok := ms.spent(types.Hash256(fcid)); ok {
			continue
		}
		fc := ms.mustFileContract(store, fcid)
		diff.MissedFileContracts = append(diff.MissedFileContracts, FileContractDiff{
			ID:       fcid,
			Contract: fc,
		})
		for i, sco := range fc.MissedProofOutputs {
			diff.ImmatureSiacoinOutputs = append(diff.ImmatureSiacoinOutputs, DelayedSiacoinOutputDiff{
				ID:             fcid.MissedOutputID(i),
				Output:         sco,
				Source:         OutputSourceMissedContract,
				MaturityHeight: s.MaturityHeight(),
			})
		}
	}
	if subsidy := s.FoundationSubsidy(); !subsidy.Value.IsZero() {
		diff.ImmatureSiacoinOutputs = append(diff.ImmatureSiacoinOutputs, DelayedSiacoinOutputDiff{
			ID:             bid.FoundationOutputID(),
			Output:         subsidy,
			Source:         OutputSourceFoundation,
			MaturityHeight: s.MaturityHeight(),
		})
	}

	return diff
}
