package consensus

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"math/bits"
	"slices"
	"time"

	"go.sia.tech/core/internal/blake2b"
	"go.sia.tech/core/types"
)

// Work represents a quantity of work.
type Work struct {
	// expected number of tries required to produce a given hash (big-endian)
	n [32]byte
}

// Cmp compares two work values.
func (w Work) Cmp(v Work) int {
	return bytes.Compare(w.n[:], v.n[:])
}

// EncodeTo implements types.EncoderTo.
func (w Work) EncodeTo(e *types.Encoder) { e.Write(w.n[:]) }

// DecodeFrom implements types.DecoderFrom.
func (w *Work) DecodeFrom(d *types.Decoder) { d.Read(w.n[:]) }

// String implements fmt.Stringer.
func (w Work) String() string { return new(big.Int).SetBytes(w.n[:]).String() }

// MarshalText implements encoding.TextMarshaler.
func (w Work) MarshalText() ([]byte, error) {
	return new(big.Int).SetBytes(w.n[:]).MarshalText()
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (w *Work) UnmarshalText(b []byte) error {
	i := new(big.Int)
	if err := i.UnmarshalText(b); err != nil {
		return err
	} else if i.Sign() < 0 {
		return errors.New("value cannot be negative")
	} else if i.BitLen() > 256 {
		return errors.New("value overflows Work representation")
	}
	i.FillBytes(w.n[:])
	return nil
}

// MarshalJSON implements json.Marshaler.
func (w Work) MarshalJSON() ([]byte, error) {
	s, err := w.MarshalText()
	return []byte(`"` + string(s) + `"`), err
}

// UnmarshalJSON implements json.Unmarshaler.
func (w *Work) UnmarshalJSON(b []byte) error {
	return w.UnmarshalText(bytes.Trim(b, `"`))
}

func (w Work) add(v Work) Work {
	var r Work
	var sum, c uint64
	for i := 24; i >= 0; i -= 8 {
		wi := binary.BigEndian.Uint64(w.n[i:])
		vi := binary.BigEndian.Uint64(v.n[i:])
		sum, c = bits.Add64(wi, vi, c)
		binary.BigEndian.PutUint64(r.n[i:], sum)
	}
	return r
}

func (w Work) sub(v Work) Work {
	var r Work
	var sum, c uint64
	for i := 24; i >= 0; i -= 8 {
		wi := binary.BigEndian.Uint64(w.n[i:])
		vi := binary.BigEndian.Uint64(v.n[i:])
		sum, c = bits.Sub64(wi, vi, c)
		binary.BigEndian.PutUint64(r.n[i:], sum)
	}
	return r
}

func (w Work) mul64(v uint64) Work {
	var r Work
	var c uint64
	for i := 24; i >= 0; i -= 8 {
		wi := binary.BigEndian.Uint64(w.n[i:])
		hi, prod := bits.Mul64(wi, v)
		prod, cc := bits.Add64(prod, c, 0)
		c = hi + cc
		binary.BigEndian.PutUint64(r.n[i:], prod)
	}
	return r
}

func (w Work) div64(v uint64) Work {
	var r Work
	var quo, rem uint64
	for i := 0; i < len(w.n); i += 8 {
		wi := binary.BigEndian.Uint64(w.n[i:])
		quo, rem = bits.Div64(rem, wi, v)
		binary.BigEndian.PutUint64(r.n[i:], quo)
	}
	return r
}

// prior to v2, work is represented in terms of "target" hashes, i.e. the inverse of Work

var maxTarget = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

func invTarget(n [32]byte) (inv [32]byte) {
	i := new(big.Int).SetBytes(n[:])
	i.Div(maxTarget, i).FillBytes(inv[:])
	return
}

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

func updateTotalWork(s State) (Work, types.BlockID) {
	// prior to the hardfork, we compute the work from the depth; after the
	// hardfork, we do the opposite
	if s.childHeight() < s.Network.HardforkV2.AllowHeight {
		depth := addTarget(s.Depth, s.ChildTarget)
		return Work{invTarget(depth)}, depth
	}
	totalWork := s.TotalWork.add(s.Difficulty)
	return totalWork, invTarget(totalWork.n)
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

func updateOakWork(s State) (Work, types.BlockID) {
	// prior to the hardfork, we compute the work from the target; after the
	// hardfork, we do the opposite
	if s.childHeight() < s.Network.HardforkV2.AllowHeight {
		target := updateOakTarget(s)
		return Work{invTarget(target)}, target
	}
	work := s.OakWork.sub(s.OakWork.div64(200)).add(s.Difficulty)
	return work, invTarget(work.n)
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

	// same as adjustDifficulty, just a bit hairier
	oakTotalTime := int64(s.OakTime / time.Second)
	var delta int64
	if s.Index.Height < s.Network.HardforkOak.FixHeight {
		delta = (blockInterval * int64(s.Index.Height)) - oakTotalTime
	} else {
		parentTimestamp := s.PrevTimestamps[0]
		delta = (blockInterval * int64(s.Index.Height)) - (parentTimestamp.Unix() - s.Network.HardforkOak.GenesisTimestamp.Unix())
	}
	shift := delta * delta
	if delta < 0 {
		shift = -shift
	}
	shift *= 10
	shift /= 10000 * 10000
	targetBlockTime := blockInterval + shift
	if minTime := blockInterval / 3; targetBlockTime < minTime {
		targetBlockTime = minTime
	} else if maxTime := blockInterval * 3; targetBlockTime > maxTime {
		targetBlockTime = maxTime
	}
	if oakTotalTime <= 0 {
		oakTotalTime = 1
	}
	if targetBlockTime == 0 {
		targetBlockTime = 1
	}
	estimatedHashrate := new(big.Int).Div(maxTarget, new(big.Int).SetBytes(s.OakTarget[:]))
	estimatedHashrate.Div(estimatedHashrate, big.NewInt(oakTotalTime))
	estimatedHashrate.Mul(estimatedHashrate, big.NewInt(targetBlockTime))
	if estimatedHashrate.Sign() == 0 {
		estimatedHashrate.SetInt64(1)
	}
	newTarget := intToTarget(new(big.Int).Div(maxTarget, estimatedHashrate))
	if s.childHeight() == s.Network.HardforkASIC.Height {
		return newTarget
	}
	minTarget := mulTargetFrac(s.ChildTarget, 1004, 1000)
	maxTarget := mulTargetFrac(s.ChildTarget, 1000, 1004)
	if newTarget.CmpWork(minTarget) < 0 {
		newTarget = minTarget
	} else if newTarget.CmpWork(maxTarget) > 0 {
		newTarget = maxTarget
	}
	return newTarget
}

func adjustDifficulty(s State, blockTimestamp time.Time, targetTimestamp time.Time) (Work, types.BlockID) {
	// prior to the hardfork, we compute the work from the target; after the
	// hardfork, we do the opposite
	if s.childHeight() < s.Network.HardforkV2.AllowHeight {
		target := adjustTarget(s, blockTimestamp, targetTimestamp)
		return Work{invTarget(target)}, target
	}

	expectedTime := s.BlockInterval() * time.Duration(s.childHeight())
	actualTime := blockTimestamp.Sub(s.Network.HardforkOak.GenesisTimestamp)
	delta := expectedTime - actualTime
	// square the delta, scaling such that a delta of 10,000 produces a shift of
	// 10 seconds,
	shift := 10 * (delta / 10000) * (delta / 10000)
	// preserve sign
	if delta < 0 {
		shift = -shift
	}

	// calculate the new target block time, clamped to a factor of 3
	targetBlockTime := s.BlockInterval() + shift
	if minTime := s.BlockInterval() / 3; targetBlockTime < minTime {
		targetBlockTime = minTime
	} else if maxTime := s.BlockInterval() * 3; targetBlockTime > maxTime {
		targetBlockTime = maxTime
	}

	// estimate current hashrate
	//
	// NOTE: to prevent overflow/truncation, we operate in terms of seconds
	if s.OakTime <= time.Second {
		s.OakTime = time.Second
	}
	estimatedHashrate := s.OakWork.div64(uint64(s.OakTime / time.Second))

	// multiply the hashrate by the target block time; this is the expected
	// number of hashes required to produce the next block, i.e. the new
	// difficulty
	newDifficulty := estimatedHashrate.mul64(uint64(targetBlockTime / time.Second))

	// clamp the adjustment to 0.4%
	maxAdjust := s.Difficulty.div64(250)
	if minDifficulty := s.Difficulty.sub(maxAdjust); newDifficulty.Cmp(minDifficulty) < 0 {
		newDifficulty = minDifficulty
	} else if maxDifficulty := s.Difficulty.add(maxAdjust); newDifficulty.Cmp(maxDifficulty) > 0 {
		newDifficulty = maxDifficulty
	}
	return newDifficulty, invTarget(newDifficulty.n)
}

// ApplyOrphan applies the work of b to s, returning the resulting state. Only
// the PoW-related fields are updated.
func ApplyOrphan(s State, b types.Block, targetTimestamp time.Time) State {
	if s.Index.Height > 0 && s.Index.ID != b.ParentID {
		panic("consensus: cannot apply non-child block")
	}

	next := s
	if b.ParentID == (types.BlockID{}) {
		// special handling for genesis block
		next.OakTime = updateOakTime(s, b.Timestamp, b.Timestamp)
		next.OakWork, next.OakTarget = updateOakWork(s)
		next.Index = types.ChainIndex{Height: 0, ID: b.ID()}
	} else {
		next.TotalWork, next.Depth = updateTotalWork(s)
		next.Difficulty, next.ChildTarget = adjustDifficulty(s, b.Timestamp, targetTimestamp)
		next.OakTime = updateOakTime(s, b.Timestamp, s.PrevTimestamps[0])
		next.OakWork, next.OakTarget = updateOakWork(s)
		next.Index = types.ChainIndex{Height: s.Index.Height + 1, ID: b.ID()}
	}
	next.PrevTimestamps[0] = b.Timestamp
	copy(next.PrevTimestamps[1:], s.PrevTimestamps[:])
	return next
}

func (ms *MidState) recordSiacoinElement(id types.SiacoinOutputID) *SiacoinElementDiff {
	if i, ok := ms.elements[id]; ok {
		return &ms.sces[i]
	}
	ms.sces = append(ms.sces, SiacoinElementDiff{})
	ms.elements[id] = len(ms.sces) - 1
	return &ms.sces[len(ms.sces)-1]
}

func (ms *MidState) createSiacoinElement(id types.SiacoinOutputID, sco types.SiacoinOutput) *SiacoinElementDiff {
	sced := ms.recordSiacoinElement(id)
	sced.SiacoinElement = types.SiacoinElement{
		StateElement:  types.StateElement{LeafIndex: types.UnassignedLeafIndex},
		ID:            id,
		SiacoinOutput: sco,
	}
	sced.Created = true
	return sced
}

func (ms *MidState) createImmatureSiacoinElement(id types.SiacoinOutputID, sco types.SiacoinOutput) *SiacoinElementDiff {
	sced := ms.createSiacoinElement(id, sco)
	sced.SiacoinElement.MaturityHeight = ms.base.MaturityHeight()
	return sced
}

func (ms *MidState) spendSiacoinElement(sce types.SiacoinElement, txid types.TransactionID) {
	sced := ms.recordSiacoinElement(sce.ID)
	sced.SiacoinElement = sce.Copy()
	sced.Spent = true
	ms.spends[sce.ID] = txid
}

func (ms *MidState) recordSiafundElement(id types.SiafundOutputID) *SiafundElementDiff {
	if i, ok := ms.elements[id]; ok {
		return &ms.sfes[i]
	}
	ms.sfes = append(ms.sfes, SiafundElementDiff{})
	ms.elements[id] = len(ms.sfes) - 1
	return &ms.sfes[len(ms.sfes)-1]
}

func (ms *MidState) createSiafundElement(id types.SiafundOutputID, sfo types.SiafundOutput) *SiafundElementDiff {
	sfed := ms.recordSiafundElement(id)
	sfed.SiafundElement = types.SiafundElement{
		StateElement:  types.StateElement{LeafIndex: types.UnassignedLeafIndex},
		ID:            id,
		SiafundOutput: sfo,
		ClaimStart:    ms.siafundTaxRevenue,
	}
	sfed.Created = true
	return sfed
}

func (ms *MidState) spendSiafundElement(sfe types.SiafundElement, txid types.TransactionID) {
	sfed := ms.recordSiafundElement(sfe.ID)
	sfed.SiafundElement = sfe.Copy()
	sfed.Spent = true
	ms.spends[sfe.ID] = txid
}

func (ms *MidState) recordFileContractElement(id types.FileContractID) *FileContractElementDiff {
	if i, ok := ms.elements[id]; ok {
		return &ms.fces[i]
	}
	ms.fces = append(ms.fces, FileContractElementDiff{})
	ms.elements[id] = len(ms.fces) - 1
	return &ms.fces[len(ms.fces)-1]
}

func (ms *MidState) createFileContractElement(id types.FileContractID, fc types.FileContract) {
	fced := ms.recordFileContractElement(id)
	fced.FileContractElement = types.FileContractElement{
		StateElement: types.StateElement{LeafIndex: types.UnassignedLeafIndex},
		ID:           id,
		FileContract: fc,
	}
	fced.Created = true
	ms.siafundTaxRevenue = ms.siafundTaxRevenue.Add(ms.base.FileContractTax(fc))
}

func (ms *MidState) reviseFileContractElement(fce types.FileContractElement, rev types.FileContract) {
	rev.Payout = fce.FileContract.Payout
	fced := ms.recordFileContractElement(fce.ID)
	if fced.Created {
		fced.FileContractElement.FileContract = rev
	} else if fced.Revision != nil {
		*fced.Revision = rev
	} else {
		fced.FileContractElement = fce.Copy()
		fced.Revision = &rev
	}
}

func (ms *MidState) resolveFileContractElement(fce types.FileContractElement, valid bool, txid types.TransactionID) {
	fced := ms.recordFileContractElement(fce.ID)
	fced.FileContractElement = fce.Copy()
	fced.Resolved = true
	fced.Valid = valid
	ms.spends[fce.ID] = txid
}

func (ms *MidState) recordV2FileContractElement(id types.FileContractID) *V2FileContractElementDiff {
	if i, ok := ms.elements[id]; ok {
		return &ms.v2fces[i]
	}
	ms.v2fces = append(ms.v2fces, V2FileContractElementDiff{})
	ms.elements[id] = len(ms.v2fces) - 1
	return &ms.v2fces[len(ms.v2fces)-1]
}

func (ms *MidState) createV2FileContractElement(id types.FileContractID, fc types.V2FileContract) {
	fced := ms.recordV2FileContractElement(id)
	fced.V2FileContractElement = types.V2FileContractElement{
		StateElement:   types.StateElement{LeafIndex: types.UnassignedLeafIndex},
		ID:             id,
		V2FileContract: fc,
	}
	fced.Created = true
	ms.siafundTaxRevenue = ms.siafundTaxRevenue.Add(ms.base.V2FileContractTax(fc))
}

func (ms *MidState) reviseV2FileContractElement(fce types.V2FileContractElement, rev types.V2FileContract) {
	fced := ms.recordV2FileContractElement(fce.ID)
	if fced.Created {
		fced.V2FileContractElement.V2FileContract = rev
	} else if fced.Revision != nil {
		*fced.Revision = rev
	} else {
		fced.V2FileContractElement = fce.Copy()
		fced.Revision = &rev
	}
}

func (ms *MidState) resolveV2FileContractElement(fce types.V2FileContractElement, res types.V2FileContractResolutionType, txid types.TransactionID) {
	fced := ms.recordV2FileContractElement(fce.ID)
	if fced.Created {
		panic("consensus: resolved a newly-created v2 contract")
	}
	fced.V2FileContractElement = fce.Copy()
	fced.Resolution = res
	ms.spends[fce.ID] = txid
}

func (ms *MidState) createAttestationElement(id types.AttestationID, a types.Attestation) {
	ms.aes = append(ms.aes, types.AttestationElement{
		StateElement: types.StateElement{LeafIndex: types.UnassignedLeafIndex},
		ID:           id,
		Attestation:  a,
	})
	ms.elements[ms.aes[len(ms.aes)-1].ID] = len(ms.aes) - 1
}

// ApplyTransaction applies a transaction to the MidState.
func (ms *MidState) ApplyTransaction(txn types.Transaction, ts V1TransactionSupplement) {
	txid := txn.ID()
	for _, sci := range txn.SiacoinInputs {
		sce, ok := ms.siacoinElement(ts, sci.ParentID)
		if !ok {
			panic("missing SiacoinElement")
		}
		ms.spendSiacoinElement(sce.Share(), txid)
	}
	for i, sco := range txn.SiacoinOutputs {
		ms.createSiacoinElement(txn.SiacoinOutputID(i), sco)
	}
	for _, sfi := range txn.SiafundInputs {
		sfe, ok := ms.siafundElement(ts, sfi.ParentID)
		if !ok {
			panic("missing SiafundElement")
		}
		claimPortion := ms.siafundTaxRevenue.Sub(sfe.ClaimStart).Div64(ms.base.SiafundCount()).Mul64(sfe.SiafundOutput.Value)
		ms.spendSiafundElement(sfe.Share(), txid)
		ms.createImmatureSiacoinElement(sfi.ParentID.ClaimOutputID(), types.SiacoinOutput{Value: claimPortion, Address: sfi.ClaimAddress})
	}
	for i, sfo := range txn.SiafundOutputs {
		ms.createSiafundElement(txn.SiafundOutputID(i), sfo)
	}
	for i, fc := range txn.FileContracts {
		ms.createFileContractElement(txn.FileContractID(i), fc)
	}
	for _, fcr := range txn.FileContractRevisions {
		fce, ok := ms.fileContractElement(ts, fcr.ParentID)
		if !ok {
			panic("missing FileContractElement")
		}
		ms.reviseFileContractElement(fce.Share(), fcr.FileContract)
	}
	for _, sp := range txn.StorageProofs {
		fce, ok := ms.fileContractElement(ts, sp.ParentID)
		if !ok {
			panic("missing V1StorageProofSupplement")
		}
		ms.resolveFileContractElement(fce.Share(), true, txid)
		for i, sco := range fce.FileContract.ValidProofOutputs {
			ms.createImmatureSiacoinElement(sp.ParentID.ValidOutputID(i), sco)
		}
	}
	if ms.base.Index.Height >= ms.base.Network.HardforkFoundation.Height {
		for _, arb := range txn.ArbitraryData {
			if bytes.HasPrefix(arb, types.SpecifierFoundation[:]) {
				var update types.FoundationAddressUpdate
				update.DecodeFrom(types.NewBufDecoder(arb[len(types.SpecifierFoundation):]))
				ms.foundationSubsidy = update.NewPrimary
				ms.foundationManagement = update.NewFailsafe
			}
		}
	}
}

// ApplyV2Transaction applies a v2 transaction to the MidState.
func (ms *MidState) ApplyV2Transaction(txn types.V2Transaction) {
	txid := txn.ID()

	for _, sci := range txn.SiacoinInputs {
		ms.spendSiacoinElement(sci.Parent.Share(), txid)
	}
	for i, sco := range txn.SiacoinOutputs {
		ms.createSiacoinElement(txn.SiacoinOutputID(txid, i), sco)
	}
	for _, sfi := range txn.SiafundInputs {
		ms.spendSiafundElement(sfi.Parent.Share(), txid)
		claimPortion := ms.siafundTaxRevenue.Sub(sfi.Parent.ClaimStart).Div64(ms.base.SiafundCount()).Mul64(sfi.Parent.SiafundOutput.Value)
		ms.createImmatureSiacoinElement(sfi.Parent.ID.V2ClaimOutputID(), types.SiacoinOutput{Value: claimPortion, Address: sfi.ClaimAddress})
	}
	for i, sfo := range txn.SiafundOutputs {
		ms.createSiafundElement(txn.SiafundOutputID(txid, i), sfo)
	}
	for i, fc := range txn.FileContracts {
		ms.createV2FileContractElement(txn.V2FileContractID(txid, i), fc)
	}
	for _, fcr := range txn.FileContractRevisions {
		ms.reviseV2FileContractElement(fcr.Parent.Share(), fcr.Revision)
	}
	for _, fcr := range txn.FileContractResolutions {
		ms.resolveV2FileContractElement(fcr.Parent.Share(), fcr.Resolution, txid)

		fc := fcr.Parent.V2FileContract
		var renter, host types.SiacoinOutput
		switch r := fcr.Resolution.(type) {
		case *types.V2FileContractRenewal:
			renter, host = r.FinalRenterOutput, r.FinalHostOutput
			ms.createV2FileContractElement(fcr.Parent.ID.V2RenewalID(), r.NewContract)
		case *types.V2StorageProof:
			renter, host = fc.RenterOutput, fc.HostOutput
		case *types.V2FileContractExpiration:
			renter, host = fc.RenterOutput, fc.MissedHostOutput()
		default:
			panic(fmt.Sprintf("unhandled resolution type %T", r))
		}
		ms.createImmatureSiacoinElement(fcr.Parent.ID.V2RenterOutputID(), renter)
		ms.createImmatureSiacoinElement(fcr.Parent.ID.V2HostOutputID(), host)
	}
	for i, a := range txn.Attestations {
		ms.createAttestationElement(txn.AttestationID(txid, i), a)
	}
	if txn.NewFoundationAddress != nil {
		// The subsidy may be waived by sending it to the void address. In this
		// case, the management address is not updated (as this would
		// permanently disable the subsidy).
		ms.foundationSubsidy = *txn.NewFoundationAddress
		if *txn.NewFoundationAddress != types.VoidAddress {
			ms.foundationManagement = *txn.NewFoundationAddress
		}
	}
}

// ApplyBlock applies a block to the MidState.
func (ms *MidState) ApplyBlock(b types.Block, bs V1BlockSupplement) {
	for i, txn := range b.Transactions {
		ms.ApplyTransaction(txn, bs.Transactions[i])
	}
	for _, txn := range b.V2Transactions() {
		ms.ApplyV2Transaction(txn)
	}
	bid := b.ID()
	for i, sco := range b.MinerPayouts {
		ms.createImmatureSiacoinElement(bid.MinerOutputID(i), sco)
	}
	if subsidy, ok := ms.base.FoundationSubsidy(); ok {
		ms.createImmatureSiacoinElement(bid.FoundationOutputID(), subsidy)
	}
	for _, fce := range bs.ExpiringFileContracts {
		if ms.isSpent(fce.ID) {
			continue
		}
		ms.resolveFileContractElement(fce.Share(), false, types.TransactionID(bid))
		for i, sco := range fce.FileContract.MissedProofOutputs {
			ms.createImmatureSiacoinElement(fce.ID.MissedOutputID(i), sco)
		}
	}

	ms.cie = types.ChainIndexElement{
		StateElement: types.StateElement{LeafIndex: types.UnassignedLeafIndex},
		ID:           bid,
		ChainIndex:   types.ChainIndex{Height: ms.base.childHeight(), ID: bid},
	}
}

func forEachAppliedElement(sces []SiacoinElementDiff, sfes []SiafundElementDiff, fces []FileContractElementDiff, v2fces []V2FileContractElementDiff, aes []types.AttestationElement, cie *types.ChainIndexElement, fn func(elementLeaf)) {
	for i := range sces {
		sce := &sces[i]
		fn(siacoinLeaf(&sce.SiacoinElement, sce.Spent))
	}
	for i := range sfes {
		sfe := &sfes[i]
		fn(siafundLeaf(&sfe.SiafundElement, sfe.Spent))
	}
	for i := range fces {
		fce := &fces[i]
		fn(fileContractLeaf(&fce.FileContractElement, fce.Revision, fce.Resolved))
	}
	for i := range v2fces {
		v2fce := &v2fces[i]
		fn(v2FileContractLeaf(&v2fce.V2FileContractElement, v2fce.Revision, v2fce.Resolution != nil))
		// NOTE: Although it is an element, we do not process the ProofIndex
		// field of V2StorageProofs. These are a special case, as they are not
		// being updated (like e.g. siacoin inputs), nor are they being created
		// (like e.g. attestations). In other words, they have no effect on the
		// accumulator, and thus including them would only cause confusion.
	}
	for i := range aes {
		fn(attestationLeaf(&aes[i]))
	}
	fn(chainIndexLeaf(cie))
}

func forEachRevertedElement(sces []SiacoinElementDiff, sfes []SiafundElementDiff, fces []FileContractElementDiff, v2fces []V2FileContractElementDiff, fn func(elementLeaf)) {
	for i := range sces {
		fn(siacoinLeaf(&sces[i].SiacoinElement, false))
	}
	for i := range sfes {
		fn(siafundLeaf(&sfes[i].SiafundElement, false))
	}
	for i := range fces {
		fn(fileContractLeaf(&fces[i].FileContractElement, nil, false))
	}
	for i := range v2fces {
		fn(v2FileContractLeaf(&v2fces[i].V2FileContractElement, nil, false))
	}
}

// An ApplyUpdate represents the effects of applying a block to a state.
type ApplyUpdate struct {
	sces   []SiacoinElementDiff
	sfes   []SiafundElementDiff
	fces   []FileContractElementDiff
	v2fces []V2FileContractElementDiff
	aes    []types.AttestationElement
	cie    types.ChainIndexElement

	eau elementApplyUpdate
}

// SiacoinElementDiffs returns the siacoin element diffs related to the applied
// block.
func (au ApplyUpdate) SiacoinElementDiffs() []SiacoinElementDiff { return au.sces }

// SiafundElementDiffs returns the siafund element diffs related to the applied
// block.
func (au ApplyUpdate) SiafundElementDiffs() []SiafundElementDiff { return au.sfes }

// FileContractElementDiffs returns the file contract element diffs related to
// the applied block.
func (au ApplyUpdate) FileContractElementDiffs() []FileContractElementDiff { return au.fces }

// V2FileContractElementDiffs returns the v2 file contract element diffs related
// to the applied block.
func (au ApplyUpdate) V2FileContractElementDiffs() []V2FileContractElementDiff { return au.v2fces }

// UpdateElementProof updates the Merkle proof of the supplied element to
// incorporate the changes made to the accumulator. The element's proof must be
// up-to-date; if it is not, UpdateElementProof may panic.
func (au ApplyUpdate) UpdateElementProof(e *types.StateElement) {
	au.eau.updateElementProof(e)
}

// ForEachTreeNode calls fn on each node in the accumulator affected by au.
func (au ApplyUpdate) ForEachTreeNode(fn func(row, col uint64, h types.Hash256)) {
	seen := make(map[[2]uint64]bool)
	forEachAppliedElement(au.sces, au.sfes, au.fces, au.v2fces, au.aes, &au.cie, func(el elementLeaf) {
		row, col := uint64(0), el.LeafIndex
		h := el.hash()
		fn(row, col, h)
		seen[[2]uint64{row, col}] = true
		for i, sibling := range el.MerkleProof {
			if el.LeafIndex&(1<<i) == 0 {
				h = blake2b.SumPair(h, sibling)
			} else {
				h = blake2b.SumPair(sibling, h)
			}
			row++
			col >>= 1
			if seen[[2]uint64{row, col}] {
				return // already seen everything above this
			}
			fn(row, col, h)
			seen[[2]uint64{row, col}] = true
		}
	})
}

// ChainIndexElement returns the chain index element for the applied block.
func (au ApplyUpdate) ChainIndexElement() types.ChainIndexElement {
	return au.cie
}

// ApplyBlock applies b to s, producing a new state and a set of effects.
func ApplyBlock(s State, b types.Block, bs V1BlockSupplement, targetTimestamp time.Time) (State, ApplyUpdate) {
	if s.Index.Height > 0 && s.Index.ID != b.ParentID {
		panic("consensus: cannot apply non-child block")
	}

	ms := NewMidState(s)
	ms.ApplyBlock(b, bs)
	s.SiafundTaxRevenue = ms.siafundTaxRevenue
	s.Attestations += uint64(len(ms.aes))
	s.FoundationSubsidyAddress = ms.foundationSubsidy
	s.FoundationManagementAddress = ms.foundationManagement

	// compute updated and added elements
	var updated, added []elementLeaf
	forEachAppliedElement(ms.sces, ms.sfes, ms.fces, ms.v2fces, ms.aes, &ms.cie, func(el elementLeaf) {
		if el.LeafIndex == types.UnassignedLeafIndex {
			added = append(added, el)
		} else {
			updated = append(updated, el)
		}
	})
	eau := s.Elements.applyBlock(updated, added)
	s = ApplyOrphan(s, b, targetTimestamp)
	return s, ApplyUpdate{ms.sces, ms.sfes, ms.fces, ms.v2fces, ms.aes, ms.cie, eau}
}

// A RevertUpdate represents the effects of reverting to a prior state. These
// are the same effects seen as when applying the block, but should be processed
// inversely. For example, if SiacoinElementDiffs reports an element with the
// Created flag set, it means the block created that element when it was
// applied; thus, when the block is reverted, the element no longer exists.
//
// Furthermore, the order of all diffs is reversed: if the block first created a
// siacoin element, then later spent it, SiacoinElementDiffs will show the
// element being spent, then later created. This simplifies diff processing.
type RevertUpdate struct {
	sces   []SiacoinElementDiff
	sfes   []SiafundElementDiff
	fces   []FileContractElementDiff
	v2fces []V2FileContractElementDiff
	aes    []types.AttestationElement
	cie    types.ChainIndexElement

	eru elementRevertUpdate
}

// SiacoinElementDiffs returns the siacoin element diffs related to the applied
// block.
func (ru RevertUpdate) SiacoinElementDiffs() []SiacoinElementDiff { return ru.sces }

// SiafundElementDiffs returns the siafund element diffs related to the applied
// block.
func (ru RevertUpdate) SiafundElementDiffs() []SiafundElementDiff { return ru.sfes }

// FileContractElementDiffs returns the file contract element diffs related to
// the applied block.
func (ru RevertUpdate) FileContractElementDiffs() []FileContractElementDiff { return ru.fces }

// V2FileContractElementDiffs returns the v2 file contract element diffs related
// to the applied block.
func (ru RevertUpdate) V2FileContractElementDiffs() []V2FileContractElementDiff { return ru.v2fces }

// UpdateElementProof updates the Merkle proof of the supplied element to
// incorporate the changes made to the accumulator. The element's proof must be
// up-to-date; if it is not, UpdateElementProof may panic.
func (ru RevertUpdate) UpdateElementProof(e *types.StateElement) {
	ru.eru.updateElementProof(e)
}

// ForEachTreeNode calls fn on each node in the accumulator affected by ru.
func (ru RevertUpdate) ForEachTreeNode(fn func(row, col uint64, h types.Hash256)) {
	seen := make(map[[2]uint64]bool)
	forEachRevertedElement(ru.sces, ru.sfes, ru.fces, ru.v2fces, func(el elementLeaf) {
		if el.LeafIndex >= ru.eru.numLeaves {
			return
		}
		row, col := uint64(0), el.LeafIndex
		h := el.hash()
		fn(row, col, h)
		seen[[2]uint64{row, col}] = true
		for i, sibling := range el.MerkleProof {
			if el.LeafIndex&(1<<i) == 0 {
				h = blake2b.SumPair(h, sibling)
			} else {
				h = blake2b.SumPair(sibling, h)
			}
			row++
			col >>= 1
			if seen[[2]uint64{row, col}] {
				return // already seen everything above this
			}
			fn(row, col, h)
			seen[[2]uint64{row, col}] = true
		}
	})
}

// RevertBlock reverts b, producing the effects undone by the block.
func RevertBlock(s State, b types.Block, bs V1BlockSupplement) RevertUpdate {
	if s.Index.ID != b.ParentID {
		panic("consensus: cannot revert non-child block")
	}
	ms := NewMidState(s)
	ms.ApplyBlock(b, bs)

	// compute updated elements
	var updated, added []elementLeaf
	forEachRevertedElement(ms.sces, ms.sfes, ms.fces, ms.v2fces, func(el elementLeaf) {
		if el.LeafIndex == types.UnassignedLeafIndex {
			added = append(added, el)
		} else {
			updated = append(updated, el)
		}
	})
	eru := s.Elements.revertBlock(updated, added)
	// Each elementLeaf points to an array index within ms, so we need to
	// duplicate before we can safely reverse in place
	for _, elems := range eru.updated {
		for i := range elems {
			se := elems[i].StateElement.Move()
			elems[i].StateElement = &se
		}
	}
	slices.Reverse(ms.sces)
	slices.Reverse(ms.sfes)
	slices.Reverse(ms.fces)
	slices.Reverse(ms.v2fces)
	return RevertUpdate{ms.sces, ms.sfes, ms.fces, ms.v2fces, ms.aes, ms.cie, eru}
}

// condensed representation of the update types for JSON marshaling
type (
	applyUpdateJSON struct {
		SiacoinElements            []SiacoinElementDiff        `json:"siacoinElements"`
		SiafundElementDiffs        []SiafundElementDiff        `json:"siafundElementDiffs"`
		FileContractElementDiffs   []FileContractElementDiff   `json:"fileContractElementDiffs"`
		V2FileContractElementDiffs []V2FileContractElementDiff `json:"v2FileContractElementDiffs"`
		AttestationElements        []types.AttestationElement  `json:"attestationElements"`
		ChainIndexElement          types.ChainIndexElement     `json:"chainIndexElement"`

		UpdatedLeaves map[int][]elementLeaf   `json:"updatedLeaves"`
		TreeGrowth    map[int][]types.Hash256 `json:"treeGrowth"`
		OldNumLeaves  uint64                  `json:"oldNumLeaves"`
		NumLeaves     uint64                  `json:"numLeaves"`
	}

	revertUpdateJSON struct {
		SiacoinElements            []SiacoinElementDiff        `json:"siacoinElements"`
		SiafundElementDiffs        []SiafundElementDiff        `json:"siafundElementDiffs"`
		FileContractElementDiffs   []FileContractElementDiff   `json:"fileContractElementDiffs"`
		V2FileContractElementDiffs []V2FileContractElementDiff `json:"v2FileContractElementDiffs"`
		AttestationElements        []types.AttestationElement  `json:"attestationElements"`
		ChainIndexElement          types.ChainIndexElement     `json:"chainIndexElement"`

		UpdatedLeaves map[int][]elementLeaf `json:"updatedLeaves"`
		NumLeaves     uint64                `json:"numLeaves"`
	}
)

// MarshalJSON implements json.Marshaler.
func (au ApplyUpdate) MarshalJSON() ([]byte, error) {
	js := applyUpdateJSON{
		SiacoinElements:            au.sces,
		SiafundElementDiffs:        au.sfes,
		FileContractElementDiffs:   au.fces,
		V2FileContractElementDiffs: au.v2fces,
		AttestationElements:        au.aes,
		ChainIndexElement:          au.cie.Share(),
	}
	js.UpdatedLeaves = make(map[int][]elementLeaf, len(au.eau.updated))
	for i, els := range au.eau.updated {
		if len(els) > 0 {
			js.UpdatedLeaves[i] = els
		}
	}
	js.TreeGrowth = make(map[int][]types.Hash256, len(au.eau.treeGrowth))
	for i, els := range au.eau.treeGrowth {
		if len(els) > 0 {
			js.TreeGrowth[i] = els
		}
	}
	js.OldNumLeaves = au.eau.oldNumLeaves
	js.NumLeaves = au.eau.numLeaves
	return json.Marshal(js)
}

// UnmarshalJSON implements json.Unmarshaler.
func (au *ApplyUpdate) UnmarshalJSON(b []byte) error {
	var js applyUpdateJSON
	if err := json.Unmarshal(b, &js); err != nil {
		return err
	}
	au.sces = js.SiacoinElements
	au.sfes = js.SiafundElementDiffs
	au.fces = js.FileContractElementDiffs
	au.v2fces = js.V2FileContractElementDiffs
	au.aes = js.AttestationElements
	au.cie = js.ChainIndexElement.Move()

	au.eau = elementApplyUpdate{
		oldNumLeaves: js.OldNumLeaves,
		numLeaves:    js.NumLeaves,
	}
	for i, els := range js.UpdatedLeaves {
		au.eau.updated[i] = els
	}
	for i, els := range js.TreeGrowth {
		au.eau.treeGrowth[i] = els
	}
	return nil
}

// MarshalJSON implements json.Marshaler.
func (ru RevertUpdate) MarshalJSON() ([]byte, error) {
	js := revertUpdateJSON{
		SiacoinElements:            ru.sces,
		SiafundElementDiffs:        ru.sfes,
		FileContractElementDiffs:   ru.fces,
		V2FileContractElementDiffs: ru.v2fces,
		AttestationElements:        ru.aes,
		ChainIndexElement:          ru.cie.Share(),
	}
	js.UpdatedLeaves = make(map[int][]elementLeaf, len(ru.eru.updated))
	for i, els := range ru.eru.updated {
		if len(els) > 0 {
			js.UpdatedLeaves[i] = els
		}
	}
	js.NumLeaves = ru.eru.numLeaves
	return json.Marshal(js)
}

// UnmarshalJSON implments json.Unmarshaler.
func (ru *RevertUpdate) UnmarshalJSON(b []byte) error {
	var js revertUpdateJSON
	if err := json.Unmarshal(b, &js); err != nil {
		return err
	}
	ru.sces = js.SiacoinElements
	ru.sfes = js.SiafundElementDiffs
	ru.fces = js.FileContractElementDiffs
	ru.v2fces = js.V2FileContractElementDiffs
	ru.aes = js.AttestationElements
	ru.cie = js.ChainIndexElement.Move()

	ru.eru = elementRevertUpdate{
		numLeaves: js.NumLeaves,
	}
	for i, els := range js.UpdatedLeaves {
		ru.eru.updated[i] = els
	}
	return nil
}
