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

func dupProof(se *types.StateElement) {
	se.MerkleProof = append([]types.Hash256(nil), se.MerkleProof...)
}

func (ms *MidState) recordSiacoinElement(id types.SiacoinOutputID) *UpdatedSiacoinElement {
	if i, ok := ms.elements[id]; ok {
		return &ms.sces[i]
	}
	ms.sces = append(ms.sces, UpdatedSiacoinElement{})
	ms.elements[id] = len(ms.sces) - 1
	return &ms.sces[len(ms.sces)-1]
}

func (ms *MidState) createSiacoinElement(id types.SiacoinOutputID, sco types.SiacoinOutput) *UpdatedSiacoinElement {
	usce := ms.recordSiacoinElement(id)
	usce.SiacoinElement = types.SiacoinElement{
		StateElement:  types.StateElement{LeafIndex: types.UnassignedLeafIndex},
		ID:            id,
		SiacoinOutput: sco,
	}
	usce.Created = true
	return usce
}

func (ms *MidState) createImmatureSiacoinElement(id types.SiacoinOutputID, sco types.SiacoinOutput) *UpdatedSiacoinElement {
	usce := ms.createSiacoinElement(id, sco)
	usce.SiacoinElement.MaturityHeight = ms.base.MaturityHeight()
	return usce
}

func (ms *MidState) spendSiacoinElement(sce types.SiacoinElement, txid types.TransactionID) {
	usce := ms.recordSiacoinElement(sce.ID)
	usce.SiacoinElement = sce
	usce.Spent = true
	dupProof(&usce.SiacoinElement.StateElement)
	ms.spends[sce.ID] = txid
}

func (ms *MidState) recordSiafundElement(id types.SiafundOutputID) *UpdatedSiafundElement {
	if i, ok := ms.elements[id]; ok {
		return &ms.sfes[i]
	}
	ms.sfes = append(ms.sfes, UpdatedSiafundElement{})
	ms.elements[id] = len(ms.sfes) - 1
	return &ms.sfes[len(ms.sfes)-1]
}

func (ms *MidState) createSiafundElement(id types.SiafundOutputID, sfo types.SiafundOutput) *UpdatedSiafundElement {
	usce := ms.recordSiafundElement(id)
	usce.SiafundElement = types.SiafundElement{
		StateElement:  types.StateElement{LeafIndex: types.UnassignedLeafIndex},
		ID:            id,
		SiafundOutput: sfo,
	}
	usce.Created = true
	return usce
}

func (ms *MidState) spendSiafundElement(sfe types.SiafundElement, txid types.TransactionID) {
	usfe := ms.recordSiafundElement(sfe.ID)
	usfe.SiafundElement = sfe
	usfe.Spent = true
	dupProof(&usfe.SiafundElement.StateElement)
	ms.spends[sfe.ID] = txid
}

func (ms *MidState) recordFileContractElement(id types.FileContractID) *UpdatedFileContractElement {
	if i, ok := ms.elements[id]; ok {
		return &ms.fces[i]
	}
	ms.fces = append(ms.fces, UpdatedFileContractElement{})
	ms.elements[id] = len(ms.fces) - 1
	return &ms.fces[len(ms.fces)-1]
}

func (ms *MidState) createFileContractElement(id types.FileContractID, fc types.FileContract) {
	ufce := ms.recordFileContractElement(id)
	ufce.FileContractElement = types.FileContractElement{
		StateElement: types.StateElement{LeafIndex: types.UnassignedLeafIndex},
		ID:           id,
		FileContract: fc,
	}
	ufce.Created = true
	ms.siafundTaxRevenue = ms.siafundTaxRevenue.Add(ms.base.FileContractTax(fc))
}

func (ms *MidState) reviseFileContractElement(fce types.FileContractElement, rev types.FileContract) {
	rev.Payout = fce.FileContract.Payout
	ufce := ms.recordFileContractElement(fce.ID)
	if ufce.Created {
		ufce.FileContractElement.FileContract = rev
	} else if ufce.Revision != nil {
		ufce.Revision.FileContract = rev
	} else {
		ufce.FileContractElement = fce
		revElement := fce
		dupProof(&revElement.StateElement)
		revElement.FileContract = rev
		ufce.Revision = &revElement
	}
}

func (ms *MidState) resolveFileContractElement(fce types.FileContractElement, valid bool, txid types.TransactionID) {
	ufce := ms.recordFileContractElement(fce.ID)
	ufce.Resolved = true
	ufce.Valid = valid
	dupProof(&fce.StateElement)
	ufce.FileContractElement = fce
	ms.spends[fce.ID] = txid
}

func (ms *MidState) recordV2FileContractElement(id types.FileContractID) *UpdatedV2FileContractElement {
	if i, ok := ms.elements[id]; ok {
		return &ms.v2fces[i]
	}
	ms.v2fces = append(ms.v2fces, UpdatedV2FileContractElement{})
	ms.elements[id] = len(ms.v2fces) - 1
	return &ms.v2fces[len(ms.v2fces)-1]
}

func (ms *MidState) createV2FileContractElement(id types.FileContractID, fc types.V2FileContract) {
	ufce := ms.recordV2FileContractElement(id)
	ufce.V2FileContractElement = types.V2FileContractElement{
		StateElement:   types.StateElement{LeafIndex: types.UnassignedLeafIndex},
		ID:             id,
		V2FileContract: fc,
	}
	ufce.Created = true
	ms.siafundTaxRevenue = ms.siafundTaxRevenue.Add(ms.base.V2FileContractTax(fc))
}

func (ms *MidState) reviseV2FileContractElement(fce types.V2FileContractElement, rev types.V2FileContract) {
	ufce := ms.recordV2FileContractElement(fce.ID)
	if ufce.Created {
		ufce.V2FileContractElement.V2FileContract = rev
	} else if ufce.Revision != nil {
		ufce.Revision.V2FileContract = rev
	} else {
		ufce.V2FileContractElement = fce
		revElement := fce
		dupProof(&revElement.StateElement)
		revElement.V2FileContract = rev
		ufce.Revision = &revElement
	}
}

func (ms *MidState) resolveV2FileContractElement(fce types.V2FileContractElement, res types.V2FileContractResolutionType, txid types.TransactionID) {
	ufce := ms.recordV2FileContractElement(fce.ID)
	if ufce.Created {
		panic("consensus: resolved a newly-created v2 contract")
	} else {
		ufce.Resolution = res
		dupProof(&fce.StateElement)
		ufce.V2FileContractElement = fce
	}
	ms.spends[fce.ID] = txid
}

func (ms *MidState) createAttestationElement(ae types.AttestationElement) {
	ms.aes = append(ms.aes, ae)
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
		ms.spendSiacoinElement(sce, txid)
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
		ms.spendSiafundElement(sfe, txid)
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
		ms.reviseFileContractElement(fce, fcr.FileContract)
	}
	for _, sp := range txn.StorageProofs {
		fce, ok := ms.fileContractElement(ts, sp.ParentID)
		if !ok {
			panic("missing V1StorageProofSupplement")
		}
		ms.resolveFileContractElement(fce, true, txid)
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
		ms.spendSiacoinElement(sci.Parent, txid)
	}
	for i, sco := range txn.SiacoinOutputs {
		ms.createSiacoinElement(txn.SiacoinOutputID(txid, i), sco)
	}
	for _, sfi := range txn.SiafundInputs {
		ms.spendSiafundElement(sfi.Parent, txid)
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
		ms.reviseV2FileContractElement(fcr.Parent, fcr.Revision)
	}
	for _, fcr := range txn.FileContractResolutions {
		ms.resolveV2FileContractElement(fcr.Parent, fcr.Resolution, txid)

		fce := fcr.Parent
		fc := fce.V2FileContract
		var renter, host types.SiacoinOutput
		switch r := fcr.Resolution.(type) {
		case *types.V2FileContractRenewal:
			renter, host = r.FinalRenterOutput, r.FinalHostOutput
			ms.createV2FileContractElement(fce.ID.V2RenewalID(), r.NewContract)
		case *types.V2StorageProof:
			renter, host = fc.RenterOutput, fc.HostOutput
		case *types.V2FileContractExpiration:
			renter, host = fc.RenterOutput, fc.MissedHostOutput()
		default:
			panic(fmt.Sprintf("unhandled resolution type %T", r))
		}
		ms.createImmatureSiacoinElement(fce.ID.V2RenterOutputID(), renter)
		ms.createImmatureSiacoinElement(fce.ID.V2HostOutputID(), host)
	}
	for i, a := range txn.Attestations {
		ms.createAttestationElement(types.AttestationElement{
			StateElement: types.StateElement{LeafIndex: types.UnassignedLeafIndex},
			ID:           txn.AttestationID(txid, i),
			Attestation:  a,
		})
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
		ms.resolveFileContractElement(fce, false, types.TransactionID(bid))
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

func (ms *MidState) forEachAppliedElement(fn func(elementLeaf)) {
	for i := range ms.sces {
		sce := &ms.sces[i]
		fn(siacoinLeaf(&sce.SiacoinElement, ms.isSpent(sce.SiacoinElement.ID)))
	}
	for i := range ms.sfes {
		sfe := &ms.sfes[i]
		fn(siafundLeaf(&sfe.SiafundElement, ms.isSpent(sfe.SiafundElement.ID)))
	}
	for i := range ms.fces {
		fce := &ms.fces[i]
		if fce.Revision != nil {
			fn(fileContractLeaf(fce.Revision, ms.isSpent(fce.FileContractElement.ID)))
		} else {
			fn(fileContractLeaf(&fce.FileContractElement, ms.isSpent(fce.FileContractElement.ID)))
		}
	}
	for i := range ms.v2fces {
		v2fce := &ms.v2fces[i]
		if v2fce.Revision != nil {
			fn(v2FileContractLeaf(v2fce.Revision, ms.isSpent(v2fce.V2FileContractElement.ID)))
		} else {
			fn(v2FileContractLeaf(&v2fce.V2FileContractElement, ms.isSpent(v2fce.V2FileContractElement.ID)))
		}
		// NOTE: Although it is an element, we do not process the ProofIndex
		// field of V2StorageProofs. These are a special case, as they are not
		// being updated (like e.g. siacoin inputs), nor are they being created
		// (like e.g. attestations). In other words, they have no effect on the
		// accumulator, and thus including them would only cause confusion.
	}
	for i := range ms.aes {
		fn(attestationLeaf(&ms.aes[i]))
	}
	fn(chainIndexLeaf(&ms.cie))
}

func (ms *MidState) forEachRevertedElement(fn func(elementLeaf)) {
	for i := range ms.sces {
		fn(siacoinLeaf(&ms.sces[i].SiacoinElement, false))
	}
	for i := range ms.sfes {
		fn(siafundLeaf(&ms.sfes[i].SiafundElement, false))
	}
	for i := range ms.fces {
		fn(fileContractLeaf(&ms.fces[i].FileContractElement, false))
	}
	for i := range ms.v2fces {
		fn(v2FileContractLeaf(&ms.v2fces[i].V2FileContractElement, false))
	}
}

// An ApplyUpdate represents the effects of applying a block to a state.
type ApplyUpdate struct {
	ms  *MidState
	eau elementApplyUpdate
}

// SiacoinElements returns the siacoin elements related to the applied block.
func (au ApplyUpdate) SiacoinElements() []UpdatedSiacoinElement { return au.ms.sces }

// SiafundElements returns the siafund elements related to the applied block.
func (au ApplyUpdate) SiafundElements() []UpdatedSiafundElement { return au.ms.sfes }

// FileContractElements returns the file contract elements related to the
// applied block.
func (au ApplyUpdate) FileContractElements() []UpdatedFileContractElement { return au.ms.fces }

// V2FileContractElements returns the v2 file contract elements related to the
// applied block.
func (au ApplyUpdate) V2FileContractElements() []UpdatedV2FileContractElement { return au.ms.v2fces }

// UpdateElementProof updates the Merkle proof of the supplied element to
// incorporate the changes made to the accumulator. The element's proof must be
// up-to-date; if it is not, UpdateElementProof may panic.
func (au ApplyUpdate) UpdateElementProof(e *types.StateElement) {
	au.eau.updateElementProof(e)
}

// ForEachSiacoinElement calls fn on each siacoin element related to the applied
// block.
//
// Deprecated: Use SiacoinElements instead.
func (au ApplyUpdate) ForEachSiacoinElement(fn func(sce types.SiacoinElement, created, spent bool)) {
	for _, sce := range au.ms.sces {
		fn(sce.SiacoinElement, sce.Created, sce.Spent)
	}
}

// ForEachSiafundElement calls fn on each siafund element related to the applied
// block.
//
// Deprecated: Use SiafundElements instead.
func (au ApplyUpdate) ForEachSiafundElement(fn func(sfe types.SiafundElement, created, spent bool)) {
	for _, sfe := range au.ms.sfes {
		fn(sfe.SiafundElement, sfe.Created, sfe.Spent)
	}
}

// ForEachFileContractElement calls fn on each file contract element related to
// the applied block.
//
// Deprecated: Use FileContractElements instead.
func (au ApplyUpdate) ForEachFileContractElement(fn func(fce types.FileContractElement, created bool, rev *types.FileContractElement, resolved, valid bool)) {
	for _, fce := range au.ms.fces {
		fn(fce.FileContractElement, fce.Created, fce.Revision, fce.Resolved, fce.Valid)
	}
}

// ForEachV2FileContractElement calls fn on each v2 file contract element
// related to the applied block.
//
// Deprecated: Use V2FileContractElements instead.
func (au ApplyUpdate) ForEachV2FileContractElement(fn func(fce types.V2FileContractElement, created bool, rev *types.V2FileContractElement, res types.V2FileContractResolutionType)) {
	for _, fce := range au.ms.v2fces {
		fn(fce.V2FileContractElement, fce.Created, fce.Revision, fce.Resolution)
	}
}

// ForEachTreeNode calls fn on each node in the accumulator affected by au.
func (au ApplyUpdate) ForEachTreeNode(fn func(row, col uint64, h types.Hash256)) {
	seen := make(map[[2]uint64]bool)
	au.ms.forEachAppliedElement(func(el elementLeaf) {
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
	cie := au.ms.cie
	dupProof(&cie.StateElement)
	return cie
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
	ms.forEachAppliedElement(func(el elementLeaf) {
		if el.LeafIndex == types.UnassignedLeafIndex {
			added = append(added, el)
		} else {
			updated = append(updated, el)
		}
	})
	eau := s.Elements.applyBlock(updated, added)
	s = ApplyOrphan(s, b, targetTimestamp)
	return s, ApplyUpdate{ms, eau}
}

// A RevertUpdate represents the effects of reverting to a prior state. These
// are the same effects seen as when applying the block, but should be processed
// inversely. For example, if ForEachSiacoinElement reports an element with the
// created flag set, it means the block created that element when it was
// applied; thus, when the block is reverted, the element no longer exists.
type RevertUpdate struct {
	ms  *MidState
	eru elementRevertUpdate
}

// SiacoinElements returns the siacoin elements related to the applied block.
func (ru RevertUpdate) SiacoinElements() []UpdatedSiacoinElement { return ru.ms.sces }

// SiafundElements returns the siafund elements related to the applied block.
func (ru RevertUpdate) SiafundElements() []UpdatedSiafundElement { return ru.ms.sfes }

// FileContractElements returns the file contract elements related to the
// applied block.
func (ru RevertUpdate) FileContractElements() []UpdatedFileContractElement { return ru.ms.fces }

// V2FileContractElements returns the v2 file contract elements related to the
// applied block.
func (ru RevertUpdate) V2FileContractElements() []UpdatedV2FileContractElement { return ru.ms.v2fces }

// UpdateElementProof updates the Merkle proof of the supplied element to
// incorporate the changes made to the accumulator. The element's proof must be
// up-to-date; if it is not, UpdateElementProof may panic.
func (ru RevertUpdate) UpdateElementProof(e *types.StateElement) {
	ru.eru.updateElementProof(e)
}

// ForEachSiacoinElement calls fn on each siacoin element related to the reverted
// block.
//
// Deprecated: Use SiacoinElements instead.
func (ru RevertUpdate) ForEachSiacoinElement(fn func(sce types.SiacoinElement, created, spent bool)) {
	for _, sce := range ru.ms.sces {
		fn(sce.SiacoinElement, sce.Created, sce.Spent)
	}
}

// ForEachSiafundElement calls fn on each siafund element related to the
// reverted block.
//
// Deprecated: Use SiafundElements instead.
func (ru RevertUpdate) ForEachSiafundElement(fn func(sfe types.SiafundElement, created, spent bool)) {
	for _, sfe := range ru.ms.sfes {
		fn(sfe.SiafundElement, sfe.Created, sfe.Spent)
	}
}

// ForEachFileContractElement calls fn on each file contract element related to
// the reverted block.
//
// Deprecated: Use FileContractElements instead.
func (ru RevertUpdate) ForEachFileContractElement(fn func(fce types.FileContractElement, created bool, rev *types.FileContractElement, resolved, valid bool)) {
	for _, fce := range ru.ms.fces {
		fn(fce.FileContractElement, fce.Created, fce.Revision, fce.Resolved, fce.Valid)
	}
}

// ForEachV2FileContractElement calls fn on each v2 file contract element
// related to the reverted block.
//
// Deprecated: Use V2FileContractElements instead.
func (ru RevertUpdate) ForEachV2FileContractElement(fn func(fce types.V2FileContractElement, created bool, rev *types.V2FileContractElement, res types.V2FileContractResolutionType)) {
	for _, fce := range ru.ms.v2fces {
		fn(fce.V2FileContractElement, fce.Created, fce.Revision, fce.Resolution)
	}
}

// ForEachTreeNode calls fn on each node in the accumulator affected by ru.
func (ru RevertUpdate) ForEachTreeNode(fn func(row, col uint64, h types.Hash256)) {
	seen := make(map[[2]uint64]bool)
	ru.ms.forEachRevertedElement(func(el elementLeaf) {
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
	ms.forEachRevertedElement(func(el elementLeaf) {
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
			se := *elems[i].StateElement
			elems[i].StateElement = &se
		}
	}
	slices.Reverse(ms.sces)
	slices.Reverse(ms.sfes)
	slices.Reverse(ms.fces)
	slices.Reverse(ms.v2fces)
	return RevertUpdate{ms, eru}
}

// condensed representation of the update types for JSON marshaling
type (
	applyUpdateJSON struct {
		SiacoinElements        []UpdatedSiacoinElement        `json:"siacoinElements"`
		SiafundElements        []UpdatedSiafundElement        `json:"siafundElements"`
		FileContractElements   []UpdatedFileContractElement   `json:"fileContractElements"`
		V2FileContractElements []UpdatedV2FileContractElement `json:"v2FileContractElements"`
		AttestationElements    []types.AttestationElement     `json:"attestationElements"`
		ChainIndexElement      types.ChainIndexElement        `json:"chainIndexElement"`

		UpdatedLeaves map[int][]elementLeaf   `json:"updatedLeaves"`
		TreeGrowth    map[int][]types.Hash256 `json:"treeGrowth"`
		OldNumLeaves  uint64                  `json:"oldNumLeaves"`
		NumLeaves     uint64                  `json:"numLeaves"`
	}

	revertUpdateJSON struct {
		SiacoinElements        []UpdatedSiacoinElement        `json:"siacoinElements"`
		SiafundElements        []UpdatedSiafundElement        `json:"siafundElements"`
		FileContractElements   []UpdatedFileContractElement   `json:"fileContractElements"`
		V2FileContractElements []UpdatedV2FileContractElement `json:"v2FileContractElements"`
		AttestationElements    []types.AttestationElement     `json:"attestationElements"`
		ChainIndexElement      types.ChainIndexElement        `json:"chainIndexElement"`

		UpdatedLeaves map[int][]elementLeaf `json:"updatedLeaves"`
		NumLeaves     uint64                `json:"numLeaves"`
	}
)

// MarshalJSON implements json.Marshaler.
func (au ApplyUpdate) MarshalJSON() ([]byte, error) {
	js := applyUpdateJSON{
		SiacoinElements:        au.ms.sces,
		SiafundElements:        au.ms.sfes,
		FileContractElements:   au.ms.fces,
		V2FileContractElements: au.ms.v2fces,
		AttestationElements:    au.ms.aes,
		ChainIndexElement:      au.ms.cie,
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
	au.ms = NewMidState(State{})
	au.ms.sces = js.SiacoinElements
	au.ms.sfes = js.SiafundElements
	au.ms.fces = js.FileContractElements
	au.ms.v2fces = js.V2FileContractElements
	au.ms.aes = js.AttestationElements
	au.ms.cie = js.ChainIndexElement

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
		SiacoinElements:        ru.ms.sces,
		SiafundElements:        ru.ms.sfes,
		FileContractElements:   ru.ms.fces,
		V2FileContractElements: ru.ms.v2fces,
		AttestationElements:    ru.ms.aes,
		ChainIndexElement:      ru.ms.cie,
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
	ru.ms = NewMidState(State{})
	ru.ms.sces = js.SiacoinElements
	ru.ms.sfes = js.SiafundElements
	ru.ms.fces = js.FileContractElements
	ru.ms.v2fces = js.V2FileContractElements
	ru.ms.aes = js.AttestationElements
	ru.ms.cie = js.ChainIndexElement

	ru.eru = elementRevertUpdate{
		numLeaves: js.NumLeaves,
	}
	for i, els := range js.UpdatedLeaves {
		ru.eru.updated[i] = els
	}
	return nil
}
