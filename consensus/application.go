package consensus

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"
	"math/bits"
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

func (ms *MidState) addSiacoinElement(id types.SiacoinOutputID, sco types.SiacoinOutput) {
	sce := types.SiacoinElement{
		StateElement:  types.StateElement{LeafIndex: types.UnassignedLeafIndex},
		ID:            id,
		SiacoinOutput: sco,
	}
	ms.sces = append(ms.sces, sce)
	ms.created[ms.sces[len(ms.sces)-1].ID] = len(ms.sces) - 1
}

func (ms *MidState) addImmatureSiacoinElement(id types.SiacoinOutputID, sco types.SiacoinOutput) {
	ms.addSiacoinElement(id, sco)
	ms.sces[len(ms.sces)-1].MaturityHeight = ms.base.MaturityHeight()
}

func (ms *MidState) spendSiacoinElement(sce types.SiacoinElement, txid types.TransactionID) {
	ms.spends[sce.ID] = txid
	if !ms.isCreated(sce.ID) {
		dupProof(&sce.StateElement)
		ms.sces = append(ms.sces, sce)
	}
}

func (ms *MidState) addSiafundElement(id types.SiafundOutputID, sfo types.SiafundOutput) {
	sfe := types.SiafundElement{
		StateElement:  types.StateElement{LeafIndex: types.UnassignedLeafIndex},
		ID:            id,
		SiafundOutput: sfo,
		ClaimStart:    ms.siafundTaxRevenue,
	}
	ms.sfes = append(ms.sfes, sfe)
	ms.created[ms.sfes[len(ms.sfes)-1].ID] = len(ms.sfes) - 1
}

func (ms *MidState) spendSiafundElement(sfe types.SiafundElement, txid types.TransactionID) {
	ms.spends[sfe.ID] = txid
	if !ms.isCreated(sfe.ID) {
		dupProof(&sfe.StateElement)
		ms.sfes = append(ms.sfes, sfe)
	}
}

func (ms *MidState) addFileContractElement(id types.FileContractID, fc types.FileContract) {
	fce := types.FileContractElement{
		StateElement: types.StateElement{LeafIndex: types.UnassignedLeafIndex},
		ID:           id,
		FileContract: fc,
	}
	ms.fces = append(ms.fces, fce)
	ms.created[ms.fces[len(ms.fces)-1].ID] = len(ms.fces) - 1
	ms.siafundTaxRevenue = ms.siafundTaxRevenue.Add(ms.base.FileContractTax(fce.FileContract))
}

func (ms *MidState) reviseFileContractElement(fce types.FileContractElement, rev types.FileContract) {
	rev.Payout = fce.FileContract.Payout
	if i, ok := ms.created[fce.ID]; ok {
		ms.fces[i].FileContract = rev
	} else {
		if r, ok := ms.revs[fce.ID]; ok {
			r.FileContract = rev
		} else {
			// store the original
			dupProof(&fce.StateElement)
			ms.fces = append(ms.fces, fce)
			// store the revision
			dupProof(&fce.StateElement)
			fce.FileContract = rev
			ms.revs[fce.ID] = &fce
		}
	}
}

func (ms *MidState) resolveFileContractElement(fce types.FileContractElement, valid bool, txid types.TransactionID) {
	ms.res[fce.ID] = valid
	ms.spends[fce.ID] = txid
	dupProof(&fce.StateElement)
	ms.fces = append(ms.fces, fce)
}

func (ms *MidState) addV2FileContractElement(id types.FileContractID, fc types.V2FileContract) {
	fce := types.V2FileContractElement{
		StateElement:   types.StateElement{LeafIndex: types.UnassignedLeafIndex},
		ID:             id,
		V2FileContract: fc,
	}
	ms.v2fces = append(ms.v2fces, fce)
	ms.created[ms.v2fces[len(ms.v2fces)-1].ID] = len(ms.v2fces) - 1
	ms.siafundTaxRevenue = ms.siafundTaxRevenue.Add(ms.base.V2FileContractTax(fce.V2FileContract))
}

func (ms *MidState) reviseV2FileContractElement(fce types.V2FileContractElement, rev types.V2FileContract) {
	if i, ok := ms.created[fce.ID]; ok {
		ms.v2fces[i].V2FileContract = rev
	} else {
		if r, ok := ms.v2revs[fce.ID]; ok {
			r.V2FileContract = rev
		} else {
			// store the original
			dupProof(&fce.StateElement)
			ms.v2fces = append(ms.v2fces, fce)
			// store the revision
			dupProof(&fce.StateElement)
			fce.V2FileContract = rev
			ms.v2revs[fce.ID] = &fce
		}
	}
}

func (ms *MidState) resolveV2FileContractElement(fce types.V2FileContractElement, res types.V2FileContractResolutionType, txid types.TransactionID) {
	ms.v2res[fce.ID] = res
	ms.spends[fce.ID] = txid
	dupProof(&fce.StateElement)
	ms.v2fces = append(ms.v2fces, fce)
}

func (ms *MidState) addAttestationElement(ae types.AttestationElement) {
	ms.aes = append(ms.aes, ae)
	ms.created[ms.aes[len(ms.aes)-1].ID] = len(ms.aes) - 1
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
		ms.addSiacoinElement(txn.SiacoinOutputID(i), sco)
	}
	for _, sfi := range txn.SiafundInputs {
		sfe, ok := ms.siafundElement(ts, sfi.ParentID)
		if !ok {
			panic("missing SiafundElement")
		}
		claimPortion := ms.siafundTaxRevenue.Sub(sfe.ClaimStart).Div64(ms.base.SiafundCount()).Mul64(sfe.SiafundOutput.Value)
		ms.spendSiafundElement(sfe, txid)
		ms.addImmatureSiacoinElement(sfi.ParentID.ClaimOutputID(), types.SiacoinOutput{Value: claimPortion, Address: sfi.ClaimAddress})
	}
	for i, sfo := range txn.SiafundOutputs {
		ms.addSiafundElement(txn.SiafundOutputID(i), sfo)
	}
	for i, fc := range txn.FileContracts {
		ms.addFileContractElement(txn.FileContractID(i), fc)
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
			ms.addImmatureSiacoinElement(sp.ParentID.ValidOutputID(i), sco)
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
		ms.addSiacoinElement(txn.SiacoinOutputID(txid, i), sco)
	}
	for _, sfi := range txn.SiafundInputs {
		ms.spendSiafundElement(sfi.Parent, txid)
		claimPortion := ms.siafundTaxRevenue.Sub(sfi.Parent.ClaimStart).Div64(ms.base.SiafundCount()).Mul64(sfi.Parent.SiafundOutput.Value)
		ms.addImmatureSiacoinElement(sfi.Parent.ID.V2ClaimOutputID(), types.SiacoinOutput{Value: claimPortion, Address: sfi.ClaimAddress})
	}
	for i, sfo := range txn.SiafundOutputs {
		ms.addSiafundElement(txn.SiafundOutputID(txid, i), sfo)
	}
	for i, fc := range txn.FileContracts {
		ms.addV2FileContractElement(txn.V2FileContractID(txid, i), fc)
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
			ms.addV2FileContractElement(fce.ID.V2RenewalID(), r.NewContract)
		case *types.V2StorageProof:
			renter, host = fc.RenterOutput, fc.HostOutput
		case *types.V2FileContractExpiration:
			renter, host = fc.RenterOutput, fc.MissedHostOutput()
		}
		ms.addImmatureSiacoinElement(fce.ID.V2RenterOutputID(), renter)
		ms.addImmatureSiacoinElement(fce.ID.V2HostOutputID(), host)
	}
	for i, a := range txn.Attestations {
		ms.addAttestationElement(types.AttestationElement{
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
		ms.addImmatureSiacoinElement(bid.MinerOutputID(i), sco)
	}
	if subsidy, ok := ms.base.FoundationSubsidy(); ok {
		ms.addImmatureSiacoinElement(bid.FoundationOutputID(), subsidy)
	}
	for _, fce := range bs.ExpiringFileContracts {
		if ms.isSpent(fce.ID) {
			continue
		}
		ms.resolveFileContractElement(fce, false, types.TransactionID(bid))
		for i, sco := range fce.FileContract.MissedProofOutputs {
			ms.addImmatureSiacoinElement(fce.ID.MissedOutputID(i), sco)
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
		fn(siacoinLeaf(&ms.sces[i], ms.isSpent(ms.sces[i].ID)))
	}
	for i := range ms.sfes {
		fn(siafundLeaf(&ms.sfes[i], ms.isSpent(ms.sfes[i].ID)))
	}
	for i := range ms.fces {
		if r, ok := ms.revs[ms.fces[i].ID]; ok {
			fn(fileContractLeaf(r, ms.isSpent(ms.fces[i].ID)))
		} else {
			fn(fileContractLeaf(&ms.fces[i], ms.isSpent(ms.fces[i].ID)))
		}
	}
	for i := range ms.v2fces {
		if r, ok := ms.v2revs[ms.v2fces[i].ID]; ok {
			fn(v2FileContractLeaf(r, ms.isSpent(ms.v2fces[i].ID)))
		} else {
			fn(v2FileContractLeaf(&ms.v2fces[i], ms.isSpent(ms.v2fces[i].ID)))
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
		fn(siacoinLeaf(&ms.sces[i], false))
	}
	for i := range ms.sfes {
		fn(siafundLeaf(&ms.sfes[i], false))
	}
	for i := range ms.fces {
		fn(fileContractLeaf(&ms.fces[i], false))
	}
	for i := range ms.v2fces {
		fn(v2FileContractLeaf(&ms.v2fces[i], false))
	}
}

// An ApplyUpdate represents the effects of applying a block to a state.
type ApplyUpdate struct {
	ms  *MidState
	eau elementApplyUpdate
}

// UpdateElementProof updates the Merkle proof of the supplied element to
// incorporate the changes made to the accumulator. The element's proof must be
// up-to-date; if it is not, UpdateElementProof may panic.
func (au ApplyUpdate) UpdateElementProof(e *types.StateElement) {
	au.eau.updateElementProof(e)
}

// ForEachSiacoinElement calls fn on each siacoin element related to the applied
// block. The created and spent flags indicate whether the element was newly
// created in the block and/or spent in the block. Note that an element may be
// both created and spent in the the same block.
func (au ApplyUpdate) ForEachSiacoinElement(fn func(sce types.SiacoinElement, created, spent bool)) {
	for _, sce := range au.ms.sces {
		fn(sce, au.ms.isCreated(sce.ID), au.ms.isSpent(sce.ID))
	}
}

// ForEachSiafundElement calls fn on each siafund element related to the applied
// block. The created and spent flags indicate whether the element was newly
// created in the block and/or spent in the block. Note that an element may be
// both created and spent in the the same block.
func (au ApplyUpdate) ForEachSiafundElement(fn func(sfe types.SiafundElement, created, spent bool)) {
	for _, sfe := range au.ms.sfes {
		fn(sfe, au.ms.isCreated(sfe.ID), au.ms.isSpent(sfe.ID))
	}
}

// ForEachFileContractElement calls fn on each file contract element related to
// the applied block. The created flag indicates whether the contract was newly
// created. If the contract was revised, rev is non-nil and represents the state
// of the element post-application. If the block revised the contract multiple
// times, rev is the revision with the highest revision number. The resolved and
// valid flags indicate whether the contract was resolved, and if so, whether it
// was resolved via storage proof. Note that a contract may be created, revised,
// and resolved all within the same block.
func (au ApplyUpdate) ForEachFileContractElement(fn func(fce types.FileContractElement, created bool, rev *types.FileContractElement, resolved, valid bool)) {
	for _, fce := range au.ms.fces {
		fn(fce, au.ms.isCreated(fce.ID), au.ms.revs[fce.ID], au.ms.isSpent(fce.ID), au.ms.res[fce.ID])
	}
}

// ForEachV2FileContractElement calls fn on each v2 file contract element
// related to the applied block. The created flag indicates whether the contract
// was newly created. If the contract was revised, rev is non-nil and represents
// the state of the element post-application. If the block revised the contract
// multiple times, rev is the revision with the highest revision number. The
// resolved and valid flags indicate whether the contract was resolved, and if
// so, whether it was resolved via storage proof. Note that, within a block, a
// contract may be created and revised, or revised and resolved, but not created
// and resolved.
func (au ApplyUpdate) ForEachV2FileContractElement(fn func(fce types.V2FileContractElement, created bool, rev *types.V2FileContractElement, res types.V2FileContractResolutionType)) {
	for _, fce := range au.ms.v2fces {
		fn(fce, au.ms.isCreated(fce.ID), au.ms.v2revs[fce.ID], au.ms.v2res[fce.ID])
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

// UpdateElementProof updates the Merkle proof of the supplied element to
// incorporate the changes made to the accumulator. The element's proof must be
// up-to-date; if it is not, UpdateElementProof may panic.
func (ru RevertUpdate) UpdateElementProof(e *types.StateElement) {
	ru.eru.updateElementProof(e)
}

// ForEachSiacoinElement calls fn on each siacoin element related to the reverted
// block. The created and spent flags indicate whether the element was newly
// created in the block and/or spent in the block. Note that an element may be
// both created and spent in the the same block.
func (ru RevertUpdate) ForEachSiacoinElement(fn func(sce types.SiacoinElement, created, spent bool)) {
	for i := range ru.ms.sces {
		sce := ru.ms.sces[len(ru.ms.sces)-i-1]
		fn(sce, ru.ms.isCreated(sce.ID), ru.ms.isSpent(sce.ID))
	}
}

// ForEachSiafundElement calls fn on each siafund element related to the
// reverted block. The created and spent flags indicate whether the element was
// newly created in the block and/or spent in the block. Note that an element
// may be both created and spent in the the same block.
func (ru RevertUpdate) ForEachSiafundElement(fn func(sfe types.SiafundElement, created, spent bool)) {
	for i := range ru.ms.sfes {
		sfe := ru.ms.sfes[len(ru.ms.sfes)-i-1]
		fn(sfe, ru.ms.isCreated(sfe.ID), ru.ms.isSpent(sfe.ID))
	}
}

// ForEachFileContractElement calls fn on each file contract element related to
// the reverted block. The created flag indicates whether the contract was newly
// created. If the contract was revised, rev is non-nil and represents the state
// of the element post-application. If the block revised the contract multiple
// times, rev is the revision with the highest revision number. The resolved and
// valid flags indicate whether the contract was resolved, and if so, whether it
// was resolved via storage proof. Note that a contract may be created, revised,
// and resolved all within the same block.
func (ru RevertUpdate) ForEachFileContractElement(fn func(fce types.FileContractElement, created bool, rev *types.FileContractElement, resolved, valid bool)) {
	for i := range ru.ms.fces {
		fce := ru.ms.fces[len(ru.ms.fces)-i-1]
		fn(fce, ru.ms.isCreated(fce.ID), ru.ms.revs[fce.ID], ru.ms.isSpent(fce.ID), ru.ms.res[fce.ID])
	}
}

// ForEachV2FileContractElement calls fn on each v2 file contract element
// related to the reverted block. The created flag indicates whether the
// contract was newly created. If the contract was revised, rev is non-nil and
// represents the state of the element post-application. If the block revised
// the contract multiple times, rev is the revision with the highest revision
// number. The resolved and valid flags indicate whether the contract was
// resolved, and if so, whether it was resolved via storage proof. Note that,
// within a block, a contract may be created and revised, or revised and
// resolved, but not created and resolved.
func (ru RevertUpdate) ForEachV2FileContractElement(fn func(fce types.V2FileContractElement, created bool, rev *types.V2FileContractElement, res types.V2FileContractResolutionType)) {
	for i := range ru.ms.v2fces {
		fce := ru.ms.v2fces[len(ru.ms.v2fces)-i-1]
		fn(fce, ru.ms.isCreated(fce.ID), ru.ms.v2revs[fce.ID], ru.ms.v2res[fce.ID])
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
	return RevertUpdate{ms, eru}
}

// condensed representation of the update types for JSON marshaling
type (
	applyUpdateJSON struct {
		Created                []types.Hash256                                             `json:"created"`
		Spent                  []types.Hash256                                             `json:"spent"`
		ValidProof             []types.FileContractID                                      `json:"validProof"`
		MissedProof            []types.FileContractID                                      `json:"missedProof"`
		Revisions              []types.FileContractElement                                 `json:"revisions"`
		V2Revisions            []types.V2FileContractElement                               `json:"v2Revisions"`
		V2Resolutions          map[types.FileContractID]types.V2FileContractResolutionType `json:"v2Resolutions"`
		SiacoinElements        []types.SiacoinElement                                      `json:"siacoinElements"`
		SiafundElements        []types.SiafundElement                                      `json:"siafundElements"`
		FileContractElements   []types.FileContractElement                                 `json:"fileContractElements"`
		V2FileContractElements []types.V2FileContractElement                               `json:"v2FileContractElements"`
		AttestationElements    []types.AttestationElement                                  `json:"attestationElements"`
		ChainIndexElement      types.ChainIndexElement                                     `json:"chainIndexElement"`

		UpdatedLeaves map[int][]elementLeaf   `json:"updatedLeaves"`
		TreeGrowth    map[int][]types.Hash256 `json:"treeGrowth"`
		OldNumLeaves  uint64                  `json:"oldNumLeaves"`
		NumLeaves     uint64                  `json:"numLeaves"`
	}

	revertUpdateJSON struct {
		Created                []types.Hash256                                             `json:"created"`
		Spent                  []types.Hash256                                             `json:"spent"`
		ValidProof             []types.FileContractID                                      `json:"validProof"`
		MissedProof            []types.FileContractID                                      `json:"missedProof"`
		Revisions              []types.FileContractElement                                 `json:"revisions"`
		V2Revisions            []types.V2FileContractElement                               `json:"v2Revisions"`
		V2Resolutions          map[types.FileContractID]types.V2FileContractResolutionType `json:"v2Resolutions"`
		SiacoinElements        []types.SiacoinElement                                      `json:"siacoinElements"`
		SiafundElements        []types.SiafundElement                                      `json:"siafundElements"`
		FileContractElements   []types.FileContractElement                                 `json:"fileContractElements"`
		V2FileContractElements []types.V2FileContractElement                               `json:"v2FileContractElements"`
		AttestationElements    []types.AttestationElement                                  `json:"attestationElements"`
		ChainIndexElement      types.ChainIndexElement                                     `json:"chainIndexElement"`

		UpdatedLeaves map[int][]elementLeaf `json:"updatedLeaves"`
		NumLeaves     uint64                `json:"numLeaves"`
	}
)

// MarshalJSON implements json.Marshaler.
func (au ApplyUpdate) MarshalJSON() ([]byte, error) {
	js := applyUpdateJSON{
		V2Resolutions:          au.ms.v2res,
		SiacoinElements:        au.ms.sces,
		SiafundElements:        au.ms.sfes,
		FileContractElements:   au.ms.fces,
		V2FileContractElements: au.ms.v2fces,
		AttestationElements:    au.ms.aes,
		ChainIndexElement:      au.ms.cie,
	}
	for id := range au.ms.created {
		js.Created = append(js.Created, id)
	}
	for id := range au.ms.spends {
		js.Spent = append(js.Spent, id)
	}
	for id, valid := range au.ms.res {
		if valid {
			js.ValidProof = append(js.ValidProof, id)
		} else {
			js.MissedProof = append(js.MissedProof, id)
		}
	}
	for _, fce := range au.ms.revs {
		js.Revisions = append(js.Revisions, *fce)
	}
	for _, v2fce := range au.ms.v2revs {
		js.V2Revisions = append(js.V2Revisions, *v2fce)
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
	for _, id := range js.Created {
		au.ms.created[id] = 0 // value doesn't matter, just need an entry
	}
	for _, id := range js.Spent {
		au.ms.spends[id] = types.TransactionID{} // value doesn't matter, just need an entry
	}
	for _, id := range js.ValidProof {
		au.ms.res[id] = true
	}
	for _, id := range js.MissedProof {
		au.ms.res[id] = false
	}
	for _, fce := range js.Revisions {
		au.ms.revs[fce.ID] = &fce
	}
	for _, v2fce := range js.V2Revisions {
		au.ms.v2revs[v2fce.ID] = &v2fce
	}
	au.ms.v2res = js.V2Resolutions
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
		V2Resolutions:          ru.ms.v2res,
		SiacoinElements:        ru.ms.sces,
		SiafundElements:        ru.ms.sfes,
		FileContractElements:   ru.ms.fces,
		V2FileContractElements: ru.ms.v2fces,
		AttestationElements:    ru.ms.aes,
		ChainIndexElement:      ru.ms.cie,
	}
	for id := range ru.ms.created {
		js.Created = append(js.Created, id)
	}
	for id := range ru.ms.spends {
		js.Spent = append(js.Spent, id)
	}
	for id, valid := range ru.ms.res {
		if valid {
			js.ValidProof = append(js.ValidProof, id)
		} else {
			js.MissedProof = append(js.MissedProof, id)
		}
	}
	for _, fce := range ru.ms.revs {
		js.Revisions = append(js.Revisions, *fce)
	}
	for _, v2fce := range ru.ms.v2revs {
		js.V2Revisions = append(js.V2Revisions, *v2fce)
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
	for _, id := range js.Created {
		ru.ms.created[id] = 0 // value doesn't matter, just need an entry
	}
	for _, id := range js.Spent {
		ru.ms.spends[id] = types.TransactionID{} // value doesn't matter, just need an entry
	}
	for _, id := range js.ValidProof {
		ru.ms.res[id] = true
	}
	for _, id := range js.MissedProof {
		ru.ms.res[id] = false
	}
	for _, fce := range js.Revisions {
		ru.ms.revs[fce.ID] = &fce
	}
	for _, v2fce := range js.V2Revisions {
		ru.ms.v2revs[v2fce.ID] = &v2fce
	}
	ru.ms.v2res = js.V2Resolutions
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
