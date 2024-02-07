package consensus

import (
	"bytes"
	"encoding/binary"
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
	if min := blockInterval / 3; targetBlockTime < min {
		targetBlockTime = min
	} else if max := blockInterval * 3; targetBlockTime > max {
		targetBlockTime = max
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
	min := mulTargetFrac(s.ChildTarget, 1004, 1000)
	max := mulTargetFrac(s.ChildTarget, 1000, 1004)
	if newTarget.CmpWork(min) < 0 {
		newTarget = min
	} else if newTarget.CmpWork(max) > 0 {
		newTarget = max
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
	if min := s.BlockInterval() / 3; targetBlockTime < min {
		targetBlockTime = min
	} else if max := s.BlockInterval() * 3; targetBlockTime > max {
		targetBlockTime = max
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
	if min := s.Difficulty.sub(maxAdjust); newDifficulty.Cmp(min) < 0 {
		newDifficulty = min
	} else if max := s.Difficulty.add(maxAdjust); newDifficulty.Cmp(max) > 0 {
		newDifficulty = max
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

func (ms *MidState) addSiacoinElement(sce types.SiacoinElement) {
	ms.sces = append(ms.sces, sce)
	ms.ephemeral[ms.sces[len(ms.sces)-1].ID] = len(ms.sces) - 1
}

func (ms *MidState) spendSiacoinElement(sce types.SiacoinElement, txid types.TransactionID) {
	ms.spends[sce.ID] = txid
	if _, ok := ms.ephemeral[sce.ID]; !ok {
		sce.MerkleProof = append([]types.Hash256(nil), sce.MerkleProof...)
		ms.sces = append(ms.sces, sce)
	}
}

func (ms *MidState) addSiafundElement(sfe types.SiafundElement) {
	ms.sfes = append(ms.sfes, sfe)
	ms.ephemeral[ms.sfes[len(ms.sfes)-1].ID] = len(ms.sfes) - 1
}

func (ms *MidState) spendSiafundElement(sfe types.SiafundElement, txid types.TransactionID) {
	ms.spends[sfe.ID] = txid
	if _, ok := ms.ephemeral[sfe.ID]; !ok {
		sfe.MerkleProof = append([]types.Hash256(nil), sfe.MerkleProof...)
		ms.sfes = append(ms.sfes, sfe)
	}
}

func (ms *MidState) addFileContractElement(fce types.FileContractElement) {
	ms.fces = append(ms.fces, fce)
	ms.ephemeral[ms.fces[len(ms.fces)-1].ID] = len(ms.fces) - 1
	ms.siafundPool = ms.siafundPool.Add(ms.base.FileContractTax(fce.FileContract))
}

func (ms *MidState) reviseFileContractElement(fce types.FileContractElement, rev types.FileContract) {
	rev.Payout = fce.FileContract.Payout
	if i, ok := ms.ephemeral[fce.ID]; ok {
		ms.fces[i].FileContract = rev
	} else {
		if r, ok := ms.revs[fce.ID]; ok {
			r.FileContract = rev
		} else {
			// store the original
			fce.MerkleProof = append([]types.Hash256(nil), fce.MerkleProof...)
			ms.fces = append(ms.fces, fce)
			// store the revision
			fce.MerkleProof = append([]types.Hash256(nil), fce.MerkleProof...)
			fce.FileContract = rev
			ms.revs[fce.ID] = &fce
		}
	}
}

func (ms *MidState) resolveFileContractElement(fce types.FileContractElement, valid bool, txid types.TransactionID) {
	ms.res[fce.ID] = valid
	ms.spends[fce.ID] = txid
	fce.MerkleProof = append([]types.Hash256(nil), fce.MerkleProof...)
	ms.fces = append(ms.fces, fce)
}

func (ms *MidState) addV2FileContractElement(fce types.V2FileContractElement) {
	ms.v2fces = append(ms.v2fces, fce)
	ms.ephemeral[ms.v2fces[len(ms.v2fces)-1].ID] = len(ms.v2fces) - 1
	ms.siafundPool = ms.siafundPool.Add(ms.base.V2FileContractTax(fce.V2FileContract))
}

func (ms *MidState) reviseV2FileContractElement(fce types.V2FileContractElement, rev types.V2FileContract) {
	if i, ok := ms.ephemeral[fce.ID]; ok {
		ms.v2fces[i].V2FileContract = rev
	} else {
		if r, ok := ms.v2revs[fce.ID]; ok {
			r.V2FileContract = rev
		} else {
			// store the original
			fce.MerkleProof = append([]types.Hash256(nil), fce.MerkleProof...)
			ms.v2fces = append(ms.v2fces, fce)
			// store the revision
			fce.MerkleProof = append([]types.Hash256(nil), fce.MerkleProof...)
			fce.V2FileContract = rev
			ms.v2revs[fce.ID] = &fce
		}
	}
}

func (ms *MidState) resolveV2FileContractElement(fce types.V2FileContractElement, res types.V2FileContractResolutionType, txid types.TransactionID) {
	ms.v2res[fce.ID] = res
	ms.spends[fce.ID] = txid
	fce.MerkleProof = append([]types.Hash256(nil), fce.MerkleProof...)
	ms.v2fces = append(ms.v2fces, fce)
}

func (ms *MidState) addAttestationElement(ae types.AttestationElement) {
	ms.aes = append(ms.aes, ae)
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
		claimPortion := ms.siafundPool.Sub(sfe.ClaimStart).Div64(ms.base.SiafundCount()).Mul64(sfe.SiafundOutput.Value)
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
		ms.resolveFileContractElement(fce, true, txid)
		for i, sco := range fce.FileContract.ValidProofOutputs {
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

	for _, sci := range txn.SiacoinInputs {
		ms.spendSiacoinElement(sci.Parent, txid)
	}
	for i, sco := range txn.SiacoinOutputs {
		ms.addSiacoinElement(types.SiacoinElement{
			StateElement:  types.StateElement{ID: types.Hash256(txn.SiacoinOutputID(txid, i))},
			SiacoinOutput: sco,
		})
	}
	for _, sfi := range txn.SiafundInputs {
		ms.spendSiafundElement(sfi.Parent, txid)
		claimPortion := ms.siafundPool.Sub(sfi.Parent.ClaimStart).Div64(ms.base.SiafundCount()).Mul64(sfi.Parent.SiafundOutput.Value)
		ms.addSiacoinElement(types.SiacoinElement{
			StateElement:   types.StateElement{ID: types.Hash256(types.SiafundOutputID(sfi.Parent.ID).V2ClaimOutputID())},
			SiacoinOutput:  types.SiacoinOutput{Value: claimPortion, Address: sfi.ClaimAddress},
			MaturityHeight: ms.base.MaturityHeight(),
		})
	}
	for i, sfo := range txn.SiafundOutputs {
		ms.addSiafundElement(types.SiafundElement{
			StateElement:  types.StateElement{ID: types.Hash256(txn.SiafundOutputID(txid, i))},
			SiafundOutput: sfo,
			ClaimStart:    ms.siafundPool,
		})
	}
	for i, fc := range txn.FileContracts {
		ms.addV2FileContractElement(types.V2FileContractElement{
			StateElement:   types.StateElement{ID: types.Hash256(txn.V2FileContractID(txid, i))},
			V2FileContract: fc,
		})
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
			renter, host = r.FinalRevision.RenterOutput, r.FinalRevision.HostOutput
			renter.Value = renter.Value.Sub(r.RenterRollover)
			host.Value = host.Value.Sub(r.HostRollover)
			ms.addV2FileContractElement(types.V2FileContractElement{
				StateElement:   types.StateElement{ID: types.Hash256(types.FileContractID(fce.ID).V2RenewalID())},
				V2FileContract: r.NewContract,
			})
		case *types.V2StorageProof:
			renter, host = fc.RenterOutput, fc.HostOutput
		case *types.V2FileContractFinalization:
			renter, host = r.RenterOutput, r.HostOutput
		case *types.V2FileContractExpiration:
			renter, host = fc.RenterOutput, fc.MissedHostOutput()
		}
		ms.addSiacoinElement(types.SiacoinElement{
			StateElement:   types.StateElement{ID: types.Hash256(types.FileContractID(fce.ID).V2RenterOutputID())},
			SiacoinOutput:  renter,
			MaturityHeight: ms.base.MaturityHeight(),
		})
		ms.addSiacoinElement(types.SiacoinElement{
			StateElement:   types.StateElement{ID: types.Hash256(types.FileContractID(fce.ID).V2HostOutputID())},
			SiacoinOutput:  host,
			MaturityHeight: ms.base.MaturityHeight(),
		})
	}
	for i, a := range txn.Attestations {
		ms.addAttestationElement(types.AttestationElement{
			StateElement: types.StateElement{ID: txn.AttestationID(txid, i)},
			Attestation:  a,
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
	for _, txn := range b.V2Transactions() {
		ms.ApplyV2Transaction(txn)
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
		ms.resolveFileContractElement(fce, false, types.TransactionID(bid))
		for i, sco := range fce.FileContract.MissedProofOutputs {
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
}

func (ms *MidState) forEachElementLeaf(fn func(elementLeaf)) {
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
func (au ApplyUpdate) ForEachFileContractElement(fn func(fce types.FileContractElement, rev *types.FileContractElement, resolved, valid bool)) {
	for _, fce := range au.ms.fces {
		fn(fce, au.ms.revs[fce.ID], au.ms.isSpent(fce.ID), au.ms.res[fce.ID])
	}
}

// ForEachV2FileContractElement calls fn on each V2 file contract element
// related to au. If the contract was revised, rev is non-nil. If the contract
// was resolved, res is non-nil.
func (au ApplyUpdate) ForEachV2FileContractElement(fn func(fce types.V2FileContractElement, rev *types.V2FileContractElement, res types.V2FileContractResolutionType)) {
	for _, fce := range au.ms.v2fces {
		fn(fce, au.ms.v2revs[fce.ID], au.ms.v2res[fce.ID])
	}
}

// ForEachTreeNode calls fn on each node in the accumulator affected by au.
func (au ApplyUpdate) ForEachTreeNode(fn func(row, col uint64, h types.Hash256)) {
	seen := make(map[[2]uint64]bool)
	au.ms.forEachElementLeaf(func(el elementLeaf) {
		row, col := uint64(0), el.LeafIndex
		h := el.hash()
		fn(row, col, h)
		for i, sibling := range el.MerkleProof {
			if el.LeafIndex&(1<<i) == 0 {
				h = blake2b.SumPair(h, sibling)
			} else {
				h = blake2b.SumPair(sibling, h)
			}
			row++
			col >>= 1
			fn(row, col, h)
			if seen[[2]uint64{row, col}] {
				return // already seen everything above this
			}
			seen[[2]uint64{row, col}] = true
		}
	})
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
	s.Attestations += uint64(len(ms.aes))
	s.FoundationPrimaryAddress = ms.foundationPrimary
	s.FoundationFailsafeAddress = ms.foundationFailsafe

	// compute updated and added elements
	var updated, added []elementLeaf
	ms.forEachElementLeaf(func(el elementLeaf) {
		if el.MerkleProof == nil {
			added = append(added, el)
		} else {
			updated = append(updated, el)
		}
	})
	eau := s.Elements.applyBlock(updated, added)
	s = ApplyOrphan(s, b, targetTimestamp)
	return s, ApplyUpdate{ms, eau}
}

// A RevertUpdate represents the effects of reverting to a prior state.
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
func (ru RevertUpdate) ForEachFileContractElement(fn func(fce types.FileContractElement, rev *types.FileContractElement, resolved, valid bool)) {
	for i := range ru.ms.fces {
		fce := ru.ms.fces[len(ru.ms.fces)-i-1]
		fn(fce, ru.ms.revs[fce.ID], ru.ms.isSpent(fce.ID), ru.ms.res[fce.ID])
	}
}

// ForEachV2FileContractElement calls fn on each V2 file contract element
// related to au. If the contract was revised, rev is non-nil. If the contract
// was resolved, res is non-nil.
func (ru RevertUpdate) ForEachV2FileContractElement(fn func(fce types.V2FileContractElement, rev *types.V2FileContractElement, res types.V2FileContractResolutionType)) {
	for i := range ru.ms.v2fces {
		fce := ru.ms.v2fces[len(ru.ms.fces)-i-1]
		fn(fce, ru.ms.v2revs[fce.ID], ru.ms.v2res[fce.ID])
	}
}

// ForEachTreeNode calls fn on each node in the accumulator affected by ru.
func (ru RevertUpdate) ForEachTreeNode(fn func(row, col uint64, h types.Hash256)) {
	seen := make(map[[2]uint64]bool)
	ru.ms.forEachElementLeaf(func(el elementLeaf) {
		el.Spent = false // reverting a block can never cause an element to become spent
		row, col := uint64(0), el.LeafIndex
		h := el.hash()
		fn(row, col, h)
		for i, sibling := range el.MerkleProof {
			if el.LeafIndex&(1<<i) == 0 {
				h = blake2b.SumPair(h, sibling)
			} else {
				h = blake2b.SumPair(sibling, h)
			}
			row++
			col >>= 1
			fn(row, col, h)
			if seen[[2]uint64{row, col}] {
				return // already seen everything above this
			}
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
	ms.forEachElementLeaf(func(el elementLeaf) {
		el.Spent = false // reverting a block can never cause an element to become spent
		if el.MerkleProof != nil {
			updated = append(updated, el)
		} else {
			added = append(added, el)
		}
	})
	eru := s.Elements.revertBlock(updated, added)
	return RevertUpdate{ms, eru}
}
