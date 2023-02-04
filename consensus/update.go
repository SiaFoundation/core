package consensus

import (
	"bytes"
	"math/big"
	"time"

	"go.sia.tech/core/types"
)

// s = 1/(1/x + 1/y) = x*y/(x+y)
func addTarget(x, y types.BlockID) (s types.BlockID) {
	xi := new(big.Int).SetBytes(x[:])
	yi := new(big.Int).SetBytes(y[:])
	yi.Div(
		new(big.Int).Mul(xi, yi),
		new(big.Int).Add(xi, yi),
	).FillBytes(s[:])
	return
}

// m = x*n/d
func mulTargetFrac(x types.BlockID, n, d int64) (m types.BlockID) {
	i := new(big.Int).SetBytes(x[:])
	i.Mul(i, big.NewInt(n))
	i.Div(i, big.NewInt(d))
	i.FillBytes(m[:])
	return
}

// m = 1/(1/x * n/d) = x*d/n
func mulDifficultyFrac(x types.BlockID, n, d int64) (m types.BlockID) {
	return mulTargetFrac(x, d, n)
}

func workRequiredForHash(id types.BlockID) *big.Int {
	if id == (types.BlockID{}) {
		panic("impossibly good BlockID")
	}
	maxTarget := new(big.Int).Lsh(big.NewInt(1), 256)
	return maxTarget.Div(maxTarget, new(big.Int).SetBytes(id[:]))
}

func hashRequiringWork(i *big.Int) types.BlockID {
	if i.Sign() == 0 {
		panic("no hash requires zero work")
	}
	// As a special case, 1 Work produces this hash. (Otherwise, the division
	// would produce 2^256, which overflows our representation.)
	if i.IsInt64() && i.Int64() == 1 {
		return types.BlockID{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		}
	}
	var id types.BlockID
	maxTarget := new(big.Int).Lsh(big.NewInt(1), 256)
	maxTarget.Div(maxTarget, i).FillBytes(id[:])
	return id
}

func updateOakTime(s State, h types.BlockHeader) time.Duration {
	if s.childHeight() == hardforkASIC-1 {
		return 120000 * time.Second
	}
	prevTotalTime := s.OakTime
	if s.childHeight() == hardforkOak-1 {
		prevTotalTime = s.BlockInterval() * time.Duration(s.childHeight())
	}
	decayedTime := (((prevTotalTime / time.Second) * 995) / 1000) * time.Second
	return decayedTime + h.Timestamp.Sub(s.PrevTimestamps[0])
}

func updateOakTarget(s State, h types.BlockHeader) types.BlockID {
	if s.childHeight() == hardforkASIC-1 {
		return types.BlockID{8: 32}
	}
	return addTarget(mulDifficultyFrac(s.OakTarget, 995, 1000), s.ChildTarget)
}

func adjustDifficulty(s State, h types.BlockHeader, store Store) types.BlockID {
	blockInterval := int64(s.BlockInterval() / time.Second)

	// pre-Oak algorithm
	if s.childHeight() <= hardforkOak {
		windowSize := uint64(1000)
		if s.childHeight()%(windowSize/2) != 0 {
			return s.ChildTarget // no change
		}
		ancestorDepth := windowSize
		if windowSize > s.childHeight() {
			ancestorDepth = s.childHeight()
		}
		targetTimestamp := store.AncestorTimestamp(s.Index.ID, ancestorDepth)
		elapsed := int64(h.Timestamp.Sub(targetTimestamp) / time.Second)
		expected := blockInterval * int64(ancestorDepth)
		// clamp
		if r := float64(elapsed) / float64(expected); r > 25.0/10.0 {
			elapsed, expected = 25, 10
		} else if r < 10.0/25.0 {
			elapsed, expected = 10, 25
		}
		// multiply
		return mulDifficultyFrac(s.ChildTarget, expected, elapsed)
	}

	oakTotalTime := int64(s.OakTime / time.Second)

	var delta int64
	if s.Index.Height < hardforkOakFix {
		delta = (blockInterval * int64(s.Index.Height)) - oakTotalTime
	} else {
		parentTimestamp := s.PrevTimestamps[0]
		delta = (blockInterval * int64(s.Index.Height)) + s.GenesisTimestamp.Unix() - parentTimestamp.Unix()
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

	// estimate the hashrate from the (decayed) total work and the (decayed,
	// clamped) total time, and multiply by the target block time; this is the
	// expected number of hashes required to produce the next block, i.e. the
	// new difficulty
	if oakTotalTime <= 0 {
		oakTotalTime = 1
	}
	if targetBlockTime == 0 {
		targetBlockTime = 1
	}
	estimatedHashrate := workRequiredForHash(s.OakTarget)
	estimatedHashrate.Div(estimatedHashrate, big.NewInt(oakTotalTime))
	estimatedHashrate.Mul(estimatedHashrate, big.NewInt(targetBlockTime))
	newTarget := hashRequiringWork(estimatedHashrate)

	// clamp the adjustment to 0.4%, except for ASIC hardfork block
	if s.childHeight() != hardforkASIC {
		if min := mulTargetFrac(s.ChildTarget, 1000, 1004); bytes.Compare(newTarget[:], min[:]) < 0 {
			newTarget = min
		} else if max := mulTargetFrac(s.ChildTarget, 1004, 1000); bytes.Compare(newTarget[:], max[:]) > 0 {
			newTarget = max
		}
	}

	return newTarget
}

// A TransactionDiff represents the changes to an ElementStore resulting from
// the application of a transaction.
type TransactionDiff struct {
	CreatedSiacoinOutputs map[types.SiacoinOutputID]types.SiacoinOutput
	DelayedSiacoinOutputs map[types.SiacoinOutputID]types.SiacoinOutput
	CreatedSiafundOutputs map[types.SiafundOutputID]types.SiafundOutput
	CreatedFileContracts  map[types.FileContractID]types.FileContract

	SpentSiacoinOutputs  map[types.SiacoinOutputID]types.SiacoinOutput
	SpentSiafundOutputs  map[types.SiafundOutputID]types.SiafundOutput
	RevisedFileContracts map[types.FileContractID]types.FileContract
	ValidFileContracts   map[types.FileContractID]types.FileContract
}

// A BlockDiff represents the changes to an ElementStore resulting from the
// application of a block.
type BlockDiff struct {
	Transactions          []TransactionDiff
	DelayedSiacoinOutputs map[types.SiacoinOutputID]types.SiacoinOutput
	MaturedSiacoinOutputs map[types.SiacoinOutputID]types.SiacoinOutput
	MissedFileContracts   map[types.FileContractID]types.FileContract
}

// ApplyBlock applies b to s, returning the resulting state and effects.
func ApplyBlock(s State, store Store, b types.Block) (State, BlockDiff) {
	if s.Index.Height > 0 && s.Index.ID != b.ParentID {
		panic("consensus: cannot apply non-child block")
	}

	// track intra-block effects
	siafundPool := s.SiafundPool
	ephemeralSC := make(map[types.SiacoinOutputID]types.SiacoinOutput)
	ephemeralSF := make(map[types.SiafundOutputID]types.SiafundOutput)
	ephemeralClaims := make(map[types.SiafundOutputID]types.Currency)
	ephemeralFC := make(map[types.FileContractID]types.FileContract)
	hasStorageProof := make(map[types.FileContractID]bool)
	getSC := func(id types.SiacoinOutputID) types.SiacoinOutput {
		sco, ok := ephemeralSC[id]
		if !ok {
			sco, ok = store.SiacoinOutput(id)
			if !ok {
				panic("consensus: siacoin output not found")
			}
		}
		return sco
	}
	getSF := func(id types.SiafundOutputID) (types.SiafundOutput, types.Currency) {
		sfo, ok := ephemeralSF[id]
		claim := ephemeralClaims[id]
		if !ok {
			sfo, claim, ok = store.SiafundOutput(id)
			if !ok {
				panic("consensus: siafund output not found")
			}
		}
		return sfo, claim
	}
	getFC := func(id types.FileContractID) types.FileContract {
		fc, ok := ephemeralFC[id]
		if !ok {
			fc, ok = store.FileContract(id)
			if !ok {
				panic("consensus: file contract not found")
			}
		}
		return fc
	}

	diff := BlockDiff{
		DelayedSiacoinOutputs: make(map[types.SiacoinOutputID]types.SiacoinOutput),
		MaturedSiacoinOutputs: make(map[types.SiacoinOutputID]types.SiacoinOutput),
		MissedFileContracts:   make(map[types.FileContractID]types.FileContract),
	}
	for _, txn := range b.Transactions {
		tdiff := TransactionDiff{
			CreatedSiacoinOutputs: make(map[types.SiacoinOutputID]types.SiacoinOutput),
			DelayedSiacoinOutputs: make(map[types.SiacoinOutputID]types.SiacoinOutput),
			CreatedSiafundOutputs: make(map[types.SiafundOutputID]types.SiafundOutput),
			CreatedFileContracts:  make(map[types.FileContractID]types.FileContract),
			SpentSiacoinOutputs:   make(map[types.SiacoinOutputID]types.SiacoinOutput),
			SpentSiafundOutputs:   make(map[types.SiafundOutputID]types.SiafundOutput),
			RevisedFileContracts:  make(map[types.FileContractID]types.FileContract),
			ValidFileContracts:    make(map[types.FileContractID]types.FileContract),
		}
		for _, sci := range txn.SiacoinInputs {
			tdiff.SpentSiacoinOutputs[sci.ParentID] = getSC(sci.ParentID)
		}
		for i, sco := range txn.SiacoinOutputs {
			tdiff.CreatedSiacoinOutputs[txn.SiacoinOutputID(i)] = sco
			ephemeralSC[txn.SiacoinOutputID(i)] = sco
		}
		for i, fc := range txn.FileContracts {
			tdiff.CreatedFileContracts[txn.FileContractID(i)] = fc
			ephemeralFC[txn.FileContractID(i)] = fc
			siafundPool = siafundPool.Add(s.FileContractTax(fc))
		}
		for _, sfi := range txn.SiafundInputs {
			sfo, claimStart := getSF(sfi.ParentID)
			tdiff.SpentSiafundOutputs[sfi.ParentID] = sfo
			claimPortion := siafundPool.Sub(claimStart).Div64(s.SiafundCount()).Mul64(sfo.Value)
			tdiff.DelayedSiacoinOutputs[sfi.ParentID.ClaimOutputID()] = types.SiacoinOutput{
				Value:   claimPortion,
				Address: sfi.ClaimAddress,
			}
		}
		for i, sfo := range txn.SiafundOutputs {
			tdiff.CreatedSiafundOutputs[txn.SiafundOutputID(i)] = sfo
			ephemeralSF[txn.SiafundOutputID(i)] = sfo
			ephemeralClaims[txn.SiafundOutputID(i)] = siafundPool
		}
		for _, fcr := range txn.FileContractRevisions {
			fc := getFC(fcr.ParentID)
			fcr.FileContract.Payout = fc.Payout // see types.FileContractRevision docstring
			tdiff.RevisedFileContracts[fcr.ParentID] = fc
			tdiff.CreatedFileContracts[fcr.ParentID] = fcr.FileContract
			ephemeralFC[fcr.ParentID] = fcr.FileContract
		}
		for _, sp := range txn.StorageProofs {
			fc := getFC(sp.ParentID)
			tdiff.ValidFileContracts[sp.ParentID] = fc
			for i, sco := range fc.ValidProofOutputs {
				tdiff.DelayedSiacoinOutputs[sp.ParentID.ValidOutputID(i)] = sco
			}
			hasStorageProof[sp.ParentID] = true
		}
		diff.Transactions = append(diff.Transactions, tdiff)
	}

	h := b.Header()
	bid := h.ID()
	for i, mp := range b.MinerPayouts {
		diff.DelayedSiacoinOutputs[bid.MinerOutputID(i)] = mp
	}
	if subsidy := s.FoundationSubsidy(); !subsidy.Value.IsZero() {
		diff.DelayedSiacoinOutputs[bid.FoundationOutputID()] = subsidy
	}
	for _, id := range store.MaturedSiacoinOutputs(s.childHeight()) {
		sco, _ := store.MaturedSiacoinOutput(s.childHeight(), id)
		diff.MaturedSiacoinOutputs[id] = sco
	}
	for _, id := range store.MissedFileContracts(s.childHeight()) {
		if hasStorageProof[id] {
			continue
		}
		fc := getFC(id)
		diff.MissedFileContracts[id] = fc
		for i, sco := range fc.MissedProofOutputs {
			diff.DelayedSiacoinOutputs[id.MissedOutputID(i)] = sco
		}
	}

	// update state
	newFoundationPrimaryAddress := s.FoundationPrimaryAddress
	newFoundationFailsafeAddress := s.FoundationFailsafeAddress
	var updatedFoundation bool // Foundation addresses can only be updated once per block
	for _, txn := range b.Transactions {
		if s.Index.Height >= hardforkFoundation {
			for _, arb := range txn.ArbitraryData {
				if bytes.HasPrefix(arb, types.SpecifierFoundation[:]) && !updatedFoundation {
					var update types.FoundationAddressUpdate
					update.DecodeFrom(types.NewBufDecoder(arb[len(types.SpecifierFoundation):]))
					newFoundationPrimaryAddress = update.NewPrimary
					newFoundationFailsafeAddress = update.NewFailsafe
					updatedFoundation = true
				}
			}
		}
	}

	var ns State
	if h.ParentID == (types.BlockID{}) {
		// special handling for genesis block
		ns = State{
			Index:                     types.ChainIndex{Height: 0, ID: bid},
			PrevTimestamps:            [11]time.Time{0: h.Timestamp},
			Depth:                     s.Depth,
			ChildTarget:               s.ChildTarget,
			OakTime:                   0,
			OakTarget:                 s.OakTarget,
			GenesisTimestamp:          h.Timestamp,
			SiafundPool:               siafundPool,
			FoundationPrimaryAddress:  newFoundationPrimaryAddress,
			FoundationFailsafeAddress: newFoundationFailsafeAddress,
		}
	} else {
		prevTimestamps := s.PrevTimestamps
		copy(prevTimestamps[1:], s.PrevTimestamps[:])
		prevTimestamps[0] = h.Timestamp
		ns = State{
			Index:                     types.ChainIndex{Height: s.Index.Height + 1, ID: bid},
			PrevTimestamps:            prevTimestamps,
			Depth:                     addTarget(s.Depth, s.ChildTarget),
			ChildTarget:               adjustDifficulty(s, h, store),
			OakTime:                   updateOakTime(s, h),
			OakTarget:                 updateOakTarget(s, h),
			GenesisTimestamp:          s.GenesisTimestamp,
			SiafundPool:               siafundPool,
			FoundationPrimaryAddress:  newFoundationPrimaryAddress,
			FoundationFailsafeAddress: newFoundationFailsafeAddress,
		}
	}

	return ns, diff
}
