// Package consensus implements the Sia consensus algorithms.
package consensus

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"sort"
	"sync"
	"time"

	"go.sia.tech/core/types"
)

const (
	blocksPerDay  = 144
	blocksPerYear = 144 * 365

	foundationHardforkHeight   = 300000
	foundationSubsidyFrequency = blocksPerYear / 12

	// NonceFactor is the factor by which all block nonces must be divisible.
	NonceFactor = 1009
)

var (
	// ErrFutureBlock is returned by AppendHeader if a block's timestamp is too far
	// in the future. The block may be valid at a later time.
	ErrFutureBlock = errors.New("timestamp is too far in the future")

	// ErrOverweight is returned when a block's weight exceeds MaxBlockWeight.
	ErrOverweight = errors.New("block is too heavy")

	// ErrOverflow is returned when the sum of a transaction's inputs and/or
	// outputs overflows the Currency representation.
	ErrOverflow = errors.New("sum of currency values overflowed")
)

// Pool for reducing heap allocations when hashing. This are only necessary
// because blake2b.New256 returns a hash.Hash interface, which prevents the
// compiler from doing escape analysis. Can be removed if we switch to an
// implementation whose constructor returns a concrete type.
var hasherPool = &sync.Pool{New: func() interface{} { return types.NewHasher() }}

// ValidationContext contains the necessary context to fully validate a block.
type ValidationContext struct {
	Index types.ChainIndex

	State          StateAccumulator
	History        HistoryAccumulator
	PrevTimestamps [11]time.Time

	TotalWork        types.Work
	Difficulty       types.Work
	OakWork          types.Work
	OakTime          time.Duration
	GenesisTimestamp time.Time

	SiafundPool       types.Currency
	FoundationAddress types.Address
}

// BlockReward returns the reward for mining a child block.
func (vc *ValidationContext) BlockReward() types.Currency {
	const initialCoinbase = 300000
	const minimumCoinbase = 30000
	blockHeight := vc.Index.Height + 1
	if blockHeight < initialCoinbase-minimumCoinbase {
		return types.Siacoins(uint32(initialCoinbase - blockHeight))
	}
	return types.Siacoins(minimumCoinbase)
}

// BlockRewardTimelock is the height at which a child block's reward becomes
// spendable.
func (vc *ValidationContext) BlockRewardTimelock() uint64 {
	return (vc.Index.Height + 1) + 144
}

// FoundationSubsidy returns the Foundation subsidy value for the child block.
func (vc *ValidationContext) FoundationSubsidy() types.Currency {
	foundationSubsidyPerBlock := types.Siacoins(30000)
	initialfoundationSubsidy := foundationSubsidyPerBlock.Mul64(blocksPerYear)

	blockHeight := vc.Index.Height + 1
	if blockHeight < foundationHardforkHeight || (blockHeight-foundationHardforkHeight)%foundationSubsidyFrequency != 0 {
		return types.ZeroCurrency
	} else if blockHeight == foundationHardforkHeight {
		return initialfoundationSubsidy
	}
	return foundationSubsidyPerBlock.Mul64(foundationSubsidyFrequency)
}

// MaxBlockWeight is the maximum "weight" of a valid child block.
func (vc *ValidationContext) MaxBlockWeight() uint64 {
	return 2_000_000
}

// TransactionWeight computes the weight of a txn.
func (vc *ValidationContext) TransactionWeight(txn types.Transaction) uint64 {
	storage := types.EncodedLen(txn)

	var signatures int
	for _, in := range txn.SiacoinInputs {
		signatures += len(in.Signatures)
	}
	for _, in := range txn.SiafundInputs {
		signatures += len(in.Signatures)
	}
	signatures += 2 * len(txn.FileContractRevisions)

	return uint64(storage) + 100*uint64(signatures)
}

// BlockWeight computes the combined weight of a block's txns.
func (vc *ValidationContext) BlockWeight(txns []types.Transaction) uint64 {
	var weight uint64
	for _, txn := range txns {
		weight += vc.TransactionWeight(txn)
	}
	return weight
}

// FileContractTax computes the tax levied on a given contract.
func (vc *ValidationContext) FileContractTax(fc types.FileContractState) types.Currency {
	sum := fc.ValidRenterOutput.Value.Add(fc.ValidHostOutput.Value)
	tax := sum.Div64(25) // 4%
	// round down to SiafundCount
	_, r := bits.Div64(0, tax.Hi, SiafundCount)
	_, r = bits.Div64(r, tax.Lo, SiafundCount)
	return tax.Sub(types.NewCurrency64(r))
}

// StorageProofSegmentIndex returns the segment index used when computing or
// validating a storage proof.
func (vc *ValidationContext) StorageProofSegmentIndex(filesize uint64, windowStart types.ChainIndex, fcid types.OutputID) uint64 {
	const segmentSize = uint64(len(types.StorageProof{}.DataSegment))
	if filesize <= segmentSize {
		return 0
	}
	numSegments := filesize / segmentSize
	if filesize%segmentSize != 0 {
		numSegments++
	}

	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	windowStart.EncodeTo(h.E)
	fcid.EncodeTo(h.E)
	seed := h.Sum()

	var r uint64
	for i := 0; i < len(seed); i += 8 {
		_, r = bits.Div64(r, binary.BigEndian.Uint64(seed[i:]), numSegments)
	}
	return r
}

// Commitment computes the commitment hash for a child block.
func (vc *ValidationContext) Commitment(minerAddr types.Address, txns []types.Transaction) types.Hash256 {
	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	h.Reset()

	// hash the context
	vc.EncodeTo(h.E)
	ctxHash := h.Sum()

	// hash the transactions
	h.Reset()
	h.E.WritePrefix(len(txns))
	for _, txn := range txns {
		txn.ID().EncodeTo(h.E)
	}
	txnsHash := h.Sum()

	// concatenate the hashes and the miner address
	h.Reset()
	ctxHash.EncodeTo(h.E)
	minerAddr.EncodeTo(h.E)
	txnsHash.EncodeTo(h.E)
	return h.Sum()
}

// SigHash returns the hash that must be signed for each transaction input.
func (vc *ValidationContext) SigHash(txn types.Transaction) types.Hash256 {
	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	for _, in := range txn.SiacoinInputs {
		in.Parent.ID.EncodeTo(h.E)
	}
	for _, out := range txn.SiacoinOutputs {
		out.EncodeTo(h.E)
	}
	for _, in := range txn.SiafundInputs {
		in.Parent.ID.EncodeTo(h.E)
	}
	for _, out := range txn.SiafundOutputs {
		out.EncodeTo(h.E)
	}
	for _, fc := range txn.FileContracts {
		fc.EncodeTo(h.E)
	}
	for _, fcr := range txn.FileContractRevisions {
		fcr.Parent.ID.EncodeTo(h.E)
		fcr.NewState.EncodeTo(h.E)
	}
	for _, fcr := range txn.FileContractResolutions {
		fcr.Parent.ID.EncodeTo(h.E)
		fcr.StorageProof.WindowStart.EncodeTo(h.E)
	}
	h.E.Write(txn.ArbitraryData)
	txn.NewFoundationAddress.EncodeTo(h.E)
	txn.MinerFee.EncodeTo(h.E)
	return h.Sum()
}

// ContractSigHash returns the hash that must be signed for a file contract revision.
func (vc *ValidationContext) ContractSigHash(fc types.FileContractState) types.Hash256 {
	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	fc.EncodeTo(h.E)
	return h.Sum()
}

func (vc *ValidationContext) numTimestamps() int {
	if vc.Index.Height+1 < uint64(len(vc.PrevTimestamps)) {
		return int(vc.Index.Height + 1)
	}
	return len(vc.PrevTimestamps)
}

func (vc *ValidationContext) medianTimestamp() time.Time {
	prevCopy := vc.PrevTimestamps
	ts := prevCopy[:vc.numTimestamps()]
	sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
	if len(ts)%2 != 0 {
		return ts[len(ts)/2]
	}
	l, r := ts[len(ts)/2-1], ts[len(ts)/2]
	return l.Add(r.Sub(l) / 2)
}

func (vc *ValidationContext) validateHeader(h types.BlockHeader) error {
	if h.Height != vc.Index.Height+1 {
		return errors.New("wrong height")
	} else if h.ParentID != vc.Index.ID {
		return errors.New("wrong parent ID")
	} else if time.Until(h.Timestamp) > 2*time.Hour {
		return ErrFutureBlock
	} else if h.Timestamp.Before(vc.medianTimestamp()) {
		return errors.New("timestamp is too far in the past")
	} else if h.Nonce%NonceFactor != 0 {
		return errors.New("nonce is not divisible by required factor")
	} else if types.WorkRequiredForHash(h.ID()).Cmp(vc.Difficulty) < 0 {
		return errors.New("insufficient work")
	}
	return nil
}

func (vc *ValidationContext) containsZeroValuedOutputs(txn types.Transaction) error {
	for i, out := range txn.SiacoinOutputs {
		if out.Value.IsZero() {
			return fmt.Errorf("siacoin output %v has zero value", i)
		}
	}
	for i, out := range txn.SiafundOutputs {
		if out.Value.IsZero() {
			return fmt.Errorf("siafund output %v has zero value", i)
		}
	}
	return nil
}

func (vc *ValidationContext) validTimeLocks(txn types.Transaction) error {
	blockHeight := vc.Index.Height + 1
	for i, in := range txn.SiacoinInputs {
		if in.Parent.Timelock > blockHeight {
			return fmt.Errorf("siacoin input %v is timelocked until block %v", i, in.Parent.Timelock)
		}
	}
	return nil
}

func (vc *ValidationContext) validFileContracts(txn types.Transaction) error {
	for i, fc := range txn.FileContracts {
		validSum := fc.ValidRenterOutput.Value.Add(fc.ValidHostOutput.Value)
		missedSum := fc.MissedRenterOutput.Value.Add(fc.MissedHostOutput.Value)
		if missedSum.Cmp(validSum) > 0 {
			return fmt.Errorf("file contract %v has missed output sum (%v SC) exceeding valid output sum (%v SC)", i, missedSum, validSum)
		} else if fc.WindowEnd <= fc.WindowStart {
			return fmt.Errorf("file contract %v has proof window (%v-%v) that ends before it begins", i, fc.WindowStart, fc.WindowEnd)
		}
	}
	return nil
}

func (vc *ValidationContext) validFileContractRevisions(txn types.Transaction) error {
	for i, fcr := range txn.FileContractRevisions {
		oldState, newState := fcr.Parent.State, fcr.NewState
		if vc.Index.Height > oldState.WindowStart {
			return fmt.Errorf("file contract revision %v cannot be applied to contract whose proof window (%v - %v) has already begun", i, oldState.WindowStart, oldState.WindowEnd)
		}
		oldValidSum := oldState.ValidRenterOutput.Value.Add(oldState.ValidHostOutput.Value)
		newValidSum := newState.ValidRenterOutput.Value.Add(newState.ValidHostOutput.Value)
		newMissedSum := newState.MissedRenterOutput.Value.Add(newState.MissedHostOutput.Value)
		switch {
		case newState.RevisionNumber <= oldState.RevisionNumber:
			return fmt.Errorf("file contract revision %v does not increase revision number (%v -> %v)", i, oldState.RevisionNumber, newState.RevisionNumber)
		case !newValidSum.Equals(oldValidSum):
			return fmt.Errorf("file contract revision %v modifies valid output sum (%v -> %v)", i, oldValidSum, newValidSum)
		case newMissedSum.Cmp(newValidSum) > 0:
			return fmt.Errorf("file contract revision %v has missed output sum (%v) exceeding valid output sum (%v)", i, newMissedSum, newValidSum)
		case newState.WindowEnd <= newState.WindowStart:
			return fmt.Errorf("file contract revision %v has proof window (%v - %v) that ends before it begins", i, newState.WindowStart, newState.WindowEnd)
		}

		// verify signatures
		//
		// NOTE: very important that we verify with the *old* keys!
		contractHash := vc.ContractSigHash(newState)
		if !ed25519.Verify(oldState.RenterPublicKey[:], contractHash[:], fcr.RenterSignature[:]) {
			return fmt.Errorf("file contract revision %v has invalid renter signature", i)
		}
		if !ed25519.Verify(oldState.HostPublicKey[:], contractHash[:], fcr.HostSignature[:]) {
			return fmt.Errorf("file contract revision %v has invalid host signature", i)
		}
	}
	return nil
}

func (vc *ValidationContext) validFileContractResolutions(txn types.Transaction) error {
	for i, fcr := range txn.FileContractResolutions {
		rev := fcr.Parent.State
		if fcr.HasStorageProof() {
			// we must be within the proof window
			if vc.Index.Height < rev.WindowStart || rev.WindowEnd < vc.Index.Height {
				return fmt.Errorf("file contract resolution %v attempts to claim valid outputs, but proof window (%v - %v) has expired", i, rev.WindowStart, rev.WindowEnd)
			}
			// validate storage proof
			if fcr.StorageProof.WindowStart.Height != rev.WindowStart {
				// see note on this field in types.StorageProof
				return fmt.Errorf("file contract resolution %v has storage proof with WindowStart (%v) that does not match final revision WindowStart (%v)", i, fcr.StorageProof.WindowStart.Height, rev.WindowStart)
			}
			segmentIndex := vc.StorageProofSegmentIndex(rev.Filesize, fcr.StorageProof.WindowStart, fcr.Parent.ID)
			if storageProofRoot(fcr.StorageProof, segmentIndex) != rev.FileMerkleRoot {
				return fmt.Errorf("file contract resolution %v has storage proof root that does not match final Merkle root", i)
			}
		} else {
			// contract must have expired
			if vc.Index.Height <= rev.WindowEnd {
				return fmt.Errorf("file contract resolution %v attempts to claim missed outputs, but proof window (%v - %v) has not expired", i, rev.WindowStart, rev.WindowEnd)
			}
		}
	}
	return nil
}

func (vc *ValidationContext) outputsEqualInputs(txn types.Transaction) error {
	var inputSC, outputSC types.Currency
	var overflowed bool
	for _, in := range txn.SiacoinInputs {
		inputSC, overflowed = inputSC.AddWithOverflow(in.Parent.Value)
		if overflowed {
			return ErrOverflow
		}
	}
	for _, out := range txn.SiacoinOutputs {
		outputSC, overflowed = outputSC.AddWithOverflow(out.Value)
		if overflowed {
			return ErrOverflow
		}
	}
	for _, fc := range txn.FileContracts {
		outputSC, overflowed = outputSC.AddWithOverflow(fc.ValidRenterOutput.Value)
		if overflowed {
			return ErrOverflow
		}
		outputSC, overflowed = outputSC.AddWithOverflow(fc.ValidHostOutput.Value)
		if overflowed {
			return ErrOverflow
		}
		outputSC, overflowed = outputSC.AddWithOverflow(vc.FileContractTax(fc))
		if overflowed {
			return ErrOverflow
		}
	}
	outputSC, overflowed = outputSC.AddWithOverflow(txn.MinerFee)
	if overflowed {
		return ErrOverflow
	}
	if inputSC != outputSC {
		return fmt.Errorf("siacoin inputs (%v SC) do not equal siacoin outputs (%v SC)", inputSC, outputSC)
	}

	var inputSF, outputSF types.Currency
	for _, in := range txn.SiafundInputs {
		inputSF, overflowed = inputSF.AddWithOverflow(in.Parent.Value)
		if overflowed {
			return ErrOverflow
		}
	}
	for _, out := range txn.SiafundOutputs {
		outputSF, overflowed = outputSF.AddWithOverflow(out.Value)
		if overflowed {
			return ErrOverflow
		}
	}
	if inputSF != outputSF {
		return fmt.Errorf("siafund inputs (%d SF) do not equal siafund outputs (%d SF)", inputSF, outputSF)
	}

	return nil
}

func (vc *ValidationContext) validStateProofs(txn types.Transaction) error {
	for i, in := range txn.SiacoinInputs {
		switch {
		case in.Parent.LeafIndex == types.EphemeralLeafIndex:
			continue
		case vc.State.ContainsUnspentSiacoinOutput(in.Parent):
			continue
		case vc.State.ContainsSpentSiacoinOutput(in.Parent):
			return fmt.Errorf("siacoin input %v double-spends output %v", i, in.Parent.ID)
		default:
			return fmt.Errorf("siacoin input %v spends output (%v) not present in the accumulator", i, in.Parent.ID)
		}
	}
	for i, in := range txn.SiafundInputs {
		switch {
		case vc.State.ContainsUnspentSiafundOutput(in.Parent):
			continue
		case vc.State.ContainsSpentSiafundOutput(in.Parent):
			return fmt.Errorf("siafund input %v double-spends output %v", i, in.Parent.ID)
		default:
			return fmt.Errorf("siafund input %v spends output (%v) not present in the accumulator", i, in.Parent.ID)
		}
	}
	for i, fcr := range txn.FileContractRevisions {
		if vc.State.ContainsUnresolvedFileContract(fcr.Parent) {
			continue
		}
		switch {
		case vc.State.ContainsValidFileContract(fcr.Parent):
			return fmt.Errorf("file contract revision %v revises a contract (%v) that has already resolved valid", i, fcr.Parent.ID)
		case vc.State.ContainsMissedFileContract(fcr.Parent):
			return fmt.Errorf("file contract revision %v revises a contract (%v) that has already resolved missed", i, fcr.Parent.ID)
		default:
			return fmt.Errorf("file contract revision %v revises a contract (%v) not present in the accumulator", i, fcr.Parent.ID)
		}
	}
	for i, fcr := range txn.FileContractResolutions {
		if vc.State.ContainsUnresolvedFileContract(fcr.Parent) {
			continue
		}
		switch {
		case vc.State.ContainsValidFileContract(fcr.Parent):
			return fmt.Errorf("file contract resolution %v resolves a contract (%v) that has already resolved valid", i, fcr.Parent.ID)
		case vc.State.ContainsMissedFileContract(fcr.Parent):
			return fmt.Errorf("file contract resolution %v resolves a contract (%v) that has already resolved missed", i, fcr.Parent.ID)
		default:
			return fmt.Errorf("file contract resolution %v resolves a contract (%v) not present in the accumulator", i, fcr.Parent.ID)
		}
	}
	return nil
}

func (vc *ValidationContext) validHistoryProofs(txn types.Transaction) error {
	for i, fcr := range txn.FileContractResolutions {
		if fcr.HasStorageProof() && !vc.History.Contains(fcr.StorageProof.WindowStart, fcr.StorageProof.WindowProof) {
			return fmt.Errorf("file contract resolution %v has storage proof with invalid history proof", i)
		}
	}
	return nil
}

func (vc *ValidationContext) validFoundationUpdate(txn types.Transaction) error {
	if txn.NewFoundationAddress == types.VoidAddress {
		return nil
	}
	for _, in := range txn.SiacoinInputs {
		if in.Parent.Address == vc.FoundationAddress {
			return nil
		}
	}
	return errors.New("transaction changes Foundation address, but does not spend an input controlled by current address")
}

func (vc *ValidationContext) validSpendPolicies(txn types.Transaction) error {
	sigHash := vc.SigHash(txn)
	verifyPolicy := func(p types.SpendPolicy, sigs []types.InputSignature) error {
		var verify func(types.SpendPolicy) error
		verify = func(p types.SpendPolicy) error {
			switch p := p.(type) {
			case types.PolicyAbove:
				if vc.Index.Height > uint64(p) {
					return nil
				}
				return fmt.Errorf("height not above %v", uint64(p))
			case types.PolicyPublicKey:
				for i := range sigs {
					if ed25519.Verify(p[:], sigHash[:], sigs[i][:]) {
						sigs = sigs[i+1:]
						return nil
					}
				}
				return errors.New("no signatures matching pubkey")
			case types.PolicyThreshold:
				for i := 0; i < len(p.Of) && p.N > 0 && len(p.Of[i:]) >= int(p.N); i++ {
					if verify(p.Of[i]) == nil {
						p.N--
					}
				}
				if p.N != 0 {
					return errors.New("threshold not reached")
				}
				return nil
			case types.PolicyUnlockConditions:
				if err := verify(types.PolicyAbove(p.Timelock)); err != nil {
					return err
				}
				thresh := types.PolicyThreshold{
					N:  p.SignaturesRequired,
					Of: make([]types.SpendPolicy, len(p.PublicKeys)),
				}
				for i, pk := range p.PublicKeys {
					thresh.Of[i] = types.PolicyPublicKey(pk)
				}
				return verify(thresh)
			}
			panic("invalid policy type") // developer error
		}
		return verify(p)
	}

	for i, in := range txn.SiacoinInputs {
		if types.PolicyAddress(in.SpendPolicy) != in.Parent.Address {
			return fmt.Errorf("siacoin input %v claims incorrect policy for parent address", i)
		} else if err := verifyPolicy(in.SpendPolicy, in.Signatures); err != nil {
			return fmt.Errorf("siacoin input %v failed to satisfy spend policy: %w", i, err)
		}
	}
	for i, in := range txn.SiafundInputs {
		if types.PolicyAddress(in.SpendPolicy) != in.Parent.Address {
			return fmt.Errorf("siafund input %v claims incorrect policy for parent address", i)
		} else if err := verifyPolicy(in.SpendPolicy, in.Signatures); err != nil {
			return fmt.Errorf("siafund input %v failed to satisfy spend policy: %w", i, err)
		}
	}
	return nil
}

// ValidateTransaction partially validates txn for inclusion in a child block.
// It does not validate ephemeral outputs.
func (vc *ValidationContext) ValidateTransaction(txn types.Transaction) error {
	if err := vc.containsZeroValuedOutputs(txn); err != nil {
		return err
	} else if err := vc.validTimeLocks(txn); err != nil {
		return err
	} else if err := vc.outputsEqualInputs(txn); err != nil {
		return err
	} else if err := vc.validStateProofs(txn); err != nil {
		return err
	} else if err := vc.validHistoryProofs(txn); err != nil {
		return err
	} else if err := vc.validFoundationUpdate(txn); err != nil {
		return err
	} else if err := vc.validFileContracts(txn); err != nil {
		return err
	} else if err := vc.validFileContractRevisions(txn); err != nil {
		return err
	} else if err := vc.validFileContractResolutions(txn); err != nil {
		return err
	} else if err := vc.validSpendPolicies(txn); err != nil {
		return err
	}
	return nil
}

func (vc *ValidationContext) validEphemeralOutputs(txns []types.Transaction) error {
	// skip this check if no ephemeral outputs are present
	for _, txn := range txns {
		for _, in := range txn.SiacoinInputs {
			if in.Parent.LeafIndex == types.EphemeralLeafIndex {
				goto validate
			}
		}
	}
	return nil

validate:
	available := make(map[types.OutputID]types.Beneficiary)
	for txnIndex, txn := range txns {
		txid := txn.ID()
		var index uint64
		nextID := func() types.OutputID {
			id := types.OutputID{
				TransactionID: txid,
				Index:         index,
			}
			index++
			return id
		}

		for _, in := range txn.SiacoinInputs {
			if in.Parent.LeafIndex == types.EphemeralLeafIndex {
				if out, ok := available[in.Parent.ID]; !ok {
					return fmt.Errorf("transaction set is invalid: transaction %v claims a non-existent ephemeral output", txnIndex)
				} else if in.Parent.Value != out.Value {
					return fmt.Errorf("transaction set is invalid: transaction %v claims wrong value for ephemeral output", txnIndex)
				} else if in.Parent.Address != out.Address {
					return fmt.Errorf("transaction set is invalid: transaction %v claims wrong address for ephemeral output", txnIndex)
				}
				delete(available, in.Parent.ID)
			}
		}
		for _, out := range txn.SiacoinOutputs {
			available[nextID()] = out
		}
	}
	return nil
}

func (vc *ValidationContext) noDoubleSpends(txns []types.Transaction) error {
	spent := make(map[types.OutputID]int)
	for i, txn := range txns {
		for _, in := range txn.SiacoinInputs {
			if prev, ok := spent[in.Parent.ID]; ok {
				return fmt.Errorf("transaction set is invalid: transaction %v double-spends siacoin output %v (previously spent in transaction %v)", i, in.Parent.ID, prev)
			}
			spent[in.Parent.ID] = i
		}
		for prev, in := range txn.SiafundInputs {
			if _, ok := spent[in.Parent.ID]; ok {
				return fmt.Errorf("transaction set is invalid: transaction %v double-spends siafund output %v (previously spent in transaction %v)", i, in.Parent.ID, prev)
			}
			spent[in.Parent.ID] = i
		}
	}
	return nil
}

// ValidateTransactionSet validates txns in their corresponding validation context.
func (vc *ValidationContext) ValidateTransactionSet(txns []types.Transaction) error {
	if vc.BlockWeight(txns) > vc.MaxBlockWeight() {
		return ErrOverweight
	} else if err := vc.validEphemeralOutputs(txns); err != nil {
		return err
	} else if err := vc.noDoubleSpends(txns); err != nil {
		return err
	}
	for i, txn := range txns {
		if err := vc.ValidateTransaction(txn); err != nil {
			return fmt.Errorf("transaction %v is invalid: %w", i, err)
		}
	}
	return nil
}

// ValidateBlock validates b in the context of vc.
func (vc *ValidationContext) ValidateBlock(b types.Block) error {
	h := b.Header
	if err := vc.validateHeader(h); err != nil {
		return err
	} else if vc.Commitment(h.MinerAddress, b.Transactions) != h.Commitment {
		return errors.New("commitment hash does not match header")
	} else if err := vc.ValidateTransactionSet(b.Transactions); err != nil {
		return err
	}
	return nil
}

// A Checkpoint pairs a block with the context used to validate its children.
type Checkpoint struct {
	Block   types.Block
	Context ValidationContext
}
