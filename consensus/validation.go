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

const foundationHardforkHeight = 300000

var (
	// ErrFutureBlock is returned by AppendHeader if a block's timestamp is too far
	// in the future. The block may be valid at a later time.
	ErrFutureBlock = errors.New("timestamp is too far in the future")

	// ErrOverweight is returned when a block's weight exceeds MaxBlockWeight.
	ErrOverweight = errors.New("block is too heavy")
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
		return types.BaseUnitsPerCoin.Mul64(initialCoinbase - blockHeight)
	}
	return types.BaseUnitsPerCoin.Mul64(minimumCoinbase)
}

// BlockRewardTimelock is the height at which a child block's reward becomes
// spendable.
func (vc *ValidationContext) BlockRewardTimelock() uint64 {
	return (vc.Index.Height + 1) + 144
}

// FoundationSubsidy returns the Foundation subsidy value for the child block.
func (vc *ValidationContext) FoundationSubsidy() types.Currency {
	const blocksPerYear = 144 * 365
	const foundationSubsidyFrequency = blocksPerYear / 12
	foundationSubsidyPerBlock := types.BaseUnitsPerCoin.Mul64(30000)
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
	return 100e3
}

// TransactionWeight computes the weight of a txn.
func (vc *ValidationContext) TransactionWeight(txn types.Transaction) (weight uint64) {
	weight += uint64(40 * len(txn.SiacoinInputs))
	weight += uint64(1 * len(txn.SiacoinOutputs))
	weight += uint64(40 * len(txn.SiafundInputs))
	weight += uint64(1 * len(txn.SiafundOutputs))
	return
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
func (vc *ValidationContext) FileContractTax(fc types.FileContractRevision) types.Currency {
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
	h.WriteChainIndex(windowStart)
	h.WriteOutputID(fcid)
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

	// instead of hashing all the data together, hash vc and txns separately;
	// this makes it possible to cheaply verify *just* the txns, or *just* the
	// minerAddr, etc.

	h.WriteUint64(vc.Index.Height)
	h.WriteHash(vc.Index.ID)
	h.WriteUint64(vc.State.NumLeaves)
	for i, root := range vc.State.Trees {
		if vc.State.HasTreeAtHeight(i) {
			h.WriteHash(root)
		}
	}
	h.WriteUint64(vc.History.NumLeaves)
	for i, root := range vc.History.Trees {
		if vc.History.HasTreeAtHeight(i) {
			h.WriteHash(root)
		}
	}
	for _, ts := range vc.PrevTimestamps {
		h.WriteTime(ts)
	}
	h.WriteHash(vc.TotalWork.NumHashes)
	h.WriteHash(vc.Difficulty.NumHashes)
	h.WriteHash(vc.OakWork.NumHashes)
	h.WriteUint64(uint64(vc.OakTime))
	h.WriteTime(vc.GenesisTimestamp)
	h.WriteCurrency(vc.SiafundPool)
	h.WriteHash(vc.FoundationAddress)
	ctxHash := h.Sum()

	h.Reset()
	for _, txn := range txns {
		for _, in := range txn.SiacoinInputs {
			h.WriteOutputID(in.Parent.ID)
			h.WriteCurrency(in.Parent.Value)
			h.WriteHash(in.Parent.Address)
			h.WriteUint64(in.Parent.Timelock)
			for _, p := range in.Parent.MerkleProof {
				h.WriteHash(p)
			}
			h.WriteUint64(in.Parent.LeafIndex)
			h.WriteHash(in.PublicKey)
			h.Write(in.Signature[:])
		}
		for _, out := range txn.SiacoinOutputs {
			h.WriteCurrency(out.Value)
			h.WriteHash(out.Address)
		}
		for _, in := range txn.SiafundInputs {
			h.WriteOutputID(in.Parent.ID)
			h.WriteCurrency(in.Parent.Value)
			h.WriteHash(in.Parent.Address)
			for _, p := range in.Parent.MerkleProof {
				h.WriteHash(p)
			}
			h.WriteUint64(in.Parent.LeafIndex)
			h.WriteHash(in.PublicKey)
			h.Write(in.Signature[:])
		}
		for _, out := range txn.SiafundOutputs {
			h.WriteCurrency(out.Value)
			h.WriteHash(out.Address)
		}
		for _, fc := range txn.FileContracts {
			h.WriteFileContractRevision(fc)
		}
		for _, fcr := range txn.FileContractResolutions {
			h.WriteOutputID(fcr.Parent.ID)
			h.WriteFileContractRevision(fcr.FinalRevision)
			h.Write(fcr.RenterSignature[:])
			h.Write(fcr.HostSignature[:])
			h.WriteChainIndex(fcr.StorageProof.WindowStart)
			for _, p := range fcr.StorageProof.WindowProof {
				h.WriteHash(p)
			}
			h.Write(fcr.StorageProof.DataSegment[:])
			for _, p := range fcr.StorageProof.SegmentProof {
				h.WriteHash(p)
			}
		}
		h.WriteHash(txn.NewFoundationAddress)
		h.WriteCurrency(txn.MinerFee)
	}
	txnsHash := h.Sum()

	h.Reset()
	h.WriteHash(ctxHash)
	h.WriteHash(minerAddr)
	h.WriteHash(txnsHash)
	return h.Sum()
}

// SigHash returns the hash that must be signed for each transaction input.
func (vc *ValidationContext) SigHash(txn types.Transaction) types.Hash256 {
	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	for _, in := range txn.SiacoinInputs {
		h.WriteOutputID(in.Parent.ID)
	}
	for _, out := range txn.SiacoinOutputs {
		h.WriteCurrency(out.Value)
		h.WriteHash(out.Address)
	}
	for _, in := range txn.SiafundInputs {
		h.WriteOutputID(in.Parent.ID)
	}
	for _, out := range txn.SiafundOutputs {
		h.WriteCurrency(out.Value)
		h.WriteHash(out.Address)
	}
	h.WriteHash(txn.NewFoundationAddress)
	h.WriteCurrency(txn.MinerFee)
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
	} else if types.WorkRequiredForHash(h.ID()).Cmp(vc.Difficulty) < 0 {
		return errors.New("insufficient work")
	} else if time.Until(h.Timestamp) > 2*time.Hour {
		return ErrFutureBlock
	} else if h.Timestamp.Before(vc.medianTimestamp()) {
		return errors.New("timestamp is too far in the past")
	}
	return nil
}

func (vc *ValidationContext) containsZeroValuedOutputs(txn types.Transaction) bool {
	for _, out := range txn.SiacoinOutputs {
		if out.Value.IsZero() {
			return true
		}
	}
	for _, out := range txn.SiafundOutputs {
		if out.Value.IsZero() {
			return true
		}
	}
	return false
}

func (vc *ValidationContext) validTimeLocks(txn types.Transaction) bool {
	blockHeight := vc.Index.Height + 1
	for _, in := range txn.SiacoinInputs {
		if in.Parent.Timelock > blockHeight {
			return false
		}
	}
	return true
}

func (vc *ValidationContext) validFileContracts(txn types.Transaction) bool {
	for _, fc := range txn.FileContracts {
		validSum := fc.ValidRenterOutput.Value.Add(fc.ValidHostOutput.Value)
		missedSum := fc.MissedRenterOutput.Value.Add(fc.MissedHostOutput.Value)
		if missedSum.Cmp(validSum) > 0 {
			return false
		} else if fc.WindowEnd <= fc.WindowStart {
			return false
		}
	}
	return true
}

func (vc *ValidationContext) validFileContractResolutions(txn types.Transaction) bool {
	for _, fcr := range txn.FileContractResolutions {
		rev := fcr.Parent.Revision
		if fcr.HasRevision() {
			oldValidSum := rev.ValidRenterOutput.Value.Add(rev.ValidHostOutput.Value)
			validSum := fcr.FinalRevision.ValidRenterOutput.Value.Add(fcr.FinalRevision.ValidHostOutput.Value)
			missedSum := fcr.FinalRevision.MissedRenterOutput.Value.Add(fcr.FinalRevision.MissedHostOutput.Value)
			switch {
			case fcr.FinalRevision.RevisionNumber <= rev.RevisionNumber:
				return false
			case !validSum.Equals(oldValidSum):
				return false
			case missedSum.Cmp(validSum) > 0:
				return false
			case fcr.FinalRevision.WindowEnd <= fcr.FinalRevision.WindowStart:
				return false
			}
			rev = fcr.FinalRevision
		}

		if fcr.HasStorageProof() {
			// we must be within the proof window
			if vc.Index.Height < rev.WindowStart || rev.WindowEnd < vc.Index.Height {
				return false
			}
			// validate storage proof
			if fcr.StorageProof.WindowStart.Height != rev.WindowStart {
				// see note on this field in types.StorageProof
				return false
			}
			segmentIndex := vc.StorageProofSegmentIndex(rev.Filesize, fcr.StorageProof.WindowStart, fcr.Parent.ID)
			if storageProofRoot(fcr.StorageProof, segmentIndex) != rev.FileMerkleRoot {
				return false
			}
		} else {
			// contract must have expired
			if vc.Index.Height <= rev.WindowEnd {
				return false
			}
		}
	}
	return true
}

func (vc *ValidationContext) validPubkeys(txn types.Transaction) bool {
	for _, in := range txn.SiacoinInputs {
		if in.PublicKey.Address() != in.Parent.Address {
			return false
		}
	}
	for _, in := range txn.SiafundInputs {
		if in.PublicKey.Address() != in.Parent.Address {
			return false
		}
	}
	return true
}

func (vc *ValidationContext) outputsEqualInputs(txn types.Transaction) bool {
	var inputSC, outputSC types.Currency
	var overflowed bool
	for _, in := range txn.SiacoinInputs {
		inputSC, overflowed = inputSC.AddWithOverflow(in.Parent.Value)
		if overflowed {
			return false
		}
	}
	for _, out := range txn.SiacoinOutputs {
		outputSC, overflowed = outputSC.AddWithOverflow(out.Value)
		if overflowed {
			return false
		}
	}
	for _, fc := range txn.FileContracts {
		outputSC, overflowed = outputSC.AddWithOverflow(fc.ValidRenterOutput.Value)
		if overflowed {
			return false
		}
		outputSC, overflowed = outputSC.AddWithOverflow(fc.ValidHostOutput.Value)
		if overflowed {
			return false
		}
		outputSC, overflowed = outputSC.AddWithOverflow(vc.FileContractTax(fc))
		if overflowed {
			return false
		}
	}
	outputSC, overflowed = outputSC.AddWithOverflow(txn.MinerFee)
	if overflowed || inputSC != outputSC {
		return false
	}

	var inputSF, outputSF types.Currency
	for _, in := range txn.SiafundInputs {
		inputSF, overflowed = inputSF.AddWithOverflow(in.Parent.Value)
		if overflowed {
			return false
		}
	}
	for _, out := range txn.SiafundOutputs {
		outputSF, overflowed = outputSF.AddWithOverflow(out.Value)
		if overflowed {
			return false
		}
	}
	if overflowed || inputSF != outputSF {
		return false
	}

	return true
}

func (vc *ValidationContext) validStateProofs(txn types.Transaction) bool {
	for _, in := range txn.SiacoinInputs {
		if in.Parent.LeafIndex != types.EphemeralLeafIndex && !vc.State.ContainsUnspentSiacoinOutput(in.Parent) {
			return false
		}
	}
	for _, in := range txn.SiafundInputs {
		if !vc.State.ContainsUnspentSiafundOutput(in.Parent) {
			return false
		}
	}
	for _, fcr := range txn.FileContractResolutions {
		if !vc.State.ContainsUnresolvedFileContract(fcr.Parent) {
			return false
		}
	}
	return true
}

func (vc *ValidationContext) validHistoryProofs(txn types.Transaction) bool {
	for _, fcr := range txn.FileContractResolutions {
		if fcr.HasStorageProof() && !vc.History.Contains(fcr.StorageProof.WindowStart, fcr.StorageProof.WindowProof) {
			return false
		}
	}
	return true
}

func (vc *ValidationContext) validFoundationUpdate(txn types.Transaction) bool {
	if txn.NewFoundationAddress == types.VoidAddress {
		return true
	}
	for _, in := range txn.SiacoinInputs {
		if in.Parent.Address == vc.FoundationAddress {
			return true
		}
	}
	return false
}

func (vc *ValidationContext) validSignatures(txn types.Transaction) bool {
	sigHash := vc.SigHash(txn)
	for _, in := range txn.SiacoinInputs {
		if !ed25519.Verify(in.PublicKey[:], sigHash[:], in.Signature[:]) {
			return false
		}
	}
	for _, in := range txn.SiafundInputs {
		if !ed25519.Verify(in.PublicKey[:], sigHash[:], in.Signature[:]) {
			return false
		}
	}
	for _, fcr := range txn.FileContractResolutions {
		// NOTE: very important that we verify with the parent keys, *not* the
		// revised keys!
		if !ed25519.Verify(fcr.Parent.Revision.RenterPublicKey[:], sigHash[:], fcr.RenterSignature[:]) {
			return false
		}
		if !ed25519.Verify(fcr.Parent.Revision.HostPublicKey[:], sigHash[:], fcr.HostSignature[:]) {
			return false
		}
	}
	return true
}

// ValidateTransaction partially validates txn for inclusion in a child block.
// It does not validate ephemeral outputs.
func (vc *ValidationContext) ValidateTransaction(txn types.Transaction) error {
	switch {
	case vc.containsZeroValuedOutputs(txn):
		return errors.New("transaction contains zero-valued outputs")
	case !vc.validTimeLocks(txn):
		return errors.New("transaction spends time-locked outputs")
	case !vc.outputsEqualInputs(txn):
		return errors.New("outputs of transaction do not equal its inputs")
	case !vc.validPubkeys(txn):
		return errors.New("transaction contains unlock conditions that do not hash to the correct address")
	case !vc.validStateProofs(txn):
		return errors.New("transaction contains an invalid state proof")
	case !vc.validHistoryProofs(txn):
		return errors.New("transaction contains an invalid history proof")
	case !vc.validFoundationUpdate(txn):
		return errors.New("transaction contains an invalid Foundation address update")
	case !vc.validFileContracts(txn):
		return errors.New("transaction contains an invalid file contract")
	case !vc.validFileContractResolutions(txn):
		return errors.New("transaction contains an invalid file contract resolution")
	case !vc.validSignatures(txn):
		return errors.New("transaction contains an invalid signature")
	}
	return nil
}

func (vc *ValidationContext) validEphemeralOutputs(txns []types.Transaction) error {
	// TODO: this is rather inefficient. Definitely need a better algorithm.
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
	spent := make(map[types.OutputID]struct{})
	for i, txn := range txns {
		for _, in := range txn.SiacoinInputs {
			if _, ok := spent[in.Parent.ID]; ok {
				return fmt.Errorf("transaction set is invalid: transaction %v double-spends %v", i, in.Parent.ID)
			}
			spent[in.Parent.ID] = struct{}{}
		}
		for _, in := range txn.SiafundInputs {
			if _, ok := spent[in.Parent.ID]; ok {
				return fmt.Errorf("transaction set is invalid: transaction %v double-spends %v", i, in.Parent.ID)
			}
			spent[in.Parent.ID] = struct{}{}
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
