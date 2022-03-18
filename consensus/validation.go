// Package consensus implements the Sia consensus algorithms.
package consensus

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"sort"
	"sync"
	"time"

	"go.sia.tech/core/merkle"
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

// Pool for reducing heap allocations when hashing. This is only necessary
// because blake2b.New256 returns a hash.Hash interface, which prevents the
// compiler from doing escape analysis. Can be removed if we switch to an
// implementation whose constructor returns a concrete type.
var hasherPool = &sync.Pool{New: func() interface{} { return types.NewHasher() }}

// ValidationContext contains the necessary context to fully validate a block.
type ValidationContext struct {
	Index types.ChainIndex `json:"index"`

	State          merkle.ElementAccumulator `json:"state"`
	History        merkle.HistoryAccumulator `json:"history"`
	PrevTimestamps [11]time.Time             `json:"prevTimestamps"`

	TotalWork        types.Work    `json:"totalWork"`
	Difficulty       types.Work    `json:"difficulty"`
	OakWork          types.Work    `json:"oakWork"`
	OakTime          time.Duration `json:"oakTime"`
	GenesisTimestamp time.Time     `json:"genesisTimestamp"`

	SiafundPool       types.Currency `json:"siafundPool"`
	FoundationAddress types.Address  `json:"foundationAddress"`
}

// EncodeTo implements types.EncoderTo.
func (vc ValidationContext) EncodeTo(e *types.Encoder) {
	vc.Index.EncodeTo(e)
	vc.State.EncodeTo(e)
	vc.History.EncodeTo(e)
	for _, ts := range vc.PrevTimestamps {
		e.WriteTime(ts)
	}
	vc.TotalWork.EncodeTo(e)
	vc.Difficulty.EncodeTo(e)
	vc.OakWork.EncodeTo(e)
	e.WriteUint64(uint64(vc.OakTime))
	e.WriteTime(vc.GenesisTimestamp)
	vc.SiafundPool.EncodeTo(e)
	vc.FoundationAddress.EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (vc *ValidationContext) DecodeFrom(d *types.Decoder) {
	vc.Index.DecodeFrom(d)
	vc.State.DecodeFrom(d)
	vc.History.DecodeFrom(d)
	for i := range vc.PrevTimestamps {
		vc.PrevTimestamps[i] = d.ReadTime()
	}
	vc.TotalWork.DecodeFrom(d)
	vc.Difficulty.DecodeFrom(d)
	vc.OakWork.DecodeFrom(d)
	vc.OakTime = time.Duration(d.ReadUint64())
	vc.GenesisTimestamp = d.ReadTime()
	vc.SiafundPool.DecodeFrom(d)
	vc.FoundationAddress.DecodeFrom(d)
}

// BlockReward returns the reward for mining a child block.
func (vc ValidationContext) BlockReward() types.Currency {
	const initialCoinbase = 300000
	const minimumCoinbase = 30000
	blockHeight := vc.Index.Height + 1
	if blockHeight < initialCoinbase-minimumCoinbase {
		return types.Siacoins(uint32(initialCoinbase - blockHeight))
	}
	return types.Siacoins(minimumCoinbase)
}

// MaturityHeight is the height at which various outputs created in the child
// block will "mature" (become spendable).
//
// To prevent reorgs from invalidating large swathes of transactions, we impose
// a timelock on any output that is "linked" to a particular block.
// Specifically, we timelock block rewards, Foundation subsidies, siafund
// claims, and contract resolutions. If a reorg occurs, these outputs may no
// longer exist, so transactions that use them may become invalid (along with
// any transaction that depend on *those* transactions, and so on). Adding a
// timelock does not completely eliminate this issue -- after all, reorgs can be
// arbitrarily deep -- but it does make it highly unlikely to occur in practice.
func (vc ValidationContext) MaturityHeight() uint64 {
	return (vc.Index.Height + 1) + 144
}

// FoundationSubsidy returns the Foundation subsidy value for the child block.
func (vc ValidationContext) FoundationSubsidy() types.Currency {
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
func (vc ValidationContext) MaxBlockWeight() uint64 {
	return 2_000_000
}

// TransactionWeight computes the weight of a txn.
func (vc ValidationContext) TransactionWeight(txn types.Transaction) uint64 {
	storage := types.EncodedLen(txn)

	var signatures int
	for _, in := range txn.SiacoinInputs {
		signatures += len(in.Signatures)
	}
	for _, in := range txn.SiafundInputs {
		signatures += len(in.Signatures)
	}
	signatures += 2 * len(txn.FileContractRevisions)
	signatures += len(txn.Attestations)

	return uint64(storage) + 100*uint64(signatures)
}

// BlockWeight computes the combined weight of a block's txns.
func (vc ValidationContext) BlockWeight(txns []types.Transaction) uint64 {
	var weight uint64
	for _, txn := range txns {
		weight += vc.TransactionWeight(txn)
	}
	return weight
}

// FileContractTax computes the tax levied on a given contract.
func (vc ValidationContext) FileContractTax(fc types.FileContract) types.Currency {
	sum := fc.RenterOutput.Value.Add(fc.HostOutput.Value)
	tax := sum.Div64(25) // 4%
	// round down to nearest multiple of SiafundCount
	_, r := bits.Div64(0, tax.Hi, SiafundCount)
	_, r = bits.Div64(r, tax.Lo, SiafundCount)
	return tax.Sub(types.NewCurrency64(r))
}

// StorageProofLeafIndex returns the leaf index used when computing or
// validating a storage proof.
func (vc ValidationContext) StorageProofLeafIndex(filesize uint64, windowStart types.ChainIndex, fcid types.ElementID) uint64 {
	const leafSize = uint64(len(types.StorageProof{}.Leaf))
	if filesize <= leafSize {
		return 0
	}
	numLeaves := filesize / leafSize
	if filesize%leafSize != 0 {
		numLeaves++
	}

	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	windowStart.EncodeTo(h.E)
	fcid.EncodeTo(h.E)
	seed := h.Sum()

	var r uint64
	for i := 0; i < len(seed); i += 8 {
		_, r = bits.Div64(r, binary.BigEndian.Uint64(seed[i:]), numLeaves)
	}
	return r
}

// Commitment computes the commitment hash for a child block.
func (vc ValidationContext) Commitment(minerAddr types.Address, txns []types.Transaction) types.Hash256 {
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
	h.E.WriteString("sia/commitment")
	ctxHash.EncodeTo(h.E)
	minerAddr.EncodeTo(h.E)
	txnsHash.EncodeTo(h.E)
	return h.Sum()
}

// InputSigHash returns the hash that must be signed for each transaction input.
func (vc ValidationContext) InputSigHash(txn types.Transaction) types.Hash256 {
	// NOTE: This currently covers exactly the same fields as txn.ID(), and for
	// similar reasons.
	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	h.E.WriteString("sia/sig/transactioninput")
	h.E.WritePrefix(len(txn.SiacoinInputs))
	for _, in := range txn.SiacoinInputs {
		in.Parent.ID.EncodeTo(h.E)
	}
	h.E.WritePrefix(len(txn.SiacoinOutputs))
	for _, out := range txn.SiacoinOutputs {
		out.EncodeTo(h.E)
	}
	h.E.WritePrefix(len(txn.SiafundInputs))
	for _, in := range txn.SiafundInputs {
		in.Parent.ID.EncodeTo(h.E)
	}
	h.E.WritePrefix(len(txn.SiafundOutputs))
	for _, out := range txn.SiafundOutputs {
		out.EncodeTo(h.E)
	}
	h.E.WritePrefix(len(txn.FileContracts))
	for _, fc := range txn.FileContracts {
		fc.EncodeTo(h.E)
	}
	h.E.WritePrefix(len(txn.FileContractRevisions))
	for _, fcr := range txn.FileContractRevisions {
		fcr.Parent.ID.EncodeTo(h.E)
		fcr.Revision.EncodeTo(h.E)
	}
	h.E.WritePrefix(len(txn.FileContractResolutions))
	for _, fcr := range txn.FileContractResolutions {
		fcr.Parent.ID.EncodeTo(h.E)
		fcr.Renewal.EncodeTo(h.E)
		fcr.StorageProof.WindowStart.EncodeTo(h.E)
		fcr.Finalization.EncodeTo(h.E)
	}
	for _, a := range txn.Attestations {
		a.EncodeTo(h.E)
	}
	h.E.WriteBytes(txn.ArbitraryData)
	txn.NewFoundationAddress.EncodeTo(h.E)
	txn.MinerFee.EncodeTo(h.E)
	return h.Sum()
}

// ContractSigHash returns the hash that must be signed for a file contract revision.
func (vc ValidationContext) ContractSigHash(fc types.FileContract) types.Hash256 {
	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	h.E.WriteString("sia/sig/filecontract")
	h.E.WriteUint64(fc.Filesize)
	fc.FileMerkleRoot.EncodeTo(h.E)
	h.E.WriteUint64(fc.WindowStart)
	h.E.WriteUint64(fc.WindowEnd)
	fc.RenterOutput.EncodeTo(h.E)
	fc.HostOutput.EncodeTo(h.E)
	fc.MissedHostValue.EncodeTo(h.E)
	fc.RenterPublicKey.EncodeTo(h.E)
	fc.HostPublicKey.EncodeTo(h.E)
	h.E.WriteUint64(fc.RevisionNumber)
	return h.Sum()
}

// RenewalSigHash returns the hash that must be signed for a file contract renewal.
func (vc ValidationContext) RenewalSigHash(fcr types.FileContractRenewal) types.Hash256 {
	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	h.E.WriteString("sia/sig/filecontractrenewal")
	fcr.FinalRevision.EncodeTo(h.E)
	fcr.InitialRevision.EncodeTo(h.E)
	fcr.RenterRollover.EncodeTo(h.E)
	fcr.HostRollover.EncodeTo(h.E)
	return h.Sum()
}

// AttestationSigHash returns the hash that must be signed for an attestation.
func (vc ValidationContext) AttestationSigHash(a types.Attestation) types.Hash256 {
	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	h.E.WriteString("sia/sig/attestation")
	a.PublicKey.EncodeTo(h.E)
	h.E.WriteString(a.Key)
	h.E.WriteBytes(a.Value)
	return h.Sum()
}

func (vc ValidationContext) numTimestamps() int {
	if vc.Index.Height+1 < uint64(len(vc.PrevTimestamps)) {
		return int(vc.Index.Height + 1)
	}
	return len(vc.PrevTimestamps)
}

func (vc ValidationContext) medianTimestamp() time.Time {
	prevCopy := vc.PrevTimestamps
	ts := prevCopy[:vc.numTimestamps()]
	sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
	if len(ts)%2 != 0 {
		return ts[len(ts)/2]
	}
	l, r := ts[len(ts)/2-1], ts[len(ts)/2]
	return l.Add(r.Sub(l) / 2)
}

func (vc ValidationContext) validateHeader(h types.BlockHeader) error {
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

func (vc ValidationContext) validateCurrencyValues(txn types.Transaction) error {
	// Add up all of the currency values in the transaction and check for
	// overflow. This allows us to freely add any currency values in later
	// validation functions without worrying about overflow.
	//
	// NOTE: This check could be a little more "tolerant" -- currently it adds
	// both the input and output values to the same sum, and it double-counts
	// some value in file contracts. Even so, it won't be possible to construct
	// a valid transaction that fails this check for ~50,000 years.

	var sum types.Currency
	var sum64 uint64
	var overflowed bool
	add := func(x types.Currency) {
		if !overflowed {
			sum, overflowed = sum.AddWithOverflow(x)
		}
	}
	add64 := func(x uint64) {
		if !overflowed {
			s, carry := bits.Add64(sum64, x, 0)
			sum64, overflowed = s, carry > 0
		}
	}
	addContract := func(fc types.FileContract) {
		add(fc.RenterOutput.Value)
		add(fc.HostOutput.Value)
		add(fc.MissedHostValue)
		add(fc.TotalCollateral)
		add(vc.FileContractTax(fc))
	}

	for _, in := range txn.SiacoinInputs {
		add(in.Parent.Value)
	}
	for i, out := range txn.SiacoinOutputs {
		if out.Value.IsZero() {
			return fmt.Errorf("siacoin output %v has zero value", i)
		}
		add(out.Value)
	}
	for _, in := range txn.SiafundInputs {
		add64(in.Parent.Value)
	}
	for i, out := range txn.SiafundOutputs {
		if out.Value == 0 {
			return fmt.Errorf("siafund output %v has zero value", i)
		}
		add64(out.Value)
	}
	for _, fc := range txn.FileContracts {
		addContract(fc)
	}
	for _, fc := range txn.FileContractRevisions {
		addContract(fc.Revision)
	}
	for _, fcr := range txn.FileContractResolutions {
		if fcr.HasRenewal() {
			add(fcr.Renewal.RenterRollover)
			add(fcr.Renewal.HostRollover)
			addContract(fcr.Renewal.InitialRevision)
		} else if fcr.HasFinalization() {
			addContract(fcr.Finalization)
		}
	}
	add(txn.MinerFee)
	if overflowed {
		return ErrOverflow
	}
	return nil
}

func (vc ValidationContext) validateTimeLocks(txn types.Transaction) error {
	blockHeight := vc.Index.Height + 1
	for i, in := range txn.SiacoinInputs {
		if in.Parent.MaturityHeight > blockHeight {
			return fmt.Errorf("siacoin input %v does not mature until block %v", i, in.Parent.MaturityHeight)
		}
	}
	return nil
}

func (vc ValidationContext) validateContract(fc types.FileContract) error {
	switch {
	case fc.WindowEnd <= vc.Index.Height:
		return fmt.Errorf("has proof window (%v-%v) that ends in the past", fc.WindowStart, fc.WindowEnd)
	case fc.WindowEnd <= fc.WindowStart:
		return fmt.Errorf("has proof window (%v-%v) that ends before it begins", fc.WindowStart, fc.WindowEnd)
	case fc.MissedHostValue.Cmp(fc.HostOutput.Value) > 0:
		return fmt.Errorf("has missed host value (%v SC) exceeding valid host value (%v SC)", fc.MissedHostValue, fc.HostOutput.Value)
	case fc.TotalCollateral.Cmp(fc.HostOutput.Value) > 0:
		return fmt.Errorf("has total collateral (%v SC) exceeding valid host value (%v SC)", fc.TotalCollateral, fc.HostOutput.Value)
	}
	contractHash := vc.ContractSigHash(fc)
	if !fc.RenterPublicKey.VerifyHash(contractHash, fc.RenterSignature) {
		return fmt.Errorf("has invalid renter signature")
	} else if !fc.HostPublicKey.VerifyHash(contractHash, fc.HostSignature) {
		return fmt.Errorf("has invalid host signature")
	}
	return nil
}

func (vc ValidationContext) validateRevision(cur, rev types.FileContract) error {
	curOutputSum := cur.RenterOutput.Value.Add(cur.HostOutput.Value)
	revOutputSum := rev.RenterOutput.Value.Add(rev.HostOutput.Value)
	switch {
	case rev.RevisionNumber <= cur.RevisionNumber:
		return fmt.Errorf("does not increase revision number (%v -> %v)", cur.RevisionNumber, rev.RevisionNumber)
	case !revOutputSum.Equals(curOutputSum):
		return fmt.Errorf("modifies output sum (%v SC -> %v SC)", curOutputSum, revOutputSum)
	case rev.TotalCollateral != cur.TotalCollateral:
		return fmt.Errorf("modifies total collateral")
	case rev.WindowEnd <= vc.Index.Height:
		return fmt.Errorf("has proof window (%v-%v) that ends in the past", rev.WindowStart, rev.WindowEnd)
	case rev.WindowEnd <= rev.WindowStart:
		return fmt.Errorf("has proof window (%v - %v) that ends before it begins", rev.WindowStart, rev.WindowEnd)
	}

	// verify signatures
	//
	// NOTE: very important that we verify with the *current* keys!
	contractHash := vc.ContractSigHash(rev)
	if !cur.RenterPublicKey.VerifyHash(contractHash, rev.RenterSignature) {
		return fmt.Errorf("has invalid renter signature")
	} else if !cur.HostPublicKey.VerifyHash(contractHash, rev.HostSignature) {
		return fmt.Errorf("has invalid host signature")
	}
	return nil
}

func (vc ValidationContext) validateFileContracts(txn types.Transaction) error {
	for i, fc := range txn.FileContracts {
		if err := vc.validateContract(fc); err != nil {
			return fmt.Errorf("file contract %v %s", i, err)
		}
	}
	return nil
}

func (vc ValidationContext) validateFileContractRevisions(txn types.Transaction) error {
	for i, fcr := range txn.FileContractRevisions {
		cur, rev := fcr.Parent.FileContract, fcr.Revision
		if vc.Index.Height > cur.WindowStart {
			return fmt.Errorf("file contract revision %v cannot be applied to contract whose proof window (%v - %v) has already begun", i, cur.WindowStart, cur.WindowEnd)
		} else if err := vc.validateRevision(cur, rev); err != nil {
			return fmt.Errorf("file contract revision %v %s", i, err)
		}
	}
	return nil
}

func (vc ValidationContext) validateFileContractResolutions(txn types.Transaction) error {
	for i, fcr := range txn.FileContractResolutions {
		// only one resolution type should be present
		var typs int
		for _, b := range [...]bool{
			fcr.HasRenewal(),
			fcr.HasStorageProof(),
			fcr.HasFinalization(),
		} {
			if b {
				typs++
			}
		}
		if typs > 1 {
			return fmt.Errorf("file contract resolution %v has multiple resolution types", i)
		}

		fc := fcr.Parent.FileContract
		if fcr.HasRenewal() {
			// renter and host want to renew the contract, carrying over some
			// funds and releasing the rest; this can be done at any point
			// before WindowEnd (even before WindowStart)
			old, renewed := fcr.Renewal.FinalRevision, fcr.Renewal.InitialRevision
			if fc.WindowEnd < vc.Index.Height {
				return fmt.Errorf("file contract renewal %v cannot be applied to contract whose proof window (%v - %v) has expired", i, fc.WindowStart, fc.WindowEnd)
			} else if old.RevisionNumber != types.MaxRevisionNumber {
				return fmt.Errorf("file contract renewal %v does not finalize old contract", i)
			} else if err := vc.validateRevision(fc, old); err != nil {
				return fmt.Errorf("file contract renewal %v has final revision that %s", i, err)
			} else if err := vc.validateContract(renewed); err != nil {
				return fmt.Errorf("file contract renewal %v has initial revision that %s", i, err)
			}

			// rollover must not exceed total contract value
			rollover := fcr.Renewal.RenterRollover.Add(fcr.Renewal.HostRollover)
			newContractCost := renewed.RenterOutput.Value.Add(renewed.HostOutput.Value).Add(vc.FileContractTax(renewed))
			if fcr.Renewal.RenterRollover.Cmp(old.RenterOutput.Value) > 0 {
				return fmt.Errorf("file contract renewal %v has renter rollover (%v SC) exceeding old output (%v SC)", i, fcr.Renewal.RenterRollover, old.RenterOutput.Value)
			} else if fcr.Renewal.HostRollover.Cmp(old.HostOutput.Value) > 0 {
				return fmt.Errorf("file contract renewal %v has host rollover (%v SC) exceeding old output (%v SC)", i, fcr.Renewal.HostRollover, old.HostOutput.Value)
			} else if rollover.Cmp(newContractCost) > 0 {
				return fmt.Errorf("file contract renewal %v has rollover (%v SC) exceeding new contract cost (%v SC)", i, rollover, newContractCost)
			}

			renewalHash := vc.RenewalSigHash(fcr.Renewal)
			if !fc.RenterPublicKey.VerifyHash(renewalHash, fcr.Renewal.RenterSignature) {
				return fmt.Errorf("file contract renewal %v has invalid renter signature", i)
			} else if !fc.HostPublicKey.VerifyHash(renewalHash, fcr.Renewal.HostSignature) {
				return fmt.Errorf("file contract renewal %v has invalid host signature", i)
			}
		} else if fcr.HasFinalization() {
			// renter and host have agreed upon an explicit final contract
			// state; this can be done at any point before WindowEnd (even
			// before WindowStart)
			if fc.WindowEnd < vc.Index.Height {
				return fmt.Errorf("file contract finalization %v cannot be applied to contract whose proof window (%v - %v) has expired", i, fc.WindowStart, fc.WindowEnd)
			} else if fcr.Finalization.RevisionNumber != types.MaxRevisionNumber {
				return fmt.Errorf("file contract finalization %v does not set maximum revision number", i)
			} else if err := vc.validateRevision(fc, fcr.Finalization); err != nil {
				return fmt.Errorf("file contract finalization %v %s", i, err)
			}
		} else if fcr.HasStorageProof() {
			// we must be within the proof window
			if vc.Index.Height < fc.WindowStart || fc.WindowEnd < vc.Index.Height {
				return fmt.Errorf("storage proof %v attempts to claim valid outputs outside the proof window (%v - %v)", i, fc.WindowStart, fc.WindowEnd)
			} else if fcr.StorageProof.WindowStart.Height != fc.WindowStart {
				// see note on this field in types.StorageProof
				return fmt.Errorf("storage proof %v has WindowStart (%v) that does not match contract WindowStart (%v)", i, fcr.StorageProof.WindowStart.Height, fc.WindowStart)
			}
			leafIndex := vc.StorageProofLeafIndex(fc.Filesize, fcr.StorageProof.WindowStart, fcr.Parent.ID)
			if merkle.StorageProofRoot(fcr.StorageProof, leafIndex) != fc.FileMerkleRoot {
				return fmt.Errorf("storage proof %v has root that does not match contract Merkle root", i)
			}
		} else if fc.Filesize == 0 {
			// empty contract; can claim valid outputs after WindowStart
			if vc.Index.Height < fc.WindowStart {
				return fmt.Errorf("file contract expiration %v attempts to claim valid outputs, but proof window (%v - %v) has not begun", i, fc.WindowStart, fc.WindowEnd)
			}
		} else {
			// non-empty contract; can claim missed outputs after WindowEnd
			if vc.Index.Height <= fc.WindowEnd {
				return fmt.Errorf("file contract expiration %v attempts to claim missed outputs, but proof window (%v - %v) has not expired", i, fc.WindowStart, fc.WindowEnd)
			}
		}
	}
	return nil
}

func (vc ValidationContext) validateAttestations(txn types.Transaction) error {
	for i, a := range txn.Attestations {
		switch {
		case len(a.Key) == 0:
			return fmt.Errorf("attestation %v has empty key", i)
		case !a.PublicKey.VerifyHash(vc.AttestationSigHash(a), a.Signature):
			return fmt.Errorf("attestation %v has invalid signature", i)
		}
	}
	return nil
}

func (vc ValidationContext) outputsEqualInputs(txn types.Transaction) error {
	var inputSC, outputSC types.Currency
	for _, in := range txn.SiacoinInputs {
		inputSC = inputSC.Add(in.Parent.Value)
	}
	for _, out := range txn.SiacoinOutputs {
		outputSC = outputSC.Add(out.Value)
	}
	for _, fc := range txn.FileContracts {
		outputSC = outputSC.Add(fc.RenterOutput.Value).Add(fc.HostOutput.Value).Add(vc.FileContractTax(fc))
	}
	for _, fcr := range txn.FileContractResolutions {
		if fcr.HasRenewal() {
			// a renewal creates a new contract, optionally "rolling over" funds
			// from the old contract
			inputSC = inputSC.Add(fcr.Renewal.RenterRollover)
			inputSC = inputSC.Add(fcr.Renewal.HostRollover)

			rev := fcr.Renewal.InitialRevision
			outputSC = outputSC.Add(rev.RenterOutput.Value).Add(rev.HostOutput.Value).Add(vc.FileContractTax(rev))
		}
	}

	outputSC = outputSC.Add(txn.MinerFee)
	if inputSC != outputSC {
		return fmt.Errorf("siacoin inputs (%v SC) do not equal siacoin outputs (%v SC)", inputSC, outputSC)
	}

	var inputSF, outputSF uint64
	for _, in := range txn.SiafundInputs {
		inputSF += in.Parent.Value
	}
	for _, out := range txn.SiafundOutputs {
		outputSF += out.Value
	}
	if inputSF != outputSF {
		return fmt.Errorf("siafund inputs (%d SF) do not equal siafund outputs (%d SF)", inputSF, outputSF)
	}

	return nil
}

func (vc ValidationContext) validateStateProofs(txn types.Transaction) error {
	for i, in := range txn.SiacoinInputs {
		switch {
		case in.Parent.LeafIndex == types.EphemeralLeafIndex:
			continue
		case vc.State.ContainsUnspentSiacoinElement(in.Parent):
			continue
		case vc.State.ContainsSpentSiacoinElement(in.Parent):
			return fmt.Errorf("siacoin input %v double-spends output %v", i, in.Parent.ID)
		default:
			return fmt.Errorf("siacoin input %v spends output (%v) not present in the accumulator", i, in.Parent.ID)
		}
	}
	for i, in := range txn.SiafundInputs {
		switch {
		case vc.State.ContainsUnspentSiafundElement(in.Parent):
			continue
		case vc.State.ContainsSpentSiafundElement(in.Parent):
			return fmt.Errorf("siafund input %v double-spends output %v", i, in.Parent.ID)
		default:
			return fmt.Errorf("siafund input %v spends output (%v) not present in the accumulator", i, in.Parent.ID)
		}
	}
	for i, fcr := range txn.FileContractRevisions {
		switch {
		case vc.State.ContainsUnresolvedFileContractElement(fcr.Parent):
			continue
		case vc.State.ContainsResolvedFileContractElement(fcr.Parent):
			return fmt.Errorf("file contract revision %v revises a contract (%v) that has already resolved", i, fcr.Parent.ID)
		default:
			return fmt.Errorf("file contract revision %v revises a contract (%v) not present in the accumulator", i, fcr.Parent.ID)
		}
	}
	for i, fcr := range txn.FileContractResolutions {
		switch {
		case vc.State.ContainsUnresolvedFileContractElement(fcr.Parent):
			continue
		case vc.State.ContainsResolvedFileContractElement(fcr.Parent):
			return fmt.Errorf("file contract resolution %v resolves a contract (%v) that has already resolved", i, fcr.Parent.ID)
		default:
			return fmt.Errorf("file contract resolution %v resolves a contract (%v) not present in the accumulator", i, fcr.Parent.ID)
		}
	}
	return nil
}

func (vc ValidationContext) validateHistoryProofs(txn types.Transaction) error {
	for i, fcr := range txn.FileContractResolutions {
		if fcr.HasStorageProof() && !vc.History.Contains(fcr.StorageProof.WindowStart, fcr.StorageProof.WindowProof) {
			return fmt.Errorf("file contract resolution %v has storage proof with invalid history proof", i)
		}
	}
	return nil
}

func (vc ValidationContext) validateFoundationUpdate(txn types.Transaction) error {
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

func (vc ValidationContext) validateSpendPolicies(txn types.Transaction) error {
	sigHash := vc.InputSigHash(txn)
	verifyPolicy := func(p types.SpendPolicy, sigs []types.Signature) error {
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
					if types.PublicKey(p).VerifyHash(sigHash, sigs[i]) {
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
func (vc ValidationContext) ValidateTransaction(txn types.Transaction) error {
	// check proofs first; that way, subsequent checks can assume that all
	// parent StateElements are valid
	if err := vc.validateStateProofs(txn); err != nil {
		return err
	} else if err := vc.validateHistoryProofs(txn); err != nil {
		return err
	}

	if err := vc.validateCurrencyValues(txn); err != nil {
		return err
	} else if err := vc.validateTimeLocks(txn); err != nil {
		return err
	} else if err := vc.outputsEqualInputs(txn); err != nil {
		return err
	} else if err := vc.validateFoundationUpdate(txn); err != nil {
		return err
	} else if err := vc.validateFileContracts(txn); err != nil {
		return err
	} else if err := vc.validateFileContractRevisions(txn); err != nil {
		return err
	} else if err := vc.validateFileContractResolutions(txn); err != nil {
		return err
	} else if err := vc.validateAttestations(txn); err != nil {
		return err
	} else if err := vc.validateSpendPolicies(txn); err != nil {
		return err
	}
	return nil
}

func (vc ValidationContext) validateEphemeralOutputs(txns []types.Transaction) error {
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
	available := make(map[types.ElementID]types.SiacoinOutput)
	for txnIndex, txn := range txns {
		txid := txn.ID()
		var index uint64
		nextID := func() types.ElementID {
			id := types.ElementID{
				Source: types.Hash256(txid),
				Index:  index,
			}
			index++
			return id
		}

		for _, in := range txn.SiacoinInputs {
			if in.Parent.LeafIndex == types.EphemeralLeafIndex {
				if out, ok := available[in.Parent.ID]; !ok {
					return fmt.Errorf("transaction set is invalid: transaction %v claims non-existent ephemeral output %v", txnIndex, in.Parent.ID)
				} else if in.Parent.Value != out.Value {
					return fmt.Errorf("transaction set is invalid: transaction %v claims wrong value for ephemeral output %v", txnIndex, in.Parent.ID)
				} else if in.Parent.Address != out.Address {
					return fmt.Errorf("transaction set is invalid: transaction %v claims wrong address for ephemeral output %v", txnIndex, in.Parent.ID)
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

func (vc ValidationContext) noDoubleSpends(txns []types.Transaction) error {
	spent := make(map[types.ElementID]int)
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

func (vc ValidationContext) noDoubleContractUpdates(txns []types.Transaction) error {
	updated := make(map[types.ElementID]int)
	for i, txn := range txns {
		for _, in := range txn.FileContractRevisions {
			if prev, ok := updated[in.Parent.ID]; ok {
				return fmt.Errorf("transaction set is invalid: transaction %v updates contract %v multiple times (previously updated in transaction %v)", i, in.Parent.ID, prev)
			}
			updated[in.Parent.ID] = i
		}
		for _, in := range txn.FileContractResolutions {
			if prev, ok := updated[in.Parent.ID]; ok {
				return fmt.Errorf("transaction set is invalid: transaction %v updates contract %v multiple times (previously updated in transaction %v)", i, in.Parent.ID, prev)
			}
			updated[in.Parent.ID] = i
		}
	}
	return nil
}

// ValidateTransactionSet validates txns in their corresponding validation context.
func (vc ValidationContext) ValidateTransactionSet(txns []types.Transaction) error {
	if vc.BlockWeight(txns) > vc.MaxBlockWeight() {
		return ErrOverweight
	} else if err := vc.validateEphemeralOutputs(txns); err != nil {
		return err
	} else if err := vc.noDoubleSpends(txns); err != nil {
		return err
	} else if err := vc.noDoubleContractUpdates(txns); err != nil {
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
func (vc ValidationContext) ValidateBlock(b types.Block) error {
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
