// Package consensus implements the Sia consensus algorithms.
package consensus

import (
	"encoding/binary"
	"math/big"
	"math/bits"
	"sort"
	"sync"
	"time"

	"go.sia.tech/core/types"
)

const (
	blocksPerYear = 144 * 365

	hardforkDevAddr      = 10000
	hardforkTax          = 21000
	hardforkStorageProof = 100000
	hardforkOak          = 135000
	hardforkOakFix       = 139000
	hardforkASIC         = 179000
	hardforkFoundation   = 298000

	foundationSubsidyFrequency = blocksPerYear / 12
)

// Pool for reducing heap allocations when hashing. This is only necessary
// because blake2b.New256 returns a hash.Hash interface, which prevents the
// compiler from doing escape analysis. Can be removed if we switch to an
// implementation whose constructor returns a concrete type.
var hasherPool = &sync.Pool{New: func() interface{} { return types.NewHasher() }}

// A Store stores blocks, siacoin outputs, siafund outputs, and file contracts.
//
// Store methods do not return errors. If a store encounters an error, it should
// save the error and thereafter return empty values from all methods. It is the
// caller's responsibility to check this error, and, if non-nil, discard any
// results computed.
type Store interface {
	BestIndex(height uint64) (types.ChainIndex, bool)
	AncestorTimestamp(id types.BlockID, n uint64) time.Time
	SiacoinOutput(id types.SiacoinOutputID) (types.SiacoinOutput, bool)
	SiafundOutput(id types.SiafundOutputID) (types.SiafundOutput, types.Currency, bool)
	FileContract(id types.FileContractID) (types.FileContract, bool)
	MaturedSiacoinOutputs(height uint64) []DelayedSiacoinOutputDiff
	MissedFileContracts(height uint64) []types.FileContractID
}

// State represents the constant-size state of the chain as of a particular
// block.
type State struct {
	Index                     types.ChainIndex `json:"index"`
	PrevTimestamps            [11]time.Time    `json:"prevTimestamps"`
	Depth                     types.BlockID    `json:"depth"`
	ChildTarget               types.BlockID    `json:"childTarget"`
	OakTarget                 types.BlockID    `json:"oakTarget"`
	OakTime                   time.Duration    `json:"oakTime"`
	GenesisTimestamp          time.Time        `json:"genesisTimestamp"`
	SiafundPool               types.Currency   `json:"siafundPool"`
	FoundationPrimaryAddress  types.Address    `json:"foundationPrimaryAddress"`
	FoundationFailsafeAddress types.Address    `json:"foundationFailsafeAddress"`
}

// EncodeTo implements types.EncoderTo.
func (s State) EncodeTo(e *types.Encoder) {
	s.Index.EncodeTo(e)
	for _, ts := range s.PrevTimestamps {
		e.WriteTime(ts)
	}
	s.Depth.EncodeTo(e)
	s.ChildTarget.EncodeTo(e)
	s.OakTarget.EncodeTo(e)
	e.WriteUint64(uint64(s.OakTime))
	e.WriteTime(s.GenesisTimestamp)
	s.SiafundPool.EncodeTo(e)
	s.FoundationPrimaryAddress.EncodeTo(e)
	s.FoundationFailsafeAddress.EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (s *State) DecodeFrom(d *types.Decoder) {
	s.Index.DecodeFrom(d)
	for i := range s.PrevTimestamps {
		s.PrevTimestamps[i] = d.ReadTime()
	}
	s.Depth.DecodeFrom(d)
	s.ChildTarget.DecodeFrom(d)
	s.OakTarget.DecodeFrom(d)
	s.OakTime = time.Duration(d.ReadUint64())
	s.GenesisTimestamp = d.ReadTime()
	s.SiafundPool.DecodeFrom(d)
	s.FoundationPrimaryAddress.DecodeFrom(d)
	s.FoundationFailsafeAddress.DecodeFrom(d)
}

func (s State) childHeight() uint64 { return s.Index.Height + 1 }

func (s State) numTimestamps() int {
	if s.childHeight() < uint64(len(s.PrevTimestamps)) {
		return int(s.childHeight())
	}
	return len(s.PrevTimestamps)
}

func (s State) medianTimestamp() time.Time {
	prevCopy := s.PrevTimestamps
	ts := prevCopy[:s.numTimestamps()]
	sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
	if len(ts)%2 != 0 {
		return ts[len(ts)/2]
	}
	l, r := ts[len(ts)/2-1], ts[len(ts)/2]
	return l.Add(r.Sub(l) / 2)
}

// MaxFutureTimestamp returns the maximum allowed timestamp for a block.
func (s State) MaxFutureTimestamp(currentTime time.Time) time.Time {
	return currentTime.Add(2 * time.Hour)
}

// BlockInterval is the expected wall clock time between consecutive blocks.
func (s State) BlockInterval() time.Duration {
	return 10 * time.Minute
}

// BlockReward returns the reward for mining a child block.
func (s State) BlockReward() types.Currency {
	const initialCoinbase = 300000
	const minimumCoinbase = 30000
	if s.childHeight() < initialCoinbase-minimumCoinbase {
		return types.Siacoins(uint32(initialCoinbase - s.childHeight()))
	}
	return types.Siacoins(minimumCoinbase)
}

// MaturityHeight is the height at which various outputs created in the child
// block will "mature" (become spendable).
func (s State) MaturityHeight() uint64 {
	return (s.Index.Height + 1) + 144
}

// SiafundCount is the number of siafunds in existence.
func (s State) SiafundCount() uint64 {
	return 10000
}

// FoundationSubsidy returns the Foundation subsidy output for the child block.
// If no subsidy is due, the returned output has a value of zero.
func (s State) FoundationSubsidy() (sco types.SiacoinOutput) {
	sco.Address = s.FoundationPrimaryAddress

	foundationSubsidyPerBlock := types.Siacoins(30000)
	initialfoundationSubsidy := foundationSubsidyPerBlock.Mul64(blocksPerYear)
	if s.childHeight() < hardforkFoundation || (s.childHeight()-hardforkFoundation)%foundationSubsidyFrequency != 0 {
		sco.Value = types.ZeroCurrency
	} else if s.childHeight() == hardforkFoundation {
		sco.Value = initialfoundationSubsidy
	} else {
		sco.Value = foundationSubsidyPerBlock.Mul64(foundationSubsidyFrequency)
	}
	return
}

// NonceFactor is the factor by which all block nonces must be divisible.
func (s State) NonceFactor() uint64 {
	if s.childHeight() < hardforkASIC {
		return 1
	}
	return 1009
}

// MaxBlockWeight is the maximum "weight" of a valid child block.
func (s State) MaxBlockWeight() int {
	return 2_000_000
}

// TransactionWeight computes the weight of a txn.
func (s State) TransactionWeight(txn types.Transaction) uint64 {
	return uint64(types.EncodedLen(txn))
}

// BlockWeight computes the combined weight of a block's txns.
func (s State) BlockWeight(txns []types.Transaction) uint64 {
	var weight uint64
	for _, txn := range txns {
		weight += s.TransactionWeight(txn)
	}
	return weight
}

// FileContractTax computes the tax levied on a given contract.
func (s State) FileContractTax(fc types.FileContract) types.Currency {
	// multiply by tax rate
	i := fc.Payout.Big()
	if s.childHeight() < hardforkTax {
		r := new(big.Rat).SetInt(i)
		r.Mul(r, new(big.Rat).SetFloat64(0.039))
		i.Div(r.Num(), r.Denom())
	} else {
		i.Mul(i, big.NewInt(39))
		i.Div(i, big.NewInt(1000))
	}

	// round down to multiple of SiafundCount
	i.Sub(i, new(big.Int).Mod(i, big.NewInt(int64(s.SiafundCount()))))

	// convert to currency
	lo := i.Uint64()
	hi := i.Rsh(i, 64).Uint64()
	return types.NewCurrency(lo, hi)
}

// StorageProofLeafIndex returns the leaf index used when computing or
// validating a storage proof.
func (s State) StorageProofLeafIndex(filesize uint64, windowStart types.ChainIndex, fcid types.FileContractID) uint64 {
	const leafSize = uint64(len(types.StorageProof{}.Leaf))
	numLeaves := filesize / leafSize
	if filesize%leafSize != 0 {
		numLeaves++
	}
	if numLeaves <= 0 {
		return 0
	}
	seed := types.HashBytes(append(windowStart.ID[:], fcid[:]...))
	var r uint64
	for i := 0; i < len(seed); i += 8 {
		_, r = bits.Div64(r, binary.BigEndian.Uint64(seed[i:]), numLeaves)
	}
	return r
}

// replayPrefix returns the replay protection prefix at the current height.
// These prefixes are included in a transaction's SigHash; a new prefix is used
// after each hardfork to prevent replay attacks.
func (s State) replayPrefix() []byte {
	switch {
	case s.Index.Height >= hardforkFoundation:
		return []byte{1}
	case s.Index.Height >= hardforkASIC:
		return []byte{0}
	default:
		return nil
	}
}

// WholeSigHash computes the hash of transaction data covered by the
// WholeTransaction flag.
func (s State) WholeSigHash(txn types.Transaction, parentID types.Hash256, pubkeyIndex uint64, timelock uint64, coveredSigs []uint64) types.Hash256 {
	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	h.Reset()

	h.E.WritePrefix(len((txn.SiacoinInputs)))
	for i := range txn.SiacoinInputs {
		h.E.Write(s.replayPrefix())
		txn.SiacoinInputs[i].EncodeTo(h.E)
	}
	h.E.WritePrefix(len((txn.SiacoinOutputs)))
	for i := range txn.SiacoinOutputs {
		txn.SiacoinOutputs[i].EncodeTo(h.E)
	}
	h.E.WritePrefix(len((txn.FileContracts)))
	for i := range txn.FileContracts {
		txn.FileContracts[i].EncodeTo(h.E)
	}
	h.E.WritePrefix(len((txn.FileContractRevisions)))
	for i := range txn.FileContractRevisions {
		txn.FileContractRevisions[i].EncodeTo(h.E)
	}
	h.E.WritePrefix(len((txn.StorageProofs)))
	for i := range txn.StorageProofs {
		txn.StorageProofs[i].EncodeTo(h.E)
	}
	h.E.WritePrefix(len((txn.SiafundInputs)))
	for i := range txn.SiafundInputs {
		h.E.Write(s.replayPrefix())
		txn.SiafundInputs[i].EncodeTo(h.E)
	}
	h.E.WritePrefix(len((txn.SiafundOutputs)))
	for i := range txn.SiafundOutputs {
		txn.SiafundOutputs[i].EncodeTo(h.E)
	}
	h.E.WritePrefix(len((txn.MinerFees)))
	for i := range txn.MinerFees {
		txn.MinerFees[i].EncodeTo(h.E)
	}
	h.E.WritePrefix(len((txn.ArbitraryData)))
	for i := range txn.ArbitraryData {
		h.E.WriteBytes(txn.ArbitraryData[i])
	}

	parentID.EncodeTo(h.E)
	h.E.WriteUint64(pubkeyIndex)
	h.E.WriteUint64(timelock)

	for _, i := range coveredSigs {
		txn.Signatures[i].EncodeTo(h.E)
	}

	return h.Sum()
}

// PartialSigHash computes the hash of the transaction data specified by cf. It
// panics if cf references fields not present in txn.
func (s State) PartialSigHash(txn types.Transaction, cf types.CoveredFields) types.Hash256 {
	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	h.Reset()

	for _, i := range cf.SiacoinInputs {
		h.E.Write(s.replayPrefix())
		txn.SiacoinInputs[i].EncodeTo(h.E)
	}
	for _, i := range cf.SiacoinOutputs {
		txn.SiacoinOutputs[i].EncodeTo(h.E)
	}
	for _, i := range cf.FileContracts {
		txn.FileContracts[i].EncodeTo(h.E)
	}
	for _, i := range cf.FileContractRevisions {
		txn.FileContractRevisions[i].EncodeTo(h.E)
	}
	for _, i := range cf.StorageProofs {
		txn.StorageProofs[i].EncodeTo(h.E)
	}
	for _, i := range cf.SiafundInputs {
		h.E.Write(s.replayPrefix())
		txn.SiafundInputs[i].EncodeTo(h.E)
	}
	for _, i := range cf.SiafundOutputs {
		txn.SiafundOutputs[i].EncodeTo(h.E)
	}
	for _, i := range cf.MinerFees {
		txn.MinerFees[i].EncodeTo(h.E)
	}
	for _, i := range cf.ArbitraryData {
		h.E.WriteBytes(txn.ArbitraryData[i])
	}
	for _, i := range cf.Signatures {
		txn.Signatures[i].EncodeTo(h.E)
	}

	return h.Sum()
}
