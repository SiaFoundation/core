package consensus

import (
	"encoding/binary"
	"math/bits"
	"sync"
	"time"

	"go.sia.tech/core/merkle"
	"go.sia.tech/core/types"
)

const (
	blocksPerYear = 144 * 365

	asicHardforkHeight       = 179000
	foundationHardforkHeight = 300000

	foundationSubsidyFrequency = blocksPerYear / 12
)

// Pool for reducing heap allocations when hashing. This is only necessary
// because blake2b.New256 returns a hash.Hash interface, which prevents the
// compiler from doing escape analysis. Can be removed if we switch to an
// implementation whose constructor returns a concrete type.
var hasherPool = &sync.Pool{New: func() interface{} { return types.NewHasher() }}

// State represents the full state of the chain as of a particular block.
type State struct {
	Index          types.ChainIndex          `json:"index"`
	Elements       merkle.ElementAccumulator `json:"elements"`
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
func (s State) EncodeTo(e *types.Encoder) {
	s.Index.EncodeTo(e)
	s.Elements.EncodeTo(e)
	s.History.EncodeTo(e)
	for _, ts := range s.PrevTimestamps {
		e.WriteTime(ts)
	}
	s.TotalWork.EncodeTo(e)
	s.Difficulty.EncodeTo(e)
	s.OakWork.EncodeTo(e)
	e.WriteUint64(uint64(s.OakTime))
	e.WriteTime(s.GenesisTimestamp)
	s.SiafundPool.EncodeTo(e)
	s.FoundationAddress.EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (s *State) DecodeFrom(d *types.Decoder) {
	s.Index.DecodeFrom(d)
	s.Elements.DecodeFrom(d)
	s.History.DecodeFrom(d)
	for i := range s.PrevTimestamps {
		s.PrevTimestamps[i] = d.ReadTime()
	}
	s.TotalWork.DecodeFrom(d)
	s.Difficulty.DecodeFrom(d)
	s.OakWork.DecodeFrom(d)
	s.OakTime = time.Duration(d.ReadUint64())
	s.GenesisTimestamp = d.ReadTime()
	s.SiafundPool.DecodeFrom(d)
	s.FoundationAddress.DecodeFrom(d)
}

func (s State) numTimestamps() int {
	if s.Index.Height+1 < uint64(len(s.PrevTimestamps)) {
		return int(s.Index.Height + 1)
	}
	return len(s.PrevTimestamps)
}

// BlockInterval is the expected wall clock time between consecutive blocks.
func (s State) BlockInterval() time.Duration {
	return 10 * time.Minute
}

// BlockReward returns the reward for mining a child block.
func (s State) BlockReward() types.Currency {
	const initialCoinbase = 300000
	const minimumCoinbase = 30000
	blockHeight := s.Index.Height + 1
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
func (s State) MaturityHeight() uint64 {
	return (s.Index.Height + 1) + 144
}

// SiafundCount is the number of siafunds in existence.
func (s State) SiafundCount() uint64 {
	return 10000
}

// FoundationSubsidy returns the Foundation subsidy value for the child block.
func (s State) FoundationSubsidy() types.Currency {
	foundationSubsidyPerBlock := types.Siacoins(30000)
	initialfoundationSubsidy := foundationSubsidyPerBlock.Mul64(blocksPerYear)

	blockHeight := s.Index.Height + 1
	if blockHeight < foundationHardforkHeight || (blockHeight-foundationHardforkHeight)%foundationSubsidyFrequency != 0 {
		return types.ZeroCurrency
	} else if blockHeight == foundationHardforkHeight {
		return initialfoundationSubsidy
	}
	return foundationSubsidyPerBlock.Mul64(foundationSubsidyFrequency)
}

// NonceFactor is the factor by which all block nonces must be divisible.
func (s State) NonceFactor() uint64 {
	blockHeight := s.Index.Height + 1
	if blockHeight < asicHardforkHeight {
		return 1
	}
	return 1009
}

// MaxBlockWeight is the maximum "weight" of a valid child block.
func (s State) MaxBlockWeight() uint64 {
	return 2_000_000
}

// TransactionWeight computes the weight of a txn.
func (s State) TransactionWeight(txn types.Transaction) uint64 {
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
func (s State) BlockWeight(txns []types.Transaction) uint64 {
	var weight uint64
	for _, txn := range txns {
		weight += s.TransactionWeight(txn)
	}
	return weight
}

// FileContractTax computes the tax levied on a given contract.
func (s State) FileContractTax(fc types.FileContract) types.Currency {
	sum := fc.RenterOutput.Value.Add(fc.HostOutput.Value)
	tax := sum.Div64(25) // 4%
	// round down to nearest multiple of SiafundCount
	_, r := bits.Div64(0, tax.Hi, s.SiafundCount())
	_, r = bits.Div64(r, tax.Lo, s.SiafundCount())
	return tax.Sub(types.NewCurrency64(r))
}

// StorageProofLeafIndex returns the leaf index used when computing or
// validating a storage proof.
func (s State) StorageProofLeafIndex(filesize uint64, windowStart types.ChainIndex, fcid types.ElementID) uint64 {
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
func (s State) Commitment(minerAddr types.Address, txns []types.Transaction) types.Hash256 {
	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	h.Reset()

	// hash the state
	s.EncodeTo(h.E)
	stateHash := h.Sum()

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
	stateHash.EncodeTo(h.E)
	minerAddr.EncodeTo(h.E)
	txnsHash.EncodeTo(h.E)
	return h.Sum()
}

// InputSigHash returns the hash that must be signed for each transaction input.
func (s State) InputSigHash(txn types.Transaction) types.Hash256 {
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
func (s State) ContractSigHash(fc types.FileContract) types.Hash256 {
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
func (s State) RenewalSigHash(fcr types.FileContractRenewal) types.Hash256 {
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
func (s State) AttestationSigHash(a types.Attestation) types.Hash256 {
	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	h.E.WriteString("sia/sig/attestation")
	a.PublicKey.EncodeTo(h.E)
	h.E.WriteString(a.Key)
	h.E.WriteBytes(a.Value)
	return h.Sum()
}
