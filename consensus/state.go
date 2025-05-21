// Package consensus implements the Sia consensus algorithms.
package consensus

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"math/bits"
	"sort"
	"sync"
	"time"

	"go.sia.tech/core/blake2b"
	"go.sia.tech/core/types"
)

// Pool for reducing heap allocations when hashing. This is only necessary
// because blake2b.New256 returns a hash.Hash interface, which prevents the
// compiler from doing escape analysis. Can be removed if we switch to an
// implementation whose constructor returns a concrete type.
var hasherPool = &sync.Pool{New: func() interface{} { return types.NewHasher() }}

func hashAll(elems ...interface{}) [32]byte {
	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	for _, e := range elems {
		if et, ok := e.(types.EncoderTo); ok {
			et.EncodeTo(h.E)
		} else {
			switch e := e.(type) {
			case string:
				h.WriteDistinguisher(e)
			case uint8:
				h.E.WriteUint8(e)
			case uint64:
				h.E.WriteUint64(e)
			default:
				panic(fmt.Sprintf("unhandled type %T", e))
			}
		}
	}
	return h.Sum()
}

// A Network specifies the fixed parameters of a Sia blockchain.
type Network struct {
	Name string `json:"name"`

	InitialCoinbase types.Currency `json:"initialCoinbase"`
	MinimumCoinbase types.Currency `json:"minimumCoinbase"`
	InitialTarget   types.BlockID  `json:"initialTarget"`
	BlockInterval   time.Duration  `json:"blockInterval"`
	MaturityDelay   uint64         `json:"maturityDelay"`

	HardforkDevAddr struct {
		Height     uint64        `json:"height"`
		OldAddress types.Address `json:"oldAddress"`
		NewAddress types.Address `json:"newAddress"`
	} `json:"hardforkDevAddr"`
	HardforkTax struct {
		Height uint64 `json:"height"`
	} `json:"hardforkTax"`
	HardforkStorageProof struct {
		Height uint64 `json:"height"`
	} `json:"hardforkStorageProof"`
	HardforkOak struct {
		Height           uint64    `json:"height"`
		FixHeight        uint64    `json:"fixHeight"`
		GenesisTimestamp time.Time `json:"genesisTimestamp"`
	} `json:"hardforkOak"`
	//nolint:tagliatelle
	HardforkASIC struct {
		Height    uint64        `json:"height"`
		OakTime   time.Duration `json:"oakTime"`
		OakTarget types.BlockID `json:"oakTarget"`
	} `json:"hardforkASIC"`
	HardforkFoundation struct {
		Height          uint64        `json:"height"`
		PrimaryAddress  types.Address `json:"primaryAddress"`
		FailsafeAddress types.Address `json:"failsafeAddress"`
	} `json:"hardforkFoundation"`
	HardforkV2 struct {
		AllowHeight   uint64 `json:"allowHeight"`
		RequireHeight uint64 `json:"requireHeight"`
	} `json:"hardforkV2"`
}

// GenesisState returns the state to which the genesis block should be applied.
func (n *Network) GenesisState() State {
	return State{
		Network: n,

		Index:             types.ChainIndex{Height: ^uint64(0)},
		PrevTimestamps:    [11]time.Time{},
		Depth:             intToTarget(maxTarget),
		ChildTarget:       n.InitialTarget,
		SiafundTaxRevenue: types.ZeroCurrency,

		OakTime:                     0,
		OakTarget:                   intToTarget(maxTarget),
		FoundationSubsidyAddress:    n.HardforkFoundation.PrimaryAddress,
		FoundationManagementAddress: n.HardforkFoundation.FailsafeAddress,
		TotalWork:                   Work{invTarget(intToTarget(maxTarget))},
		Difficulty:                  Work{invTarget(n.InitialTarget)},
		OakWork:                     Work{invTarget(intToTarget(maxTarget))},
	}
}

// State represents the state of the chain as of a particular block.
type State struct {
	Network *Network `json:"-"` // network parameters are not encoded

	Index             types.ChainIndex `json:"index"`
	PrevTimestamps    [11]time.Time    `json:"prevTimestamps"` // newest -> oldest
	Depth             types.BlockID    `json:"depth"`
	ChildTarget       types.BlockID    `json:"childTarget"`
	SiafundTaxRevenue types.Currency   `json:"siafundTaxRevenue"`

	// Oak hardfork state
	OakTime   time.Duration `json:"oakTime"`
	OakTarget types.BlockID `json:"oakTarget"`
	// Foundation hardfork state
	FoundationSubsidyAddress    types.Address `json:"foundationSubsidyAddress"`
	FoundationManagementAddress types.Address `json:"foundationManagementAddress"`
	// v2 hardfork state
	TotalWork    Work               `json:"totalWork"`
	Difficulty   Work               `json:"difficulty"`
	OakWork      Work               `json:"oakWork"`
	Elements     ElementAccumulator `json:"elements"`
	Attestations uint64             `json:"attestations"`
}

// EncodeTo implements types.EncoderTo.
func (s State) EncodeTo(e *types.Encoder) {
	s.Index.EncodeTo(e)
	for _, ts := range s.PrevTimestamps[:s.numTimestamps()] {
		e.WriteTime(ts)
	}
	s.Depth.EncodeTo(e)
	s.ChildTarget.EncodeTo(e)
	types.V2Currency(s.SiafundTaxRevenue).EncodeTo(e)

	e.WriteUint64(uint64(s.OakTime))
	s.OakTarget.EncodeTo(e)
	s.FoundationSubsidyAddress.EncodeTo(e)
	s.FoundationManagementAddress.EncodeTo(e)
	s.TotalWork.EncodeTo(e)
	s.Difficulty.EncodeTo(e)
	s.OakWork.EncodeTo(e)
	s.Elements.EncodeTo(e)
	e.WriteUint64(s.Attestations)
}

// DecodeFrom implements types.DecoderFrom.
func (s *State) DecodeFrom(d *types.Decoder) {
	s.Index.DecodeFrom(d)
	for i := range s.PrevTimestamps[:s.numTimestamps()] {
		s.PrevTimestamps[i] = d.ReadTime()
	}
	s.Depth.DecodeFrom(d)
	s.ChildTarget.DecodeFrom(d)
	(*types.V2Currency)(&s.SiafundTaxRevenue).DecodeFrom(d)

	s.OakTime = time.Duration(d.ReadUint64())
	s.OakTarget.DecodeFrom(d)
	s.FoundationSubsidyAddress.DecodeFrom(d)
	s.FoundationManagementAddress.DecodeFrom(d)
	s.TotalWork.DecodeFrom(d)
	s.Difficulty.DecodeFrom(d)
	s.OakWork.DecodeFrom(d)
	s.Elements.DecodeFrom(d)
	s.Attestations = d.ReadUint64()
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

// MaxFutureTimestamp returns a reasonable maximum value for a child block's
// timestamp. Note that this is not a consensus rule.
func (s State) MaxFutureTimestamp(currentTime time.Time) time.Time {
	return currentTime.Add(3 * time.Hour)
}

// SufficientlyHeavierThan returns whether s is sufficiently heavier than t.
// Nodes should use this method rather than directly comparing the Depth or
// TotalWork fields. Note that this is not a consensus rule.
func (s State) SufficientlyHeavierThan(t State) bool {
	// The need for a "sufficiently heavier" threshold arises from Sia's use of
	// a per-block difficulty adjustment algorithm. Imagine you are a miner who
	// has just found a block. Unfortunately, another miner also found a block,
	// and they broadcast theirs first. Normally, you would just eat the loss
	// and switch to mining on their chain. This time, however, you notice that
	// their block's timestamp is slightly later than yours. That means that the
	// difficulty of their *next* block will be slightly lower than it would be
	// for your block. So if you both mine one additional block, your chain will
	// have more total work than theirs! Thus, the most rational thing to do is
	// to keep mining on your own chain. Even better, you don't have to directly
	// compete with other miners, because you haven't broadcast your block yet.
	//
	// There's a term for this: selfish mining. And it's not something we want
	// to encourage! To prevent it, we require that a competing chain have
	// substantially more work than the current chain before we reorg to it,
	// where "substantially" means at least 20% of the current difficulty.
	// That's high enough that you can't get there by merely manipulating
	// timestamps, but low enough that an entire additional block will
	// definitely qualify.
	return s.TotalWork.Cmp(t.TotalWork.add(t.Difficulty.div64(5))) > 0
}

// BlockInterval is the expected wall clock time between consecutive blocks.
func (s State) BlockInterval() time.Duration {
	return s.Network.BlockInterval
}

// BlockReward returns the reward for mining a child block.
func (s State) BlockReward() types.Currency {
	r, underflow := s.Network.InitialCoinbase.SubWithUnderflow(types.Siacoins(uint32(s.childHeight())))
	if underflow || r.Cmp(s.Network.MinimumCoinbase) < 0 {
		return s.Network.MinimumCoinbase
	}
	return r
}

// MaturityHeight is the height at which various outputs created in the child
// block will "mature" (become spendable).
func (s State) MaturityHeight() uint64 {
	return s.childHeight() + s.Network.MaturityDelay
}

// SiafundCount is the number of siafunds in existence.
func (s State) SiafundCount() uint64 {
	return 10000
}

// AncestorDepth is the depth used to determine the target timestamp in the
// pre-Oak difficulty adjustment algorithm.
func (s State) AncestorDepth() uint64 {
	return 1000
}

// FoundationSubsidy returns the Foundation subsidy output for the child block.
func (s State) FoundationSubsidy() (sco types.SiacoinOutput, exists bool) {
	if s.FoundationSubsidyAddress == types.VoidAddress {
		return types.SiacoinOutput{}, false
	}
	sco.Address = s.FoundationSubsidyAddress
	subsidyPerBlock := types.Siacoins(30000)
	blocksPerYear := uint64(365 * 24 * time.Hour / s.BlockInterval())
	blocksPerMonth := blocksPerYear / 12
	hardforkHeight := s.Network.HardforkFoundation.Height
	if s.childHeight() < hardforkHeight || (s.childHeight()-hardforkHeight)%blocksPerMonth != 0 {
		return types.SiacoinOutput{}, false
	} else if s.childHeight() == hardforkHeight {
		sco.Value = subsidyPerBlock.Mul64(blocksPerYear)
	} else {
		sco.Value = subsidyPerBlock.Mul64(blocksPerMonth)
	}
	return sco, true
}

// NonceFactor is the factor by which all block nonces must be divisible.
func (s State) NonceFactor() uint64 {
	if s.childHeight() < s.Network.HardforkASIC.Height {
		return 1
	}
	return 1009
}

// MaxBlockWeight is the maximum "weight" of a valid child block.
func (s State) MaxBlockWeight() uint64 {
	return 2_000_000
}

type writeCounter struct{ n int }

func (wc *writeCounter) Write(p []byte) (int, error) {
	wc.n += len(p)
	return len(p), nil
}

// TransactionWeight computes the weight of a txn.
func (s State) TransactionWeight(txn types.Transaction) uint64 {
	var wc writeCounter
	e := types.NewEncoder(&wc)
	txn.EncodeTo(e)
	e.Flush()
	return uint64(wc.n)
}

// V2TransactionWeight computes the weight of a txn.
func (s State) V2TransactionWeight(txn types.V2Transaction) uint64 {
	var wc writeCounter
	e := types.NewEncoder(&wc)
	for _, sci := range txn.SiacoinInputs {
		sci.Parent.StateElement.MerkleProof = nil
		sci.EncodeTo(e)
	}
	for _, sco := range txn.SiacoinOutputs {
		types.V2SiacoinOutput(sco).EncodeTo(e)
	}
	for _, sfi := range txn.SiafundInputs {
		sfi.Parent.StateElement.MerkleProof = nil
		sfi.EncodeTo(e)
	}
	for _, sfo := range txn.SiafundOutputs {
		types.V2SiafundOutput(sfo).EncodeTo(e)
	}
	for _, fc := range txn.FileContracts {
		fc.EncodeTo(e)
	}
	for _, fcr := range txn.FileContractRevisions {
		fcr.Parent.StateElement.MerkleProof = nil
		fcr.EncodeTo(e)
	}
	for _, fcr := range txn.FileContractResolutions {
		fcr.Parent.StateElement.MerkleProof = nil
		if sp, ok := fcr.Resolution.(*types.V2StorageProof); ok {
			c := *sp // don't modify original
			c.ProofIndex.StateElement.MerkleProof = nil
			fcr.Resolution = &c
		}
		fcr.EncodeTo(e)
	}
	for _, a := range txn.Attestations {
		a.EncodeTo(e)
	}
	e.Write(txn.ArbitraryData)
	if txn.NewFoundationAddress != nil {
		txn.NewFoundationAddress.EncodeTo(e)
	}
	e.Flush()
	return uint64(wc.n)
}

// FileContractTax computes the tax levied on a given contract.
func (s State) FileContractTax(fc types.FileContract) types.Currency {
	// multiply by tax rate
	i := fc.Payout.Big()
	if s.childHeight() < s.Network.HardforkTax.Height {
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

// V2FileContractTax computes the tax levied on a given v2 contract.
func (s State) V2FileContractTax(fc types.V2FileContract) types.Currency {
	return fc.RenterOutput.Value.Add(fc.HostOutput.Value).Div64(25) // 4%
}

// StorageProofLeafIndex returns the leaf index used when computing or
// validating a storage proof.
func (s State) StorageProofLeafIndex(filesize uint64, windowID types.BlockID, fcid types.FileContractID) uint64 {
	const leafSize = uint64(len(types.StorageProof{}.Leaf))
	numLeaves := filesize / leafSize
	if filesize%leafSize != 0 {
		numLeaves++
	}
	if numLeaves == 0 {
		return 0
	}
	seed := hashAll(windowID, fcid)
	var r uint64
	for i := 0; i < len(seed); i += 8 {
		_, r = bits.Div64(r, binary.BigEndian.Uint64(seed[i:]), numLeaves)
	}
	return r
}

// StorageProofLeafHash computes the leaf hash of file contract data. If
// len(leaf) < 64, it will be extended with zeros.
func (s State) StorageProofLeafHash(leaf []byte) types.Hash256 {
	if len(leaf) == 64 {
		return blake2b.SumLeaf((*[64]byte)(leaf))
	}
	var buf [64]byte
	copy(buf[:], leaf)
	return blake2b.SumLeaf(&buf)
}

// replayPrefix returns the replay protection prefix at the current height.
// These prefixes are included in a transaction's SigHash; a new prefix is used
// after each hardfork to prevent replay attacks.
func (s State) replayPrefix() []byte {
	switch {
	case s.Index.Height >= s.Network.HardforkV2.AllowHeight:
		return []byte{2}
	case s.Index.Height >= s.Network.HardforkFoundation.Height:
		return []byte{1}
	case s.Index.Height >= s.Network.HardforkASIC.Height:
		return []byte{0}
	default:
		return nil
	}
}

// v2ReplayPrefix returns the replay protection prefix at the current height.
// These prefixes are included in various hashes; a new prefix is used after
// each hardfork to prevent replay attacks.
func (s State) v2ReplayPrefix() uint8 {
	return 2
}

// WholeSigHash computes the hash of transaction data covered by the
// WholeTransaction flag.
func (s State) WholeSigHash(txn types.Transaction, parentID types.Hash256, pubkeyIndex uint64, timelock uint64, coveredSigs []uint64) types.Hash256 {
	h := hasherPool.Get().(*types.Hasher)
	defer hasherPool.Put(h)
	h.Reset()

	h.E.WriteUint64(uint64(len((txn.SiacoinInputs))))
	for i := range txn.SiacoinInputs {
		h.E.Write(s.replayPrefix())
		txn.SiacoinInputs[i].EncodeTo(h.E)
	}
	h.E.WriteUint64(uint64(len((txn.SiacoinOutputs))))
	for i := range txn.SiacoinOutputs {
		types.V1SiacoinOutput(txn.SiacoinOutputs[i]).EncodeTo(h.E)
	}
	h.E.WriteUint64(uint64(len((txn.FileContracts))))
	for i := range txn.FileContracts {
		txn.FileContracts[i].EncodeTo(h.E)
	}
	h.E.WriteUint64(uint64(len((txn.FileContractRevisions))))
	for i := range txn.FileContractRevisions {
		txn.FileContractRevisions[i].EncodeTo(h.E)
	}
	h.E.WriteUint64(uint64(len((txn.StorageProofs))))
	for i := range txn.StorageProofs {
		txn.StorageProofs[i].EncodeTo(h.E)
	}
	h.E.WriteUint64(uint64(len((txn.SiafundInputs))))
	for i := range txn.SiafundInputs {
		h.E.Write(s.replayPrefix())
		txn.SiafundInputs[i].EncodeTo(h.E)
	}
	h.E.WriteUint64(uint64(len((txn.SiafundOutputs))))
	for i := range txn.SiafundOutputs {
		types.V1SiafundOutput(txn.SiafundOutputs[i]).EncodeTo(h.E)
	}
	h.E.WriteUint64(uint64(len((txn.MinerFees))))
	for i := range txn.MinerFees {
		types.V1Currency(txn.MinerFees[i]).EncodeTo(h.E)
	}
	h.E.WriteUint64(uint64(len((txn.ArbitraryData))))
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
		types.V1SiacoinOutput(txn.SiacoinOutputs[i]).EncodeTo(h.E)
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
		types.V1SiafundOutput(txn.SiafundOutputs[i]).EncodeTo(h.E)
	}
	for _, i := range cf.MinerFees {
		types.V1Currency(txn.MinerFees[i]).EncodeTo(h.E)
	}
	for _, i := range cf.ArbitraryData {
		h.E.WriteBytes(txn.ArbitraryData[i])
	}
	for _, i := range cf.Signatures {
		txn.Signatures[i].EncodeTo(h.E)
	}

	return h.Sum()
}

// Commitment computes the commitment hash for a child block with the given
// transactions and miner address.
func (s State) Commitment(minerAddr types.Address, txns []types.Transaction, v2txns []types.V2Transaction) types.Hash256 {
	var acc blake2b.Accumulator
	acc.AddLeaf(hashAll(uint8(0), "commitment", s.v2ReplayPrefix(), types.Hash256(hashAll(s)), minerAddr))
	for _, txn := range txns {
		acc.AddLeaf(txn.FullHash())
	}
	for _, txn := range v2txns {
		acc.AddLeaf(txn.FullHash())
	}
	return acc.Root()
}

// InputSigHash returns the hash that must be signed for each v2 transaction input.
func (s State) InputSigHash(txn types.V2Transaction) types.Hash256 {
	return hashAll("sig/input", s.v2ReplayPrefix(), types.V2TransactionSemantics(txn))
}

func nilSigs(sigs ...*types.Signature) {
	for i := range sigs {
		*sigs[i] = types.Signature{}
	}
}

// ContractSigHash returns the hash that must be signed for a v2 contract revision.
func (s State) ContractSigHash(fc types.V2FileContract) types.Hash256 {
	nilSigs(&fc.RenterSignature, &fc.HostSignature)
	return hashAll("sig/filecontract", s.v2ReplayPrefix(), fc)
}

// RenewalSigHash returns the hash that must be signed for a file contract renewal.
func (s State) RenewalSigHash(fcr types.V2FileContractRenewal) types.Hash256 {
	nilSigs(
		&fcr.NewContract.RenterSignature, &fcr.NewContract.HostSignature,
		&fcr.RenterSignature, &fcr.HostSignature,
	)
	return hashAll("sig/filecontractrenewal", s.v2ReplayPrefix(), fcr)
}

// AttestationSigHash returns the hash that must be signed for an attestation.
func (s State) AttestationSigHash(a types.Attestation) types.Hash256 {
	nilSigs(&a.Signature)
	return hashAll("sig/attestation", s.v2ReplayPrefix(), a)
}

// A SiacoinElementDiff is a SiacoinElement that was created and/or spent within
// a block. Note that an element may be both created and spent in the the same
// block.
type SiacoinElementDiff struct {
	SiacoinElement types.SiacoinElement `json:"siacoinElement"`
	Created        bool                 `json:"created"`
	Spent          bool                 `json:"spent"`
}

// A SiafundElementDiff is a SiafundElement that was created and/or spent within
// a block. Note that an element may be both created and spent in the the same
// block.
type SiafundElementDiff struct {
	SiafundElement types.SiafundElement `json:"siafundElement"`
	Created        bool                 `json:"created"`
	Spent          bool                 `json:"spent"`
}

// A FileContractElementDiff is a FileContractElement that was created, revised,
// and/or resolved within a block. Note that a contract may be created, revised,
// and resolved all within the same block.
type FileContractElementDiff struct {
	FileContractElement types.FileContractElement `json:"fileContractElement"`
	Created             bool                      `json:"created"`
	// Non-nil if the contract was revised. If the contract was revised multiple
	// times, this is the revision with the highest revision number.
	Revision *types.FileContract `json:"revision"`
	Resolved bool                `json:"resolved"`
	Valid    bool                `json:"valid"`
}

// RevisionElement returns the revision, if present, as a FileContractElement.
// It returns a boolean indicating whether the revision exists or not. The
// element's memory is shared.
func (diff FileContractElementDiff) RevisionElement() (types.FileContractElement, bool) {
	if diff.Revision == nil {
		return types.FileContractElement{}, false
	}
	return types.FileContractElement{
		ID:           diff.FileContractElement.ID,
		StateElement: diff.FileContractElement.StateElement.Share(),
		FileContract: *diff.Revision,
	}, true
}

// A V2FileContractElementDiff is a V2FileContractElement that was created,
// revised, and/or resolved within a block. Note that, within a block, a v2
// contract may be both created and revised, or revised and resolved, but not
// created and resolved.
type V2FileContractElementDiff struct {
	V2FileContractElement types.V2FileContractElement `json:"v2FileContractElement"`
	Created               bool                        `json:"created"`
	// Non-nil if the contract was revised. If the contract was revised multiple
	// times, this is the revision with the highest revision number.
	Revision *types.V2FileContract `json:"revision"`
	// Non-nil if the contract was resolved.
	Resolution types.V2FileContractResolutionType `json:"resolution"`
}

// V2RevisionElement returns the revision, if present, as a
// V2FileContractElement. It returns a boolean indicating whether the revision
// exists or not. The element's memory is shared.
func (diff V2FileContractElementDiff) V2RevisionElement() (types.V2FileContractElement, bool) {
	if diff.Revision == nil {
		return types.V2FileContractElement{}, false
	}
	return types.V2FileContractElement{
		ID:             diff.V2FileContractElement.ID,
		StateElement:   diff.V2FileContractElement.StateElement.Share(),
		V2FileContract: *diff.Revision,
	}, true
}

// A MidState represents the state of the chain within a block.
type MidState struct {
	base                 State
	elements             map[types.ElementID]int // indices into element slices
	spends               map[types.ElementID]types.TransactionID
	siafundTaxRevenue    types.Currency
	foundationSubsidy    types.Address
	foundationManagement types.Address

	// elements created/updated by block
	sces   []SiacoinElementDiff
	sfes   []SiafundElementDiff
	fces   []FileContractElementDiff
	v2fces []V2FileContractElementDiff
	aes    []types.AttestationElement
	cie    types.ChainIndexElement
}

func (ms *MidState) siacoinElement(ts V1TransactionSupplement, id types.SiacoinOutputID) (types.SiacoinElement, bool) {
	if i, ok := ms.elements[id]; ok {
		return ms.sces[i].SiacoinElement, true
	}
	for _, sce := range ts.SiacoinInputs {
		if sce.ID == id {
			return sce, true
		}
	}
	return types.SiacoinElement{}, false
}

func (ms *MidState) siafundElement(ts V1TransactionSupplement, id types.SiafundOutputID) (types.SiafundElement, bool) {
	if i, ok := ms.elements[id]; ok {
		return ms.sfes[i].SiafundElement, true
	}
	for _, sfe := range ts.SiafundInputs {
		if sfe.ID == id {
			return sfe, true
		}
	}
	return types.SiafundElement{}, false
}

func (ms *MidState) fileContractElement(ts V1TransactionSupplement, id types.FileContractID) (types.FileContractElement, bool) {
	if i, ok := ms.elements[id]; ok {
		rev, ok := ms.fces[i].RevisionElement()
		if ok {
			return rev, ok
		}
		return ms.fces[i].FileContractElement, true
	}
	for _, fce := range ts.RevisedFileContracts {
		if fce.ID == id {
			return fce, true
		}
	}
	for _, sps := range ts.StorageProofs {
		if sps.FileContract.ID == id {
			return sps.FileContract, true
		}
	}
	return types.FileContractElement{}, false
}

func (ms *MidState) storageProofWindowID(ts V1TransactionSupplement, id types.FileContractID) (types.BlockID, bool) {
	if i, ok := ms.elements[id]; ok && ms.fces[i].FileContractElement.FileContract.WindowStart == ms.base.childHeight() {
		return ms.base.Index.ID, true
	}
	for _, sps := range ts.StorageProofs {
		if sps.FileContract.ID == id {
			return sps.WindowID, true
		}
	}
	return types.BlockID{}, false
}

func (ms *MidState) spent(id types.ElementID) (types.TransactionID, bool) {
	txid, ok := ms.spends[id]
	return txid, ok
}

func (ms *MidState) isSpent(id types.ElementID) bool {
	_, ok := ms.spends[id]
	return ok
}

// NewMidState constructs a MidState initialized to the provided base state.
func NewMidState(s State) *MidState {
	return &MidState{
		base:                 s,
		elements:             make(map[types.ElementID]int),
		spends:               make(map[types.ElementID]types.TransactionID),
		siafundTaxRevenue:    s.SiafundTaxRevenue,
		foundationSubsidy:    s.FoundationSubsidyAddress,
		foundationManagement: s.FoundationManagementAddress,
	}
}

// A V1StorageProofSupplement pairs a file contract with the block ID used to
// derive its storage proof leaf index.
type V1StorageProofSupplement struct {
	FileContract types.FileContractElement
	WindowID     types.BlockID
}

// EncodeTo implements types.EncoderTo.
func (sps V1StorageProofSupplement) EncodeTo(e *types.Encoder) {
	sps.FileContract.EncodeTo(e)
	sps.WindowID.EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (sps *V1StorageProofSupplement) DecodeFrom(d *types.Decoder) {
	sps.FileContract.DecodeFrom(d)
	sps.WindowID.DecodeFrom(d)
}

// A V1TransactionSupplement contains elements that are associated with a v1
// transaction, but not included in the transaction. For example, v1
// transactions reference the ID of each SiacoinOutput they spend, but do not
// contain the output itself. Consequently, in order to validate the
// transaction, those outputs must be loaded from a Store. Collecting these
// elements into an explicit struct allows us to preserve them even after the
// Store has been mutated.
type V1TransactionSupplement struct {
	SiacoinInputs        []types.SiacoinElement
	SiafundInputs        []types.SiafundElement
	RevisedFileContracts []types.FileContractElement
	StorageProofs        []V1StorageProofSupplement
}

// EncodeTo implements types.EncoderTo.
func (ts V1TransactionSupplement) EncodeTo(e *types.Encoder) {
	types.EncodeSlice(e, ts.SiacoinInputs)
	types.EncodeSlice(e, ts.SiafundInputs)
	types.EncodeSlice(e, ts.RevisedFileContracts)
	types.EncodeSlice(e, ts.StorageProofs)
}

// DecodeFrom implements types.DecoderFrom.
func (ts *V1TransactionSupplement) DecodeFrom(d *types.Decoder) {
	types.DecodeSlice(d, &ts.SiacoinInputs)
	types.DecodeSlice(d, &ts.SiafundInputs)
	types.DecodeSlice(d, &ts.RevisedFileContracts)
	types.DecodeSlice(d, &ts.StorageProofs)
}

// A V1BlockSupplement contains elements that are associated with a v1 block,
// but not included in the block. This includes supplements for each v1
// transaction, as well as any file contracts that expired at the block's
// height.
type V1BlockSupplement struct {
	Transactions          []V1TransactionSupplement
	ExpiringFileContracts []types.FileContractElement
}

// EncodeTo implements types.EncoderTo.
func (bs V1BlockSupplement) EncodeTo(e *types.Encoder) {
	types.EncodeSlice(e, bs.Transactions)
	types.EncodeSlice(e, bs.ExpiringFileContracts)
}

// DecodeFrom implements types.DecoderFrom.
func (bs *V1BlockSupplement) DecodeFrom(d *types.Decoder) {
	types.DecodeSlice(d, &bs.Transactions)
	types.DecodeSlice(d, &bs.ExpiringFileContracts)
}
