package consensus

import (
	"time"

	"go.sia.tech/core/types"
)

// EncodeTo implements types.EncoderTo.
func (sa *StateAccumulator) EncodeTo(e *types.Encoder) {
	e.WriteUint64(sa.NumLeaves)
	for i, root := range sa.Trees {
		if sa.HasTreeAtHeight(i) {
			e.WriteHash(root)
		}
	}
}

// DecodeFrom implements types.DecoderFrom.
func (sa *StateAccumulator) DecodeFrom(d *types.Decoder) {
	sa.NumLeaves = d.ReadUint64()
	for i := range sa.Trees {
		if sa.HasTreeAtHeight(i) {
			sa.Trees[i] = d.ReadHash()
		}
	}
}

// EncodeTo implements types.EncoderTo.
func (ha *HistoryAccumulator) EncodeTo(e *types.Encoder) {
	(*StateAccumulator)(ha).EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (ha *HistoryAccumulator) DecodeFrom(d *types.Decoder) {
	(*StateAccumulator)(ha).DecodeFrom(d)
}

// EncodeTo implements types.EncoderTo.
func (vc *ValidationContext) EncodeTo(e *types.Encoder) {
	e.WriteChainIndex(vc.Index)
	vc.State.EncodeTo(e)
	vc.History.EncodeTo(e)
	for _, ts := range vc.PrevTimestamps {
		e.WriteTime(ts)
	}
	e.WriteWork(vc.TotalWork)
	e.WriteWork(vc.Difficulty)
	e.WriteWork(vc.OakWork)
	e.WriteUint64(uint64(vc.OakTime))
	e.WriteTime(vc.GenesisTimestamp)
	e.WriteCurrency(vc.SiafundPool)
	e.WriteAddress(vc.FoundationAddress)
}

// DecodeFrom implements types.DecoderFrom.
func (vc *ValidationContext) DecodeFrom(d *types.Decoder) {
	vc.Index = d.ReadChainIndex()
	vc.State.DecodeFrom(d)
	vc.History.DecodeFrom(d)
	for i := range vc.PrevTimestamps {
		vc.PrevTimestamps[i] = d.ReadTime()
	}
	vc.TotalWork = d.ReadWork()
	vc.Difficulty = d.ReadWork()
	vc.OakWork = d.ReadWork()
	vc.OakTime = time.Duration(d.ReadUint64())
	vc.GenesisTimestamp = d.ReadTime()
	vc.SiafundPool = d.ReadCurrency()
	vc.FoundationAddress = d.ReadAddress()
}

// A CompressedBlock encodes a block in compressed form by merging its
// individual Merkle proofs into a single multiproof.
type CompressedBlock types.Block

// EncodeTo implements types.EncoderTo.
func (b CompressedBlock) EncodeTo(e *types.Encoder) {
	e.WriteHeader(b.Header)
	e.WritePrefix(len(b.Transactions))
	for _, txn := range b.Transactions {
		(compressedTransaction)(txn).EncodeTo(e)
	}
	for _, p := range ComputeMultiproof(b.Transactions) {
		e.WriteHash(p)
	}
}

// DecodeFrom implements types.DecoderFrom.
func (b *CompressedBlock) DecodeFrom(d *types.Decoder) {
	b.Header = d.ReadHeader()
	b.Transactions = make([]types.Transaction, d.ReadPrefix())
	for i := range b.Transactions {
		(*compressedTransaction)(&b.Transactions[i]).DecodeFrom(d)
	}
	proof := make([]types.Hash256, MultiproofSize(b.Transactions))
	for i := range proof {
		proof[i] = d.ReadHash()
	}
	ExpandMultiproof(b.Transactions, proof)
}

// helper types for compressed encoding

type compressedSiacoinOutput types.SiacoinOutput

func (out compressedSiacoinOutput) EncodeTo(e *types.Encoder) {
	e.WriteOutputID(out.ID)
	e.WriteCurrency(out.Value)
	e.WriteAddress(out.Address)
	e.WriteUint64(out.Timelock)
	e.WritePrefix(len(out.MerkleProof)) // omit proof data
	e.WriteUint64(out.LeafIndex)
}

func (out *compressedSiacoinOutput) DecodeFrom(d *types.Decoder) {
	*out = compressedSiacoinOutput{
		d.ReadOutputID(),
		d.ReadCurrency(),
		d.ReadAddress(),
		d.ReadUint64(),
		make([]types.Hash256, d.ReadPrefix()), // omit proof data
		d.ReadUint64(),
	}
}

type compressedSiacoinInput types.SiacoinInput

func (in compressedSiacoinInput) EncodeTo(e *types.Encoder) {
	(compressedSiacoinOutput)(in.Parent).EncodeTo(e)
	e.WritePolicy(in.SpendPolicy)
	e.WritePrefix(len(in.Signatures))
	for _, sig := range in.Signatures {
		e.WriteSignature(sig)
	}
}

func (in *compressedSiacoinInput) DecodeFrom(d *types.Decoder) {
	(*compressedSiacoinOutput)(&in.Parent).DecodeFrom(d)
	in.SpendPolicy = d.ReadPolicy()
	in.Signatures = make([]types.InputSignature, d.ReadPrefix())
	for i := range in.Signatures {
		in.Signatures[i] = d.ReadSignature()
	}
	return
}

type compressedSiafundOutput types.SiafundOutput

func (out compressedSiafundOutput) EncodeTo(e *types.Encoder) {
	e.WriteOutputID(out.ID)
	e.WriteCurrency(out.Value)
	e.WriteAddress(out.Address)
	e.WriteCurrency(out.ClaimStart)
	e.WritePrefix(len(out.MerkleProof)) // omit proof data
	e.WriteUint64(out.LeafIndex)
}

func (out *compressedSiafundOutput) DecodeFrom(d *types.Decoder) {
	*out = compressedSiafundOutput{
		d.ReadOutputID(),
		d.ReadCurrency(),
		d.ReadAddress(),
		d.ReadCurrency(),
		make([]types.Hash256, d.ReadPrefix()), // omit proof data
		d.ReadUint64(),
	}
}

type compressedSiafundInput types.SiafundInput

func (in compressedSiafundInput) EncodeTo(e *types.Encoder) {
	(compressedSiafundOutput)(in.Parent).EncodeTo(e)
	e.WriteAddress(in.ClaimAddress)
	e.WritePolicy(in.SpendPolicy)
	e.WritePrefix(len(in.Signatures))
	for _, sig := range in.Signatures {
		e.WriteSignature(sig)
	}
}

func (in *compressedSiafundInput) DecodeFrom(d *types.Decoder) {
	(*compressedSiafundOutput)(&in.Parent).DecodeFrom(d)
	in.ClaimAddress = d.ReadAddress()
	in.SpendPolicy = d.ReadPolicy()
	in.Signatures = make([]types.InputSignature, d.ReadPrefix())
	for i := range in.Signatures {
		in.Signatures[i] = d.ReadSignature()
	}
	return
}

type compressedFileContract types.FileContract

func (fc compressedFileContract) EncodeTo(e *types.Encoder) {
	e.WriteOutputID(fc.ID)
	e.WriteFileContractState(fc.State)
	e.WritePrefix(len(fc.MerkleProof)) // omit proof data
	e.WriteUint64(fc.LeafIndex)
}

func (fc *compressedFileContract) DecodeFrom(d *types.Decoder) {
	*fc = compressedFileContract{
		d.ReadOutputID(),
		d.ReadFileContractState(),
		make([]types.Hash256, d.ReadPrefix()), // omit proof data
		d.ReadUint64(),
	}
}

type compressedFileContractRevision types.FileContractRevision

func (rev compressedFileContractRevision) EncodeTo(e *types.Encoder) {
	(compressedFileContract)(rev.Parent).EncodeTo(e)
	e.WriteFileContractState(rev.NewState)
	e.WriteSignature(rev.RenterSignature)
	e.WriteSignature(rev.HostSignature)
}

func (rev *compressedFileContractRevision) DecodeFrom(d *types.Decoder) {
	(*compressedFileContract)(&rev.Parent).DecodeFrom(d)
	rev.NewState = d.ReadFileContractState()
	rev.RenterSignature = d.ReadSignature()
	rev.HostSignature = d.ReadSignature()
}

type compressedFileContractResolution types.FileContractResolution

func (res compressedFileContractResolution) EncodeTo(e *types.Encoder) {
	(compressedFileContract)(res.Parent).EncodeTo(e)
	e.WriteStorageProof(res.StorageProof)
}

func (res *compressedFileContractResolution) DecodeFrom(d *types.Decoder) {
	(*compressedFileContract)(&res.Parent).DecodeFrom(d)
	res.StorageProof = d.ReadStorageProof()
}

type compressedTransaction types.Transaction

func (txn compressedTransaction) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(txn.SiacoinInputs))
	for _, in := range txn.SiacoinInputs {
		(compressedSiacoinInput)(in).EncodeTo(e)
	}
	e.WritePrefix(len(txn.SiacoinOutputs))
	for _, out := range txn.SiacoinOutputs {
		e.WriteBeneficiary(out)
	}
	e.WritePrefix(len(txn.SiafundInputs))
	for _, in := range txn.SiafundInputs {
		(compressedSiafundInput)(in).EncodeTo(e)
	}
	e.WritePrefix(len(txn.SiafundOutputs))
	for _, out := range txn.SiafundOutputs {
		e.WriteBeneficiary(out)
	}
	e.WritePrefix(len(txn.FileContracts))
	for _, fc := range txn.FileContracts {
		e.WriteFileContractState(fc)
	}
	e.WritePrefix(len(txn.FileContractRevisions))
	for _, rev := range txn.FileContractRevisions {
		(compressedFileContractRevision)(rev).EncodeTo(e)
	}
	e.WritePrefix(len(txn.FileContractResolutions))
	for _, res := range txn.FileContractResolutions {
		(compressedFileContractResolution)(res).EncodeTo(e)
	}
	e.WritePrefix(len(txn.ArbitraryData))
	e.Write(txn.ArbitraryData)
	e.WriteAddress(txn.NewFoundationAddress)
	e.WriteCurrency(txn.MinerFee)
}

func (txn *compressedTransaction) DecodeFrom(d *types.Decoder) {
	txn.SiacoinInputs = make([]types.SiacoinInput, d.ReadPrefix())
	for i := range txn.SiacoinInputs {
		(*compressedSiacoinInput)(&txn.SiacoinInputs[i]).DecodeFrom(d)
	}
	txn.SiacoinOutputs = make([]types.Beneficiary, d.ReadPrefix())
	for i := range txn.SiacoinOutputs {
		txn.SiacoinOutputs[i] = d.ReadBeneficiary()
	}
	txn.SiafundInputs = make([]types.SiafundInput, d.ReadPrefix())
	for i := range txn.SiafundInputs {
		(*compressedSiafundInput)(&txn.SiafundInputs[i]).DecodeFrom(d)
	}
	txn.SiafundOutputs = make([]types.Beneficiary, d.ReadPrefix())
	for i := range txn.SiafundOutputs {
		txn.SiafundOutputs[i] = d.ReadBeneficiary()
	}
	txn.FileContracts = make([]types.FileContractState, d.ReadPrefix())
	for i := range txn.FileContracts {
		txn.FileContracts[i] = d.ReadFileContractState()
	}
	txn.FileContractRevisions = make([]types.FileContractRevision, d.ReadPrefix())
	for i := range txn.FileContractRevisions {
		(*compressedFileContractRevision)(&txn.FileContractRevisions[i]).DecodeFrom(d)
	}
	txn.FileContractResolutions = make([]types.FileContractResolution, d.ReadPrefix())
	for i := range txn.FileContractResolutions {
		(*compressedFileContractResolution)(&txn.FileContractResolutions[i]).DecodeFrom(d)
	}
	txn.ArbitraryData = make([]byte, d.ReadPrefix())
	d.Read(txn.ArbitraryData)
	txn.NewFoundationAddress = d.ReadAddress()
	txn.MinerFee = d.ReadCurrency()
}
