package consensus

import (
	"time"

	"go.sia.tech/core/types"
)

// EncodeTo implements types.EncoderTo.
func (sa StateAccumulator) EncodeTo(e *types.Encoder) {
	e.WriteUint64(sa.NumLeaves)
	for i, root := range sa.Trees {
		if sa.HasTreeAtHeight(i) {
			e.Encode(root)
		}
	}
}

// DecodeFrom implements types.DecoderFrom.
func (sa *StateAccumulator) DecodeFrom(d *types.Decoder) {
	sa.NumLeaves = d.ReadUint64()
	for i := range sa.Trees {
		if sa.HasTreeAtHeight(i) {
			d.Decode(&sa.Trees[i])
		}
	}
}

// EncodeTo implements types.EncoderTo.
func (ha HistoryAccumulator) EncodeTo(e *types.Encoder) {
	(StateAccumulator)(ha).EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (ha *HistoryAccumulator) DecodeFrom(d *types.Decoder) {
	(*StateAccumulator)(ha).DecodeFrom(d)
}

// EncodeTo implements types.EncoderTo.
func (vc ValidationContext) EncodeTo(e *types.Encoder) {
	e.EncodeAll(vc.Index, vc.State, vc.History)
	for _, ts := range vc.PrevTimestamps {
		e.WriteTime(ts)
	}
	e.EncodeAll(vc.TotalWork, vc.Difficulty, vc.OakWork)
	e.WriteUint64(uint64(vc.OakTime))
	e.WriteTime(vc.GenesisTimestamp)
	e.EncodeAll(vc.SiafundPool, vc.FoundationAddress)
}

// DecodeFrom implements types.DecoderFrom.
func (vc *ValidationContext) DecodeFrom(d *types.Decoder) {
	d.DecodeAll(&vc.Index, &vc.State, &vc.History)
	for i := range vc.PrevTimestamps {
		vc.PrevTimestamps[i] = d.ReadTime()
	}
	d.DecodeAll(&vc.TotalWork, &vc.Difficulty, &vc.OakWork)
	vc.OakTime = time.Duration(d.ReadUint64())
	vc.GenesisTimestamp = d.ReadTime()
	d.DecodeAll(&vc.SiafundPool, &vc.FoundationAddress)
}

// A CompressedBlock encodes a block in compressed form by merging its
// individual Merkle proofs into a single multiproof.
type CompressedBlock types.Block

// EncodeTo implements types.EncoderTo.
func (b CompressedBlock) EncodeTo(e *types.Encoder) {
	e.Encode(b.Header)
	e.WritePrefix(len(b.Transactions))
	for _, txn := range b.Transactions {
		e.Encode((compressedTransaction)(txn))
	}
	for _, p := range ComputeMultiproof(b.Transactions) {
		e.Encode(p)
	}
}

// DecodeFrom implements types.DecoderFrom.
func (b *CompressedBlock) DecodeFrom(d *types.Decoder) {
	d.Decode(&b.Header)
	b.Transactions = make([]types.Transaction, d.ReadPrefix())
	for i := range b.Transactions {
		(*compressedTransaction)(&b.Transactions[i]).DecodeFrom(d)
	}
	proof := make([]types.Hash256, MultiproofSize(b.Transactions))
	for i := range proof {
		d.Decode(&proof[i])
	}
	ExpandMultiproof(b.Transactions, proof)
}

// helper types for compressed encoding

type compressedSiacoinOutput types.SiacoinOutput

func (out compressedSiacoinOutput) EncodeTo(e *types.Encoder) {
	e.EncodeAll(out.ID, out.Value, out.Address)
	e.WriteUint64(out.Timelock)
	e.WritePrefix(len(out.MerkleProof)) // omit proof data
	e.WriteUint64(out.LeafIndex)
}

func (out *compressedSiacoinOutput) DecodeFrom(d *types.Decoder) {
	d.DecodeAll(&out.ID, &out.Value, &out.Address)
	out.Timelock = d.ReadUint64()
	out.MerkleProof = make([]types.Hash256, d.ReadPrefix()) // omit proof data
	out.LeafIndex = d.ReadUint64()
}

type compressedSiacoinInput types.SiacoinInput

func (in compressedSiacoinInput) EncodeTo(e *types.Encoder) {
	e.Encode((compressedSiacoinOutput)(in.Parent))
	e.WritePolicy(in.SpendPolicy)
	e.WritePrefix(len(in.Signatures))
	for _, sig := range in.Signatures {
		e.Encode(sig)
	}
}

func (in *compressedSiacoinInput) DecodeFrom(d *types.Decoder) {
	d.Decode((*compressedSiacoinOutput)(&in.Parent))
	in.SpendPolicy = d.ReadPolicy()
	in.Signatures = make([]types.InputSignature, d.ReadPrefix())
	for i := range in.Signatures {
		d.Decode(&in.Signatures[i])
	}
}

type compressedSiafundOutput types.SiafundOutput

func (out compressedSiafundOutput) EncodeTo(e *types.Encoder) {
	e.EncodeAll(out.ID, out.Value, out.Address, out.ClaimStart)
	e.WritePrefix(len(out.MerkleProof)) // omit proof data
	e.WriteUint64(out.LeafIndex)
}

func (out *compressedSiafundOutput) DecodeFrom(d *types.Decoder) {
	d.DecodeAll(&out.ID, &out.Value, &out.Address, &out.ClaimStart)
	out.MerkleProof = make([]types.Hash256, d.ReadPrefix()) // omit proof data
	out.LeafIndex = d.ReadUint64()
}

type compressedSiafundInput types.SiafundInput

func (in compressedSiafundInput) EncodeTo(e *types.Encoder) {
	e.EncodeAll((compressedSiafundOutput)(in.Parent), in.ClaimAddress)
	e.WritePolicy(in.SpendPolicy)
	e.WritePrefix(len(in.Signatures))
	for _, sig := range in.Signatures {
		e.Encode(sig)
	}
}

func (in *compressedSiafundInput) DecodeFrom(d *types.Decoder) {
	d.DecodeAll((*compressedSiafundOutput)(&in.Parent), &in.ClaimAddress)
	in.SpendPolicy = d.ReadPolicy()
	in.Signatures = make([]types.InputSignature, d.ReadPrefix())
	for i := range in.Signatures {
		d.Decode(&in.Signatures[i])
	}
}

type compressedFileContract types.FileContract

func (fc compressedFileContract) EncodeTo(e *types.Encoder) {
	e.EncodeAll(fc.ID, fc.State)
	e.WritePrefix(len(fc.MerkleProof)) // omit proof data
	e.WriteUint64(fc.LeafIndex)
}

func (fc *compressedFileContract) DecodeFrom(d *types.Decoder) {
	d.DecodeAll(&fc.ID, &fc.State)
	fc.MerkleProof = make([]types.Hash256, d.ReadPrefix()) // omit proof data
	fc.LeafIndex = d.ReadUint64()
}

type compressedFileContractRevision types.FileContractRevision

func (rev compressedFileContractRevision) EncodeTo(e *types.Encoder) {
	e.EncodeAll(
		(compressedFileContract)(rev.Parent),
		rev.NewState,
		rev.RenterSignature,
		rev.HostSignature,
	)
}

func (rev *compressedFileContractRevision) DecodeFrom(d *types.Decoder) {
	d.DecodeAll(
		(*compressedFileContract)(&rev.Parent),
		&rev.NewState,
		&rev.RenterSignature,
		&rev.HostSignature,
	)
}

type compressedFileContractResolution types.FileContractResolution

func (res compressedFileContractResolution) EncodeTo(e *types.Encoder) {
	e.EncodeAll((compressedFileContract)(res.Parent), res.StorageProof)
}

func (res *compressedFileContractResolution) DecodeFrom(d *types.Decoder) {
	d.DecodeAll((*compressedFileContract)(&res.Parent), &res.StorageProof)
}

type compressedTransaction types.Transaction

func (txn compressedTransaction) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(txn.SiacoinInputs))
	for _, in := range txn.SiacoinInputs {
		e.Encode((compressedSiacoinInput)(in))
	}
	e.WritePrefix(len(txn.SiacoinOutputs))
	for _, out := range txn.SiacoinOutputs {
		e.Encode(out)
	}
	e.WritePrefix(len(txn.SiafundInputs))
	for _, in := range txn.SiafundInputs {
		e.Encode((compressedSiafundInput)(in))
	}
	e.WritePrefix(len(txn.SiafundOutputs))
	for _, out := range txn.SiafundOutputs {
		e.Encode(out)
	}
	e.WritePrefix(len(txn.FileContracts))
	for _, fc := range txn.FileContracts {
		e.Encode(fc)
	}
	e.WritePrefix(len(txn.FileContractRevisions))
	for _, rev := range txn.FileContractRevisions {
		e.Encode((compressedFileContractRevision)(rev))
	}
	e.WritePrefix(len(txn.FileContractResolutions))
	for _, res := range txn.FileContractResolutions {
		e.Encode((compressedFileContractResolution)(res))
	}
	e.WritePrefix(len(txn.ArbitraryData))
	e.Write(txn.ArbitraryData)
	e.Encode(txn.NewFoundationAddress)
	e.Encode(txn.MinerFee)
}

func (txn *compressedTransaction) DecodeFrom(d *types.Decoder) {
	txn.SiacoinInputs = make([]types.SiacoinInput, d.ReadPrefix())
	for i := range txn.SiacoinInputs {
		d.Decode((*compressedSiacoinInput)(&txn.SiacoinInputs[i]))
	}
	txn.SiacoinOutputs = make([]types.Beneficiary, d.ReadPrefix())
	for i := range txn.SiacoinOutputs {
		d.Decode(&txn.SiacoinOutputs[i])
	}
	txn.SiafundInputs = make([]types.SiafundInput, d.ReadPrefix())
	for i := range txn.SiafundInputs {
		d.Decode((*compressedSiafundInput)(&txn.SiafundInputs[i]))
	}
	txn.SiafundOutputs = make([]types.Beneficiary, d.ReadPrefix())
	for i := range txn.SiafundOutputs {
		d.Decode(&txn.SiafundOutputs[i])
	}
	txn.FileContracts = make([]types.FileContractState, d.ReadPrefix())
	for i := range txn.FileContracts {
		d.Decode(&txn.FileContracts[i])
	}
	txn.FileContractRevisions = make([]types.FileContractRevision, d.ReadPrefix())
	for i := range txn.FileContractRevisions {
		d.Decode((*compressedFileContractRevision)(&txn.FileContractRevisions[i]))
	}
	txn.FileContractResolutions = make([]types.FileContractResolution, d.ReadPrefix())
	for i := range txn.FileContractResolutions {
		d.Decode((*compressedFileContractResolution)(&txn.FileContractResolutions[i]))
	}
	txn.ArbitraryData = make([]byte, d.ReadPrefix())
	d.Read(txn.ArbitraryData)
	d.Decode(&txn.NewFoundationAddress)
	d.Decode(&txn.MinerFee)
}
