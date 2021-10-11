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
			root.EncodeTo(e)
		}
	}
}

// DecodeFrom implements types.DecoderFrom.
func (sa *StateAccumulator) DecodeFrom(d *types.Decoder) {
	sa.NumLeaves = d.ReadUint64()
	for i := range sa.Trees {
		if sa.HasTreeAtHeight(i) {
			sa.Trees[i].DecodeFrom(d)
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

// A CompressedBlock encodes a block in compressed form by merging its
// individual Merkle proofs into a single multiproof.
type CompressedBlock types.Block

// EncodeTo implements types.EncoderTo.
func (b CompressedBlock) EncodeTo(e *types.Encoder) {
	b.Header.EncodeTo(e)
	e.WritePrefix(len(b.Transactions))
	for _, txn := range b.Transactions {
		(compressedTransaction)(txn).EncodeTo(e)
	}
	for _, p := range ComputeMultiproof(b.Transactions) {
		p.EncodeTo(e)
	}
}

// DecodeFrom implements types.DecoderFrom.
func (b *CompressedBlock) DecodeFrom(d *types.Decoder) {
	b.Header.DecodeFrom(d)
	b.Transactions = make([]types.Transaction, d.ReadPrefix())
	for i := range b.Transactions {
		(*compressedTransaction)(&b.Transactions[i]).DecodeFrom(d)
	}
	proof := make([]types.Hash256, MultiproofSize(b.Transactions))
	for i := range proof {
		proof[i].DecodeFrom(d)
	}
	ExpandMultiproof(b.Transactions, proof)
}

// helper types for compressed encoding

type compressedStateElement types.StateElement

func (se compressedStateElement) EncodeTo(e *types.Encoder) {
	se.ID.EncodeTo(e)
	e.WriteUint64(se.LeafIndex)
	e.WritePrefix(len(se.MerkleProof)) // omit proof data
}

func (se *compressedStateElement) DecodeFrom(d *types.Decoder) {
	se.ID.DecodeFrom(d)
	se.LeafIndex = d.ReadUint64()
	se.MerkleProof = make([]types.Hash256, d.ReadPrefix()) // omit proof data
}

type compressedSiacoinElement types.SiacoinElement

func (sce compressedSiacoinElement) EncodeTo(e *types.Encoder) {
	sce.StateElement.EncodeTo(e)
	sce.SiacoinOutput.EncodeTo(e)
	e.WriteUint64(sce.Timelock)
}

func (sce *compressedSiacoinElement) DecodeFrom(d *types.Decoder) {
	sce.StateElement.DecodeFrom(d)
	sce.SiacoinOutput.DecodeFrom(d)
	sce.Timelock = d.ReadUint64()
}

type compressedSiacoinInput types.SiacoinInput

func (in compressedSiacoinInput) EncodeTo(e *types.Encoder) {
	(compressedSiacoinElement)(in.Parent).EncodeTo(e)
	e.WritePolicy(in.SpendPolicy)
	e.WritePrefix(len(in.Signatures))
	for _, sig := range in.Signatures {
		sig.EncodeTo(e)
	}
}

func (in *compressedSiacoinInput) DecodeFrom(d *types.Decoder) {
	(*compressedSiacoinElement)(&in.Parent).DecodeFrom(d)
	in.SpendPolicy = d.ReadPolicy()
	in.Signatures = make([]types.InputSignature, d.ReadPrefix())
	for i := range in.Signatures {
		in.Signatures[i].DecodeFrom(d)
	}
}

type compressedSiafundElement types.SiafundElement

func (sfe compressedSiafundElement) EncodeTo(e *types.Encoder) {
	sfe.StateElement.EncodeTo(e)
	sfe.SiafundOutput.EncodeTo(e)
	sfe.ClaimStart.EncodeTo(e)
}

func (sfe *compressedSiafundElement) DecodeFrom(d *types.Decoder) {
	sfe.StateElement.DecodeFrom(d)
	sfe.SiafundOutput.DecodeFrom(d)
	sfe.ClaimStart.DecodeFrom(d)
}

type compressedSiafundInput types.SiafundInput

func (in compressedSiafundInput) EncodeTo(e *types.Encoder) {
	(compressedSiafundElement)(in.Parent).EncodeTo(e)
	in.ClaimAddress.EncodeTo(e)
	e.WritePolicy(in.SpendPolicy)
	e.WritePrefix(len(in.Signatures))
	for _, sig := range in.Signatures {
		sig.EncodeTo(e)
	}
}

func (in *compressedSiafundInput) DecodeFrom(d *types.Decoder) {
	(*compressedSiafundElement)(&in.Parent).DecodeFrom(d)
	in.ClaimAddress.DecodeFrom(d)
	in.SpendPolicy = d.ReadPolicy()
	in.Signatures = make([]types.InputSignature, d.ReadPrefix())
	for i := range in.Signatures {
		in.Signatures[i].DecodeFrom(d)
	}
}

type compressedFileContractElement types.FileContractElement

func (fce compressedFileContractElement) EncodeTo(e *types.Encoder) {
	fce.StateElement.EncodeTo(e)
	fce.FileContract.EncodeTo(e)
}

func (fce *compressedFileContractElement) DecodeFrom(d *types.Decoder) {
	fce.StateElement.DecodeFrom(d)
	fce.FileContract.DecodeFrom(d)
}

type compressedFileContractRevision types.FileContractRevision

func (rev compressedFileContractRevision) EncodeTo(e *types.Encoder) {
	(compressedFileContractElement)(rev.Parent).EncodeTo(e)
	rev.Revision.EncodeTo(e)
	rev.RenterSignature.EncodeTo(e)
	rev.HostSignature.EncodeTo(e)
}

func (rev *compressedFileContractRevision) DecodeFrom(d *types.Decoder) {
	(*compressedFileContractElement)(&rev.Parent).DecodeFrom(d)
	rev.Revision.DecodeFrom(d)
	rev.RenterSignature.DecodeFrom(d)
	rev.HostSignature.DecodeFrom(d)
}

type compressedFileContractResolution types.FileContractResolution

func (res compressedFileContractResolution) EncodeTo(e *types.Encoder) {
	(compressedFileContractElement)(res.Parent).EncodeTo(e)
	res.StorageProof.EncodeTo(e)
}

func (res *compressedFileContractResolution) DecodeFrom(d *types.Decoder) {
	(*compressedFileContractElement)(&res.Parent).DecodeFrom(d)
	res.StorageProof.DecodeFrom(d)
}

type compressedTransaction types.Transaction

func (txn compressedTransaction) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(txn.SiacoinInputs))
	for _, in := range txn.SiacoinInputs {
		(compressedSiacoinInput)(in).EncodeTo(e)
	}
	e.WritePrefix(len(txn.SiacoinOutputs))
	for _, out := range txn.SiacoinOutputs {
		out.EncodeTo(e)
	}
	e.WritePrefix(len(txn.SiafundInputs))
	for _, in := range txn.SiafundInputs {
		(compressedSiafundInput)(in).EncodeTo(e)
	}
	e.WritePrefix(len(txn.SiafundOutputs))
	for _, out := range txn.SiafundOutputs {
		out.EncodeTo(e)
	}
	e.WritePrefix(len(txn.FileContracts))
	for _, fc := range txn.FileContracts {
		fc.EncodeTo(e)
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
	txn.NewFoundationAddress.EncodeTo(e)
	txn.MinerFee.EncodeTo(e)
}

func (txn *compressedTransaction) DecodeFrom(d *types.Decoder) {
	txn.SiacoinInputs = make([]types.SiacoinInput, d.ReadPrefix())
	for i := range txn.SiacoinInputs {
		(*compressedSiacoinInput)(&txn.SiacoinInputs[i]).DecodeFrom(d)
	}
	txn.SiacoinOutputs = make([]types.SiacoinOutput, d.ReadPrefix())
	for i := range txn.SiacoinOutputs {
		txn.SiacoinOutputs[i].DecodeFrom(d)
	}
	txn.SiafundInputs = make([]types.SiafundInput, d.ReadPrefix())
	for i := range txn.SiafundInputs {
		(*compressedSiafundInput)(&txn.SiafundInputs[i]).DecodeFrom(d)
	}
	txn.SiafundOutputs = make([]types.SiafundOutput, d.ReadPrefix())
	for i := range txn.SiafundOutputs {
		txn.SiafundOutputs[i].DecodeFrom(d)
	}
	txn.FileContracts = make([]types.FileContract, d.ReadPrefix())
	for i := range txn.FileContracts {
		txn.FileContracts[i].DecodeFrom(d)
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
	txn.NewFoundationAddress.DecodeFrom(d)
	txn.MinerFee.DecodeFrom(d)
}
