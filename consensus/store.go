package consensus

import (
	"go.sia.tech/core/types"
)

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
	ValidFileContracts   []types.FileContractElement
	StorageProofBlockIDs []types.BlockID
}

// EncodeTo implements types.EncoderTo.
func (ts V1TransactionSupplement) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(ts.SiacoinInputs))
	for i := range ts.SiacoinInputs {
		ts.SiacoinInputs[i].EncodeTo(e)
	}
	e.WritePrefix(len(ts.SiafundInputs))
	for i := range ts.SiafundInputs {
		ts.SiafundInputs[i].EncodeTo(e)
	}
	e.WritePrefix(len(ts.RevisedFileContracts))
	for i := range ts.RevisedFileContracts {
		ts.RevisedFileContracts[i].EncodeTo(e)
	}
	e.WritePrefix(len(ts.ValidFileContracts))
	for i := range ts.ValidFileContracts {
		ts.ValidFileContracts[i].EncodeTo(e)
	}
}

// DecodeFrom implements types.DecoderFrom.
func (ts *V1TransactionSupplement) DecodeFrom(d *types.Decoder) {
	ts.SiacoinInputs = make([]types.SiacoinElement, d.ReadPrefix())
	for i := range ts.SiacoinInputs {
		ts.SiacoinInputs[i].DecodeFrom(d)
	}
	ts.SiafundInputs = make([]types.SiafundElement, d.ReadPrefix())
	for i := range ts.SiafundInputs {
		ts.SiafundInputs[i].DecodeFrom(d)
	}
	ts.RevisedFileContracts = make([]types.FileContractElement, d.ReadPrefix())
	for i := range ts.RevisedFileContracts {
		ts.RevisedFileContracts[i].DecodeFrom(d)
	}
	ts.ValidFileContracts = make([]types.FileContractElement, d.ReadPrefix())
	for i := range ts.ValidFileContracts {
		ts.ValidFileContracts[i].DecodeFrom(d)
	}
}

func (ts V1TransactionSupplement) siacoinElement(id types.SiacoinOutputID) (sce types.SiacoinElement, ok bool) {
	for _, sce := range ts.SiacoinInputs {
		if types.SiacoinOutputID(sce.ID) == id {
			return sce, true
		}
	}
	return
}

func (ts V1TransactionSupplement) siafundElement(id types.SiafundOutputID) (sce types.SiafundElement, ok bool) {
	for _, sfe := range ts.SiafundInputs {
		if types.SiafundOutputID(sfe.ID) == id {
			return sfe, true
		}
	}
	return
}

func (ts V1TransactionSupplement) fileContractElement(id types.FileContractID) (sce types.FileContractElement, ok bool) {
	for _, fce := range ts.RevisedFileContracts {
		if types.FileContractID(fce.ID) == id {
			return fce, true
		}
	}
	for _, fce := range ts.ValidFileContracts {
		if types.FileContractID(fce.ID) == id {
			return fce, true
		}
	}
	return
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
	e.WritePrefix(len(bs.Transactions))
	for i := range bs.Transactions {
		bs.Transactions[i].EncodeTo(e)
	}
	e.WritePrefix(len(bs.ExpiringFileContracts))
	for i := range bs.ExpiringFileContracts {
		bs.ExpiringFileContracts[i].EncodeTo(e)
	}
}

// DecodeFrom implements types.DecoderFrom.
func (bs *V1BlockSupplement) DecodeFrom(d *types.Decoder) {
	bs.Transactions = make([]V1TransactionSupplement, d.ReadPrefix())
	for i := range bs.Transactions {
		bs.Transactions[i].DecodeFrom(d)
	}
	bs.ExpiringFileContracts = make([]types.FileContractElement, d.ReadPrefix())
	for i := range bs.ExpiringFileContracts {
		bs.ExpiringFileContracts[i].DecodeFrom(d)
	}
}
