package types_test

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"lukechampine.com/frand"
)

// Multiproof encoding only works with "real" transactions -- we can't generate
// fake Merkle proofs randomly, because they won't share nodes with each other
// the way they should. This is annoying.
func multiproofTxns(numTxns int, numElems int) []types.V2Transaction {
	// fake accumulator state
	cs := (&consensus.Network{InitialTarget: types.BlockID{0: 1}}).GenesisState()
	cs.Elements.NumLeaves = 19527 // arbitrary
	for i := range cs.Elements.Trees {
		cs.Elements.Trees[i] = frand.Entropy256()
	}
	// create a bunch of elements in a fake block
	b := types.Block{
		V2: &types.V2BlockData{
			Transactions: []types.V2Transaction{{
				// NOTE: this creates more elements than necessary, but that's
				// desirable; otherwise they'll be contiguous and we'll end up
				// with an uncharacteristically-small multiproof
				SiacoinOutputs: make([]types.SiacoinOutput, numTxns*numElems),
				SiafundOutputs: make([]types.SiafundOutput, numTxns*numElems),
				FileContracts:  make([]types.V2FileContract, numTxns*numElems),
			}},
		},
	}
	// apply the block and extract the created elements
	cs, cau := consensus.ApplyBlock(cs, b, consensus.V1BlockSupplement{}, time.Time{})
	var sces []types.SiacoinElement
	cau.ForEachSiacoinElement(func(sce types.SiacoinElement, spent bool) { sces = append(sces, sce) })
	var sfes []types.SiafundElement
	cau.ForEachSiafundElement(func(sfe types.SiafundElement, spent bool) { sfes = append(sfes, sfe) })
	var fces []types.V2FileContractElement
	cau.ForEachV2FileContractElement(func(fce types.V2FileContractElement, rev *types.V2FileContractElement, res types.V2FileContractResolutionType) {
		fces = append(fces, fce)
	})
	// select randomly
	rng := frand.NewCustom(make([]byte, 32), 1024, 12)
	rng.Shuffle(len(sces), reflect.Swapper(sces))
	rng.Shuffle(len(sfes), reflect.Swapper(sfes))
	rng.Shuffle(len(fces), reflect.Swapper(fces))

	// use the elements in fake txns
	sp := types.SatisfiedPolicy{Policy: types.AnyoneCanSpend()}
	txns := make([]types.V2Transaction, numTxns)
	for i := range txns {
		txn := &txns[i]
		for j := 0; j < numElems; j++ {
			switch j % 4 {
			case 0:
				sce := sces[0]
				sces = sces[1:]
				txn.SiacoinInputs = append(txn.SiacoinInputs, types.V2SiacoinInput{
					Parent:          sce,
					SatisfiedPolicy: sp,
				})
			case 1:
				sfe := sfes[0]
				sfes = sfes[1:]
				txn.SiafundInputs = append(txn.SiafundInputs, types.V2SiafundInput{
					Parent:          sfe,
					SatisfiedPolicy: sp,
				})
			case 2:
				fce := fces[0]
				fces = fces[1:]
				txn.FileContractRevisions = append(txn.FileContractRevisions, types.V2FileContractRevision{
					Parent: fce,
				})
			case 3:
				fce := fces[0]
				fces = fces[1:]
				txn.FileContractResolutions = append(txn.FileContractResolutions, types.V2FileContractResolution{
					Parent:     fce,
					Resolution: &types.V2FileContractExpiration{},
				})
			}
		}
	}
	return txns
}

func TestMultiproofEncoding(t *testing.T) {
	for _, n := range []int{0, 1, 2, 10} {
		b := types.V2BlockData{Transactions: multiproofTxns(n, n)}
		// placate reflect.DeepEqual
		for i := range b.Transactions {
			var buf bytes.Buffer
			e := types.NewEncoder(&buf)
			b.Transactions[i].EncodeTo(e)
			e.Flush()
			b.Transactions[i].DecodeFrom(types.NewBufDecoder(buf.Bytes()))
		}

		var buf bytes.Buffer
		e := types.NewEncoder(&buf)
		b.EncodeTo(e)
		e.Flush()
		d := types.NewBufDecoder(buf.Bytes())
		var b2 types.V2BlockData
		b2.DecodeFrom(d)
		if err := d.Err(); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(b, b2) {
			t.Fatalf("multiproof encoding of %v txns did not survive roundtrip: expected %v, got %v", n, b, b2)
		}
	}
}

type uncompressedBlock types.Block

func (b uncompressedBlock) EncodeTo(e *types.Encoder) {
	types.V1Block(b).EncodeTo(e)
	e.WriteBool(b.V2 != nil)
	if b.V2 != nil {
		e.WriteUint64(b.V2.Height)
		b.V2.Commitment.EncodeTo(e)
		e.WritePrefix(len(b.V2.Transactions))
		for i := range b.V2.Transactions {
			b.V2.Transactions[i].EncodeTo(e)
		}
	}
}

func TestBlockCompression(t *testing.T) {
	encSize := func(v types.EncoderTo) int {
		var buf bytes.Buffer
		e := types.NewEncoder(&buf)
		v.EncodeTo(e)
		e.Flush()
		return buf.Len()
	}
	ratio := func(txns []types.V2Transaction) float64 {
		b := types.Block{V2: &types.V2BlockData{Transactions: txns}}
		return float64(encSize(types.V2Block(b))) / float64(encSize(uncompressedBlock(b)))
	}

	tests := []struct {
		desc  string
		txns  []types.V2Transaction
		exp   float64
		exact bool
	}{
		{"nil", nil, 1, true},
		{"0 elements", make([]types.V2Transaction, 10), 1, true},
		{"1 element", multiproofTxns(1, 1), 1.01, false},
		{"4 elements", multiproofTxns(2, 2), 0.90, false},
		{"10 elements", multiproofTxns(2, 5), 0.85, false},
		{"25 elements", multiproofTxns(5, 5), 0.75, false},
		{"100 elements", multiproofTxns(10, 10), 0.70, false},
	}
	for _, test := range tests {
		if r := ratio(test.txns); test.exact && r != test.exp {
			t.Errorf("%s compression ratio: expected %.3g, got %.3g", test.desc, test.exp, r)
		} else if !test.exact && r >= test.exp {
			t.Errorf("%s compression ratio: expected <%.3g, got %.3g", test.desc, test.exp, r)
		}
	}
}
