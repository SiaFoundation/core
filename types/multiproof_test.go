package types_test

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"sort"
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
	return multiproofTxnsWithLeaves(numTxns, numElems, 19527)
}

func multiproofTxnsWithLeaves(numTxns int, numElems int, numLeaves uint64) []types.V2Transaction {
	// fake accumulator state
	cs := (&consensus.Network{InitialTarget: types.BlockID{0: 1}, BlockInterval: time.Second}).GenesisState()
	cs.Elements.NumLeaves = numLeaves
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
	sces := make([]types.SiacoinElement, len(cau.SiacoinElementDiffs()))
	for i := range sces {
		sces[i] = cau.SiacoinElementDiffs()[i].SiacoinElement.Copy()
	}
	sfes := make([]types.SiafundElement, len(cau.SiafundElementDiffs()))
	for i := range sfes {
		sfes[i] = cau.SiafundElementDiffs()[i].SiafundElement.Copy()
	}
	fces := make([]types.V2FileContractElement, len(cau.V2FileContractElementDiffs()))
	for i := range fces {
		fces[i] = cau.V2FileContractElementDiffs()[i].V2FileContractElement.Copy()
	}

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
				txn.SiacoinInputs, sces = append(txn.SiacoinInputs, types.V2SiacoinInput{
					Parent:          sces[0].Copy(),
					SatisfiedPolicy: sp,
				}), sces[1:]
			case 1:
				txn.SiafundInputs, sfes = append(txn.SiafundInputs, types.V2SiafundInput{
					Parent:          sfes[0].Copy(),
					SatisfiedPolicy: sp,
				}), sfes[1:]
			case 2:
				txn.FileContractRevisions, fces = append(txn.FileContractRevisions, types.V2FileContractRevision{
					Parent: fces[0].Copy(),
				}), fces[1:]
			case 3:
				txn.FileContractResolutions, fces = append(txn.FileContractResolutions, types.V2FileContractResolution{
					Parent:     fces[0].Copy(),
					Resolution: &types.V2FileContractExpiration{},
				}), fces[1:]
			}
		}
	}
	// make every 5th siacoin input ephemeral
	n := 0
	for i := range txns {
		for j := range txns[i].SiacoinInputs {
			if (n+1)%5 == 0 {
				txns[i].SiacoinInputs[j].Parent.StateElement = types.StateElement{LeafIndex: types.UnassignedLeafIndex}
			}
			n++
		}
	}
	return txns
}

func TestMultiproofEncoding(t *testing.T) {
	for _, n := range []int{0, 1, 2, 10} {
		txns := multiproofTxns(n, n)
		if len(txns) == 0 {
			txns = nil // DecodeSlice leaves empty slices nil
		}
		b := types.V2BlockData{Transactions: txns}
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

func referenceMultiproofSize(txns []types.V2Transaction) int {
	var trees [64][]uint64
	add := func(se types.StateElement) {
		if se.LeafIndex != types.UnassignedLeafIndex {
			trees[len(se.MerkleProof)] = append(trees[len(se.MerkleProof)], se.LeafIndex)
		}
	}
	for _, txn := range txns {
		for _, in := range txn.SiacoinInputs {
			add(in.Parent.StateElement)
		}
		for _, in := range txn.SiafundInputs {
			add(in.Parent.StateElement)
		}
		for _, rev := range txn.FileContractRevisions {
			add(rev.Parent.StateElement)
		}
		for _, res := range txn.FileContractResolutions {
			add(res.Parent.StateElement)
			if sp, ok := res.Resolution.(*types.V2StorageProof); ok {
				add(sp.ProofIndex.StateElement)
			}
		}
	}
	// Count missing subtrees recursively, independently of the adjacent-index
	// formula used to size the decoder's proof buffer.
	var count func(i, j uint64, indices []uint64) int
	count = func(i, j uint64, indices []uint64) int {
		if len(indices) == 0 {
			return 1
		} else if j-i == 1 {
			return 0
		}
		mid := i + (j-i)/2
		split := sort.Search(len(indices), func(i int) bool { return indices[i] >= mid })
		return count(i, mid, indices[:split]) + count(mid, j, indices[split:])
	}
	var size int
	for height, indices := range trees {
		if len(indices) != 0 {
			slices.Sort(indices)
			start := indices[0] &^ (uint64(1)<<height - 1)
			size += count(start, start+1<<height, indices)
		}
	}
	return size
}

func TestMultiproofSize(t *testing.T) {
	rng := frand.NewCustom(make([]byte, 32), 1024, 12)
	for iteration := range 32 {
		numLeaves := rng.Uint64n(1 << 62)
		if iteration%2 != 0 {
			numLeaves |= 1 << 63
		} else if iteration == 0 {
			numLeaves = 1<<63 - 1 // carry into a tree of height 63
		}
		t.Run(fmt.Sprint(iteration), func(t *testing.T) {
			numTxns, numElems := rng.Intn(8)+1, rng.Intn(8)+1
			if iteration == 0 {
				numTxns, numElems = 1, 1
			}
			txns := multiproofTxnsWithLeaves(numTxns, numElems, numLeaves)
			if iteration == 0 && len(txns[0].SiacoinInputs[0].Parent.StateElement.MerkleProof) != 63 {
				t.Fatal("expected a height 63 proof")
			}
			// Repeated inputs must not increase the multiproof size.
			for _, txn := range txns {
				for _, in := range txn.SiacoinInputs {
					in.Parent = in.Parent.Copy()
					txns[0].SiacoinInputs = append(txns[0].SiacoinInputs, in)
				}
			}
			encode := func(v types.EncoderTo) []byte {
				var buf bytes.Buffer
				e := types.NewEncoder(&buf)
				v.EncodeTo(e)
				if err := e.Flush(); err != nil {
					t.Fatal(err)
				}
				return buf.Bytes()
			}
			const marker = uint64(0x0123456789ABCDEF)
			var buf bytes.Buffer
			e := types.NewEncoder(&buf)
			types.V2TransactionsMultiproof(txns).EncodeTo(e)
			e.WriteUint64(marker)
			if err := e.Flush(); err != nil {
				t.Fatal(err)
			}
			// The recursive reference count must locate the end of the encoded
			// proof, and decoding must consume exactly that many hashes.
			d := types.NewBufDecoder(buf.Bytes())
			var proofless []types.V2Transaction
			types.DecodeSlice(d, &proofless)
			_ = d.ReadUint64() // number of leaves
			for range referenceMultiproofSize(txns) {
				var h types.Hash256
				h.DecodeFrom(d)
			}
			if d.ReadUint64() != marker || d.Err() != nil {
				t.Fatal("reference size disagrees with encoded multiproof")
			}
			d = types.NewBufDecoder(buf.Bytes())
			var decoded types.V2TransactionsMultiproof
			decoded.DecodeFrom(d)
			if d.ReadUint64() != marker || d.Err() != nil {
				t.Fatal("decoder consumed the wrong number of proof hashes")
			}
			for i := range txns {
				if !bytes.Equal(encode(txns[i]), encode(decoded[i])) {
					t.Fatal("expanded transaction proofs differ from originals")
				}
			}
		})
	}
}

type uncompressedBlock types.Block

func (b uncompressedBlock) EncodeTo(e *types.Encoder) {
	types.V1Block(b).EncodeTo(e)
	e.WriteBool(b.V2 != nil)
	if b.V2 != nil {
		e.WriteUint64(b.V2.Height)
		b.V2.Commitment.EncodeTo(e)
		types.EncodeSlice(e, b.V2.Transactions)
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
		desc string
		txns []types.V2Transaction
		exp  float64
	}{
		{"nil", nil, 1.071},
		{"0 elements", make([]types.V2Transaction, 10), 1.04},
		{"1 element", multiproofTxns(1, 1), 1.025},
		{"4 elements", multiproofTxns(2, 2), 0.90},
		{"10 elements", multiproofTxns(2, 5), 0.85},
		{"25 elements", multiproofTxns(5, 5), 0.75},
		{"100 elements", multiproofTxns(10, 10), 0.71},
	}
	for _, test := range tests {
		if r := ratio(test.txns); r >= test.exp {
			t.Errorf("%s compression ratio: expected <%g, got %g", test.desc, test.exp, r)
		}
	}
}
