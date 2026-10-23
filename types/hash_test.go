package types

import (
	"bytes"
	"testing"

	"go.sia.tech/core/blake2b"
	"lukechampine.com/frand"
)

// TestStratumBlockMerkleRoot tests the merkle root logic for
// stratum miners to ensure it is compatible with existing
// hardware.
func TestStratumBlockMerkleRoot(t *testing.T) {
	minerPayouts := make([]SiacoinOutput, frand.Intn(100))
	txns := make([]Transaction, frand.Intn(100))
	for i := range minerPayouts {
		minerPayouts[i].Address = frand.Entropy256()
		minerPayouts[i].Value = NewCurrency64(frand.Uint64n(100))
	}
	for i := range txns {
		txns[i].ArbitraryData = [][]byte{frand.Bytes(32)}
	}

	h := hasherPool.Get().(*Hasher)
	defer hasherPool.Put(h)
	var acc blake2b.Accumulator
	for _, mp := range minerPayouts {
		h.Reset()
		h.E.WriteUint8(leafHashPrefix)
		V1SiacoinOutput(mp).EncodeTo(h.E)
		acc.AddLeaf(h.Sum())
	}
	for _, txn := range txns {
		h.Reset()
		h.E.WriteUint8(leafHashPrefix)
		txn.EncodeTo(h.E)
		acc.AddLeaf(h.Sum())
	}

	var trees []Hash256
	for i, root := range acc.Trees {
		if acc.NumLeaves&(1<<i) != 0 {
			trees = append(trees, root)
		}
	}

	coinbaseTxn := Transaction{
		ArbitraryData: [][]byte{[]byte("hello, world!")},
	}
	h.Reset()
	h.E.WriteUint8(0x00)
	coinbaseTxn.EncodeTo(h.E)
	root := h.Sum()

	for _, tree := range trees {
		root = blake2b.SumPair(tree, root)
	}

	expectedRoot := blockMerkleRoot(minerPayouts, append(txns, coinbaseTxn))
	if root != expectedRoot {
		t.Fatalf("expected %x, got %x", expectedRoot, root)
	}
}

func BenchmarkMultiproofSize(b *testing.B) {
	for _, tc := range []struct {
		name       string
		count      int
		stride     uint64
		duplicates int
	}{
		{"Single", 1, 1, 1},
		{"Sparse64", 64, 1 << 20, 1},
		{"Sparse1024", 1024, 1 << 20, 1},
		{"Clustered64", 64, 1, 1},
		{"Clustered1024", 1024, 1, 1},
		{"Duplicates1024", 1024, 1 << 20, 4},
	} {
		b.Run(tc.name, func(b *testing.B) {
			// Count only: grouping and sorting are covered by the decoding
			// benchmark below. The leaves are already sorted in a height-32 tree.
			elements := make([]StateElement, tc.count)
			var trees [64][]elementLeaf
			for i := range elements {
				elements[i].LeafIndex = uint64(i/tc.duplicates) * tc.stride
				trees[32] = append(trees[32], elementLeaf{StateElement: &elements[i]})
			}
			b.ReportAllocs()
			for b.Loop() {
				multiproofSize(&trees)
			}
		})
	}
}

// benchmarkMultiproofTxns constructs consistent proofs for a deterministic
// height-12 tree, with inputs in a permuted order to exercise the decoder's sort.
func benchmarkMultiproofTxns(count, duplicates int) V2TransactionsMultiproof {
	const numLeaves = 1 << 12
	elements := make([]SiacoinElement, numLeaves)
	levels := [][]Hash256{make([]Hash256, numLeaves)}
	for i := range elements {
		elements[i] = SiacoinElement{
			ID:           SiacoinOutputID{byte(i), byte(i >> 8)},
			StateElement: StateElement{LeafIndex: uint64(i)},
			SiacoinOutput: SiacoinOutput{
				Value: NewCurrency64(uint64(i + 1)),
			},
		}
		levels[0][i] = siacoinLeaf(&elements[i]).hash()
	}
	for len(levels[len(levels)-1]) > 1 {
		children := levels[len(levels)-1]
		parents := make([]Hash256, len(children)/2)
		for i := range parents {
			parents[i] = blake2b.SumPair(children[2*i], children[2*i+1])
		}
		levels = append(levels, parents)
	}
	const inputsPerTxn = 8
	txns := make(V2TransactionsMultiproof, (count+inputsPerTxn-1)/inputsPerTxn)
	for i := range count {
		index := (i / duplicates * 2659) % numLeaves
		parent := elements[index]
		for height := 0; height < len(levels)-1; height++ {
			parent.StateElement.MerkleProof = append(parent.StateElement.MerkleProof, levels[height][(index>>height)^1])
		}
		txn := &txns[i/inputsPerTxn]
		txn.SiacoinInputs = append(txn.SiacoinInputs, V2SiacoinInput{
			Parent:          parent,
			SatisfiedPolicy: SatisfiedPolicy{Policy: AnyoneCanSpend()},
		})
	}
	return txns
}

func BenchmarkMultiproofDecode(b *testing.B) {
	for _, tc := range []struct {
		name       string
		count      int
		duplicates int
	}{
		{"Inputs64", 64, 1},
		{"Inputs1024", 1024, 1},
		{"Duplicates1024", 1024, 4},
	} {
		b.Run(tc.name, func(b *testing.B) {
			txns := benchmarkMultiproofTxns(tc.count, tc.duplicates)
			var buf bytes.Buffer
			e := NewEncoder(&buf)
			txns.EncodeTo(e)
			if err := e.Flush(); err != nil {
				b.Fatal(err)
			}
			encoded := buf.Bytes()

			// Check the complete expanded proofs before timing the decoder.
			d := NewBufDecoder(encoded)
			var decoded V2TransactionsMultiproof
			decoded.DecodeFrom(d)
			if err := d.Err(); err != nil {
				b.Fatal(err)
			}
			encodeFull := func(txns V2TransactionsMultiproof) []byte {
				var buf bytes.Buffer
				e := NewEncoder(&buf)
				EncodeSlice(e, txns)
				if err := e.Flush(); err != nil {
					b.Fatal(err)
				}
				return buf.Bytes()
			}
			if !bytes.Equal(encodeFull(txns), encodeFull(decoded)) {
				b.Fatal("expanded proofs differ from the originals")
			}

			b.SetBytes(int64(len(encoded)))
			b.ReportAllocs()
			for b.Loop() {
				var txns V2TransactionsMultiproof
				d := NewBufDecoder(encoded)
				txns.DecodeFrom(d)
				if err := d.Err(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
