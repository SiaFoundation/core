package merkle_test

import (
	"bytes"
	"io"
	"math"
	"math/rand"
	"reflect"
	"testing"

	"go.sia.tech/core/internal/chainutil"
	"go.sia.tech/core/merkle"
	"go.sia.tech/core/types"
)

func TestEncoding(t *testing.T) {
	// NOTE: Multiproof encoding only works with "real" blocks -- we can't
	// generate fake Merkle proofs randomly, because they won't share nodes with
	// each other the way they should.

	sim := chainutil.NewChainSim()
	block := sim.MineBlocks(100)[99]

	// to prevent nil/[] mismatches, roundtrip each transaction with standard encoding
	for i := range block.Transactions {
		var buf bytes.Buffer
		e := types.NewEncoder(&buf)
		block.Transactions[i].EncodeTo(e)
		e.Flush()
		d := types.NewDecoder(io.LimitedReader{R: &buf, N: math.MaxInt64})
		block.Transactions[i].DecodeFrom(d)
	}

	var buf bytes.Buffer
	e := types.NewEncoder(&buf)
	d := types.NewDecoder(io.LimitedReader{R: &buf, N: math.MaxInt64})
	(*merkle.CompressedBlock)(&block).EncodeTo(e)
	e.Flush()

	var read types.Block
	(*merkle.CompressedBlock)(&read).DecodeFrom(d)
	if err := d.Err(); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(block, read) {
		t.Fatalf("CompressedBlock did not survive roundtrip: expected %v, got %v", block, read)
	}
}

func TestBlockCompression(t *testing.T) {
	ratio := func(b types.Block) float64 {
		var buf bytes.Buffer
		e := types.NewEncoder(&buf)
		e.WriteUint8(1) // version
		b.Header.EncodeTo(e)
		e.WritePrefix(len(b.Transactions))
		for i := range b.Transactions {
			b.Transactions[i].EncodeTo(e)
		}
		e.Flush()
		uncompressed := buf.Len()

		buf.Reset()
		(*merkle.CompressedBlock)(&b).EncodeTo(e)
		e.Flush()
		compressed := buf.Len()

		return float64(compressed) / float64(uncompressed)
	}

	// empty block
	b := types.Block{}
	if r := ratio(b); r != 1 {
		t.Errorf("empty block compression ratio: expected %.3g, got %.3g", 1.0, r)
	}

	// 10 empty transactions
	b = types.Block{Transactions: make([]types.Transaction, 10)}
	if r := ratio(b); r != 1 {
		t.Errorf("empty txns compression ratio: expected %.3g, got %.3g", 1.0, r)
	}

	// 10 random transactions
	rng := rand.New(rand.NewSource(0))
	sim := chainutil.NewChainSim()
	for i, minedBlock := range sim.MineBlocks(10) {
		b.Transactions[i] = minedBlock.Transactions[rng.Intn(len(minedBlock.Transactions))]
	}
	if r := ratio(b); r >= 0.9 {
		t.Errorf("random txns compression ratio: expected <%.3g, got %.3g", 0.9, r)
	}

	// a simulated block
	b = sim.MineBlock()
	if r := ratio(b); r >= 0.9 {
		t.Errorf("simulated block compression ratio: expected <%.3g, got %.3g", 0.9, r)
	}
}
