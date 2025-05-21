package consensus

import (
	"testing"

	"go.sia.tech/core/blake2b"
	"go.sia.tech/core/types"
	"lukechampine.com/frand"
)

// TestStratumBlockMerkleRoot tests the merkle root logic for
// stratum miners to ensure it is compatible with existing
// hardware.
func TestStratumBlockMerkleRoot(t *testing.T) {
	n, genesis := testnet()
	n.HardforkV2.AllowHeight = 0

	_, cs := newConsensusDB(n, genesis)

	txns := make([]types.Transaction, frand.Intn(100))
	for i := range txns {
		txns[i].ArbitraryData = [][]byte{frand.Bytes(16)}
	}
	v2Txns := make([]types.V2Transaction, frand.Intn(100))
	for i := range v2Txns {
		v2Txns[i].ArbitraryData = frand.Bytes(16)
	}

	// build the commitment tree manually, leaving out the coinbase transaction
	var acc blake2b.Accumulator
	acc.AddLeaf(hashAll(uint8(0), "commitment", cs.v2ReplayPrefix(), types.Hash256(hashAll(cs)), types.VoidAddress))
	for _, txn := range txns {
		acc.AddLeaf(txn.FullHash())
	}
	for _, txn := range v2Txns {
		acc.AddLeaf(txn.FullHash())
	}

	var trees []types.Hash256
	for i, root := range acc.Trees {
		if acc.NumLeaves&(1<<i) != 0 {
			trees = append(trees, root)
		}
	}
	coinbaseTxn := types.V2Transaction{
		ArbitraryData: []byte("hello, world!"),
	}
	root := coinbaseTxn.FullHash()
	for _, tree := range trees {
		root = blake2b.SumPair(tree, root)
	}

	expectedRoot := cs.Commitment(types.VoidAddress, txns, append(v2Txns, coinbaseTxn))
	if root != expectedRoot {
		t.Fatalf("expected %q, got %q", expectedRoot, types.Hash256(root))
	}
}
