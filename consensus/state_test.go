package consensus

import (
	"encoding/json"
	"math"
	"reflect"
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
	acc.AddLeaf(hashAll(leafHashPrefix, "commitment", cs.v2ReplayPrefix(), types.Hash256(hashAll(cs)), types.VoidAddress))
	for _, txn := range txns {
		acc.AddLeaf(txn.MerkleLeafHash())
	}
	for _, txn := range v2Txns {
		acc.AddLeaf(txn.MerkleLeafHash())
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
	root := coinbaseTxn.MerkleLeafHash()
	for _, tree := range trees {
		root = blake2b.SumPair(tree, root)
	}

	expectedRoot := cs.Commitment(types.VoidAddress, txns, append(v2Txns, coinbaseTxn))
	if root != expectedRoot {
		t.Fatalf("expected %q, got %q", expectedRoot, types.Hash256(root))
	}
}

func TestV2FileContractElementDiffJSON(t *testing.T) {
	randContract := func(t *testing.T) types.V2FileContract {
		t.Helper()
		return types.V2FileContract{
			Capacity:         frand.Uint64n(math.MaxUint64),
			Filesize:         frand.Uint64n(math.MaxUint64),
			FileMerkleRoot:   frand.Entropy256(),
			ProofHeight:      frand.Uint64n(math.MaxUint64),
			ExpirationHeight: frand.Uint64n(math.MaxUint64),
			RenterOutput: types.SiacoinOutput{
				Value:   types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
				Address: frand.Entropy256(),
			},
			HostOutput: types.SiacoinOutput{
				Value:   types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
				Address: frand.Entropy256(),
			},
			MissedHostValue: types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
			TotalCollateral: types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
			RenterPublicKey: frand.Entropy256(),
			HostPublicKey:   frand.Entropy256(),
			RevisionNumber:  frand.Uint64n(math.MaxUint64),

			// signatures cover above fields
			RenterSignature: (types.Signature)(frand.Bytes(64)),
			HostSignature:   (types.Signature)(frand.Bytes(64)),
		}
	}

	fce := types.V2FileContractElement{
		ID: frand.Entropy256(),
		StateElement: types.StateElement{
			LeafIndex: frand.Uint64n(math.MaxUint64),
			MerkleProof: []types.Hash256{
				frand.Entropy256(),
				frand.Entropy256(),
				frand.Entropy256(),
			},
		},
		V2FileContract: randContract(t),
	}

	var tests = []types.V2FileContractResolutionType{
		&types.V2StorageProof{
			ProofIndex: types.ChainIndexElement{
				ID: frand.Entropy256(),
				StateElement: types.StateElement{
					LeafIndex: frand.Uint64n(math.MaxUint64),
					MerkleProof: []types.Hash256{
						frand.Entropy256(),
						frand.Entropy256(),
					},
				},
				ChainIndex: types.ChainIndex{
					Height: frand.Uint64n(math.MaxUint64),
					ID:     frand.Entropy256(),
				},
			},
			Leaf: ([64]byte)(frand.Bytes(64)),
			Proof: []types.Hash256{
				frand.Entropy256(),
				frand.Entropy256(),
				frand.Entropy256(),
			},
		},
		&types.V2FileContractRenewal{
			FinalRenterOutput: types.SiacoinOutput{
				Value:   types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
				Address: frand.Entropy256(),
			},
			FinalHostOutput: types.SiacoinOutput{
				Value:   types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
				Address: frand.Entropy256(),
			},
			RenterRollover:  types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
			HostRollover:    types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
			RenterSignature: (types.Signature)(frand.Bytes(64)),
			HostSignature:   (types.Signature)(frand.Bytes(64)),
		},
		&types.V2FileContractExpiration{},
	}

	assertRoundTrip := func(t *testing.T, diff V2FileContractElementDiff) {
		t.Helper()
		buf, err := json.Marshal(diff)
		if err != nil {
			t.Fatalf("failed to marshal V2FileContractElementDiff: %v", err)
		}
		var diff2 V2FileContractElementDiff
		if err := json.Unmarshal(buf, &diff2); err != nil {
			t.Fatalf("failed to unmarshal V2FileContractElementDiff: %v", err)
		} else if !reflect.DeepEqual(diff, diff2) {
			t.Log(string(buf))
			t.Fatal("unmarshaled V2FileContractElementDiff does not match original")
		}
	}

	for _, res := range tests {
		d1 := V2FileContractElementDiff{
			V2FileContractElement: fce,
		}
		assertRoundTrip(t, d1)

		d1.Created = true
		assertRoundTrip(t, d1)

		rev := randContract(t)
		d1.Revision = &rev
		assertRoundTrip(t, d1)

		d1.Resolution = res
		assertRoundTrip(t, d1)
	}
}
