package gateway

import (
	"testing"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"lukechampine.com/frand"
)

func TestBlockOutline(t *testing.T) {
	cs := consensus.State{Network: new(consensus.Network)}
	b := types.Block{
		ParentID:  cs.Index.ID,
		Timestamp: types.CurrentTimestamp(),
		MinerPayouts: []types.SiacoinOutput{{
			Value:   cs.BlockReward(),
			Address: types.Address(frand.Entropy256()),
		}},
		Transactions: []types.Transaction{{
			SiacoinInputs:  []types.SiacoinInput{{}},
			SiacoinOutputs: []types.SiacoinOutput{{Value: types.Siacoins(1)}},
		}},
		V2: &types.V2BlockData{
			Height: 1,
			Transactions: []types.V2Transaction{{
				SiacoinInputs: []types.V2SiacoinInput{{
					Parent:          types.SiacoinElement{StateElement: types.StateElement{MerkleProof: make([]types.Hash256, 10)}},
					SatisfiedPolicy: types.SatisfiedPolicy{Policy: types.AnyoneCanSpend(), Signatures: make([]types.Signature, 1)},
				}},
				SiacoinOutputs: []types.SiacoinOutput{{Value: types.Siacoins(2)}},
			}},
		},
	}
	b.V2.Commitment = cs.Commitment(cs.TransactionsCommitment(b.Transactions, b.V2Transactions()), b.MinerPayouts[0].Address)

	bo := OutlineBlock(b, b.Transactions, b.V2Transactions())
	if bo.ID(cs) != b.ID() {
		t.Fatal("outline ID mismatch")
	} else if len(bo.Missing()) != len(b.Transactions)+len(b.V2Transactions()) {
		t.Fatal("expected all transactions to be missing")
	}
	_, rem := bo.Complete(cs, b.Transactions, nil)
	if len(rem) != len(b.V2Transactions()) {
		t.Fatal("expected v2 transactions to remain")
	}
	b2, rem := bo.Complete(cs, b.Transactions, b.V2Transactions())
	if len(rem) != 0 {
		t.Fatal("expected no remaining transactions")
	}
	if b2.ID() != b.ID() {
		t.Fatal("block ID mismatch")
	}

	bo = OutlineBlock(b, b.Transactions, nil)
	if bo.ID(cs) != b.ID() {
		t.Fatal("outline ID mismatch")
	}
	b2, rem = bo.Complete(cs, b.Transactions, nil)
	if len(rem) != 0 {
		t.Fatal("expected no remaining transactions")
	}
	if b2.ID() != b.ID() {
		t.Fatal("block ID mismatch")
	}

	bo = OutlineBlock(b, nil, b.V2Transactions())
	if bo.ID(cs) != b.ID() {
		t.Fatal("outline ID mismatch")
	}
	b2, rem = bo.Complete(cs, nil, b.V2Transactions())
	if len(rem) != 0 {
		t.Fatal("expected no remaining transactions")
	}
	if b2.ID() != b.ID() {
		t.Fatal("block ID mismatch")
	}

	bo = OutlineBlock(b, nil, nil)
	if bo.ID(cs) != b.ID() {
		t.Fatal("outline ID mismatch")
	}
	b2, rem = bo.Complete(cs, nil, nil)
	if len(rem) != 0 {
		t.Fatal("expected no remaining transactions")
	}
	if b2.ID() != b.ID() {
		t.Fatal("block ID mismatch")
	}
}
