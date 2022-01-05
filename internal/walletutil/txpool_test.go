package walletutil

import (
	"testing"
	"time"

	"go.sia.tech/core/chain"
	"go.sia.tech/core/consensus"
	"go.sia.tech/core/internal/chainutil"
	"go.sia.tech/core/types"
	"lukechampine.com/frand"
)

var testingDifficulty = types.Work{NumHashes: [32]byte{30: 1}}

func genesisWithSiacoinOutputs(scos []types.SiacoinOutput) types.Block {
	return types.Block{
		Header:       types.BlockHeader{Timestamp: time.Unix(734600000, 0)},
		Transactions: []types.Transaction{{SiacoinOutputs: scos}},
	}
}

func mineBlock(vc consensus.ValidationContext, txns ...types.Transaction) types.Block {
	b := types.Block{
		Header: types.BlockHeader{
			Height:    vc.Index.Height + 1,
			ParentID:  vc.Index.ID,
			Timestamp: time.Now(),
		},
		Transactions: txns,
	}
	b.Header.Commitment = vc.Commitment(b.Header.MinerAddress, b.Transactions)
	chainutil.FindBlockNonce(&b.Header, types.HashRequiringWork(vc.Difficulty))
	return b
}

func TestTxPool(t *testing.T) {
	privKey := types.NewPrivateKeyFromSeed(frand.Entropy256())
	spendPolicy := types.PolicyPublicKey(privKey.PublicKey())
	addr := types.PolicyAddress(spendPolicy)
	block := genesisWithSiacoinOutputs([]types.SiacoinOutput{
		{Value: types.Siacoins(10), Address: addr},
	})
	genesisUpdate := consensus.GenesisUpdate(block, testingDifficulty)
	store := chainutil.NewEphemeralStore(consensus.Checkpoint{
		Block:   block,
		Context: genesisUpdate.Context,
	})
	cm := chain.NewManager(store, genesisUpdate.Context)
	t.Cleanup(func() {
		cm.Close()
	})
	tp := NewTxPool(genesisUpdate.Context)
	if err := cm.AddSubscriber(tp, cm.Tip()); err != nil {
		t.Fatal(err)
	}

	vc, err := cm.TipContext()
	if err != nil {
		t.Fatal(err)
	}

	// add a transaction to the pool
	txn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			Parent:      genesisUpdate.NewSiacoinElements[1],
			SpendPolicy: types.PolicyPublicKey(privKey.PublicKey()),
		}},
		SiacoinOutputs: []types.SiacoinOutput{
			{Value: types.Siacoins(1), Address: types.VoidAddress},
			{Value: types.Siacoins(8), Address: addr},
		},
		MinerFee: types.Siacoins(1),
	}
	txn.SiacoinInputs[0].Signatures = append(txn.SiacoinInputs[0].Signatures, types.InputSignature(privKey.SignHash(vc.SigHash(txn))))
	if err := tp.AddTransaction(txn); err != nil {
		t.Fatal(err)
	}

	// add another transaction spending the ephemeral output to the pool
	ephemeralTxn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			Parent: types.SiacoinElement{
				StateElement: types.StateElement{
					ID:        txn.SiacoinOutputID(1),
					LeafIndex: types.EphemeralLeafIndex,
				},
				SiacoinOutput: txn.SiacoinOutputs[1],
			},
			SpendPolicy: types.PolicyPublicKey(privKey.PublicKey()),
		}},
		SiacoinOutputs: []types.SiacoinOutput{
			{Value: types.Siacoins(7), Address: types.VoidAddress},
		},
		MinerFee: types.Siacoins(1),
	}
	ephemeralTxn.SiacoinInputs[0].Signatures = append(ephemeralTxn.SiacoinInputs[0].Signatures, types.InputSignature(privKey.SignHash(vc.SigHash(ephemeralTxn))))
	if err := tp.AddTransaction(ephemeralTxn); err != nil {
		t.Fatal(err)
	}

	block = mineBlock(vc, tp.TransactionsForBlock()...)
	if err := cm.AddTipBlock(block); err != nil {
		t.Fatal(err)
	}

	if len(tp.txns) != 0 {
		t.Error("expected transaction pool to be empty")
	}
}
