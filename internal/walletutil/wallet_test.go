package walletutil

import (
	"testing"

	"go.sia.tech/core/chain"
	"go.sia.tech/core/consensus"
	"go.sia.tech/core/internal/chainutil"
	"go.sia.tech/core/types"
	"lukechampine.com/frand"
)

func TestWallet(t *testing.T) {
	privKey := types.NewPrivateKeyFromSeed(frand.Entropy256())
	block := genesisWithSiacoinOutputs([]types.SiacoinOutput{
		{Value: types.Siacoins(100), Address: types.PolicyAddress(types.PolicyPublicKey(privKey.PublicKey()))},
	})
	genesisUpdate := consensus.GenesisUpdate(block, testingDifficulty)
	w := NewEphemeralWallet(privKey, &chain.ApplyUpdate{
		ApplyUpdate: genesisUpdate,
		Block:       block,
	})
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
	} else if err := cm.AddSubscriber(w, cm.Tip()); err != nil {
		t.Fatal(err)
	}

	// add a transaction to the pool
	txn := types.Transaction{
		SiacoinOutputs: []types.SiacoinOutput{
			{Value: types.Siacoins(10), Address: types.VoidAddress},
			{Value: types.Siacoins(10), Address: w.Address()},
			{Value: types.Siacoins(10), Address: w.Address()},
			{Value: types.Siacoins(10), Address: w.Address()},
			{Value: types.Siacoins(10), Address: w.Address()},
			{Value: types.Siacoins(10), Address: w.Address()},
			{Value: types.Siacoins(10), Address: w.Address()},
			{Value: types.Siacoins(10), Address: w.Address()},
			{Value: types.Siacoins(10), Address: w.Address()},
			{Value: types.Siacoins(10), Address: w.Address()},
		},
	}
	toSign, release, err := w.FundTransaction(&txn, types.Siacoins(100), nil)
	if err != nil {
		t.Fatal(err)
	} else if len(toSign) != len(txn.SiacoinInputs) {
		t.Fatalf("expected %v siacoin inputs to sign, got %v", len(txn.SiacoinInputs), len(toSign))
	} else if len(w.spent) != len(txn.SiacoinInputs) {
		t.Fatalf("expected %v siacoin inputs to be spent, got %v", len(txn.SiacoinInputs), len(w.spent))
	}
	defer release()

	// sign and validate the transaction
	vc, err := cm.TipContext()
	if err != nil {
		t.Fatal(err)
	} else if err := w.SignTransaction(vc, &txn, toSign); err != nil {
		t.Fatal(err)
	} else if err := vc.ValidateTransaction(txn); err != nil {
		t.Fatal(err)
	}

	// add the transaction to the pool and mine a block
	if err := tp.AddTransaction(txn); err != nil {
		t.Fatal(err)
	} else if err := cm.AddTipBlock(mineBlock(vc, tp.TransactionsForBlock()...)); err != nil {
		t.Fatal(err)
	}

	// check the wallet has the correct number of unspent outputs
	// (should be 10 - 1)
	if n := len(w.unspent); n != len(txn.SiacoinOutputs)-1 {
		t.Fatalf("expected wallet to have %v unspent outputs, got %v", len(txn.SiacoinOutputs)-1, n)
	} else if w.Balance() != types.Siacoins(90) {
		t.Fatalf("expected wallet balance %v, got %v", types.Siacoins(90), w.Balance())
	}

	// build and fund a new transaction that spends multiple outputs
	txn = types.Transaction{
		SiacoinOutputs: []types.SiacoinOutput{
			{Value: types.Siacoins(50), Address: types.VoidAddress},
		},
		MinerFee: types.Siacoins(10),
	}
	toSign, release, err = w.FundTransaction(&txn, types.Siacoins(60), nil)
	if err != nil {
		t.Fatal(err)
	} else if len(toSign) != len(txn.SiacoinInputs) {
		t.Fatalf("expected %v siacoin inputs to sign, got %v", len(txn.SiacoinInputs), len(toSign))
	} else if len(w.spent) != len(txn.SiacoinInputs) {
		t.Fatalf("expected %v siacoin inputs to be spent, got %v", len(txn.SiacoinInputs), len(w.spent))
	}
	defer release()

	// sign and validate the transaction
	vc, err = cm.TipContext()
	if err != nil {
		t.Fatal(err)
	} else if err := w.SignTransaction(vc, &txn, toSign); err != nil {
		t.Fatal(err)
	} else if err := vc.ValidateTransaction(txn); err != nil {
		t.Fatal(err)
	}

	// add the transaction to the pool and mine a block
	if err := tp.AddTransaction(txn); err != nil {
		t.Fatal(err)
	} else if err := cm.AddTipBlock(mineBlock(vc, tp.TransactionsForBlock()...)); err != nil {
		t.Fatal(err)
	}

	// check if the wallet has the correct number of unspent outputs
	// and the correct balance
	if n := len(w.unspent); n != 3 {
		t.Fatalf("expected wallet to have %v unspent outputs, got %v", 3, n)
	} else if w.Balance() != types.Siacoins(30) {
		t.Fatalf("expected wallet balance %v, got %v", types.Siacoins(30), w.Balance())
	} else if len(w.spent) != 0 {
		t.Fatalf("expected wallet to have 0 spent outputs, got %v", len(w.spent))
	}
}
