package consensus

import (
	"crypto/ed25519"
	"testing"
	"time"

	"go.sia.tech/core/types"
)

var testingDifficulty = types.Work{NumHashes: [32]byte{30: 1}}

func testingKeypair() (types.PublicKey, ed25519.PrivateKey) {
	var pubkey types.PublicKey
	privkey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	copy(pubkey[:], privkey[32:])
	return pubkey, privkey
}

func genesisWithBeneficiaries(beneficiaries ...types.Beneficiary) types.Block {
	return types.Block{
		Header:       types.BlockHeader{Timestamp: time.Unix(734600000, 0)},
		Transactions: []types.Transaction{{SiacoinOutputs: beneficiaries}},
	}
}

func signAllInputs(txn *types.Transaction, vc ValidationContext, priv ed25519.PrivateKey) {
	sigHash := vc.SigHash(*txn)
	for i := range txn.SiacoinInputs {
		txn.SiacoinInputs[i].Signature = types.SignTransaction(priv, sigHash)
	}
	for i := range txn.SiafundInputs {
		txn.SiafundInputs[i].Signature = types.SignTransaction(priv, sigHash)
	}
}

func TestEphemeralOutputs(t *testing.T) {
	pubkey, privkey := testingKeypair()
	sau := GenesisUpdate(genesisWithBeneficiaries(types.Beneficiary{
		Address: pubkey.Address(),
		Value:   types.Siacoins(1),
	}), testingDifficulty)

	// create an ephemeral output
	parentTxn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			Parent:    sau.NewSiacoinOutputs[1],
			PublicKey: pubkey,
		}},
		SiacoinOutputs: []types.Beneficiary{{
			Address: pubkey.Address(),
			Value:   types.Siacoins(1),
		}},
	}
	signAllInputs(&parentTxn, sau.Context, privkey)
	ephemeralOutput := types.SiacoinOutput{
		ID: types.OutputID{
			TransactionID: parentTxn.ID(),
			Index:         0,
		},
		Value:     parentTxn.SiacoinOutputs[0].Value,
		Address:   pubkey.Address(),
		LeafIndex: types.EphemeralLeafIndex,
	}

	// create a transaction that spends the ephemeral output
	childTxn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			Parent:    ephemeralOutput,
			PublicKey: pubkey,
		}},
		SiacoinOutputs: []types.Beneficiary{{
			Address: pubkey.Address(),
			Value:   ephemeralOutput.Value,
		}},
	}
	signAllInputs(&childTxn, sau.Context, privkey)

	// the transaction set should be valid
	err := sau.Context.ValidateTransactionSet([]types.Transaction{parentTxn, childTxn})
	if err != nil {
		t.Fatal(err)
	}

	// change the value of the output and attempt to spend it
	mintTxn := childTxn.DeepCopy()
	mintTxn.SiacoinInputs[0].Parent.Value = types.Siacoins(1e6)
	mintTxn.SiacoinOutputs[0].Value = mintTxn.SiacoinInputs[0].Parent.Value
	signAllInputs(&mintTxn, sau.Context, privkey)

	err = sau.Context.ValidateTransactionSet([]types.Transaction{parentTxn, mintTxn})
	if err == nil {
		t.Fatal("ephemeral output with wrong value should be rejected")
	}

	// add another transaction to the set that double-spends the output
	doubleSpendTxn := childTxn.DeepCopy()
	doubleSpendTxn.SiacoinOutputs[0].Address = types.VoidAddress
	signAllInputs(&doubleSpendTxn, sau.Context, privkey)

	err = sau.Context.ValidateTransactionSet([]types.Transaction{parentTxn, childTxn, doubleSpendTxn})
	if err == nil {
		t.Fatal("ephemeral output double-spend not rejected")
	}
}
