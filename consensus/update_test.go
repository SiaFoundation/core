package consensus

import (
	"testing"
	"time"

	"go.sia.tech/core/types"
)

func TestSiafunds(t *testing.T) {
	pubkey, privkey := testingKeypair()
	b := types.Block{
		Header: types.BlockHeader{Timestamp: time.Unix(734600000, 0)},
		Transactions: []types.Transaction{{SiafundOutputs: []types.Beneficiary{{
			Address: pubkey.Address(),
			Value:   types.NewCurrency64(100),
		}}}},
	}
	sau := GenesisUpdate(b, testingDifficulty)

	// send siafunds to a new address
	claimPubkey, claimPrivkey := testingKeypair()
	txn := types.Transaction{
		SiafundInputs: []types.SiafundInput{{
			Parent:       sau.NewSiafundOutputs[0],
			PublicKey:    pubkey,
			ClaimAddress: claimPubkey.Address(),
		}},
		SiafundOutputs: []types.Beneficiary{{
			Address: claimPubkey.Address(),
			Value:   types.NewCurrency64(100),
		}},
	}
	signAllInputs(&txn, sau.Context, privkey)
	b = mineBlock(sau.Context, b, txn)
	if err := sau.Context.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(sau.Context, b)

	// should have created a siafund output, a block reward, and a claim output
	if len(sau.NewSiafundOutputs) != 1 || sau.NewSiafundOutputs[0].Value != types.NewCurrency64(100) {
		t.Fatal("expected one new siafund output")
	} else if len(sau.NewSiacoinOutputs) != 2 {
		t.Fatal("expected one block reward and one claim output")
	}

	// attempt to spend the claim output; it should be timelocked
	txn = types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			Parent:    sau.NewSiacoinOutputs[1],
			PublicKey: claimPubkey,
		}},
		MinerFee: sau.NewSiacoinOutputs[1].Value,
	}
	signAllInputs(&txn, sau.Context, claimPrivkey)
	b = mineBlock(sau.Context, b, txn)
	if err := sau.Context.ValidateBlock(b); err == nil {
		t.Fatal("expected error when attempting to spend timelocked claim output")
	}

	// skip to timelock height and try again
	sau.Context.Index.Height = sau.NewSiacoinOutputs[1].Timelock + 1
	sau.Context.Index.ID = b.ID()
	b.Header.Height = sau.Context.Index.Height
	signAllInputs(&txn, sau.Context, claimPrivkey)
	b = mineBlock(sau.Context, b, txn)
	if err := sau.Context.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
}

func TestFoundationSubsidy(t *testing.T) {
	// mine genesis block with initial Foundation address
	pubkey, privkey := testingKeypair()
	b := genesisWithBeneficiaries(types.Beneficiary{
		Address: pubkey.Address(),
		Value:   types.NewCurrency64(100),
	})
	b.Transactions[0].NewFoundationAddress = pubkey.Address()
	sau := GenesisUpdate(b, testingDifficulty)
	if sau.Context.FoundationAddress != pubkey.Address() {
		t.Fatal("Foundation address not updated")
	}
	initialOutput := sau.NewSiacoinOutputs[1]

	// skip to Foundation hardfork height; we should receive the initial subsidy
	b.Header.Height = foundationHardforkHeight - 1
	sau.Context.Index.Height = foundationHardforkHeight - 1
	b = mineBlock(sau.Context, b)
	if err := sau.Context.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(sau.Context, b)
	sau.UpdateSiacoinOutputProof(&initialOutput)
	subsidyID := types.OutputID{
		TransactionID: types.TransactionID(b.ID()),
		Index:         1,
	}
	var subsidyOutput types.SiacoinOutput
	for _, o := range sau.NewSiacoinOutputs {
		if o.ID == subsidyID {
			subsidyOutput = o
			break
		}
	}
	if subsidyOutput.ID != subsidyID {
		t.Fatal("subsidy output not created")
	}

	// update the Foundation subsidy address
	newAddress := types.Address{1, 2, 3}
	txn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			Parent:    initialOutput,
			PublicKey: pubkey,
		}},
		NewFoundationAddress: newAddress,
		MinerFee:             initialOutput.Value,
	}
	signAllInputs(&txn, sau.Context, privkey)
	b = mineBlock(sau.Context, b, txn)
	if err := sau.Context.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(sau.Context, b)
	sau.UpdateSiacoinOutputProof(&subsidyOutput)
	if sau.Context.FoundationAddress != newAddress {
		t.Fatal("Foundation address not updated")
	}

	// skip beyond the timelock of the initial subsidy output, and spend it
	sau.Context.Index.Height = subsidyOutput.Timelock + 1
	txn = types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			Parent:    subsidyOutput,
			PublicKey: pubkey,
		}},
		MinerFee: subsidyOutput.Value,
	}
	signAllInputs(&txn, sau.Context, privkey)
	if err := sau.Context.ValidateTransaction(txn); err != nil {
		t.Fatal(err)
	}
}
