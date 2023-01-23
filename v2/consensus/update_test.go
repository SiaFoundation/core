package consensus

import (
	"math"
	"reflect"
	"testing"
	"time"

	"go.sia.tech/core/v2/merkle"
	"go.sia.tech/core/v2/types"

	"lukechampine.com/frand"
)

func randAddr() types.Address {
	return frand.Entropy256()
}

func randAmount() types.Currency {
	return types.NewCurrency(
		frand.Uint64n(math.MaxUint64),
		frand.Uint64n(math.MaxUint64),
	)
}

func TestApplyBlock(t *testing.T) {
	b := genesisWithSiacoinOutputs([]types.SiacoinOutput{
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
	}...)
	update1 := GenesisUpdate(b, testingDifficulty)
	acc1 := update1.State.Elements
	origOutputs := update1.NewSiacoinElements
	if len(origOutputs) != len(b.Transactions[0].SiacoinOutputs)+1 {
		t.Fatalf("expected %v new outputs, got %v", len(b.Transactions[0].SiacoinOutputs)+1, len(origOutputs))
	}
	// none of the outputs should be marked as spent
	for _, o := range origOutputs {
		if update1.SiacoinElementWasSpent(o) {
			t.Error("update should not mark output as spent:", o)
		}
		if acc1.ContainsSpentSiacoinElement(o) || !acc1.ContainsUnspentSiacoinElement(o) {
			t.Error("accumulator should contain unspent output:", o)
		}
	}

	// apply a block that spends some outputs
	txn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{Parent: origOutputs[6], SpendPolicy: types.AnyoneCanSpend()},
			{Parent: origOutputs[7], SpendPolicy: types.AnyoneCanSpend()},
			{Parent: origOutputs[8], SpendPolicy: types.AnyoneCanSpend()},
			{Parent: origOutputs[9], SpendPolicy: types.AnyoneCanSpend()},
		},
		SiacoinOutputs: []types.SiacoinOutput{{
			Value:   randAmount(),
			Address: randAddr(),
		}},
		MinerFee: randAmount(),
	}
	b = types.Block{
		Header: types.BlockHeader{
			Height:       b.Header.Height + 1,
			ParentID:     b.ID(),
			MinerAddress: randAddr(),
		},
		Transactions: []types.Transaction{txn},
	}

	update2 := ApplyBlock(update1.State, b)
	acc2 := update2.State.Elements
	for i := range origOutputs {
		update2.UpdateElementProof(&origOutputs[i].StateElement)
	}

	// the update should mark each input as spent
	for _, in := range txn.SiacoinInputs {
		if !update2.SiacoinElementWasSpent(in.Parent) {
			t.Error("update should mark input as spent:", in)
		}
	}
	// the new accumulator should contain both the spent and unspent outputs
	for _, o := range origOutputs {
		if update2.SiacoinElementWasSpent(o) {
			if acc2.ContainsUnspentSiacoinElement(o) || !acc2.ContainsSpentSiacoinElement(o) {
				t.Error("accumulator should contain spent output:", o)
			}
		} else {
			if acc2.ContainsSpentSiacoinElement(o) || !acc2.ContainsUnspentSiacoinElement(o) {
				t.Error("accumulator should contain unspent output:", o)
			}
		}
	}

	// if we instead revert that block, we should see the inputs being "created"
	// again and the outputs being destroyed
	revertUpdate := RevertBlock(update1.State, b)
	revertAcc := revertUpdate.State.Elements
	if len(revertUpdate.SpentSiacoins) != len(txn.SiacoinInputs) {
		t.Error("number of spent outputs after revert should equal number of inputs")
	}
	for _, o := range update2.NewSiacoinElements {
		if !revertUpdate.SiacoinElementWasRemoved(o) {
			t.Error("output created in reverted block should be marked as removed")
		}
	}
	// update (a copy of) the proofs to reflect the revert
	outputsWithRevert := append([]types.SiacoinElement(nil), origOutputs...)
	for i := range outputsWithRevert {
		outputsWithRevert[i].MerkleProof = append([]types.Hash256(nil), outputsWithRevert[i].MerkleProof...)
		revertUpdate.UpdateElementProof(&outputsWithRevert[i].StateElement)
	}
	// the reverted proofs should be identical to the proofs prior to b
	for _, o := range outputsWithRevert {
		if update1.SiacoinElementWasSpent(o) {
			t.Error("update should not mark output as spent:", o)
		}
		if revertAcc.ContainsSpentSiacoinElement(o) {
			t.Error("output should not be marked as spent:", o)
		}
	}

	// spend one of the outputs whose proof we've been maintaining,
	// using an intermediary transaction to test "ephemeral" outputs
	parentTxn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{Parent: origOutputs[2], SpendPolicy: types.AnyoneCanSpend()},
		},
		SiacoinOutputs: []types.SiacoinOutput{{
			Value:   randAmount(),
			Address: randAddr(),
		}},
	}
	childTxn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			Parent: types.SiacoinElement{
				StateElement: types.StateElement{
					ID: types.ElementID{
						Source: types.Hash256(parentTxn.ID()),
						Index:  0,
					},
					LeafIndex: types.EphemeralLeafIndex,
				},
				SiacoinOutput: types.SiacoinOutput{
					Value:   randAmount(),
					Address: randAddr(),
				},
			},
			SpendPolicy: types.AnyoneCanSpend(),
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Value:   randAmount(),
			Address: randAddr(),
		}},
		MinerFee: randAmount(),
	}

	b = types.Block{
		Header: types.BlockHeader{
			Height:       b.Header.Height + 1,
			ParentID:     b.ID(),
			MinerAddress: randAddr(),
		},
		Transactions: []types.Transaction{parentTxn, childTxn},
	}

	update3 := ApplyBlock(update2.State, b)
	acc3 := update3.State.Elements
	for i := range origOutputs {
		update3.UpdateElementProof(&origOutputs[i].StateElement)
	}

	// the update should mark each input as spent
	for _, in := range parentTxn.SiacoinInputs {
		if !update3.SiacoinElementWasSpent(in.Parent) {
			t.Error("update should mark input as spent:", in)
		}
	}
	// the new accumulator should contain both the spent and unspent outputs
	for _, o := range origOutputs {
		if update2.SiacoinElementWasSpent(o) || update3.SiacoinElementWasSpent(o) {
			if acc3.ContainsUnspentSiacoinElement(o) || !acc3.ContainsSpentSiacoinElement(o) {
				t.Error("accumulator should contain spent output:", o)
			}
		} else {
			if acc3.ContainsSpentSiacoinElement(o) || !acc3.ContainsUnspentSiacoinElement(o) {
				t.Error("accumulator should contain unspent output:", o)
			}
		}
	}

	// TODO: we should also be checking childTxn, but we can't check the
	// ephemeral output without knowing its index
}

func TestRevertBlock(t *testing.T) {
	b := genesisWithSiacoinOutputs([]types.SiacoinOutput{
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
	}...)
	update1 := GenesisUpdate(b, testingDifficulty)
	origOutputs := update1.NewSiacoinElements
	if len(origOutputs) != len(b.Transactions[0].SiacoinOutputs)+1 {
		t.Fatalf("expected %v new outputs, got %v", len(b.Transactions[0].SiacoinOutputs)+1, len(origOutputs))
	}

	txn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{Parent: origOutputs[5], SpendPolicy: types.AnyoneCanSpend()},
		},
		SiacoinOutputs: []types.SiacoinOutput{{
			Value:   randAmount(),
			Address: randAddr(),
		}},
		MinerFee: randAmount(),
	}
	b = types.Block{
		Header: types.BlockHeader{
			Height:       b.Header.Height + 1,
			ParentID:     b.ID(),
			MinerAddress: randAddr(),
		},
		Transactions: []types.Transaction{txn},
	}

	update2 := ApplyBlock(update1.State, b)
	for i := range origOutputs {
		update2.UpdateElementProof(&origOutputs[i].StateElement)
	}

	// revert the block. We should see the inputs being "created" again
	// and the outputs being destroyed
	revertUpdate := RevertBlock(update1.State, b)
	if len(revertUpdate.SpentSiacoins) != len(txn.SiacoinInputs) {
		t.Error("number of spent outputs after revert should equal number of inputs")
	}
	for _, o := range update2.NewSiacoinElements {
		if !revertUpdate.SiacoinElementWasRemoved(o) {
			t.Error("output created in reverted block should be marked as removed")
		}
	}
	// update the proofs to reflect the revert
	for i := range origOutputs {
		revertUpdate.UpdateElementProof(&origOutputs[i].StateElement)
	}
	// the reverted proofs should be identical to the proofs prior to b
	for _, o := range origOutputs {
		if update1.SiacoinElementWasSpent(o) {
			t.Error("update should not mark output as spent:", o)
		}
		if !update1.State.Elements.ContainsUnspentSiacoinElement(o) {
			t.Error("output should be in the accumulator, marked as unspent:", o)
		}
	}
}

func TestSiafunds(t *testing.T) {
	pubkey, privkey := testingKeypair(0)
	b := types.Block{
		Header: types.BlockHeader{Timestamp: time.Unix(734600000, 0)},
		Transactions: []types.Transaction{{SiafundOutputs: []types.SiafundOutput{{
			Address: types.StandardAddress(pubkey),
			Value:   100,
		}}}},
	}
	sau := GenesisUpdate(b, testingDifficulty)

	// send siafunds to a new address
	claimPubkey, claimPrivkey := testingKeypair(1)
	txn := types.Transaction{
		SiafundInputs: []types.SiafundInput{{
			Parent:       sau.NewSiafundElements[0],
			SpendPolicy:  types.PolicyPublicKey(pubkey),
			ClaimAddress: types.StandardAddress(claimPubkey),
		}},
		SiafundOutputs: []types.SiafundOutput{{
			Address: types.StandardAddress(claimPubkey),
			Value:   100,
		}},
	}
	signAllInputs(&txn, sau.State, privkey)
	b = mineBlock(sau.State, b, txn)
	if err := sau.State.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(sau.State, b)

	// should have created a siafund output, a block reward, and a claim output
	if len(sau.NewSiafundElements) != 1 || sau.NewSiafundElements[0].Value != 100 {
		t.Fatal("expected one new siafund output")
	} else if len(sau.NewSiacoinElements) != 2 {
		t.Fatal("expected one block reward and one claim output")
	}

	// attempt to spend the claim output before it matures
	txn = types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			Parent:      sau.NewSiacoinElements[1],
			SpendPolicy: types.PolicyPublicKey(claimPubkey),
		}},
		MinerFee: sau.NewSiacoinElements[1].Value,
	}
	signAllInputs(&txn, sau.State, claimPrivkey)
	b = mineBlock(sau.State, b, txn)
	if err := sau.State.ValidateBlock(b); err == nil {
		t.Fatal("expected error when attempting to spend immature claim output")
	}

	// skip to maturity height and try again
	sau.State.Index.Height = sau.NewSiacoinElements[1].MaturityHeight + 1
	sau.State.Index.ID = b.ID()
	for i := range sau.State.PrevTimestamps {
		sau.State.PrevTimestamps[i] = b.Header.Timestamp
	}
	b.Header.Height = sau.State.Index.Height
	signAllInputs(&txn, sau.State, claimPrivkey)
	b = mineBlock(sau.State, b, txn)
	if err := sau.State.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
}

func TestFoundationSubsidy(t *testing.T) {
	// mine genesis block with initial Foundation address
	pubkey, privkey := testingKeypair(0)
	b := genesisWithSiacoinOutputs(types.SiacoinOutput{
		Address: types.StandardAddress(pubkey),
		Value:   types.NewCurrency64(100),
	})
	b.Transactions[0].NewFoundationAddress = types.StandardAddress(pubkey)
	sau := GenesisUpdate(b, testingDifficulty)
	if sau.State.FoundationAddress != types.StandardAddress(pubkey) {
		t.Fatal("Foundation address not updated")
	}
	initialOutput := sau.NewSiacoinElements[1]

	// skip to Foundation hardfork height; we should receive the initial subsidy
	b.Header.Height = foundationHardforkHeight - 1
	sau.State.Index.Height = foundationHardforkHeight - 1
	for i := range sau.State.PrevTimestamps {
		sau.State.PrevTimestamps[i] = b.Header.Timestamp
	}
	b = mineBlock(sau.State, b)
	if err := sau.State.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(sau.State, b)
	sau.UpdateElementProof(&initialOutput.StateElement)
	subsidyID := types.ElementID{
		Source: types.Hash256(b.ID()),
		Index:  1,
	}
	var subsidyOutput types.SiacoinElement
	for _, o := range sau.NewSiacoinElements {
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
			Parent:      initialOutput,
			SpendPolicy: types.PolicyPublicKey(pubkey),
		}},
		NewFoundationAddress: newAddress,
		MinerFee:             initialOutput.Value,
	}
	signAllInputs(&txn, sau.State, privkey)
	b = mineBlock(sau.State, b, txn)
	if err := sau.State.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(sau.State, b)
	sau.UpdateElementProof(&subsidyOutput.StateElement)
	if sau.State.FoundationAddress != newAddress {
		t.Fatal("Foundation address not updated")
	}

	// skip beyond the maturity height of the initial subsidy output, and spend it
	sau.State.Index.Height = subsidyOutput.MaturityHeight + 1
	txn = types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			Parent:      subsidyOutput,
			SpendPolicy: types.PolicyPublicKey(pubkey),
		}},
		MinerFee: subsidyOutput.Value,
	}
	signAllInputs(&txn, sau.State, privkey)
	if err := sau.State.ValidateTransaction(txn); err != nil {
		t.Fatal(err)
	}

	// skip to the next foundation subsidy height; the foundation address should
	// receive a new subsidy.
	sau.State.Index.Height = foundationHardforkHeight + foundationSubsidyFrequency - 1
	b.Header.Height = sau.State.Index.Height
	b = mineBlock(sau.State, b, txn)
	if err := sau.State.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(sau.State, b)
	subsidyID = types.ElementID{
		Source: types.Hash256(b.ID()),
		Index:  1,
	}
	for _, o := range sau.NewSiacoinElements {
		if o.ID == subsidyID {
			subsidyOutput = o
			break
		}
	}

	// check that the output was created and has the expected value of
	// 30000 SC * 4380 blocks per month.
	if subsidyOutput.ID != subsidyID {
		t.Fatal("subsidy output not created")
	} else if exp := types.Siacoins(30000).Mul64(foundationSubsidyFrequency); !subsidyOutput.Value.Equals(exp) {
		t.Fatalf("expected subsidy to be %v SC, got %v SC", exp, subsidyOutput.Value)
	}
}

func TestUpdateWindowProof(t *testing.T) {
	for before := 0; before < 10; before++ {
		for after := 0; after < 10; after++ {
			b := genesisWithSiacoinOutputs()
			sau := GenesisUpdate(b, testingDifficulty)
			for i := 0; i < before; i++ {
				b = mineBlock(sau.State, b)
				sau = ApplyBlock(sau.State, b)
			}
			sp := types.StorageProof{
				WindowStart: sau.State.Index,
				WindowProof: sau.HistoryProof(),
			}
			for i := 0; i < after; i++ {
				b = mineBlock(sau.State, b)
				sau = ApplyBlock(sau.State, b)
				sau.UpdateWindowProof(&sp)
			}
			if !sau.State.History.Contains(sp.WindowStart, sp.WindowProof) {
				t.Fatal("UpdateWindowProof created invalid history proof")
			}
		}
	}
}

func TestFileContracts(t *testing.T) {
	renterPubkey, renterPrivkey := testingKeypair(0)
	hostPubkey, hostPrivkey := testingKeypair(1)
	b := genesisWithSiacoinOutputs(types.SiacoinOutput{
		Address: types.StandardAddress(renterPubkey),
		Value:   types.Siacoins(100),
	}, types.SiacoinOutput{
		Address: types.StandardAddress(hostPubkey),
		Value:   types.Siacoins(7),
	})
	sau := GenesisUpdate(b, testingDifficulty)
	renterOutput := sau.NewSiacoinElements[1]
	hostOutput := sau.NewSiacoinElements[2]

	// form initial contract
	initialRev := types.FileContract{
		WindowStart: 5,
		WindowEnd:   10,
		RenterOutput: types.SiacoinOutput{
			Address: types.StandardAddress(renterPubkey),
			Value:   types.Siacoins(58),
		},
		HostOutput: types.SiacoinOutput{
			Address: types.StandardAddress(hostPubkey),
			Value:   types.Siacoins(19),
		},
		MissedHostValue: types.Siacoins(17),
		TotalCollateral: types.Siacoins(18),
		RenterPublicKey: renterPubkey,
		HostPublicKey:   hostPubkey,
	}
	outputSum := initialRev.RenterOutput.Value.Add(initialRev.HostOutput.Value).Add(sau.State.FileContractTax(initialRev))
	txn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{Parent: renterOutput, SpendPolicy: types.PolicyPublicKey(renterPubkey)},
			{Parent: hostOutput, SpendPolicy: types.PolicyPublicKey(hostPubkey)},
		},
		FileContracts: []types.FileContract{initialRev},
		MinerFee:      renterOutput.Value.Add(hostOutput.Value).Sub(outputSum),
	}
	fc := &txn.FileContracts[0]
	contractHash := sau.State.ContractSigHash(*fc)
	fc.RenterSignature = renterPrivkey.SignHash(contractHash)
	fc.HostSignature = hostPrivkey.SignHash(contractHash)
	sigHash := sau.State.InputSigHash(txn)
	txn.SiacoinInputs[0].Signatures = []types.Signature{renterPrivkey.SignHash(sigHash)}
	txn.SiacoinInputs[1].Signatures = []types.Signature{hostPrivkey.SignHash(sigHash)}

	b = mineBlock(sau.State, b, txn)
	if err := sau.State.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(sau.State, b)

	if len(sau.NewFileContracts) != 1 {
		t.Fatal("expected one new file contract")
	}
	fce := sau.NewFileContracts[0]
	if !sau.State.Elements.ContainsUnresolvedFileContractElement(fce) {
		t.Fatal("accumulator should contain unresolved contract")
	}
	if sau.State.SiafundPool != sau.State.FileContractTax(initialRev) {
		t.Fatal("expected siafund pool to increase")
	}

	// renter and host now exchange data + revisions out-of-band; we simulate
	// the final revision
	data := frand.Bytes(64 * 2)
	finalRev := types.FileContractRevision{
		Parent:   fce,
		Revision: fce.FileContract,
	}
	finalRev.Revision.FileMerkleRoot = merkle.NodeHash(
		merkle.StorageProofLeafHash(data[:64]),
		merkle.StorageProofLeafHash(data[64:]),
	)
	finalRev.Revision.RevisionNumber++
	finalRev.Revision.Filesize = uint64(len(data))
	contractHash = sau.State.ContractSigHash(finalRev.Revision)
	finalRev.Revision.RenterSignature = renterPrivkey.SignHash(contractHash)
	finalRev.Revision.HostSignature = hostPrivkey.SignHash(contractHash)
	txn = types.Transaction{
		FileContractRevisions: []types.FileContractRevision{finalRev},
	}

	b = mineBlock(sau.State, b, txn)
	if err := sau.State.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(sau.State, b)
	if len(sau.RevisedFileContracts) != 1 {
		t.Fatal("expected one revised file contract")
	}
	fce = sau.RevisedFileContracts[0]
	sau.UpdateElementProof(&fce.StateElement)

	// mine until we enter the proof window
	//
	// NOTE: unlike other tests, we can't "cheat" here by fast-forwarding,
	// because we need to maintain a history proof
	for sau.State.Index.Height < fc.WindowStart {
		b = mineBlock(sau.State, b)
		sau = ApplyBlock(sau.State, b)
		sau.UpdateElementProof(&fce.StateElement)
	}
	sp := types.StorageProof{
		WindowStart: sau.State.Index,
		WindowProof: sau.HistoryProof(),
	}
	proofIndex := sau.State.StorageProofLeafIndex(finalRev.Revision.Filesize, sp.WindowStart, fce.ID)
	copy(sp.Leaf[:], data[64*proofIndex:])
	if proofIndex == 0 {
		sp.Proof = append(sp.Proof, merkle.StorageProofLeafHash(data[64:]))
	} else {
		sp.Proof = append(sp.Proof, merkle.StorageProofLeafHash(data[:64]))
	}

	// create valid contract resolution
	txn = types.Transaction{
		FileContractResolutions: []types.FileContractResolution{{
			Parent:       fce,
			StorageProof: sp,
		}},
	}

	validBlock := mineBlock(sau.State, b, txn)
	if err := sau.State.ValidateBlock(validBlock); err != nil {
		t.Fatal(err)
	}
	validSAU := ApplyBlock(sau.State, validBlock)
	if len(validSAU.ResolvedFileContracts) != 1 {
		t.Fatal("expected one resolved file contract")
	} else if len(validSAU.NewSiacoinElements) != 3 {
		t.Fatal("expected three new siacoin outputs")
	} else if validSAU.NewSiacoinElements[1].SiacoinOutput != finalRev.Revision.RenterOutput {
		t.Fatal("expected renter output to be created")
	} else if validSAU.NewSiacoinElements[2].SiacoinOutput != finalRev.Revision.HostOutput {
		t.Fatal("expected valid host output to be created")
	}

	// revert the block and instead mine past the proof window
	for sau.State.Index.Height <= fc.WindowEnd {
		b = mineBlock(sau.State, b)
		sau = ApplyBlock(sau.State, b)
		sau.UpdateElementProof(&txn.FileContractResolutions[0].Parent.StateElement)
		sau.UpdateWindowProof(&txn.FileContractResolutions[0].StorageProof)
	}
	// storage proof resolution should now be rejected
	if err := sau.State.ValidateTransaction(txn); err == nil {
		t.Fatal("expected too-late storage proof to be rejected")
	}
	// missed resolution should be accepted, though
	txn.FileContractResolutions[0].StorageProof = types.StorageProof{}
	b = mineBlock(sau.State, b, txn)
	if err := sau.State.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(sau.State, b)
	if len(sau.ResolvedFileContracts) != 1 {
		t.Fatal("expected one resolved file contract")
	} else if len(sau.NewSiacoinElements) != 3 {
		t.Fatal("expected three new siacoin outputs")
	} else if sau.NewSiacoinElements[1].SiacoinOutput != finalRev.Revision.RenterOutput {
		t.Fatal("expected renter output to be created")
	} else if sau.NewSiacoinElements[2].SiacoinOutput != finalRev.Revision.MissedHostOutput() {
		t.Fatal("expected missed host output to be created")
	}
}

func TestContractRenewal(t *testing.T) {
	renterPubkey, renterPrivkey := testingKeypair(0)
	hostPubkey, hostPrivkey := testingKeypair(1)
	b := genesisWithSiacoinOutputs(types.SiacoinOutput{
		Address: types.StandardAddress(renterPubkey),
		Value:   types.Siacoins(100),
	}, types.SiacoinOutput{
		Address: types.StandardAddress(hostPubkey),
		Value:   types.Siacoins(7),
	}, types.SiacoinOutput{
		Address: types.StandardAddress(renterPubkey),
		Value:   types.Siacoins(200),
	})
	sau := GenesisUpdate(b, testingDifficulty)
	renterOutput := sau.NewSiacoinElements[1]
	hostOutput := sau.NewSiacoinElements[2]
	renewOutput := sau.NewSiacoinElements[3]

	// form initial contract
	initialRev := types.FileContract{
		WindowStart: 5,
		WindowEnd:   10,
		RenterOutput: types.SiacoinOutput{
			Address: types.StandardAddress(renterPubkey),
			Value:   types.Siacoins(58),
		},
		HostOutput: types.SiacoinOutput{
			Address: types.StandardAddress(hostPubkey),
			Value:   types.Siacoins(19),
		},
		MissedHostValue: types.Siacoins(17),
		TotalCollateral: types.Siacoins(18),
		RenterPublicKey: renterPubkey,
		HostPublicKey:   hostPubkey,
	}
	contractHash := sau.State.ContractSigHash(initialRev)
	initialRev.RenterSignature = renterPrivkey.SignHash(contractHash)
	initialRev.HostSignature = hostPrivkey.SignHash(contractHash)
	outputSum := initialRev.RenterOutput.Value.Add(initialRev.HostOutput.Value).Add(sau.State.FileContractTax(initialRev))
	txn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{Parent: renterOutput, SpendPolicy: types.PolicyPublicKey(renterPubkey)},
			{Parent: hostOutput, SpendPolicy: types.PolicyPublicKey(hostPubkey)},
		},
		FileContracts: []types.FileContract{initialRev},
		MinerFee:      renterOutput.Value.Add(hostOutput.Value).Sub(outputSum),
	}
	sigHash := sau.State.InputSigHash(txn)
	txn.SiacoinInputs[0].Signatures = []types.Signature{renterPrivkey.SignHash(sigHash)}
	txn.SiacoinInputs[1].Signatures = []types.Signature{hostPrivkey.SignHash(sigHash)}

	b = mineBlock(sau.State, b, txn)
	if err := sau.State.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(sau.State, b)
	sau.UpdateElementProof(&renewOutput.StateElement)

	if len(sau.NewFileContracts) != 1 {
		t.Fatal("expected one new file contract")
	}
	fc := sau.NewFileContracts[0]
	if !sau.State.Elements.ContainsUnresolvedFileContractElement(fc) {
		t.Fatal("accumulator should contain unresolved contract")
	}

	// construct the renewal by finalizing the old contract and initializing the
	// new contract, rolling over some SC into the new contract
	finalRev := fc.FileContract
	finalRev.RevisionNumber = types.MaxRevisionNumber
	contractHash = sau.State.ContractSigHash(finalRev)
	finalRev.RenterSignature = renterPrivkey.SignHash(contractHash)
	finalRev.HostSignature = hostPrivkey.SignHash(contractHash)

	initialRev = fc.FileContract
	initialRev.RevisionNumber = 0
	initialRev.WindowStart += 10
	initialRev.WindowEnd += 10
	initialRev.RenterOutput.Value = types.Siacoins(100)
	initialRev.HostOutput.Value = types.Siacoins(100)
	initialRev.MissedHostValue = types.Siacoins(100)
	initialRev.TotalCollateral = types.Siacoins(100)
	contractHash = sau.State.ContractSigHash(initialRev)
	initialRev.RenterSignature = renterPrivkey.SignHash(contractHash)
	initialRev.HostSignature = hostPrivkey.SignHash(contractHash)

	renewal := types.FileContractRenewal{
		FinalRevision:   finalRev,
		InitialRevision: initialRev,
		RenterRollover:  types.Siacoins(3),
		HostRollover:    types.Siacoins(6),
	}
	renewalHash := sau.State.RenewalSigHash(renewal)
	renewal.RenterSignature = renterPrivkey.SignHash(renewalHash)
	renewal.HostSignature = hostPrivkey.SignHash(renewalHash)

	// since we increased the amount of value in the contract, we need to add
	// more inputs
	rollover := renewal.RenterRollover.Add(renewal.HostRollover)
	contractCost := initialRev.RenterOutput.Value.Add(initialRev.HostOutput.Value).Add(sau.State.FileContractTax(initialRev)).Sub(rollover)
	txn = types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			Parent:      renewOutput,
			SpendPolicy: types.PolicyPublicKey(renterPubkey),
		}},
		FileContractResolutions: []types.FileContractResolution{{
			Parent:  fc,
			Renewal: renewal,
		}},
		MinerFee: renewOutput.Value.Sub(contractCost),
	}
	sigHash = sau.State.InputSigHash(txn)
	txn.SiacoinInputs[0].Signatures = []types.Signature{renterPrivkey.SignHash(sigHash)}

	// after applying the transaction, we should observe a number of effects:
	// - the old contract should be marked resolved
	// - the new contract should be created
	// - the old contract payouts, sans rollover, should be created
	b = mineBlock(sau.State, b, txn)
	if err := sau.State.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(sau.State, b)
	expRenterOutput := types.SiacoinOutput{
		Value:   finalRev.RenterOutput.Value.Sub(renewal.RenterRollover),
		Address: finalRev.RenterOutput.Address,
	}
	expHostOutput := types.SiacoinOutput{
		Value:   finalRev.HostOutput.Value.Sub(renewal.HostRollover),
		Address: finalRev.HostOutput.Address,
	}
	if len(sau.ResolvedFileContracts) != 1 {
		t.Fatal("expected one resolved file contract")
	} else if len(sau.NewFileContracts) != 1 {
		t.Fatal("expected one created file contract")
	} else if len(sau.NewSiacoinElements) != 3 {
		t.Fatal("expected three new siacoin outputs")
	} else if sau.NewSiacoinElements[1].SiacoinOutput != expRenterOutput {
		t.Fatal("expected valid renter output to be created", sau.NewSiacoinElements[1].SiacoinOutput, expRenterOutput)
	} else if sau.NewSiacoinElements[1].MaturityHeight != sau.State.MaturityHeight()-1 {
		t.Fatal("renter output has wrong maturity height")
	} else if sau.NewSiacoinElements[2].SiacoinOutput != expHostOutput {
		t.Fatal("expected valid host output to be created", sau.NewSiacoinElements[2].SiacoinOutput, expHostOutput)
	} else if sau.NewSiacoinElements[2].MaturityHeight != sau.State.MaturityHeight()-1 {
		t.Fatal("host output has wrong maturity height")
	}
	fc = sau.NewFileContracts[0]
	if !sau.State.Elements.ContainsUnresolvedFileContractElement(fc) {
		t.Fatal("accumulator should contain unresolved contract")
	}

	// renew the contract again, this time with a total value less than the
	// current contract; no additional funding should be required
	finalRev = fc.FileContract
	finalRev.RevisionNumber = types.MaxRevisionNumber
	contractHash = sau.State.ContractSigHash(finalRev)
	finalRev.RenterSignature = renterPrivkey.SignHash(contractHash)
	finalRev.HostSignature = hostPrivkey.SignHash(contractHash)

	initialRev = fc.FileContract
	initialRev.RevisionNumber = 0
	initialRev.WindowStart += 10
	initialRev.WindowEnd += 10
	initialRev.RenterOutput.Value = types.Siacoins(10)
	initialRev.HostOutput.Value = types.Siacoins(10)
	initialRev.MissedHostValue = types.Siacoins(10)
	initialRev.TotalCollateral = types.Siacoins(10)
	contractHash = sau.State.ContractSigHash(initialRev)
	initialRev.RenterSignature = renterPrivkey.SignHash(contractHash)
	initialRev.HostSignature = hostPrivkey.SignHash(contractHash)

	renewal = types.FileContractRenewal{
		FinalRevision:   finalRev,
		InitialRevision: initialRev,
		RenterRollover:  types.Siacoins(17).Add(sau.State.FileContractTax(initialRev)),
		HostRollover:    types.Siacoins(3),
	}
	renewalHash = sau.State.RenewalSigHash(renewal)
	renewal.RenterSignature = renterPrivkey.SignHash(renewalHash)
	renewal.HostSignature = hostPrivkey.SignHash(renewalHash)

	txn = types.Transaction{
		FileContractResolutions: []types.FileContractResolution{{
			Parent:  fc,
			Renewal: renewal,
		}},
	}

	// apply the transaction
	b = mineBlock(sau.State, b, txn)
	if err := sau.State.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(sau.State, b)
	expRenterOutput = types.SiacoinOutput{
		Value:   finalRev.RenterOutput.Value.Sub(renewal.RenterRollover),
		Address: finalRev.RenterOutput.Address,
	}
	expHostOutput = types.SiacoinOutput{
		Value:   finalRev.HostOutput.Value.Sub(renewal.HostRollover),
		Address: finalRev.HostOutput.Address,
	}
	if len(sau.ResolvedFileContracts) != 1 {
		t.Fatal("expected one resolved file contract")
	} else if len(sau.NewFileContracts) != 1 {
		t.Fatal("expected one created file contract")
	} else if len(sau.NewSiacoinElements) != 3 {
		t.Fatal("expected three new siacoin outputs")
	} else if sau.NewSiacoinElements[1].SiacoinOutput != expRenterOutput {
		t.Fatal("expected valid renter output to be created", sau.NewSiacoinElements[1].SiacoinOutput, expRenterOutput)
	} else if sau.NewSiacoinElements[1].MaturityHeight != sau.State.MaturityHeight()-1 {
		t.Fatal("renter output has wrong maturity height")
	} else if sau.NewSiacoinElements[2].SiacoinOutput != expHostOutput {
		t.Fatal("expected valid host output to be created", sau.NewSiacoinElements[2].SiacoinOutput, expHostOutput)
	} else if sau.NewSiacoinElements[2].MaturityHeight != sau.State.MaturityHeight()-1 {
		t.Fatal("host output has wrong maturity height")
	}
}

func TestContractFinalization(t *testing.T) {
	renterPubkey, renterPrivkey := testingKeypair(0)
	hostPubkey, hostPrivkey := testingKeypair(1)
	b := genesisWithSiacoinOutputs(types.SiacoinOutput{
		Address: types.StandardAddress(renterPubkey),
		Value:   types.Siacoins(100),
	}, types.SiacoinOutput{
		Address: types.StandardAddress(hostPubkey),
		Value:   types.Siacoins(7),
	})
	sau := GenesisUpdate(b, testingDifficulty)
	renterOutput := sau.NewSiacoinElements[1]
	hostOutput := sau.NewSiacoinElements[2]

	// form initial contract
	initialRev := types.FileContract{
		WindowStart: 5,
		WindowEnd:   10,
		RenterOutput: types.SiacoinOutput{
			Address: types.StandardAddress(renterPubkey),
			Value:   types.Siacoins(58),
		},
		HostOutput: types.SiacoinOutput{
			Address: types.StandardAddress(hostPubkey),
			Value:   types.Siacoins(19),
		},
		MissedHostValue: types.Siacoins(17),
		TotalCollateral: types.Siacoins(18),
		RenterPublicKey: renterPubkey,
		HostPublicKey:   hostPubkey,
	}
	contractHash := sau.State.ContractSigHash(initialRev)
	initialRev.RenterSignature = renterPrivkey.SignHash(contractHash)
	initialRev.HostSignature = hostPrivkey.SignHash(contractHash)
	outputSum := initialRev.RenterOutput.Value.Add(initialRev.HostOutput.Value).Add(sau.State.FileContractTax(initialRev))
	txn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{Parent: renterOutput, SpendPolicy: types.PolicyPublicKey(renterPubkey)},
			{Parent: hostOutput, SpendPolicy: types.PolicyPublicKey(hostPubkey)},
		},
		FileContracts: []types.FileContract{initialRev},
		MinerFee:      renterOutput.Value.Add(hostOutput.Value).Sub(outputSum),
	}
	sigHash := sau.State.InputSigHash(txn)
	txn.SiacoinInputs[0].Signatures = []types.Signature{renterPrivkey.SignHash(sigHash)}
	txn.SiacoinInputs[1].Signatures = []types.Signature{hostPrivkey.SignHash(sigHash)}

	b = mineBlock(sau.State, b, txn)
	if err := sau.State.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(sau.State, b)

	if len(sau.NewFileContracts) != 1 {
		t.Fatal("expected one new file contract")
	}
	fc := sau.NewFileContracts[0]
	if !sau.State.Elements.ContainsUnresolvedFileContractElement(fc) {
		t.Fatal("accumulator should contain unresolved contract")
	}
	if sau.State.SiafundPool != sau.State.FileContractTax(initialRev) {
		t.Fatal("expected siafund pool to increase")
	}

	// finalize the contract
	finalRev := fc.FileContract
	finalRev.RevisionNumber = types.MaxRevisionNumber
	contractHash = sau.State.ContractSigHash(finalRev)
	finalRev.RenterSignature = renterPrivkey.SignHash(contractHash)
	finalRev.HostSignature = hostPrivkey.SignHash(contractHash)
	txn = types.Transaction{
		FileContractResolutions: []types.FileContractResolution{{
			Parent:       fc,
			Finalization: finalRev,
		}},
	}

	// after applying the transaction, the contract's outputs should be created immediately
	b = mineBlock(sau.State, b, txn)
	if err := sau.State.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(sau.State, b)
	if len(sau.ResolvedFileContracts) != 1 {
		t.Fatal("expected one resolved file contract")
	} else if len(sau.NewSiacoinElements) != 3 {
		t.Fatal("expected three new siacoin outputs")
	} else if sau.NewSiacoinElements[1].SiacoinOutput != finalRev.RenterOutput {
		t.Fatal("expected renter output to be created")
	} else if sau.NewSiacoinElements[2].SiacoinOutput != finalRev.HostOutput {
		t.Fatal("expected valid host output to be created")
	}
}

func TestRevertFileContractRevision(t *testing.T) {
	renterPubkey, renterPrivkey := testingKeypair(0)
	hostPubkey, hostPrivkey := testingKeypair(1)
	b := genesisWithSiacoinOutputs(types.SiacoinOutput{
		Address: types.StandardAddress(renterPubkey),
		Value:   types.Siacoins(100),
	}, types.SiacoinOutput{
		Address: types.StandardAddress(hostPubkey),
		Value:   types.Siacoins(7),
	})
	parent := b
	sau := GenesisUpdate(b, testingDifficulty)
	renterOutput := sau.NewSiacoinElements[1]
	hostOutput := sau.NewSiacoinElements[2]
	prevState, s := sau.State, sau.State

	// form initial contract
	initialRev := types.FileContract{
		WindowStart: 5,
		WindowEnd:   10,
		RenterOutput: types.SiacoinOutput{
			Address: types.StandardAddress(renterPubkey),
			Value:   types.Siacoins(58),
		},
		HostOutput: types.SiacoinOutput{
			Address: types.StandardAddress(hostPubkey),
			Value:   types.Siacoins(19),
		},
		MissedHostValue: types.Siacoins(17),
		TotalCollateral: types.Siacoins(18),
		RenterPublicKey: renterPubkey,
		HostPublicKey:   hostPubkey,
	}
	contractHash := s.ContractSigHash(initialRev)
	initialRev.RenterSignature = renterPrivkey.SignHash(contractHash)
	initialRev.HostSignature = hostPrivkey.SignHash(contractHash)
	outputSum := initialRev.RenterOutput.Value.Add(initialRev.HostOutput.Value).Add(s.FileContractTax(initialRev))
	txn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{Parent: renterOutput, SpendPolicy: types.PolicyPublicKey(renterPubkey)},
			{Parent: hostOutput, SpendPolicy: types.PolicyPublicKey(hostPubkey)},
		},
		FileContracts: []types.FileContract{initialRev},
		MinerFee:      renterOutput.Value.Add(hostOutput.Value).Sub(outputSum),
	}
	sigHash := s.InputSigHash(txn)
	txn.SiacoinInputs[0].Signatures = []types.Signature{renterPrivkey.SignHash(sigHash)}
	txn.SiacoinInputs[1].Signatures = []types.Signature{hostPrivkey.SignHash(sigHash)}

	// mine a block confirming the contract
	parent, b = b, mineBlock(s, b, txn)
	if err := s.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(s, b)
	prevState, s = s, sau.State

	// verify that the contract is now in the consensus set
	if len(sau.NewFileContracts) != 1 {
		t.Fatal("expected one new file contract")
	}
	fce := sau.NewFileContracts[0]
	if !s.Elements.ContainsUnresolvedFileContractElement(fce) {
		t.Fatal("accumulator should contain unresolved contract")
	} else if !reflect.DeepEqual(fce.FileContract, initialRev) {
		t.Fatal("expected file contract to match initial revision")
	}

	// create a revision of the contract
	rev1 := types.FileContractRevision{
		Parent:   fce,
		Revision: fce.FileContract,
	}
	rev1.Revision.RevisionNumber = 2
	contractHash = s.ContractSigHash(rev1.Revision)
	rev1.Revision.RenterSignature = renterPrivkey.SignHash(contractHash)
	rev1.Revision.HostSignature = hostPrivkey.SignHash(contractHash)
	parent, b = b, mineBlock(s, b, types.Transaction{
		FileContractRevisions: []types.FileContractRevision{rev1},
	})
	if err := s.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(s, b)
	prevState, s = s, sau.State
	if len(sau.RevisedFileContracts) != 1 {
		t.Fatal("expected one revised file contract")
	}
	fce = sau.RevisedFileContracts[0]
	if !reflect.DeepEqual(fce.FileContract, rev1.Revision) {
		t.Fatal("revision 1 should be applied")
	}
	sau.UpdateElementProof(&fce.StateElement)

	// create a second revision of the contract
	rev2 := types.FileContractRevision{
		Parent:   fce,
		Revision: fce.FileContract,
	}
	rev2.Revision.RevisionNumber = 4
	contractHash = s.ContractSigHash(rev2.Revision)
	rev2.Revision.RenterSignature = renterPrivkey.SignHash(contractHash)
	rev2.Revision.HostSignature = hostPrivkey.SignHash(contractHash)
	parent, b = b, mineBlock(s, b, types.Transaction{
		FileContractRevisions: []types.FileContractRevision{rev2},
	})
	if err := s.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(s, b)
	prevState, s = s, sau.State
	if len(sau.RevisedFileContracts) != 1 {
		t.Fatal("expected one revised file contract")
	}
	fce = sau.RevisedFileContracts[0]
	if !reflect.DeepEqual(fce.FileContract, rev2.Revision) {
		t.Fatal("revision 2 should be applied")
	}
	sau.UpdateElementProof(&fce.StateElement)

	// revert the revision and confirm that the contract is reverted to it's
	// rev1 state.
	sru := RevertBlock(prevState, b)
	b = parent
	s = sru.State
	fce = sru.RevisedFileContracts[0]
	if !reflect.DeepEqual(fce.FileContract, rev1.Revision) {
		t.Fatal("contract should revert to revision 1")
	}
	sru.UpdateElementProof(&fce.StateElement)

	// create a final revision of the contract
	rev3 := types.FileContractRevision{
		Parent:   fce,
		Revision: fce.FileContract,
	}
	rev3.Revision.RevisionNumber = 3
	contractHash = s.ContractSigHash(rev3.Revision)
	rev3.Revision.RenterSignature = renterPrivkey.SignHash(contractHash)
	rev3.Revision.HostSignature = hostPrivkey.SignHash(contractHash)
	txn = types.Transaction{
		FileContractRevisions: []types.FileContractRevision{rev3},
	}
	parent, b = b, mineBlock(s, b, txn)
	if err := s.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(s, b)
	prevState, s = s, sau.State
	if len(sau.RevisedFileContracts) != 1 {
		t.Fatal("expected one revised file contract")
	}
	fce = sau.RevisedFileContracts[0]
	if !reflect.DeepEqual(fce.FileContract, rev3.Revision) {
		t.Fatal("revision 3 should be applied")
	}
}

func BenchmarkApplyBlock(b *testing.B) {
	block := types.Block{
		Transactions: []types.Transaction{{
			SiacoinInputs: []types.SiacoinInput{{
				Parent: types.SiacoinElement{
					StateElement: types.StateElement{
						LeafIndex: types.EphemeralLeafIndex,
					},
				},
				SpendPolicy: types.AnyoneCanSpend(),
			}},
			SiacoinOutputs: make([]types.SiacoinOutput, 1000),
		}},
	}
	for i := 0; i < b.N; i++ {
		ApplyBlock(State{}, block)
	}
}
