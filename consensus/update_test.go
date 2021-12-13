package consensus

import (
	"math"
	"testing"
	"time"

	"go.sia.tech/core/merkle"
	"go.sia.tech/core/types"
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
	acc1 := update1.Context.State
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

	update2 := ApplyBlock(update1.Context, b)
	acc2 := update2.Context.State
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
	revertUpdate := RevertBlock(update1.Context, b)
	revertAcc := revertUpdate.Context.State
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

	update3 := ApplyBlock(update2.Context, b)
	acc3 := update3.Context.State
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

	update2 := ApplyBlock(update1.Context, b)
	for i := range origOutputs {
		update2.UpdateElementProof(&origOutputs[i].StateElement)
	}

	// revert the block. We should see the inputs being "created" again
	// and the outputs being destroyed
	revertUpdate := RevertBlock(update1.Context, b)
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
		if !update1.Context.State.ContainsUnspentSiacoinElement(o) {
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
	signAllInputs(&txn, sau.Context, privkey)
	b = mineBlock(sau.Context, b, txn)
	if err := sau.Context.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(sau.Context, b)

	// should have created a siafund output, a block reward, and a claim output
	if len(sau.NewSiafundElements) != 1 || sau.NewSiafundElements[0].Value != 100 {
		t.Fatal("expected one new siafund output")
	} else if len(sau.NewSiacoinElements) != 2 {
		t.Fatal("expected one block reward and one claim output")
	}

	// attempt to spend the claim output; it should be timelocked
	txn = types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			Parent:      sau.NewSiacoinElements[1],
			SpendPolicy: types.PolicyPublicKey(claimPubkey),
		}},
		MinerFee: sau.NewSiacoinElements[1].Value,
	}
	signAllInputs(&txn, sau.Context, claimPrivkey)
	b = mineBlock(sau.Context, b, txn)
	if err := sau.Context.ValidateBlock(b); err == nil {
		t.Fatal("expected error when attempting to spend timelocked claim output")
	}

	// skip to timelock height and try again
	sau.Context.Index.Height = sau.NewSiacoinElements[1].Timelock + 1
	sau.Context.Index.ID = b.ID()
	for i := range sau.Context.PrevTimestamps {
		sau.Context.PrevTimestamps[i] = b.Header.Timestamp
	}
	b.Header.Height = sau.Context.Index.Height
	signAllInputs(&txn, sau.Context, claimPrivkey)
	b = mineBlock(sau.Context, b, txn)
	if err := sau.Context.ValidateBlock(b); err != nil {
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
	if sau.Context.FoundationAddress != types.StandardAddress(pubkey) {
		t.Fatal("Foundation address not updated")
	}
	initialOutput := sau.NewSiacoinElements[1]

	// skip to Foundation hardfork height; we should receive the initial subsidy
	b.Header.Height = foundationHardforkHeight - 1
	sau.Context.Index.Height = foundationHardforkHeight - 1
	for i := range sau.Context.PrevTimestamps {
		sau.Context.PrevTimestamps[i] = b.Header.Timestamp
	}
	b = mineBlock(sau.Context, b)
	if err := sau.Context.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(sau.Context, b)
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
	signAllInputs(&txn, sau.Context, privkey)
	b = mineBlock(sau.Context, b, txn)
	if err := sau.Context.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(sau.Context, b)
	sau.UpdateElementProof(&subsidyOutput.StateElement)
	if sau.Context.FoundationAddress != newAddress {
		t.Fatal("Foundation address not updated")
	}

	// skip beyond the timelock of the initial subsidy output, and spend it
	sau.Context.Index.Height = subsidyOutput.Timelock + 1
	txn = types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			Parent:      subsidyOutput,
			SpendPolicy: types.PolicyPublicKey(pubkey),
		}},
		MinerFee: subsidyOutput.Value,
	}
	signAllInputs(&txn, sau.Context, privkey)
	if err := sau.Context.ValidateTransaction(txn); err != nil {
		t.Fatal(err)
	}

	// skip to the next foundation subsidy height; the foundation address should
	// receive a new subsidy.
	sau.Context.Index.Height = foundationHardforkHeight + foundationSubsidyFrequency - 1
	b.Header.Height = sau.Context.Index.Height
	b = mineBlock(sau.Context, b, txn)
	if err := sau.Context.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(sau.Context, b)
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
				b = mineBlock(sau.Context, b)
				sau = ApplyBlock(sau.Context, b)
			}
			sp := types.StorageProof{
				WindowStart: sau.Context.Index,
				WindowProof: sau.HistoryProof(),
			}
			for i := 0; i < after; i++ {
				b = mineBlock(sau.Context, b)
				sau = ApplyBlock(sau.Context, b)
				sau.UpdateWindowProof(&sp)
			}
			if !sau.Context.History.Contains(sp.WindowStart, sp.WindowProof) {
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
		ValidRenterOutput: types.SiacoinOutput{
			Address: types.StandardAddress(renterPubkey),
			Value:   types.Siacoins(58),
		},
		ValidHostOutput: types.SiacoinOutput{
			Address: types.StandardAddress(renterPubkey),
			Value:   types.Siacoins(19),
		},
		MissedRenterOutput: types.SiacoinOutput{
			Address: types.StandardAddress(renterPubkey),
			Value:   types.Siacoins(58),
		},
		MissedHostOutput: types.SiacoinOutput{
			Address: types.StandardAddress(renterPubkey),
			Value:   types.Siacoins(19),
		},
		RenterPublicKey: renterPubkey,
		HostPublicKey:   hostPubkey,
	}
	outputSum := initialRev.ValidRenterOutput.Value.Add(initialRev.ValidHostOutput.Value).Add(sau.Context.FileContractTax(initialRev))
	txn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{Parent: renterOutput, SpendPolicy: types.PolicyPublicKey(renterPubkey)},
			{Parent: hostOutput, SpendPolicy: types.PolicyPublicKey(hostPubkey)},
		},
		FileContracts: []types.FileContract{initialRev},
		MinerFee:      renterOutput.Value.Add(hostOutput.Value).Sub(outputSum),
	}
	sigHash := sau.Context.SigHash(txn)
	txn.SiacoinInputs[0].Signatures = []types.InputSignature{types.InputSignature(renterPrivkey.SignHash(sigHash))}
	txn.SiacoinInputs[1].Signatures = []types.InputSignature{types.InputSignature(hostPrivkey.SignHash(sigHash))}

	b = mineBlock(sau.Context, b, txn)
	if err := sau.Context.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(sau.Context, b)

	if len(sau.NewFileContracts) != 1 {
		t.Fatal("expected one new file contract")
	}
	fc := sau.NewFileContracts[0]
	if !sau.Context.State.ContainsUnresolvedFileContractElement(fc) {
		t.Fatal("accumulator should contain unresolved contract")
	}
	if sau.Context.SiafundPool != sau.Context.FileContractTax(initialRev) {
		t.Fatal("expected siafund pool to increase")
	}

	// renter and host now exchange data + revisions out-of-band; we simulate
	// the final revision
	data := frand.Bytes(64 * 2)
	finalRev := types.FileContractRevision{
		Parent:   fc,
		Revision: fc.FileContract,
	}
	finalRev.Revision.FileMerkleRoot = merkle.NodeHash(
		merkle.StorageProofLeafHash(data[:64]),
		merkle.StorageProofLeafHash(data[64:]),
	)
	finalRev.Revision.RevisionNumber++
	contractHash := sau.Context.ContractSigHash(finalRev.Revision)
	finalRev.RenterSignature = renterPrivkey.SignHash(contractHash)
	finalRev.HostSignature = hostPrivkey.SignHash(contractHash)
	txn = types.Transaction{
		FileContractRevisions: []types.FileContractRevision{finalRev},
	}

	b = mineBlock(sau.Context, b, txn)
	if err := sau.Context.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(sau.Context, b)
	if len(sau.RevisedFileContracts) != 1 {
		t.Fatal("expected one revised file contract")
	}
	fc = sau.RevisedFileContracts[0]
	sau.UpdateElementProof(&fc.StateElement)

	// mine until we enter the proof window
	//
	// NOTE: unlike other tests, we can't "cheat" here by fast-forwarding,
	// because we need to maintain a history proof
	for sau.Context.Index.Height < fc.WindowStart {
		b = mineBlock(sau.Context, b)
		sau = ApplyBlock(sau.Context, b)
		sau.UpdateElementProof(&fc.StateElement)
	}
	sp := types.StorageProof{
		WindowStart: sau.Context.Index,
		WindowProof: sau.HistoryProof(),
	}
	proofIndex := sau.Context.StorageProofSegmentIndex(fc.Filesize, sp.WindowStart, fc.ID)
	copy(sp.DataSegment[:], data[64*proofIndex:])
	if proofIndex == 0 {
		sp.SegmentProof = append(sp.SegmentProof, merkle.StorageProofLeafHash(data[64:]))
	} else {
		sp.SegmentProof = append(sp.SegmentProof, merkle.StorageProofLeafHash(data[:64]))
	}

	// create valid contract resolution
	txn = types.Transaction{
		FileContractResolutions: []types.FileContractResolution{{
			Parent:       fc,
			StorageProof: sp,
		}},
	}

	validBlock := mineBlock(sau.Context, b, txn)
	if err := sau.Context.ValidateBlock(validBlock); err != nil {
		t.Fatal(err)
	}
	validSAU := ApplyBlock(sau.Context, validBlock)
	if len(validSAU.NewSiacoinElements) != 3 {
		t.Fatal("expected three new siacoin outputs")
	}

	// revert the block and instead mine past the proof window
	for sau.Context.Index.Height <= fc.WindowEnd {
		b = mineBlock(sau.Context, b)
		sau = ApplyBlock(sau.Context, b)
		sau.UpdateElementProof(&txn.FileContractResolutions[0].Parent.StateElement)
		sau.UpdateWindowProof(&txn.FileContractResolutions[0].StorageProof)
	}
	// storage proof resolution should now be rejected
	if err := sau.Context.ValidateTransaction(txn); err == nil {
		t.Fatal("expected too-late storage proof to be rejected")
	}
	// missed resolution should be accepted, though
	txn.FileContractResolutions[0].StorageProof = types.StorageProof{}
	b = mineBlock(sau.Context, b, txn)
	if err := sau.Context.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(sau.Context, b)

	if len(sau.NewSiacoinElements) != 3 {
		t.Fatal("expected three new siacoin outputs")
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
		ApplyBlock(ValidationContext{}, block)
	}
}
