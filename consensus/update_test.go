package consensus

import (
	"crypto/rand"
	"testing"
	"time"

	"go.sia.tech/core/types"
)

func TestSiafunds(t *testing.T) {
	pubkey, privkey := testingKeypair(0)
	b := types.Block{
		Header: types.BlockHeader{Timestamp: time.Unix(734600000, 0)},
		Transactions: []types.Transaction{{SiafundOutputs: []types.Beneficiary{{
			Address: types.StandardAddress(pubkey),
			Value:   types.NewCurrency64(100),
		}}}},
	}
	sau := GenesisUpdate(b, testingDifficulty)

	// send siafunds to a new address
	claimPubkey, claimPrivkey := testingKeypair(1)
	txn := types.Transaction{
		SiafundInputs: []types.SiafundInput{{
			Parent:       sau.NewSiafundOutputs[0],
			SpendPolicy:  types.PolicyPublicKey(pubkey),
			ClaimAddress: types.StandardAddress(claimPubkey),
		}},
		SiafundOutputs: []types.Beneficiary{{
			Address: types.StandardAddress(claimPubkey),
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
			Parent:      sau.NewSiacoinOutputs[1],
			SpendPolicy: types.PolicyPublicKey(claimPubkey),
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
	b := genesisWithBeneficiaries(types.Beneficiary{
		Address: types.StandardAddress(pubkey),
		Value:   types.NewCurrency64(100),
	})
	b.Transactions[0].NewFoundationAddress = types.StandardAddress(pubkey)
	sau := GenesisUpdate(b, testingDifficulty)
	if sau.Context.FoundationAddress != types.StandardAddress(pubkey) {
		t.Fatal("Foundation address not updated")
	}
	initialOutput := sau.NewSiacoinOutputs[1]

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
	sau.UpdateSiacoinOutputProof(&subsidyOutput)
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
	subsidyID = types.OutputID{
		TransactionID: types.TransactionID(b.ID()),
		Index:         1,
	}
	for _, o := range sau.NewSiacoinOutputs {
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
			b := genesisWithBeneficiaries()
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
	b := genesisWithBeneficiaries(types.Beneficiary{
		Address: types.StandardAddress(renterPubkey),
		Value:   types.Siacoins(100),
	}, types.Beneficiary{
		Address: types.StandardAddress(hostPubkey),
		Value:   types.Siacoins(7),
	})
	sau := GenesisUpdate(b, testingDifficulty)
	renterOutput := sau.NewSiacoinOutputs[1]
	hostOutput := sau.NewSiacoinOutputs[2]

	// form initial contract
	initialRev := types.FileContractState{
		WindowStart: 5,
		WindowEnd:   10,
		ValidRenterOutput: types.Beneficiary{
			Address: types.StandardAddress(renterPubkey),
			Value:   types.Siacoins(58),
		},
		ValidHostOutput: types.Beneficiary{
			Address: types.StandardAddress(renterPubkey),
			Value:   types.Siacoins(19),
		},
		MissedRenterOutput: types.Beneficiary{
			Address: types.StandardAddress(renterPubkey),
			Value:   types.Siacoins(58),
		},
		MissedHostOutput: types.Beneficiary{
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
		FileContracts: []types.FileContractState{initialRev},
		MinerFee:      renterOutput.Value.Add(hostOutput.Value).Sub(outputSum),
	}
	sigHash := sau.Context.SigHash(txn)
	txn.SiacoinInputs[0].Signatures = []types.InputSignature{types.SignTransaction(renterPrivkey, sigHash)}
	txn.SiacoinInputs[1].Signatures = []types.InputSignature{types.SignTransaction(hostPrivkey, sigHash)}

	b = mineBlock(sau.Context, b, txn)
	if err := sau.Context.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(sau.Context, b)

	if len(sau.NewFileContracts) != 1 {
		t.Fatal("expected one new file contract")
	}
	fc := sau.NewFileContracts[0]
	if !sau.Context.State.ContainsUnresolvedFileContract(fc) {
		t.Fatal("accumulator should contain unresolved contract")
	}
	if sau.Context.SiafundPool != sau.Context.FileContractTax(initialRev) {
		t.Fatal("expected siafund pool to increase")
	}

	// renter and host now exchange data + revisions out-of-band; we simulate
	// the final revision
	segmentLeafHash := func(segment []byte) types.Hash256 {
		buf := make([]byte, 1+64)
		buf[0] = leafHashPrefix
		copy(buf[1:], segment)
		return types.HashBytes(buf)
	}
	data := make([]byte, 64*2)
	rand.Read(data)
	finalRev := types.FileContractRevision{
		Parent:   fc,
		NewState: fc.State,
	}
	finalRev.NewState.FileMerkleRoot = merkleNodeHash(
		segmentLeafHash(data[:64]),
		segmentLeafHash(data[64:]),
	)
	finalRev.NewState.RevisionNumber++
	contractHash := sau.Context.ContractSigHash(finalRev.NewState)
	finalRev.RenterSignature = types.SignTransaction(renterPrivkey, contractHash)
	finalRev.HostSignature = types.SignTransaction(hostPrivkey, contractHash)
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
	sau.UpdateFileContractProof(&fc)

	// mine until we enter the proof window
	//
	// NOTE: unlike other tests, we can't "cheat" here by fast-forwarding,
	// because we need to maintain a history proof
	for sau.Context.Index.Height < fc.State.WindowStart {
		b = mineBlock(sau.Context, b)
		sau = ApplyBlock(sau.Context, b)
		sau.UpdateFileContractProof(&fc)
	}
	sp := types.StorageProof{
		WindowStart: sau.Context.Index,
		WindowProof: sau.HistoryProof(),
	}
	proofIndex := sau.Context.StorageProofSegmentIndex(fc.State.Filesize, sp.WindowStart, fc.ID)
	copy(sp.DataSegment[:], data[64*proofIndex:])
	if proofIndex == 0 {
		sp.SegmentProof = append(sp.SegmentProof, segmentLeafHash(data[64:]))
	} else {
		sp.SegmentProof = append(sp.SegmentProof, segmentLeafHash(data[:64]))
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
	if len(validSAU.NewSiacoinOutputs) != 3 {
		t.Fatal("expected three new siacoin outputs")
	}

	// revert the block and instead mine past the proof window
	for sau.Context.Index.Height <= fc.State.WindowEnd {
		b = mineBlock(sau.Context, b)
		sau = ApplyBlock(sau.Context, b)
		sau.UpdateFileContractProof(&txn.FileContractResolutions[0].Parent)
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

	if len(sau.NewSiacoinOutputs) != 3 {
		t.Fatal("expected three new siacoin outputs")
	}
}
