package consensus

import (
	"math/rand"
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

func TestFileContracts(t *testing.T) {
	renterPubkey, renterPrivkey := testingKeypair()
	hostPubkey, hostPrivkey := testingKeypair()
	b := genesisWithBeneficiaries(types.Beneficiary{
		Address: renterPubkey.Address(),
		Value:   types.Siacoins(100),
	}, types.Beneficiary{
		Address: hostPubkey.Address(),
		Value:   types.Siacoins(7),
	})
	sau := GenesisUpdate(b, testingDifficulty)
	renterOutput := sau.NewSiacoinOutputs[1]
	hostOutput := sau.NewSiacoinOutputs[2]

	// form initial contract
	initialRev := types.FileContractRevision{
		WindowStart: 5,
		WindowEnd:   10,
		ValidRenterOutput: types.Beneficiary{
			Address: renterPubkey.Address(),
			Value:   types.Siacoins(58),
		},
		ValidHostOutput: types.Beneficiary{
			Address: renterPubkey.Address(),
			Value:   types.Siacoins(19),
		},
		MissedRenterOutput: types.Beneficiary{
			Address: renterPubkey.Address(),
			Value:   types.Siacoins(58),
		},
		MissedHostOutput: types.Beneficiary{
			Address: renterPubkey.Address(),
			Value:   types.Siacoins(19),
		},
		RenterPublicKey: renterPubkey,
		HostPublicKey:   hostPubkey,
	}
	outputSum := initialRev.ValidRenterOutput.Value.Add(initialRev.ValidHostOutput.Value).Add(sau.Context.FileContractTax(initialRev))
	txn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{Parent: renterOutput, PublicKey: renterPubkey},
			{Parent: hostOutput, PublicKey: hostPubkey},
		},
		FileContracts: []types.FileContractRevision{initialRev},
		MinerFee:      renterOutput.Value.Add(hostOutput.Value).Sub(outputSum),
	}
	sigHash := sau.Context.SigHash(txn)
	txn.SiacoinInputs[0].Signature = types.SignTransaction(renterPrivkey, sigHash)
	txn.SiacoinInputs[1].Signature = types.SignTransaction(hostPrivkey, sigHash)

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
	res := types.FileContractResolution{
		Parent:        fc,
		FinalRevision: fc.Revision,
	}
	finalRev := &res.FinalRevision
	sp := &res.StorageProof
	data := make([]byte, 64*2)
	rand.Read(data)
	finalRev.FileMerkleRoot = merkleNodeHash(
		segmentLeafHash(data[:64]),
		segmentLeafHash(data[64:]),
	)
	finalRev.RevisionNumber++
	txn = types.Transaction{
		FileContractResolutions: []types.FileContractResolution{res},
	}
	sigHash = sau.Context.SigHash(txn)
	txn.FileContractResolutions[0].RenterSignature = types.SignTransaction(renterPrivkey, sigHash)
	txn.FileContractResolutions[0].HostSignature = types.SignTransaction(hostPrivkey, sigHash)

	// resolution shouldn't be valid yet
	if err := sau.Context.ValidateTransaction(txn); err == nil {
		t.Fatal("expected early resolution to be rejected")
	}

	// mine until we enter the proof window
	//
	// NOTE: unlike other tests, we can't "cheat" here by fast-forwarding,
	// because we need to maintain a history proof
	for sau.Context.Index.Height < fc.Revision.WindowStart {
		b = mineBlock(sau.Context, b)
		sau = ApplyBlock(sau.Context, b)
		sau.UpdateFileContractProof(&res.Parent)
	}
	sp.WindowStart = sau.Context.Index
	proofIndex := sau.Context.StorageProofSegmentIndex(res.FinalRevision.Filesize, sp.WindowStart, res.Parent.ID)
	copy(sp.DataSegment[:], data[64*proofIndex:])
	if proofIndex == 0 {
		sp.SegmentProof = append(sp.SegmentProof, segmentLeafHash(data[64:]))
	} else {
		sp.SegmentProof = append(sp.SegmentProof, segmentLeafHash(data[:64]))
	}

	// resolution should be accepted now
	txn = types.Transaction{
		FileContractResolutions: []types.FileContractResolution{res},
	}
	sigHash = sau.Context.SigHash(txn)
	txn.FileContractResolutions[0].RenterSignature = types.SignTransaction(renterPrivkey, sigHash)
	txn.FileContractResolutions[0].HostSignature = types.SignTransaction(hostPrivkey, sigHash)
	b = mineBlock(sau.Context, b, txn)
	if err := sau.Context.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	validSAU := ApplyBlock(sau.Context, b)
	if len(validSAU.ResolvedFileContracts) != 1 {
		t.Fatal("expected one resolved file contract")
	} else if len(validSAU.NewSiacoinOutputs) != 3 {
		t.Fatal("expected three new siacoin outputs")
	}

	// revert the block and instead mine past the proof window
	for sau.Context.Index.Height <= fc.Revision.WindowEnd {
		b = mineBlock(sau.Context, b)
		sau = ApplyBlock(sau.Context, b)
		sau.UpdateFileContractProof(&res.Parent)
		sau.UpdateWindowProof(sp)
	}
	// storage proof resolution should now be rejected
	txn = types.Transaction{
		FileContractResolutions: []types.FileContractResolution{res},
	}
	sigHash = sau.Context.SigHash(txn)
	txn.FileContractResolutions[0].RenterSignature = types.SignTransaction(renterPrivkey, sigHash)
	txn.FileContractResolutions[0].HostSignature = types.SignTransaction(hostPrivkey, sigHash)
	if err := sau.Context.ValidateTransaction(txn); err == nil {
		t.Fatal("expected too-late storage proof to be rejected")
	}
	// missed resolution should be accepted, though
	res.StorageProof = types.StorageProof{}
	txn = types.Transaction{
		FileContractResolutions: []types.FileContractResolution{res},
	}
	sigHash = sau.Context.SigHash(txn)
	txn.FileContractResolutions[0].RenterSignature = types.SignTransaction(renterPrivkey, sigHash)
	txn.FileContractResolutions[0].HostSignature = types.SignTransaction(hostPrivkey, sigHash)
	b = mineBlock(sau.Context, b, txn)
	if err := sau.Context.ValidateBlock(b); err != nil {
		t.Fatal(err)
	}
	sau = ApplyBlock(sau.Context, b)

	if len(sau.ResolvedFileContracts) != 1 {
		t.Fatal("expected one resolved file contract")
	} else if len(sau.NewSiacoinOutputs) != 3 {
		t.Fatal("expected three new siacoin outputs")
	}
}
