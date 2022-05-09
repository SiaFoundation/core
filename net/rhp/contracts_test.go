package rhp

import (
	"encoding/binary"
	"reflect"
	"testing"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

func outputValue(amount types.Currency) types.SiacoinOutput {
	return types.SiacoinOutput{Value: amount}
}

func testingKeypair(seed uint64) (types.PublicKey, types.PrivateKey) {
	var b [32]byte
	binary.LittleEndian.PutUint64(b[:], seed)
	privkey := types.NewPrivateKeyFromSeed(b)
	return privkey.PublicKey(), privkey
}

func TestPaymentRevision(t *testing.T) {
	amount := types.Siacoins(10)
	fc := types.FileContract{
		RenterOutput:    outputValue(amount.Mul64(1)),
		HostOutput:      outputValue(amount.Mul64(2)),
		MissedHostValue: amount.Mul64(3),
		RevisionNumber:  5,
	}
	rev, err := PaymentRevision(fc, amount)
	if err != nil {
		t.Fatal(err)
	}

	expected := types.FileContract{
		RenterOutput:    outputValue(types.Siacoins(0)),
		HostOutput:      outputValue(amount.Mul64(3)),
		MissedHostValue: amount.Mul64(4),
		RevisionNumber:  6,
	}
	if !reflect.DeepEqual(rev, expected) {
		t.Fatalf("expected %v got %v", expected, rev)
	}

	if _, err := PaymentRevision(fc, amount.Mul64(20)); err == nil {
		t.Fatal("expected insufficient funds error")
	}
}

func TestFinalizeProgramRevision(t *testing.T) {
	amount := types.Siacoins(10)
	fc := types.FileContract{
		MissedHostValue: amount.Mul64(3),
		RevisionNumber:  5,
	}
	rev, err := FinalizeProgramRevision(fc, amount)
	if err != nil {
		t.Fatal(err)
	}

	expected := types.FileContract{
		MissedHostValue: amount.Mul64(2),
		RevisionNumber:  6,
	}
	if !reflect.DeepEqual(rev, expected) {
		t.Fatalf("expected %v got %v", expected, rev)
	}

	if _, err := FinalizeProgramRevision(fc, amount.Mul64(20)); err == nil {
		t.Fatal("expected insufficient funds error")
	}
}

func TestValidateContractSignatures(t *testing.T) {
	var cs consensus.State
	renterPubkey, renterPrivkey := testingKeypair(0)
	hostPubkey, hostPrivkey := testingKeypair(0)

	amount := types.Siacoins(10)
	fc := types.FileContract{
		RenterOutput:    outputValue(amount.Mul64(1)),
		HostOutput:      outputValue(amount.Mul64(2)),
		MissedHostValue: amount.Mul64(3),
		RevisionNumber:  5,
		HostPublicKey:   hostPubkey,
		RenterPublicKey: renterPubkey,
	}
	hash := cs.ContractSigHash(fc)

	fc.HostSignature = hostPrivkey.SignHash(hash)
	fc.RenterSignature = renterPrivkey.SignHash(hash)

	if err := ValidateContractSignatures(cs, fc); err != nil {
		t.Fatal(err)
	}

	fc.HostSignature[0] ^= 255

	if err := ValidateContractSignatures(cs, fc); err != ErrInvalidHostSignature {
		t.Fatalf("expected %v, got %v", ErrInvalidHostSignature, err)
	}

	// fix host signature
	fc.HostSignature[0] ^= 255

	fc.RenterSignature[0] ^= 255
	if err := ValidateContractSignatures(cs, fc); err != ErrInvalidRenterSignature {
		t.Fatalf("expected %v, got %v", ErrInvalidRenterSignature, err)
	}
}

func TestValidateContractRenewalFinalization(t *testing.T) {
	currentHeight := uint64(5)
	settings := HostSettings{
		WindowSize:    10,
		MaxDuration:   100,
		ContractFee:   types.Siacoins(500),
		MaxCollateral: types.Siacoins(1000),
	}
	renterPubkey, _ := testingKeypair(0)
	hostPubkey, _ := testingKeypair(0)

	windowStart := currentHeight + settings.WindowSize
	windowEnd := windowStart + settings.WindowSize
	totalCollateral := types.Siacoins(700)
	fc := types.FileContract{
		WindowStart:     windowStart,
		WindowEnd:       windowEnd,
		TotalCollateral: totalCollateral,
		MissedHostValue: settings.ContractFee.Add(totalCollateral),
		HostOutput:      outputValue(settings.ContractFee.Add(totalCollateral)),
		RenterOutput:    outputValue(types.Siacoins(10)),
		HostPublicKey:   hostPubkey,
		RenterPublicKey: renterPubkey,
	}

	if err := ValidateContractFormation(fc, currentHeight, settings); err != nil {
		t.Fatal(err)
	}

	formChanges := []struct {
		corrupt func(fc *types.FileContract)
		desc    string
	}{
		{
			func(fc *types.FileContract) {
				fc.Filesize = 5
			},
			"initial filesize should be 0",
		},
		{
			func(fc *types.FileContract) {
				fc.RevisionNumber = 5
			},
			"initial revision number should be 0",
		},
		{
			func(fc *types.FileContract) {
				fc.FileMerkleRoot = types.Hash256{31: 1}
			},
			"initial Merkle root should be empty",
		},
		{
			func(fc *types.FileContract) {
				fc.WindowStart = windowStart / 2
			},
			"contract ends too soon to safely submit the contract transaction",
		},
		{
			func(fc *types.FileContract) {
				fc.WindowStart = currentHeight + 2*settings.MaxDuration
			},
			"contract duration is too long",
		},
		{
			func(fc *types.FileContract) {
				fc.WindowEnd = windowStart + settings.WindowSize/2
			},
			"proof window is too small",
		},
		{
			func(fc *types.FileContract) {
				fc.HostOutput.Address = types.Address{31: 1}
			},
			"wrong address for host valid output",
		},
		{
			func(fc *types.FileContract) {
				fc.MissedHostValue = fc.HostOutput.Value.Mul64(2)
			},
			"host valid output value does not equal missed value",
		},
		{
			func(fc *types.FileContract) {
				fc.HostOutput.Value = fc.HostOutput.Value.Mul64(1000)
				fc.MissedHostValue = fc.HostOutput.Value
			},
			"wrong initial host output value",
		},
		{
			func(fc *types.FileContract) {
				fc.TotalCollateral = settings.MaxCollateral.Mul64(1000)
				fc.HostOutput.Value = settings.ContractFee.Add(fc.TotalCollateral)
				fc.MissedHostValue = fc.HostOutput.Value
			},
			"excessive initial collateral",
		},
	}

	for _, change := range formChanges {
		fcCopy := fc
		change.corrupt(&fcCopy)
		if err := ValidateContractFormation(fcCopy, currentHeight, settings); err.Error() != change.desc {
			t.Fatalf("expected error %s, got %s", change.desc, err.Error())
		}
	}

	currentHeight = windowEnd

	renewal := fc
	renewal.WindowEnd += 3 * settings.WindowSize
	renewal.WindowStart = fc.WindowEnd + settings.WindowSize

	if err := ValidateContractRenewal(fc, renewal, currentHeight, settings); err != nil {
		t.Fatal(err)
	}

	renewalChanges := []struct {
		corrupt func(existing, renewal *types.FileContract)
		desc    string
	}{
		{
			func(existing, renewal *types.FileContract) {
				renewal.HostPublicKey[0] ^= 255
			},
			"host public key must not change",
		},
		{
			func(existing, renewal *types.FileContract) {
				renewal.RenterPublicKey[0] ^= 255
			},
			"renter public key must not change",
		},
		{
			func(existing, renewal *types.FileContract) {
				renewal.RevisionNumber++
			},
			"revision number must be zero",
		},
		{
			func(existing, renewal *types.FileContract) {
				renewal.Filesize = existing.Filesize + 5
			},
			"filesize must not change",
		},
		{
			func(existing, renewal *types.FileContract) {
				renewal.FileMerkleRoot[0] ^= 255
			},
			"file Merkle root must not change",
		},
		{
			func(existing, renewal *types.FileContract) {
				renewal.WindowEnd = existing.WindowEnd - 5
			},
			"renewal window must not end before current window",
		},
		{
			func(existing, renewal *types.FileContract) {
				renewal.WindowStart = currentHeight
			},
			"contract ends too soon to safely submit the contract transaction",
		},
		{
			func(existing, renewal *types.FileContract) {
				renewal.WindowStart = currentHeight + 2*settings.MaxDuration
			},
			"contract duration is too long",
		},
		{
			func(existing, renewal *types.FileContract) {
				renewal.WindowEnd = renewal.WindowStart + settings.WindowSize/2
			},
			"proof window is too small",
		},
		{
			func(existing, renewal *types.FileContract) {
				renewal.HostOutput.Value = renewal.HostOutput.Value.Sub(settings.ContractFee)
			},
			"insufficient initial host payout",
		},
		{
			func(existing, renewal *types.FileContract) {
				renewal.TotalCollateral = settings.MaxCollateral.Mul64(1000)
				renewal.HostOutput.Value = settings.ContractFee.Add(renewal.TotalCollateral)
			},
			"excessive initial collateral",
		},
	}

	for _, change := range renewalChanges {
		renewCopy := renewal
		change.corrupt(&fc, &renewCopy)
		if err := ValidateContractRenewal(fc, renewCopy, currentHeight, settings); err.Error() != change.desc {
			t.Fatalf("expected error %s, got %s", change.desc, err.Error())
		}
	}

	final := renewal
	final.RevisionNumber = types.MaxRevisionNumber

	if err := ValidateContractFinalization(renewal, final); err != nil {
		t.Fatal(err)
	}

	finalChanges := []struct {
		corrupt func(current, final *types.FileContract)
		desc    string
	}{
		{
			func(current, final *types.FileContract) {
				final.Filesize++
			},
			"file size must not change",
		},
		{
			func(current, final *types.FileContract) {
				final.FileMerkleRoot[0] ^= 255
			},
			"file merkle root must not change",
		},
		{
			func(current, final *types.FileContract) {
				final.WindowStart++
			},
			"window start must not change",
		},
		{
			func(current, final *types.FileContract) {
				final.WindowEnd++
			},
			"window end must not change",
		},
		{
			func(current, final *types.FileContract) {
				final.RenterOutput.Value = final.RenterOutput.Value.Add(types.Siacoins(1))
			},
			"renter output must not change",
		},
		{
			func(current, final *types.FileContract) {
				final.HostOutput.Value = final.HostOutput.Value.Add(types.Siacoins(1))
			},
			"valid host output must not change",
		},
		{
			func(current, final *types.FileContract) {
				final.MissedHostValue = final.MissedHostValue.Add(types.Siacoins(1))
			},
			"missed host payout must not change",
		},
		{
			func(current, final *types.FileContract) {
				final.TotalCollateral = final.TotalCollateral.Add(types.Siacoins(1))
			},
			"total collateral must not change",
		},
		{
			func(current, final *types.FileContract) {
				final.RenterPublicKey[0] ^= 255
			},
			"renter public key must not change",
		},
		{
			func(current, final *types.FileContract) {
				final.HostPublicKey[0] ^= 255
			},
			"host public key must not change",
		},
		{
			func(current, final *types.FileContract) {
				final.RevisionNumber = types.MaxRevisionNumber / 2
			},
			"revision number must be max value",
		},
	}

	for _, change := range finalChanges {
		finalCopy := final
		change.corrupt(&renewal, &finalCopy)
		if err := ValidateContractFinalization(renewal, finalCopy); err.Error() != change.desc {
			t.Fatalf("expected error %s, got %s", change.desc, err.Error())
		}
	}
}

func TestValidateContractRevision(t *testing.T) {
	currentHeight := uint64(5)
	settings := HostSettings{
		WindowSize:    10,
		MaxDuration:   100,
		ContractFee:   types.Siacoins(500),
		MaxCollateral: types.Siacoins(1000),
	}
	renterPubkey, _ := testingKeypair(0)
	hostPubkey, _ := testingKeypair(0)

	windowStart := currentHeight + settings.WindowSize
	windowEnd := windowStart + settings.WindowSize
	totalCollateral := types.Siacoins(700)
	fc := types.FileContract{
		WindowStart:     windowStart,
		WindowEnd:       windowEnd,
		TotalCollateral: totalCollateral,
		MissedHostValue: settings.ContractFee.Add(totalCollateral),
		HostOutput:      outputValue(settings.ContractFee.Add(totalCollateral)),
		RenterOutput:    outputValue(types.Siacoins(10)),
		HostPublicKey:   hostPubkey,
		RenterPublicKey: renterPubkey,
	}

	if err := ValidateContractFormation(fc, currentHeight, settings); err != nil {
		t.Fatal(err)
	}

	revision := fc
	revision.RevisionNumber++

	if err := ValidateProgramRevision(fc, revision, types.ZeroCurrency, types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}

	revisionChanges := []struct {
		corrupt func(current, revision *types.FileContract)
		desc    string
	}{
		{
			func(current, revision *types.FileContract) {
				revision.RevisionNumber = current.RevisionNumber
			},
			"revision number must increase",
		},
		{
			func(current, revision *types.FileContract) {
				revision.WindowStart++
			},
			"window start must not change",
		},
		{
			func(current, revision *types.FileContract) {
				revision.WindowEnd++
			},
			"window end must not change",
		},
		{
			func(current, revision *types.FileContract) {
				revision.RenterPublicKey[0] ^= 255
			},
			"renter public key must not change",
		},
		{
			func(current, revision *types.FileContract) {
				revision.HostPublicKey[0] ^= 255
			},
			"host public key must not change",
		},
		{
			func(current, revision *types.FileContract) {
				revision.RenterOutput.Address[0] ^= 255
			},
			"renter address must not change",
		},
		{
			func(current, revision *types.FileContract) {
				revision.RenterOutput.Value = revision.RenterOutput.Value.Add(types.Siacoins(1))
			},
			"renter output should not change",
		},
		{
			func(current, revision *types.FileContract) {
				revision.HostOutput.Value = revision.HostOutput.Value.Add(types.Siacoins(1))
			},
			"host valid output should not change",
		},
		{
			func(current, revision *types.FileContract) {
				revision.HostOutput.Address[0] ^= 255
			},
			"host address must not change",
		},
		{
			func(current, revision *types.FileContract) {
				revision.TotalCollateral = current.TotalCollateral.Add(types.Siacoins(1))
			},
			"total collateral must not change",
		},
	}

	for _, change := range revisionChanges {
		revCopy := revision
		change.corrupt(&fc, &revCopy)
		if err := ValidateProgramRevision(fc, revCopy, types.ZeroCurrency, types.ZeroCurrency); err.Error() != change.desc {
			t.Fatalf("expected error %s, got %s", change.desc, err.Error())
		}
	}

	if err := ValidatePaymentRevision(fc, revision, types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}

	paymentRevisionChanges := []struct {
		corrupt func(revision *types.FileContract)
		desc    string
	}{
		{
			func(revision *types.FileContract) {
				revision.FileMerkleRoot[0] ^= 255
			},
			"file merkle root must not change",
		},
		{
			func(revision *types.FileContract) {
				revision.Filesize++
			},
			"file size must not change",
		},
		{
			func(revision *types.FileContract) {
				revision.RenterOutput.Value = revision.RenterOutput.Value.Add(types.Siacoins(1))
			},
			"renter output value should decrease by the amount",
		},
		{
			func(revision *types.FileContract) {
				revision.HostOutput.Value = revision.HostOutput.Value.Sub(types.Siacoins(1))
			},
			"host output value should increase by the amount",
		},
		{
			func(revision *types.FileContract) {
				revision.MissedHostValue = revision.MissedHostValue.Sub(types.Siacoins(1))
			},
			"host missed output value should increase by the amount",
		}}

	for _, change := range paymentRevisionChanges {
		revCopy := revision
		change.corrupt(&revCopy)
		if err := ValidatePaymentRevision(fc, revCopy, types.ZeroCurrency); err.Error() != change.desc {
			t.Fatalf("expected error %s, got %s", change.desc, err.Error())
		}
	}
}
