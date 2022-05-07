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
		change func(fc types.FileContract) types.FileContract
		error  string
	}{
		{
			func(fc types.FileContract) types.FileContract {
				fc.Filesize = 5
				return fc
			},
			"initial filesize should be 0",
		},
		{
			func(fc types.FileContract) types.FileContract {
				fc.RevisionNumber = 5
				return fc
			},
			"initial revision number should be 0",
		},
		{
			func(fc types.FileContract) types.FileContract {
				fc.FileMerkleRoot = types.Hash256{31: 1}
				return fc
			},
			"initial Merkle root should be empty",
		},
		{
			func(fc types.FileContract) types.FileContract {
				fc.WindowStart = windowStart / 2
				return fc
			},
			"contract ends too soon to safely submit the contract transaction",
		},
		{
			func(fc types.FileContract) types.FileContract {
				fc.WindowStart = currentHeight + 2*settings.MaxDuration
				return fc
			},
			"contract duration is too long",
		},
		{
			func(fc types.FileContract) types.FileContract {
				fc.WindowEnd = windowStart + settings.WindowSize/2
				return fc
			},
			"proof window is too small",
		},
		{
			func(fc types.FileContract) types.FileContract {
				fc.HostOutput.Address = types.Address{31: 1}
				return fc
			},
			"wrong address for host valid output",
		},
		{
			func(fc types.FileContract) types.FileContract {
				fc.MissedHostValue = fc.HostOutput.Value.Mul64(2)
				return fc
			},
			"host valid output value does not equal missed value",
		},
		{
			func(fc types.FileContract) types.FileContract {
				fc.HostOutput.Value = fc.HostOutput.Value.Mul64(1000)
				fc.MissedHostValue = fc.HostOutput.Value
				return fc
			},
			"wrong initial host output value",
		},
		{
			func(fc types.FileContract) types.FileContract {
				fc.TotalCollateral = settings.MaxCollateral.Mul64(1000)
				fc.HostOutput.Value = settings.ContractFee.Add(fc.TotalCollateral)
				fc.MissedHostValue = fc.HostOutput.Value
				return fc
			},
			"excessive initial collateral",
		},
	}

	for _, change := range formChanges {
		changed := change.change(fc)
		if err := ValidateContractFormation(changed, currentHeight, settings); err == nil {
			t.Fatalf("expected error: %s", change.error)
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
		change func(existing, renewal types.FileContract) types.FileContract
		error  string
	}{
		{
			func(existing, renewal types.FileContract) types.FileContract {
				renewal.HostPublicKey[0] ^= 255
				return renewal
			},
			"host public key must not change",
		},
		{
			func(existing, renewal types.FileContract) types.FileContract {
				renewal.RenterPublicKey[0] ^= 255
				return renewal
			},
			"renter public key must not change",
		},
		{
			func(existing, renewal types.FileContract) types.FileContract {
				renewal.RevisionNumber++
				return renewal
			},
			"revision number must be zero",
		},
		{
			func(existing, renewal types.FileContract) types.FileContract {
				renewal.Filesize = existing.Filesize + 5
				return renewal
			},
			"filesize must not change",
		},
		{
			func(existing, renewal types.FileContract) types.FileContract {
				renewal.FileMerkleRoot[0] ^= 255
				return renewal
			},
			"file Merkle root must not change",
		},
		{
			func(existing, renewal types.FileContract) types.FileContract {
				renewal.WindowEnd = existing.WindowEnd - 5
				return renewal
			},
			"renewal window must not end before current window",
		},
		{
			func(existing, renewal types.FileContract) types.FileContract {
				renewal.WindowStart = currentHeight
				return renewal
			},
			"contract ends too soon to safely submit the contract transaction",
		},
		{
			func(existing, renewal types.FileContract) types.FileContract {
				renewal.WindowStart = currentHeight + 2*settings.MaxDuration
				return renewal
			},
			"contract duration is too long",
		},
		{
			func(existing, renewal types.FileContract) types.FileContract {
				renewal.WindowEnd = renewal.WindowStart + settings.WindowSize/2
				return renewal
			},
			"proof window is too small",
		},
		{
			func(existing, renewal types.FileContract) types.FileContract {
				renewal.HostOutput.Address[0] ^= 255
				return renewal
			},
			"proof window is too small",
		},
		{
			func(existing, renewal types.FileContract) types.FileContract {
				renewal.HostOutput.Value = renewal.HostOutput.Value.Sub(settings.ContractFee)
				return renewal
			},
			"insufficient initial host payout",
		},
		{
			func(existing, renewal types.FileContract) types.FileContract {
				renewal.TotalCollateral = settings.MaxCollateral.Mul64(1000)
				renewal.HostOutput.Value = settings.ContractFee.Add(renewal.TotalCollateral)
				return renewal
			},
			"excessive initial collateral",
		},
	}

	for _, change := range renewalChanges {
		changed := change.change(fc, renewal)
		if err := ValidateContractRenewal(fc, changed, currentHeight, settings); err == nil {
			t.Fatalf("expected error: %s", change.error)
		}
	}

	final := renewal
	final.RevisionNumber = types.MaxRevisionNumber

	if err := ValidateContractFinalization(renewal, final); err != nil {
		t.Fatal(err)
	}

	finalChanges := []struct {
		change func(current, final types.FileContract) types.FileContract
		error  string
	}{
		{
			func(current, final types.FileContract) types.FileContract {
				final.Filesize++
				return final
			},
			"file size must not change",
		},
		{
			func(current, final types.FileContract) types.FileContract {
				final.FileMerkleRoot[0] ^= 255
				return final
			},
			"file merkle root must not change",
		},
		{
			func(current, final types.FileContract) types.FileContract {
				final.WindowStart++
				return final
			},
			"window start must not change",
		},
		{
			func(current, final types.FileContract) types.FileContract {
				final.WindowEnd++
				return final
			},
			"window end must not change",
		},
		{
			func(current, final types.FileContract) types.FileContract {
				final.RenterOutput.Value = final.RenterOutput.Value.Add(types.Siacoins(1))
				return final
			},
			"renter output must not change",
		},
		{
			func(current, final types.FileContract) types.FileContract {
				final.HostOutput.Value = final.HostOutput.Value.Add(types.Siacoins(1))
				return final
			},
			"valid host output must not change",
		},
		{
			func(current, final types.FileContract) types.FileContract {
				final.MissedHostValue = final.MissedHostValue.Add(types.Siacoins(1))
				return final
			},
			"missed host payout must not change",
		},
		{
			func(current, final types.FileContract) types.FileContract {
				final.TotalCollateral = final.TotalCollateral.Add(types.Siacoins(1))
				return final
			},
			"total collateral must not change",
		},
		{
			func(current, final types.FileContract) types.FileContract {
				final.RenterPublicKey[0] ^= 255
				return final
			},
			"renter public key must not change",
		},
		{
			func(current, final types.FileContract) types.FileContract {
				final.HostPublicKey[0] ^= 255
				return final
			},
			"host public key must not change",
		},
		{
			func(current, final types.FileContract) types.FileContract {
				final.RevisionNumber = types.MaxRevisionNumber / 2
				return final
			},
			"revision number must be max value",
		},
	}

	for _, change := range finalChanges {
		changed := change.change(renewal, final)
		if err := ValidateContractFinalization(renewal, changed); err == nil {
			t.Fatalf("expected error: %s", change.error)
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
		change func(current, revision types.FileContract) types.FileContract
		error  string
	}{
		{
			func(current, revision types.FileContract) types.FileContract {
				revision.RevisionNumber = current.RevisionNumber
				return revision
			},
			"revision number must increase",
		},
		{
			func(current, revision types.FileContract) types.FileContract {
				revision.WindowStart++
				return revision
			},
			"window start must not change",
		},
		{
			func(current, revision types.FileContract) types.FileContract {
				revision.WindowEnd++
				return revision
			},
			"window end must not change",
		},
		{
			func(current, revision types.FileContract) types.FileContract {
				revision.RenterPublicKey[0] ^= 255
				return revision
			},
			"renter public key must not change",
		},
		{
			func(current, revision types.FileContract) types.FileContract {
				revision.HostPublicKey[0] ^= 255
				return revision
			},
			"host public key must not change",
		},
		{
			func(current, revision types.FileContract) types.FileContract {
				revision.RenterOutput.Address[0] ^= 255
				return revision
			},
			"renter address must not change",
		},
		{
			func(current, revision types.FileContract) types.FileContract {
				revision.RenterOutput.Value = revision.RenterOutput.Value.Add(types.Siacoins(1))
				return revision
			},
			"renter output must not change",
		},
		{
			func(current, revision types.FileContract) types.FileContract {
				revision.HostOutput.Value = revision.HostOutput.Value.Add(types.Siacoins(1))
				return revision
			},
			"host output must not change",
		},
		{
			func(current, revision types.FileContract) types.FileContract {
				revision.HostOutput.Address[0] ^= 255
				return revision
			},
			"host address must not change",
		},
		{
			func(current, revision types.FileContract) types.FileContract {
				revision.TotalCollateral = current.TotalCollateral.Add(types.Siacoins(1))
				return revision
			},
			"host address must not change",
		},
	}

	for _, change := range revisionChanges {
		changed := change.change(fc, revision)
		if err := ValidateProgramRevision(fc, changed, types.ZeroCurrency, types.ZeroCurrency); err == nil {
			t.Fatalf("expected error: %s", change.error)
		}
	}

	if err := ValidatePaymentRevision(fc, revision, types.ZeroCurrency); err != nil {
		t.Fatal(err)
	}

	paymentRevisionChanges := []struct {
		change func(current, revision types.FileContract) types.FileContract
		error  string
	}{
		{
			func(current, revision types.FileContract) types.FileContract {
				revision.FileMerkleRoot[0] ^= 255
				return revision
			},
			"file merkle root must not change",
		},
		{
			func(current, revision types.FileContract) types.FileContract {
				revision.Filesize++
				return revision
			},
			"file size must not change",
		},
		{
			func(current, revision types.FileContract) types.FileContract {
				revision.RenterOutput.Value = revision.RenterOutput.Value.Add(types.Siacoins(1))
				return revision
			},
			"renter output value should decrease by the amount",
		},
		{
			func(current, revision types.FileContract) types.FileContract {
				revision.HostOutput.Value = revision.HostOutput.Value.Sub(types.Siacoins(1))
				return revision
			},
			"host output value should increase by the amount",
		},
		{
			func(current, revision types.FileContract) types.FileContract {
				revision.MissedHostValue = revision.MissedHostValue.Sub(types.Siacoins(1))
				return revision
			},
			"host missed output value should increase by the amount",
		}}

	for _, change := range paymentRevisionChanges {
		changed := change.change(fc, revision)
		if err := ValidatePaymentRevision(fc, changed, types.ZeroCurrency); err == nil {
			t.Fatalf("expected error: %s", change.error)
		}
	}
}
