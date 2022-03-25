package rhp

import (
	"errors"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

var (
	// ErrInvalidRenterSignature is returned when a contract's renter signature is invalid.
	ErrInvalidRenterSignature = errors.New("invalid renter signature")

	// ErrInvalidHostSignature is returned when a contract's host signature is invalid.
	ErrInvalidHostSignature = errors.New("invalid host signature")
)

// A Contract pairs a file contract with its ID.
type Contract struct {
	ID       types.ElementID
	Revision types.FileContract
}

// EncodeTo implements types.EncoderTo.
func (c *Contract) EncodeTo(enc *types.Encoder) {
	c.ID.EncodeTo(enc)
	c.Revision.EncodeTo(enc)
}

// DecodeFrom implements types.DecoderFrom.
func (c *Contract) DecodeFrom(dec *types.Decoder) {
	c.ID.DecodeFrom(dec)
	c.Revision.DecodeFrom(dec)
}

// MaxLen implements rpc.Object.
func (c *Contract) MaxLen() uint64 {
	return 10e3
}

// PaymentRevision returns a new file contract revision with the specified
// amount moved from the renter's payout to the host's payout (both valid and
// missed). The revision number is incremented.
func PaymentRevision(fc types.FileContract, amount types.Currency) (types.FileContract, error) {
	if fc.RenterOutput.Value.Cmp(amount) < 0 {
		return fc, errors.New("insufficient funds")
	}
	fc.RevisionNumber++
	fc.RenterOutput.Value = fc.RenterOutput.Value.Sub(amount)
	fc.HostOutput.Value = fc.HostOutput.Value.Add(amount)
	fc.MissedHostValue = fc.MissedHostValue.Add(amount)
	return fc, nil
}

// FinalizeProgramRevision returns a new file contract revision with the burn
// amount subtracted from the host output. The revision number is incremented.
func FinalizeProgramRevision(fc types.FileContract, burn types.Currency) (types.FileContract, error) {
	if fc.MissedHostValue.Cmp(burn) < 0 {
		return fc, errors.New("not enough funds")
	}
	fc.RevisionNumber++
	fc.MissedHostValue = fc.MissedHostValue.Sub(burn)
	return fc, nil
}

// ValidateContractSignatures validates a contract's renter and host signatures.
func ValidateContractSignatures(vc consensus.ValidationContext, fc types.FileContract) (err error) {
	hash := vc.ContractSigHash(fc)
	if !fc.RenterPublicKey.VerifyHash(hash, fc.RenterSignature) {
		return ErrInvalidRenterSignature
	} else if !fc.HostPublicKey.VerifyHash(hash, fc.HostSignature) {
		return ErrInvalidHostSignature
	}
	return nil
}

// ValidateContractFormation verifies that the new contract is valid given the
// host's settings.
func ValidateContractFormation(fc types.FileContract, currentHeight uint64, settings HostSettings) error {
	switch {
	case fc.Filesize != 0:
		return errors.New("initial filesize should be 0")
	case fc.RevisionNumber != 0:
		return errors.New("initial revision number should be 0")
	case fc.FileMerkleRoot != types.Hash256{}:
		return errors.New("initial Merkle root should be empty")
	case fc.WindowStart < currentHeight+settings.WindowSize:
		return errors.New("contract ends too soon to safely submit the contract transaction")
	case fc.WindowStart > currentHeight+settings.MaxDuration:
		return errors.New("contract duration is too long")
	case fc.WindowEnd < fc.WindowStart+settings.WindowSize:
		return errors.New("proof window is too small")
	case fc.HostOutput.Address != settings.Address:
		return errors.New("wrong address for host valid output")
	case fc.HostOutput.Value != fc.MissedHostValue:
		return errors.New("host valid output value does not equal missed value")
	case fc.HostOutput.Value != settings.ContractFee.Add(fc.TotalCollateral):
		return errors.New("wrong initial host output value")
	case fc.TotalCollateral.Cmp(settings.MaxCollateral) > 0:
		return errors.New("excessive initial collateral")
	}
	return nil
}

// ValidateContractRenewal verifies that the renewed contract is valid given the
// old contract. A renewal is valid if the contract fields match and the
// revision number is 0.
func ValidateContractRenewal(existing, renewal types.FileContract, currentHeight uint64, settings HostSettings) error {
	switch {
	case renewal.HostPublicKey != existing.HostPublicKey:
		return errors.New("host public key must not change")
	case renewal.RenterPublicKey != existing.RenterPublicKey:
		return errors.New("renter public key must not change")
	case renewal.RevisionNumber != 0:
		return errors.New("revision number must be zero")
	case renewal.Filesize != existing.Filesize:
		return errors.New("filesize must not change")
	case renewal.FileMerkleRoot != existing.FileMerkleRoot:
		return errors.New("file Merkle root must not change")
	case renewal.WindowEnd < existing.WindowEnd:
		return errors.New("renewal window must not end before current window")
	case renewal.WindowStart < currentHeight+settings.WindowSize:
		return errors.New("contract ends too soon to safely submit the contract transaction")
	case renewal.WindowStart > currentHeight+settings.MaxDuration:
		return errors.New("contract duration is too long")
	case renewal.WindowEnd < renewal.WindowStart+settings.WindowSize:
		return errors.New("proof window is too small")
	case renewal.HostOutput.Address != settings.Address:
		return errors.New("wrong address for host output")
	case renewal.HostOutput.Value.Cmp(settings.ContractFee.Add(renewal.TotalCollateral)) < 0:
		return errors.New("insufficient initial host payout")
	case renewal.TotalCollateral.Cmp(settings.MaxCollateral) > 0:
		return errors.New("excessive initial collateral")
	}
	return nil
}

// ValidateContractFinalization verifies that the revision locks the current
// contract by setting its revision number to the maximum legal value. No other
// fields should change. Signatures are not validated.
func ValidateContractFinalization(current, final types.FileContract) error {
	switch {
	case current.Filesize != final.Filesize:
		return errors.New("file size must not change")
	case current.FileMerkleRoot != final.FileMerkleRoot:
		return errors.New("file merkle root must not change")
	case current.WindowStart != final.WindowStart:
		return errors.New("window start must not change")
	case current.WindowEnd != final.WindowEnd:
		return errors.New("window end must not change")
	case current.RenterOutput != final.RenterOutput:
		return errors.New("renter output must not change")
	case current.HostOutput != final.HostOutput:
		return errors.New("valid host output must not change")
	case current.MissedHostValue != final.MissedHostValue:
		return errors.New("missed host payout must not change")
	case current.TotalCollateral != final.TotalCollateral:
		return errors.New("total collateral must not change")
	case current.RenterPublicKey != final.RenterPublicKey:
		return errors.New("renter public key must not change")
	case current.HostPublicKey != final.HostPublicKey:
		return errors.New("host public key must not change")
	case final.RevisionNumber != types.MaxRevisionNumber:
		return errors.New("revision number must be max value")
	}
	return nil
}

// ValidateStdRevision verifies that a new contract revision is valid given the
// existing revision.
func ValidateStdRevision(current, revision types.FileContract) error {
	switch {
	case revision.RevisionNumber <= current.RevisionNumber:
		return errors.New("revision number must increase")
	case revision.WindowStart != current.WindowStart:
		return errors.New("window start must not change")
	case revision.WindowEnd != current.WindowEnd:
		return errors.New("window end must not change")
	case revision.RenterPublicKey != current.RenterPublicKey:
		return errors.New("renter public key must not change")
	case revision.HostPublicKey != current.HostPublicKey:
		return errors.New("host public key must not change")
	case revision.RenterOutput.Address != current.RenterOutput.Address:
		return errors.New("renter address must not change")
	case revision.HostOutput.Address != current.HostOutput.Address:
		return errors.New("host address must not change")
	case revision.TotalCollateral != current.TotalCollateral:
		return errors.New("total collateral must not change")
	}
	return nil
}

// ValidateProgramRevision verifies that a contract program revision is valid
// and only the missed host output value is modified by the expected burn amount
// all other usage will have been paid for by the RPC budget. Signatures are not
// validated.
func ValidateProgramRevision(current, revision types.FileContract, additionalStorage, additionalCollateral types.Currency) error {
	// verify the new revision is valid given the existing revision and the
	// public keys have not changed
	if err := ValidateStdRevision(current, revision); err != nil {
		return err
	}

	expectedBurn := additionalStorage.Add(additionalCollateral)
	if expectedBurn.Cmp(current.MissedHostValue) > 0 {
		return errors.New("expected burn amount is greater than the missed host output value")
	}
	missedHostValue := current.MissedHostValue.Sub(expectedBurn)

	switch {
	case revision.MissedHostValue != missedHostValue:
		return errors.New("revision has incorrect collateral transfer")
	case revision.RenterOutput != current.RenterOutput:
		return errors.New("renter output should not change")
	case revision.HostOutput != current.HostOutput:
		return errors.New("host valid output should not change")
	}
	return nil
}

// ValidatePaymentRevision verifies that a payment revision is valid and the
// amount is properly deducted from both renter outputs and added to both host
// outputs. Signatures are not validated.
func ValidatePaymentRevision(current, revision types.FileContract, amount types.Currency) error {
	// verify the new revision is valid given the existing revision and the
	// public keys have not changed.
	if err := ValidateStdRevision(current, revision); err != nil {
		return err
	}

	// validate that all fields are consistent with only transferring the amount
	// from the renter payouts to the host payouts.
	switch {
	case revision.FileMerkleRoot != current.FileMerkleRoot:
		return errors.New("file merkle root must not change")
	case revision.Filesize != current.Filesize:
		return errors.New("file size must not change")
	case revision.RenterOutput.Value.Add(amount) != current.RenterOutput.Value:
		return errors.New("renter output value should decrease by the amount")
	case revision.HostOutput.Value != current.HostOutput.Value.Add(amount):
		return errors.New("host output value should increase by the amount")
	case revision.MissedHostValue != current.MissedHostValue.Add(amount):
		return errors.New("host missed output value should increase by the amount")
	}
	return nil
}
