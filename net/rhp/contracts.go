package rhp

import (
	"errors"
	"fmt"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

var (
	// ErrInvalidSignature is returned when a contract's signature is invalid.
	ErrInvalidSignature = errors.New("signature invalid")
)

// A Contract pairs the latest revision with signatures from both parties.
type Contract struct {
	ID       types.ElementID
	Revision types.FileContract
}

// ValidateSignatures checks that the renter and host signatures are valid.
func (c *Contract) ValidateSignatures(vc consensus.ValidationContext) (err error) {
	hash := vc.ContractSigHash(c.Revision)
	if !c.Revision.HostPublicKey.VerifyHash(hash, c.Revision.HostSignature) {
		err = fmt.Errorf("failed to validate host signature: %w", ErrInvalidSignature)
	} else if !c.Revision.RenterPublicKey.VerifyHash(hash, c.Revision.RenterSignature) {
		err = fmt.Errorf("failed to validate renter signature: %w", ErrInvalidSignature)
	}
	return
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

// PaymentRevision returns a new file contract revision with the amount added to
// the host payout fields and subtracted from the renter payout fields.
func PaymentRevision(fc types.FileContract, amount types.Currency) (types.FileContract, error) {
	if fc.ValidRenterOutput.Value.Cmp(amount) < 0 || fc.MissedRenterOutput.Value.Cmp(amount) < 0 {
		return fc, errors.New("insufficient funds")
	}

	fc.RevisionNumber++
	fc.ValidHostOutput.Value = fc.ValidHostOutput.Value.Add(amount)
	fc.MissedHostOutput.Value = fc.MissedHostOutput.Value.Add(amount)
	fc.ValidRenterOutput.Value = fc.ValidRenterOutput.Value.Sub(amount)
	fc.MissedRenterOutput.Value = fc.MissedRenterOutput.Value.Sub(amount)
	return fc, nil
}

// FinalizeProgramRevision returns a new file contract revision with the burn
// amount subtracted from the missed host output.
func FinalizeProgramRevision(fc types.FileContract, burn types.Currency) (types.FileContract, error) {
	if fc.MissedHostOutput.Value.Cmp(burn) < 0 {
		return fc, errors.New("not enough funds")
	}
	fc.RevisionNumber++
	fc.MissedHostOutput.Value = fc.MissedHostOutput.Value.Sub(burn)
	return fc, nil
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
	case fc.ValidHostOutput.Address != settings.Address:
		return errors.New("wrong address for host valid output")
	case fc.MissedHostOutput.Address != settings.Address:
		return errors.New("wrong address for host missed output")
	case fc.ValidHostOutput.Value.Cmp(fc.MissedHostOutput.Value) != 0:
		return errors.New("host valid output value does not match host missed output value")
	case fc.ValidRenterOutput.Value.Cmp(fc.MissedRenterOutput.Value) != 0:
		return errors.New("renter valid output value does not match renter missed output value")
	case fc.ValidHostOutput.Value.Cmp(settings.ContractFee) < 0:
		return errors.New("insufficient initial host payout")
	case fc.ValidHostOutput.Value.Sub(settings.ContractFee).Cmp(settings.MaxCollateral) > 0:
		return errors.New("excessive initial collateral")
	}
	return nil
}

// ValidateContractRenewal verifies that the renewed contract is valid given the
// old contract. A renewal is valid if the file fields match and the revision
// number is 0.
func ValidateContractRenewal(existing, renewal types.FileContract, currentHeight uint64, settings HostSettings) error {
	switch {
	case renewal.HostPublicKey != existing.HostPublicKey:
		return errors.New("host public key must not change")
	case renewal.RenterPublicKey != existing.RenterPublicKey:
		return errors.New("renter public key must not change")
	case renewal.RevisionNumber != 0:
		return errors.New("revision number must be zero")
	case renewal.Filesize != existing.Filesize:
		return errors.New("file size must not change")
	case renewal.FileMerkleRoot != existing.FileMerkleRoot:
		return errors.New("file merkle root must not change")
	case renewal.WindowEnd < existing.WindowEnd:
		return errors.New("renewal window end must be after existing window end")
	case renewal.WindowStart < currentHeight+settings.WindowSize:
		return errors.New("contract ends too soon to safely submit the contract transaction")
	case renewal.WindowStart > currentHeight+settings.MaxDuration:
		return errors.New("contract duration is too long")
	case renewal.WindowEnd < renewal.WindowStart+settings.WindowSize:
		return errors.New("proof window is too small")
	case renewal.ValidHostOutput.Address != settings.Address:
		return errors.New("wrong address for host valid output")
	case renewal.MissedHostOutput.Address != settings.Address:
		return errors.New("wrong address for host missed output")
	case renewal.ValidHostOutput.Value.Cmp(settings.ContractFee) < 0:
		return errors.New("insufficient initial host payout")
	}
	return nil
}

// ValidateContractFinalization verifies that the revision locks the current
// contract by setting its revision number to the maximum legal value, no other
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
	case current.ValidRenterOutput != final.ValidRenterOutput:
		return errors.New("valid renter output must not change")
	case current.ValidHostOutput != final.ValidHostOutput:
		return errors.New("valid host output must not change")
	case current.MissedRenterOutput != final.MissedRenterOutput:
		return errors.New("missed renter output must not change")
	case current.MissedHostOutput != final.MissedHostOutput:
		return errors.New("missed host output must not change")
	case current.RenterPublicKey != final.RenterPublicKey:
		return errors.New("renter public key must not change")
	case current.HostPublicKey != final.HostPublicKey:
		return errors.New("host public key must not change")
	case final.RevisionNumber != types.MaxRevisionNumber:
		return errors.New("revision number must be max value")
	}
	return nil
}

func validateStdRevision(current, revision types.FileContract) error {
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
	case revision.ValidRenterOutput.Address != current.ValidRenterOutput.Address:
		return errors.New("address of valid renter output must not change")
	case revision.ValidHostOutput.Address != current.ValidHostOutput.Address:
		return errors.New("address of valid host output must not change")
	case revision.MissedRenterOutput.Address != current.MissedRenterOutput.Address:
		return errors.New("address of missed renter output must not change")
	case revision.MissedHostOutput.Address != current.MissedHostOutput.Address:
		return errors.New("address of missed host output must not change")
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
	if err := validateStdRevision(current, revision); err != nil {
		return err
	}

	expectedBurn := additionalStorage.Add(additionalCollateral)
	if expectedBurn.Cmp(current.MissedHostOutput.Value) > 0 {
		return errors.New("expected burn amount is greater than the missed host output value")
	}
	missedHostValue := current.MissedHostOutput.Value.Sub(expectedBurn)

	switch {
	case revision.MissedHostOutput.Value != missedHostValue:
		return errors.New("revision has incorrect collateral transfer")
	case revision.ValidHostOutput.Value != current.ValidHostOutput.Value:
		return errors.New("host valid output value should not change")
	case revision.ValidRenterOutput.Value != current.ValidRenterOutput.Value:
		return errors.New("renter valid output value should not change")
	case revision.MissedRenterOutput.Value != current.MissedRenterOutput.Value:
		return errors.New("renter missed output value should not change")
	}
	return nil
}

// ValidatePaymentRevision verifies that a payment revision is valid and the
// amount is properly deducted from both renter outputs and added to both host
// outputs. Signatures are not validated.
func ValidatePaymentRevision(current, revision types.FileContract, amount types.Currency) error {
	// verify the new revision is valid given the existing revision and the
	// public keys have not changed.
	if err := validateStdRevision(current, revision); err != nil {
		return err
	}

	// validate that all fields are consistent with only transferring the amount
	// from the renter payouts to the host payouts.
	switch {
	case revision.FileMerkleRoot != current.FileMerkleRoot:
		return errors.New("file merkle root must not change")
	case revision.Filesize != current.Filesize:
		return errors.New("file size must not change")
	case revision.MissedHostOutput.Value.Cmp(amount) < 0:
		return errors.New("host missed output value should increase by the amount")
	case revision.ValidHostOutput.Value.Cmp(amount) < 0:
		return errors.New("host valid output value should increase by the amount")
	case revision.MissedHostOutput.Value.Sub(amount) != current.MissedHostOutput.Value:
		return errors.New("host missed output value should increase by the amount")
	case revision.ValidHostOutput.Value.Sub(amount) != current.ValidHostOutput.Value:
		return errors.New("host valid output value should increase by the amount")
	case revision.MissedRenterOutput.Value.Add(amount) != current.MissedRenterOutput.Value:
		return errors.New("renter missed output value should decrease by the amount")
	case revision.ValidRenterOutput.Value.Add(amount) != current.ValidRenterOutput.Value:
		return errors.New("renter valid output value should decrease by the amount")
	}
	return nil
}
