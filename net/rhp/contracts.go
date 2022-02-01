package rhp

import (
	"errors"
	"fmt"
	"math"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

var (
	// ErrInvalidSignature is returned when a contract's signature is invalid.
	ErrInvalidSignature = errors.New("signature invalid")
)

// A Contract pairs the latest revision with signatures from both parties.
type Contract struct {
	ID              types.ElementID
	Revision        types.FileContract
	HostSignature   types.Signature
	RenterSignature types.Signature
}

// ValidateSignatures checks that the renter and host signatures are valid.
func (c *Contract) ValidateSignatures(vc consensus.ValidationContext) (err error) {
	hash := vc.ContractSigHash(c.Revision)
	if !c.Revision.HostPublicKey.VerifyHash(hash, c.HostSignature) {
		err = fmt.Errorf("failed to validate host signature: %w", ErrInvalidSignature)
	} else if !c.Revision.RenterPublicKey.VerifyHash(hash, c.RenterSignature) {
		err = fmt.Errorf("failed to validate renter signature: %w", ErrInvalidSignature)
	}
	return
}

// EncodeTo implements types.EncoderTo.
func (c *Contract) EncodeTo(enc *types.Encoder) {
	c.ID.EncodeTo(enc)
	c.Revision.EncodeTo(enc)
	c.HostSignature.EncodeTo(enc)
	c.RenterSignature.EncodeTo(enc)
}

// DecodeFrom implements types.DecoderFrom.
func (c *Contract) DecodeFrom(dec *types.Decoder) {
	c.ID.DecodeFrom(dec)
	c.Revision.DecodeFrom(dec)
	c.HostSignature.DecodeFrom(dec)
	c.RenterSignature.DecodeFrom(dec)
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

// ClearingRevision returns a new file contract with the revision
// number set to uint64 max, the file fields set to their zero value, and the
// missed proof outputs set to the valid proof outputs.
func ClearingRevision(fc types.FileContract) types.FileContract {
	fc.RevisionNumber = math.MaxUint64
	fc.Filesize = 0
	fc.FileMerkleRoot = types.Hash256{}
	fc.MissedHostOutput = fc.ValidHostOutput
	fc.MissedRenterOutput = fc.ValidRenterOutput
	return fc
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

func validateStdRevision(vc consensus.ValidationContext, current, revision Contract) error {
	switch {
	case revision.Revision.RevisionNumber <= current.Revision.RevisionNumber:
		return errors.New("revision number must increase")
	case revision.Revision.WindowStart != current.Revision.WindowStart:
		return errors.New("window start must not change")
	case revision.Revision.WindowEnd != current.Revision.WindowEnd:
		return errors.New("window end must not change")
	case revision.Revision.RenterPublicKey != current.Revision.RenterPublicKey:
		return errors.New("renter public key must not change")
	case revision.Revision.HostPublicKey != current.Revision.HostPublicKey:
		return errors.New("host public key must not change")
	case revision.Revision.ValidRenterOutput.Address != current.Revision.ValidRenterOutput.Address:
		return errors.New("address of valid renter output must not change")
	case revision.Revision.ValidHostOutput.Address != current.Revision.ValidHostOutput.Address:
		return errors.New("address of valid host output must not change")
	case revision.Revision.MissedRenterOutput.Address != current.Revision.MissedRenterOutput.Address:
		return errors.New("address of missed renter output must not change")
	case revision.Revision.MissedHostOutput.Address != current.Revision.MissedHostOutput.Address:
		return errors.New("address of missed host output must not change")
	}
	return revision.ValidateSignatures(vc)
}

// ValidateProgramRevision verifies that a contract program revision is valid and
// only the missed host output value is modified by the expected burn amount all
// other usage will have been paid for by the RPC budget.
func ValidateProgramRevision(vc consensus.ValidationContext, current, revision Contract, additionalStorage, additionalCollateral types.Currency) error {
	// verify the new revision is valid given the existing revision, the public
	// keys have not changed, and the signatures are correct.
	if err := validateStdRevision(vc, current, revision); err != nil {
		return err
	}

	expectedBurn := additionalStorage.Add(additionalCollateral)
	if expectedBurn.Cmp(current.Revision.MissedHostOutput.Value) > 0 {
		return errors.New("expected burn amount is greater than the missed host output value")
	}
	missedHostValue := current.Revision.MissedHostOutput.Value.Sub(expectedBurn)

	switch {
	case revision.Revision.MissedHostOutput.Value != missedHostValue:
		return errors.New("revision has incorrect collateral transfer")
	case revision.Revision.ValidHostOutput.Value != current.Revision.ValidHostOutput.Value:
		return errors.New("host valid output value should not change")
	case revision.Revision.ValidRenterOutput.Value != current.Revision.ValidRenterOutput.Value:
		return errors.New("renter valid output value should not change")
	case revision.Revision.MissedRenterOutput.Value != current.Revision.MissedRenterOutput.Value:
		return errors.New("renter missed output value should not change")
	}
	return nil
}

// ValidatePaymentRevision verifies that a payment revision is valid and the amount
// is properly deducted from both renter outputs and added to both host outputs.
func ValidatePaymentRevision(vc consensus.ValidationContext, current, revision Contract, amount types.Currency) error {
	// verify the new revision is valid given the existing revision, the public
	// keys have not changed, and the signatures are correct.
	if err := validateStdRevision(vc, current, revision); err != nil {
		return err
	}

	// validate that all fields are consistent with only transferring the amount
	// from the renter payouts to the host payouts.
	switch {
	case revision.Revision.FileMerkleRoot != current.Revision.FileMerkleRoot:
		return errors.New("file merkle root must not change")
	case revision.Revision.Filesize != current.Revision.Filesize:
		return errors.New("file size must not change")
	case revision.Revision.MissedHostOutput.Value.Cmp(amount) < 0:
		return errors.New("host missed output value should increase by the amount")
	case revision.Revision.ValidHostOutput.Value.Cmp(amount) < 0:
		return errors.New("host valid output value should increase by the amount")
	case revision.Revision.MissedHostOutput.Value.Sub(amount) != current.Revision.MissedHostOutput.Value:
		return errors.New("host missed output value should increase by the amount")
	case revision.Revision.ValidHostOutput.Value.Sub(amount) != current.Revision.ValidHostOutput.Value:
		return errors.New("host valid output value should increase by the amount")
	case revision.Revision.MissedRenterOutput.Value.Add(amount) != current.Revision.MissedRenterOutput.Value:
		return errors.New("renter missed output value should decrease by the amount")
	case revision.Revision.ValidRenterOutput.Value.Add(amount) != current.Revision.ValidRenterOutput.Value:
		return errors.New("renter valid output value should decrease by the amount")
	}
	return nil
}

// ValidateClearingRevision verifies that the revision clears the current contract
// by clearing the file fields, making the missed and valid payouts equivalent,
// and locking the contract for further revisions.
func ValidateClearingRevision(vc consensus.ValidationContext, current, clearing Contract) error {
	// verify the new revision is valid given the existing revision, the public
	// keys have not changed, and the signatures are correct.
	if err := validateStdRevision(vc, current, clearing); err != nil {
		return err
	}

	switch {
	case clearing.Revision.RevisionNumber != math.MaxUint64:
		return errors.New("revision number must be max value")
	case clearing.Revision.Filesize != 0:
		return errors.New("file size must be zero")
	case clearing.Revision.FileMerkleRoot != types.Hash256{}:
		return errors.New("file merkle root must be cleared")
	case clearing.Revision.ValidHostOutput.Value.Cmp(current.Revision.ValidHostOutput.Value) != 0:
		return errors.New("host valid output value must not change")
	case clearing.Revision.ValidRenterOutput.Value.Cmp(current.Revision.ValidRenterOutput.Value) != 0:
		return errors.New("renter valid output value must not change")
	case clearing.Revision.MissedHostOutput.Value.Cmp(current.Revision.ValidHostOutput.Value) != 0:
		return errors.New("host missed output value must equal host valid output value")
	case clearing.Revision.MissedRenterOutput.Value.Cmp(current.Revision.ValidRenterOutput.Value) != 0:
		return errors.New("renter missed output value must equal renter valid output value")
	}
	return nil
}
