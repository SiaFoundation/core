package rhp

import (
	"errors"
	"fmt"

	"go.sia.tech/core/types"
)

// Validate validates a read sector request.
func (req *RPCReadSectorRequest) Validate() error {
	switch {
	case req.Length == 0:
		return errors.New("length must be greater than 0")
	case req.Offset+req.Length > SectorSize:
		return errors.New("read request exceeds sector bounds")
	case (req.Offset+req.Length)%LeafSize != 0:
		return errors.New("read request must be segment aligned")
	}
	return nil
}

// Validate validates a write sector request.
func (req *RPCWriteSectorRequest) Validate() error {
	switch {
	case req.Duration == 0:
		return errors.New("duration must be greater than 0")
	case len(req.Sector) == 0:
		return errors.New("sector must not be empty")
	case len(req.Sector)%LeafSize != 0:
		return errors.New("sector must be segment aligned")
	}
	return nil
}

// Validate validates a write sector request.
func (req *RPCWriteSectorStreamingRequest) Validate() error {
	switch {
	case req.Duration == 0:
		return errors.New("duration must be greater than 0")
	case req.DataLength == 0:
		return errors.New("sector must not be empty")
	case req.DataLength%LeafSize != 0:
		return errors.New("sector must be segment aligned")
	}
	return nil
}

// Validate validates a sector roots request. Signatures are not validated.
func (req *RPCSectorRootsRequest) Validate(fc types.V2FileContract) error {
	contractSectors := fc.Filesize / SectorSize

	switch {
	case req.Length == 0:
		return errors.New("length must be greater than 0")
	case req.Length+req.Offset > contractSectors:
		return fmt.Errorf("read request range exceeds contract sectors: %d > %d", req.Length+req.Offset, contractSectors)
	}
	return nil
}

// Validate validates a form contract request. Prices are not validated
func (req *RPCFormContractRequest) Validate(hs HostSettings, tip types.ChainIndex) error {
	// validate the request fields
	switch {
	case req.MinerFee.IsZero():
		return errors.New("miner fee must be greater than 0")
	case req.Basis == (types.ChainIndex{}):
		return errors.New("basis must be set")
	case len(req.RenterInputs) == 0:
		return errors.New("renter inputs must not be empty")
	}

	// validate the contract fields
	hp := hs.Prices
	expirationHeight := req.Contract.ProofHeight + proofWindow
	duration := expirationHeight - hp.TipHeight
	// calculate the minimum allowance required for the contract based on the
	// host's locked collateral and the contract duration
	minRenterAllowance := MinRenterAllowance(hp, duration, req.Contract.Collateral)

	switch {
	case expirationHeight <= tip.Height: // must be validated against tip instead of prices
		return errors.New("contract expiration height is in the past")
	case req.Contract.Allowance.IsZero():
		return errors.New("allowance is zero")
	case req.Contract.Collateral.Cmp(hs.MaxCollateral) > 0:
		return fmt.Errorf("collateral %v exceeds max collateral %v", req.Contract.Collateral, hs.MaxCollateral)
	case duration > hs.MaxContractDuration:
		return fmt.Errorf("contract duration %v exceeds max duration %v", duration, hs.MaxContractDuration)
	case req.Contract.Allowance.Cmp(minRenterAllowance) < 0:
		return fmt.Errorf("allowance %v is less than minimum %v for collateral", req.Contract.Allowance, minRenterAllowance)
	default:
		return nil
	}
}

// Validate validates a renew contract request. Prices are not validated
func (req *RPCRenewContractRequest) Validate(hs HostSettings, tip types.ChainIndex) error {
	// validate the request fields
	switch {
	case req.MinerFee.IsZero():
		return errors.New("miner fee must be greater than 0")
	case req.Basis == (types.ChainIndex{}):
		return errors.New("basis must be set")
	case len(req.RenterInputs) == 0:
		return errors.New("renter inputs must not be empty")
	}

	// validate the contract fields
	hp := hs.Prices
	expirationHeight := req.Renewal.ProofHeight + proofWindow
	duration := expirationHeight - hp.TipHeight
	// calculate the minimum allowance required for the contract based on the
	// host's locked collateral and the contract duration
	minRenterAllowance := MinRenterAllowance(hp, duration, req.Renewal.Collateral)

	switch {
	case expirationHeight <= tip.Height: // must be validated against tip instead of prices
		return errors.New("contract expiration height is in the past")
	case req.Renewal.Allowance.IsZero():
		return errors.New("allowance is zero")
	case req.Renewal.Collateral.Cmp(hs.MaxCollateral) > 0:
		return fmt.Errorf("collateral %v exceeds max collateral %v", req.Renewal.Collateral, hs.MaxCollateral)
	case duration > hs.MaxContractDuration:
		return fmt.Errorf("contract duration %v exceeds max duration %v", duration, hs.MaxContractDuration)
	case req.Renewal.Allowance.Cmp(minRenterAllowance) < 0:
		return fmt.Errorf("allowance %v is less than minimum %v for collateral", req.Renewal.Allowance, minRenterAllowance)
	default:
		return nil
	}
}

// Validate checks that the request is valid
func (req *RPCVerifySectorRequest) Validate() error {
	if req.LeafIndex >= LeavesPerSector {
		return fmt.Errorf("leaf index must be less than %d", LeavesPerSector)
	}
	return nil
}
