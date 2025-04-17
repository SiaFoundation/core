package rhp

import (
	"errors"
	"fmt"
	"time"

	"go.sia.tech/core/types"
)

// Validate checks the host prices for validity. It returns an error if the
// prices have expired or the signature is invalid.
func (hp *HostPrices) Validate(pk types.PublicKey) error {
	if time.Until(hp.ValidUntil) <= 0 {
		return ErrPricesExpired
	}
	if !pk.VerifyHash(hp.SigHash(), hp.Signature) {
		return ErrInvalidSignature
	}
	return nil
}

// Validate verifies the account token is valid for use. It returns an error if
// the token has expired or the signature is invalid.
func (at AccountToken) Validate(hostKey types.PublicKey) error {
	switch {
	case at.HostKey != hostKey:
		return NewRPCError(ErrorCodeBadRequest, "host key mismatch")
	case time.Now().After(at.ValidUntil):
		return NewRPCError(ErrorCodeBadRequest, "account token expired")
	case !types.PublicKey(at.Account).VerifyHash(at.SigHash(), at.Signature):
		return ErrInvalidSignature
	}
	return nil
}

// Validate validates a read sector request.
func (req *RPCReadSectorRequest) Validate(hostKey types.PublicKey) error {
	if err := req.Prices.Validate(hostKey); err != nil {
		return fmt.Errorf("prices are invalid: %w", err)
	} else if err := req.Token.Validate(hostKey); err != nil {
		return fmt.Errorf("token is invalid: %w", err)
	}
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
func (req *RPCWriteSectorRequest) Validate(hostKey types.PublicKey) error {
	if err := req.Prices.Validate(hostKey); err != nil {
		return fmt.Errorf("prices are invalid: %w", err)
	} else if err := req.Token.Validate(hostKey); err != nil {
		return fmt.Errorf("token is invalid: %w", err)
	}
	switch {
	case req.DataLength == 0:
		return errors.New("sector must not be empty")
	case req.DataLength%LeafSize != 0:
		return errors.New("sector must be segment aligned")
	case req.DataLength > SectorSize:
		return errors.New("sector exceeds sector bounds")
	}
	return nil
}

// Validate validates a modify sectors request. Signatures are not validated.
func (req *RPCFreeSectorsRequest) Validate(pk types.PublicKey, fc types.V2FileContract) error {
	if err := req.Prices.Validate(pk); err != nil {
		return fmt.Errorf("prices are invalid: %w", err)
	} else if uint64(len(req.Indices)) > MaxSectorBatchSize {
		return fmt.Errorf("removing too many sectors at once: %d > %d", len(req.Indices), MaxSectorBatchSize)
	}
	seen := make(map[uint64]bool)
	sectors := fc.Filesize / SectorSize
	for _, index := range req.Indices {
		if index >= sectors {
			return fmt.Errorf("sector index %d exceeds contract sectors %d", index, sectors)
		} else if seen[index] {
			return fmt.Errorf("duplicate sector index %d", index)
		}
		seen[index] = true
	}
	return nil
}

// Validate validates a sector roots request. Signatures are not validated.
func (req *RPCSectorRootsRequest) Validate(pk types.PublicKey, fc types.V2FileContract) error {
	if err := req.Prices.Validate(pk); err != nil {
		return fmt.Errorf("prices are invalid: %w", err)
	}

	contractSectors := fc.Filesize / SectorSize
	switch {
	case req.Length == 0:
		return errors.New("length must be greater than 0")
	case req.Length+req.Offset > contractSectors:
		return fmt.Errorf("read request range exceeds contract sectors: %d > %d", req.Length+req.Offset, contractSectors)
	case req.Length > MaxSectorBatchSize:
		return fmt.Errorf("read request range exceeds maximum sectors: %d > %d", req.Length, MaxSectorBatchSize)
	}
	return nil
}

// Validate validates a form contract request. Prices are not validated
func (req *RPCFormContractRequest) Validate(pk types.PublicKey, tip types.ChainIndex, maxCollateral types.Currency, maxDuration uint64) error {
	if err := req.Prices.Validate(pk); err != nil {
		return fmt.Errorf("prices are invalid: %w", err)
	}

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
	hp := req.Prices
	expirationHeight := req.Contract.ProofHeight + ProofWindow
	duration := expirationHeight - hp.TipHeight
	// calculate the minimum allowance required for the contract based on the
	// host's locked collateral and the contract duration
	minRenterAllowance := MinRenterAllowance(hp, duration, req.Contract.Collateral)

	switch {
	case expirationHeight <= tip.Height: // must be validated against tip instead of prices
		return errors.New("contract expiration height is in the past")
	case req.Contract.Allowance.IsZero():
		return errors.New("allowance must be greater than zero")
	case req.Contract.Collateral.Cmp(maxCollateral) > 0:
		return fmt.Errorf("collateral %v exceeds max collateral %v", req.Contract.Collateral, maxCollateral)
	case duration > maxDuration:
		return fmt.Errorf("contract duration %v exceeds max duration %v", duration, maxDuration)
	case req.Contract.Allowance.Cmp(minRenterAllowance) < 0:
		return fmt.Errorf("allowance %v is less than minimum allowance %v", req.Contract.Allowance, minRenterAllowance)
	default:
		return nil
	}
}

// Validate validates a renew contract request. Prices are not validated
func (req *RPCRenewContractRequest) Validate(pk types.PublicKey, tip types.ChainIndex, existingSize uint64, existingProofHeight uint64, maxCollateral types.Currency, maxDuration uint64) error {
	if err := req.Prices.Validate(pk); err != nil {
		return fmt.Errorf("prices are invalid: %w", err)
	}

	// validate the request fields
	switch {
	case req.MinerFee.IsZero():
		return errors.New("miner fee must be greater than 0")
	case req.Basis == (types.ChainIndex{}):
		return errors.New("basis must be set")
	case req.Renewal.ProofHeight <= existingProofHeight:
		return fmt.Errorf("renewal proof height must be greater than existing proof height %v", existingProofHeight)
	}

	// validate the contract fields
	hp := req.Prices
	expirationHeight := req.Renewal.ProofHeight + ProofWindow
	duration := expirationHeight - hp.TipHeight
	// calculate the minimum allowance required for the contract based on the
	// host's locked collateral and the contract duration
	minRenterAllowance := MinRenterAllowance(hp, duration, req.Renewal.Collateral)
	// collateral is risked for the entire contract duration
	riskedCollateral := req.Prices.Collateral.Mul64(existingSize).Mul64(expirationHeight - req.Prices.TipHeight)
	// renewals add collateral on top of the required risked collateral
	totalCollateral := req.Renewal.Collateral.Add(riskedCollateral)

	switch {
	case expirationHeight <= tip.Height: // must be validated against tip instead of prices
		return errors.New("contract expiration height is in the past")
	case req.Renewal.Allowance.IsZero():
		return errors.New("allowance must be greater than zero")
	case totalCollateral.Cmp(maxCollateral) > 0:
		return fmt.Errorf("required collateral %v exceeds max collateral %v", totalCollateral, maxCollateral)
	case duration > maxDuration:
		return fmt.Errorf("contract duration %v exceeds max duration %v", duration, maxDuration)
	case req.Renewal.Allowance.Cmp(minRenterAllowance) < 0:
		return fmt.Errorf("allowance %v is less than minimum allowance %v", req.Renewal.Allowance, minRenterAllowance)
	default:
		return nil
	}
}

// Validate validates a refresh contract request. Prices are not validated
// pk - the public key of the host
// existingCollateral - the existing, unallocated collateral of the contract
// existingTotalCollateral - the existing total (allocated+unallocated) collateral of the contract
// existingAllowance - the existing, remaining allowance of the contract
func (req *RPCRefreshContractRequest) Validate(pk types.PublicKey, existingCollateral, existingTotalCollateral, existingAllowance types.Currency, expirationHeight uint64, maxCollateral types.Currency) error {
	if err := req.Prices.Validate(pk); err != nil {
		return fmt.Errorf("prices are invalid: %w", err)
	}

	// validate the request fields
	switch {
	case req.MinerFee.IsZero():
		return errors.New("miner fee must be greater than 0")
	case req.Basis == (types.ChainIndex{}):
		return errors.New("basis must be set")
	}

	// validate the contract fields
	hp := req.Prices
	// calculate the minimum allowance required for the contract based on the
	// host's locked collateral and the contract duration
	postRefreshAllowance := req.Refresh.Allowance.Add(existingAllowance)
	postRefreshCollateral := req.Refresh.Collateral.Add(existingCollateral)
	minRenterAllowance := MinRenterAllowance(hp, expirationHeight-req.Prices.TipHeight, postRefreshCollateral)
	// refreshes add collateral on top of the existing collateral
	totalCollateral := req.Refresh.Collateral.Add(existingTotalCollateral)

	switch {
	case req.Refresh.Allowance.IsZero():
		return errors.New("allowance must be greater than zero")
	case totalCollateral.Cmp(maxCollateral) > 0:
		return fmt.Errorf("required collateral %v exceeds max collateral %v", totalCollateral, maxCollateral)
	case postRefreshAllowance.Cmp(minRenterAllowance) < 0:
		return fmt.Errorf("post-refresh allowance %v is less than minimum allowance %v", postRefreshAllowance, minRenterAllowance)
	default:
		return nil
	}
}

// Validate checks that the request is valid
func (req *RPCVerifySectorRequest) Validate(hostKey types.PublicKey) error {
	if err := req.Prices.Validate(hostKey); err != nil {
		return fmt.Errorf("prices are invalid: %w", err)
	} else if err := req.Token.Validate(hostKey); err != nil {
		return fmt.Errorf("token is invalid: %w", err)
	} else if req.LeafIndex >= LeavesPerSector {
		return fmt.Errorf("leaf index must be less than %d", LeavesPerSector)
	}
	return nil
}

// Validate checks that the request is valid
func (req *RPCAppendSectorsRequest) Validate(pk types.PublicKey) error {
	if err := req.Prices.Validate(pk); err != nil {
		return fmt.Errorf("prices are invalid: %w", err)
	} else if len(req.Sectors) == 0 {
		return errors.New("no sectors to append")
	} else if uint64(len(req.Sectors)) > MaxSectorBatchSize {
		return fmt.Errorf("too many sectors to append: %d > %d", len(req.Sectors), MaxSectorBatchSize)
	}
	return nil
}

// Validate checks that the request is valid
func (req *RPCFundAccountsRequest) Validate() error {
	switch {
	case req.ContractID == (types.FileContractID{}):
		return errors.New("contract ID must be set")
	case req.RenterSignature == (types.Signature{}):
		return errors.New("renter signature must be set")
	case len(req.Deposits) == 0:
		return errors.New("no deposits to fund")
	case len(req.Deposits) > MaxAccountBatchSize:
		return fmt.Errorf("too many deposits to fund: %d > %d", len(req.Deposits), MaxAccountBatchSize)
	}
	for i, deposit := range req.Deposits {
		switch {
		case deposit.Account == (Account{}):
			return fmt.Errorf("deposit %d has no account", i)
		case deposit.Amount.IsZero():
			return fmt.Errorf("deposit %d has no amount", i)
		}
	}
	return nil
}

// Validate checks that the request is valid
func (req *RPCReplenishAccountsRequest) Validate() error {
	switch {
	case req.ContractID == (types.FileContractID{}):
		return errors.New("contract ID must be set")
	case req.ChallengeSignature == (types.Signature{}):
		return errors.New("challenge signature must be set")
	case len(req.Accounts) == 0:
		return errors.New("no accounts to replenish")
	case len(req.Accounts) > MaxAccountBatchSize:
		return fmt.Errorf("too many accounts to replenish: %d > %d", len(req.Accounts), MaxAccountBatchSize)
	case req.Target.IsZero():
		return errors.New("target must be greater than zero")
	}
	for i, account := range req.Accounts {
		if account == (Account{}) {
			return fmt.Errorf("account %d is empty", i)
		}
	}
	return nil
}
