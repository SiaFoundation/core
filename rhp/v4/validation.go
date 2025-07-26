package rhp

import (
	"fmt"
	"time"

	"go.sia.tech/core/types"
)

func rpcBadRequestError(format string, args ...any) error {
	return NewRPCError(ErrorCodeBadRequest, fmt.Sprintf(format, args...))
}

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
		return ErrHostKeyMismatch
	case time.Now().After(at.ValidUntil):
		return ErrTokenExpired
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
		return rpcBadRequestError("length must be greater than 0")
	case req.Offset+req.Length > SectorSize:
		return rpcBadRequestError("read request exceeds sector bounds")
	case (req.Offset+req.Length)%LeafSize != 0:
		return rpcBadRequestError("read request must be segment aligned")
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
		return rpcBadRequestError("sector must not be empty")
	case req.DataLength%LeafSize != 0:
		return rpcBadRequestError("sector must be segment aligned")
	case req.DataLength > SectorSize:
		return rpcBadRequestError("sector exceeds sector bounds")
	}
	return nil
}

// Validate validates a modify sectors request. Signatures are not validated.
func (req *RPCFreeSectorsRequest) Validate(pk types.PublicKey, fc types.V2FileContract) error {
	if err := req.Prices.Validate(pk); err != nil {
		return fmt.Errorf("prices are invalid: %w", err)
	} else if uint64(len(req.Indices)) > MaxSectorBatchSize {
		return rpcBadRequestError("removing too many sectors at once: %d > %d", len(req.Indices), MaxSectorBatchSize)
	}
	seen := make(map[uint64]bool)
	sectors := fc.Filesize / SectorSize
	for _, index := range req.Indices {
		if index >= sectors {
			return rpcBadRequestError("sector index %d exceeds contract sectors %d", index, sectors)
		} else if seen[index] {
			return rpcBadRequestError("duplicate sector index %d", index)
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
		return rpcBadRequestError("length must be greater than 0")
	case req.Length+req.Offset > contractSectors:
		return rpcBadRequestError("read request range exceeds contract sectors: %d > %d", req.Length+req.Offset, contractSectors)
	case req.Length > MaxSectorBatchSize:
		return rpcBadRequestError("read request range exceeds maximum sectors: %d > %d", req.Length, MaxSectorBatchSize)
	}
	return nil
}

// Validate validates a form contract request. Prices are not validated
func (req *RPCFormContractRequest) Validate(pk types.PublicKey, tip types.ChainIndex, maxCollateral types.Currency, maxDuration uint64) error {
	if err := req.Prices.Validate(pk); err != nil {
		return fmt.Errorf("prices are invalid: %w", err)
	}

	minProofHeight := minProofHeight(tip, req.Prices)
	maxExpirationHeight := req.Prices.TipHeight + maxDuration
	expirationHeight := req.Contract.ProofHeight + ProofWindow
	// validate the request fields
	switch {
	case req.MinerFee.IsZero():
		return rpcBadRequestError("miner fee must be greater than 0")
	case req.Basis == (types.ChainIndex{}):
		return rpcBadRequestError("basis must be set")
	case len(req.RenterInputs) == 0:
		return rpcBadRequestError("renter inputs must not be empty")
	case req.Contract.ProofHeight < minProofHeight:
		return rpcBadRequestError("proof height must be greater than %v", minProofHeight)
	case expirationHeight > maxExpirationHeight:
		return rpcBadRequestError("expiration height %v exceeds max expiration height %v", expirationHeight, maxExpirationHeight)
	}

	// validate the contract fields
	hp := req.Prices
	duration := expirationHeight - hp.TipHeight
	// calculate the minimum allowance required for the contract based on the
	// host's locked collateral
	minRenterAllowance := MinRenterAllowance(hp, req.Contract.Collateral)

	switch {
	case req.Contract.Allowance.IsZero():
		return rpcBadRequestError("allowance must be greater than zero")
	case req.Contract.Collateral.Cmp(maxCollateral) > 0:
		return rpcBadRequestError("collateral %v exceeds max collateral %v", req.Contract.Collateral, maxCollateral)
	case duration > maxDuration:
		return rpcBadRequestError("contract duration %v exceeds max duration %v", duration, maxDuration)
	case req.Contract.Allowance.Cmp(minRenterAllowance) < 0:
		return rpcBadRequestError("allowance %v is less than minimum allowance %v", req.Contract.Allowance, minRenterAllowance)
	default:
		return nil
	}
}

// Validate validates a renew contract request. Prices are not validated
func (req *RPCRenewContractRequest) Validate(pk types.PublicKey, tip types.ChainIndex, existing types.V2FileContract, maxCollateral types.Currency, maxDuration uint64) error {
	if err := req.Prices.Validate(pk); err != nil {
		return fmt.Errorf("prices are invalid: %w", err)
	}

	// calculate the minimum proof height for the renewal.
	minProofHeight := minProofHeight(tip, req.Prices)
	maxExpirationHeight := req.Prices.TipHeight + maxDuration
	expirationHeight := req.Renewal.ProofHeight + ProofWindow
	// validate the request fields
	switch {
	case req.MinerFee.IsZero():
		return rpcBadRequestError("miner fee must be greater than 0")
	case req.Basis == (types.ChainIndex{}):
		return rpcBadRequestError("basis must be set")
	case req.Renewal.ProofHeight <= existing.ProofHeight:
		return rpcBadRequestError("renewal proof height must be greater than existing proof height %v", existing.ProofHeight)
	case req.Renewal.ProofHeight < minProofHeight:
		return rpcBadRequestError("renewal proof height must be at least %v", minProofHeight)
	case expirationHeight > maxExpirationHeight:
		return rpcBadRequestError("renewal expiration height %v exceeds max expiration height %v", expirationHeight, maxExpirationHeight)
	}

	// validate the contract fields
	hp := req.Prices
	duration := expirationHeight - hp.TipHeight
	// calculate the minimum allowance required for the contract based on the
	// host's locked collateral and the contract duration
	minRenterAllowance := MinRenterAllowance(hp, req.Renewal.Collateral)
	// collateral is risked for the entire contract duration
	riskedCollateral := req.Prices.Collateral.Mul64(existing.Filesize).Mul64(duration)
	// renewals add collateral on top of the required risked collateral
	totalCollateral := req.Renewal.Collateral.Add(riskedCollateral)

	switch {
	case req.Renewal.Allowance.IsZero():
		return rpcBadRequestError("allowance must be greater than zero")
	case totalCollateral.Cmp(maxCollateral) > 0:
		return rpcBadRequestError("required collateral %v exceeds max collateral %v", totalCollateral, maxCollateral)
	case req.Renewal.Allowance.Cmp(minRenterAllowance) < 0:
		return rpcBadRequestError("allowance %v is less than minimum allowance %v", req.Renewal.Allowance, minRenterAllowance)
	default:
		return nil
	}
}

// Validate validates a refresh contract request against the existing contract.
func (req *RPCRefreshContractRequest) Validate(pk types.PublicKey, tip types.ChainIndex, existing types.V2FileContract, maxCollateral types.Currency) error {
	if err := req.Prices.Validate(pk); err != nil {
		return fmt.Errorf("prices are invalid: %w", err)
	}

	// validate the request fields
	minProofHeight := minProofHeight(tip, req.Prices)
	switch {
	case req.MinerFee.IsZero():
		return rpcBadRequestError("miner fee must be greater than 0")
	case req.Basis == (types.ChainIndex{}):
		return rpcBadRequestError("basis must be set")
	case existing.ProofHeight <= minProofHeight:
		return rpcBadRequestError("contract too close to proof window %v", existing.ProofHeight)
	}

	// validate the contract fields
	hp := req.Prices
	// calculate the minimum allowance required for the contract based on the
	// host's locked collateral
	minRenterAllowance := MinRenterAllowance(hp, req.Refresh.Collateral)
	totalHostCollateral := existing.TotalCollateral.Add(req.Refresh.Collateral)

	switch {
	case req.Refresh.Allowance.IsZero():
		return rpcBadRequestError("allowance must be greater than zero")
	case req.Refresh.Allowance.Cmp(minRenterAllowance) < 0:
		return rpcBadRequestError("renter allowance %v is less than minimum allowance %v", req.Refresh.Allowance, minRenterAllowance)
	case totalHostCollateral.Cmp(maxCollateral) > 0:
		return rpcBadRequestError("required collateral %v exceeds max collateral %v", totalHostCollateral, maxCollateral)
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
		return rpcBadRequestError("leaf index must be less than %d", LeavesPerSector)
	}
	return nil
}

// Validate checks that the request is valid
func (req *RPCAppendSectorsRequest) Validate(pk types.PublicKey) error {
	if err := req.Prices.Validate(pk); err != nil {
		return fmt.Errorf("prices are invalid: %w", err)
	} else if len(req.Sectors) == 0 {
		return rpcBadRequestError("no sectors to append")
	} else if uint64(len(req.Sectors)) > MaxSectorBatchSize {
		return rpcBadRequestError("too many sectors to append: %d > %d", len(req.Sectors), MaxSectorBatchSize)
	}
	return nil
}

// Validate checks that the request is valid
func (req *RPCFundAccountsRequest) Validate() error {
	switch {
	case req.ContractID == (types.FileContractID{}):
		return rpcBadRequestError("contract ID must be set")
	case req.RenterSignature == (types.Signature{}):
		return rpcBadRequestError("renter signature must be set")
	case len(req.Deposits) == 0:
		return rpcBadRequestError("no deposits to fund")
	case len(req.Deposits) > MaxAccountBatchSize:
		return rpcBadRequestError("too many deposits to fund: %d > %d", len(req.Deposits), MaxAccountBatchSize)
	}
	for i, deposit := range req.Deposits {
		switch {
		case deposit.Account == (Account{}):
			return rpcBadRequestError("deposit %d has no account", i)
		case deposit.Amount.IsZero():
			return rpcBadRequestError("deposit %d has no amount", i)
		}
	}
	return nil
}

// Validate checks that the request is valid
func (req *RPCReplenishAccountsRequest) Validate() error {
	switch {
	case req.ContractID == (types.FileContractID{}):
		return rpcBadRequestError("contract ID must be set")
	case req.ChallengeSignature == (types.Signature{}):
		return rpcBadRequestError("challenge signature must be set")
	case len(req.Accounts) == 0:
		return rpcBadRequestError("no accounts to replenish")
	case len(req.Accounts) > MaxAccountBatchSize:
		return rpcBadRequestError("too many accounts to replenish: %d > %d", len(req.Accounts), MaxAccountBatchSize)
	case req.Target.IsZero():
		return rpcBadRequestError("target must be greater than zero")
	}
	for i, account := range req.Accounts {
		if account == (Account{}) {
			return rpcBadRequestError("account %d is empty", i)
		}
	}
	return nil
}

// minProofHeight returns the minimum proof height necessary for a
// host to accept a contract. This is to ensure the contract
// has enough time to be confirmed before the proof window begins.
func minProofHeight(tip types.ChainIndex, hp HostPrices) uint64 {
	return max(tip.Height, hp.TipHeight) + MinContractDuration
}
