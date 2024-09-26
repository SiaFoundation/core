package rhp

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

const (
	proofWindow = 144 // 24 hours

	// SectorSize is the size of one sector in bytes.
	SectorSize = 1 << 22 // 4 MiB
)

// RPC identifiers.
var (
	RPCAccountBalanceID = types.NewSpecifier("AccountBalance")
	RPCFormContractID   = types.NewSpecifier("FormContract")
	RPCFundAccountsID   = types.NewSpecifier("FundAccounts")
	RPCLatestRevisionID = types.NewSpecifier("LatestRevision")
	RPCModifySectorsID  = types.NewSpecifier("ModifySectors")
	RPCReadSectorID     = types.NewSpecifier("ReadSector")
	RPCRenewContractID  = types.NewSpecifier("RenewContract")
	RPCSectorRootsID    = types.NewSpecifier("SectorRoots")
	RPCSettingsID       = types.NewSpecifier("Settings")
	RPCWriteSectorID    = types.NewSpecifier("WriteSector")
)

func round4KiB(n uint64) uint64 {
	return (n + (1<<12 - 1)) &^ (1<<12 - 1)
}

// HostPrices specify a time-bound set of parameters used to calculate the cost
// of various RPCs.
type HostPrices struct {
	ContractPrice           types.Currency `json:"contractPrice"`
	Collateral              types.Currency `json:"collateral"`
	StoragePrice            types.Currency `json:"storagePrice"`
	IngressPrice            types.Currency `json:"ingressPrice"`
	EgressPrice             types.Currency `json:"egressPrice"`
	ModifySectorActionPrice types.Currency `json:"modifySectorActionPrice"`
	TipHeight               uint64         `json:"tipHeight"`
	ValidUntil              time.Time      `json:"validUntil"`

	// covers above fields
	Signature types.Signature `json:"signature"`
}

// RPCReadSectorCost returns the cost of reading a sector of the given length.
func (hp HostPrices) RPCReadSectorCost(length uint64) types.Currency {
	return hp.EgressPrice.Mul64(round4KiB(length))
}

// RPCWriteSectorCost returns the cost of executing the WriteSector RPC with the
// given sector length and duration.
func (hp HostPrices) RPCWriteSectorCost(sectorLength uint64, duration uint64) types.Currency {
	storage, _ := hp.StoreSectorCost(duration)
	return hp.IngressPrice.Mul64(round4KiB(sectorLength)).Add(storage)
}

// StoreSectorCost returns the cost of storing a sector for the given duration.
func (hp HostPrices) StoreSectorCost(duration uint64) (storage types.Currency, collateral types.Currency) {
	storage = hp.StoragePrice.Mul64(SectorSize).Mul64(duration)
	collateral = hp.Collateral.Mul64(SectorSize).Mul64(duration)
	return
}

// RPCSectorRootsCost returns the cost of fetching sector roots for the given length.
func (hp HostPrices) RPCSectorRootsCost(length uint64) types.Currency {
	return hp.EgressPrice.Mul64(round4KiB(32 * length))
}

// RPCModifySectorsCost returns the cost of modifying a contract's sectors with the
// given actions. The duration parameter is the number of blocks until the
// contract's expiration height.
func (hp HostPrices) RPCModifySectorsCost(actions []WriteAction, duration uint64) (cost, collateral types.Currency) {
	var n int
	for _, action := range actions {
		switch action.Type {
		case ActionAppend:
			n++
		case ActionTrim:
			n -= int(action.N)
		default:
			// no change
		}
	}

	if n > 0 {
		storage, collateral := hp.StoreSectorCost(duration)
		storage = storage.Mul64(uint64(n))
		collateral = collateral.Mul64(uint64(n))
		actions := hp.ModifySectorActionPrice.Mul64(uint64(len(actions)))
		return storage.Add(actions), collateral
	}
	return types.ZeroCurrency, types.ZeroCurrency
}

// SigHash returns the hash of the host settings used for signing.
func (hp HostPrices) SigHash() types.Hash256 {
	h := types.NewHasher()
	types.V2Currency(hp.ContractPrice).EncodeTo(h.E)
	types.V2Currency(hp.Collateral).EncodeTo(h.E)
	types.V2Currency(hp.StoragePrice).EncodeTo(h.E)
	types.V2Currency(hp.IngressPrice).EncodeTo(h.E)
	types.V2Currency(hp.EgressPrice).EncodeTo(h.E)
	types.V2Currency(hp.ModifySectorActionPrice).EncodeTo(h.E)
	h.E.WriteUint64(hp.TipHeight)
	h.E.WriteTime(hp.ValidUntil)
	return h.Sum()
}

// Validate checks the host prices for validity. It returns an error if the
// prices have expired or the signature is invalid.
func (hp *HostPrices) Validate(pk types.PublicKey) error {
	if time.Until(hp.ValidUntil) <= 0 {
		return NewRPCError(ErrorCodeBadRequest, "prices expired")
	}
	if !pk.VerifyHash(hp.SigHash(), hp.Signature) {
		return ErrInvalidSignature
	}
	return nil
}

// HostSettings specify the settings of a host.
type HostSettings struct {
	ProtocolVersion     [3]uint8       `json:"protocolVersion"`
	Release             string         `json:"release"`
	WalletAddress       types.Address  `json:"walletAddress"`
	AcceptingContracts  bool           `json:"acceptingContracts"`
	MaxCollateral       types.Currency `json:"maxCollateral"`
	MaxContractDuration uint64         `json:"maxContractDuration"`
	MaxSectorDuration   uint64         `json:"maxSectorDuration"`
	MaxModifyActions    uint64         `json:"maxModifyActions"`
	RemainingStorage    uint64         `json:"remainingStorage"`
	TotalStorage        uint64         `json:"totalStorage"`
	Prices              HostPrices     `json:"prices"`
}

// A WriteAction adds or modifies sectors within a contract.
type WriteAction struct {
	Type uint8         `json:"type"`
	Root types.Hash256 `json:"root,omitempty"` // Append
	A    uint64        `json:"a,omitempty"`    // Swap
	B    uint64        `json:"b,omitempty"`    // Swap
	N    uint64        `json:"n,omitempty"`    // Trim
}

// WriteAction types.
const (
	ActionAppend = iota + 1
	ActionSwap
	ActionTrim
	ActionUpdate
)

// An Account represents an ephemeral balance that can be funded via contract
// revision and spent to pay for RPCs.
type Account types.PublicKey

// String implements fmt.Stringer.
func (a Account) String() string { return fmt.Sprintf("acct:%x", a[:]) }

// MarshalText implements encoding.TextMarshaler.
func (a Account) MarshalText() []byte { return []byte(a.String()) }

// UnmarshalText implements encoding.TextUnmarshaler.
func (a *Account) UnmarshalText(b []byte) error {
	n, err := hex.Decode(a[:], bytes.TrimPrefix(b, []byte("acct:")))
	if err != nil {
		return fmt.Errorf("decoding acct:<hex> failed: %w", err)
	} else if n < len(a) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// An AccountToken authorizes an account action.
type AccountToken struct {
	Account    Account         `json:"account"`
	ValidUntil time.Time       `json:"validUntil"`
	Signature  types.Signature `json:"signature"`
}

// SigHash returns the hash of the account token used for signing.
func (at *AccountToken) SigHash() types.Hash256 {
	h := types.NewHasher()
	at.Account.EncodeTo(h.E)
	h.E.WriteTime(at.ValidUntil)
	return h.Sum()
}

// Validate verifies the account token is valid for use. It returns an error if
// the token has expired or the signature is invalid.
func (at AccountToken) Validate() error {
	if time.Now().After(at.ValidUntil) {
		return NewRPCError(ErrorCodeBadRequest, "account token expired")
	} else if !types.PublicKey(at.Account).VerifyHash(at.SigHash(), at.Signature) {
		return ErrInvalidSignature
	}
	return nil
}

// GenerateAccount generates a pair of private key and Account from a secure
// entropy source.
func GenerateAccount() (types.PrivateKey, Account) {
	sk := types.GeneratePrivateKey()
	return sk, Account(sk.PublicKey())
}

type (
	// RPCSettingsRequest implements Request.
	RPCSettingsRequest struct{}

	// RPCSettingsResponse implements Object.
	RPCSettingsResponse struct {
		Settings HostSettings `json:"settings"`
	}

	// RPCFormContractParams includes the contract details required to construct
	// a contract.
	RPCFormContractParams struct {
		RenterPublicKey types.PublicKey `json:"renterPublicKey"`
		RenterAddress   types.Address   `json:"renterAddress"`
		Allowance       types.Currency  `json:"allowance"`
		Collateral      types.Currency  `json:"collateral"`
		ProofHeight     uint64          `json:"proofHeight"`
	}

	// RPCFormContractRequest implements Request.
	RPCFormContractRequest struct {
		Prices        HostPrices             `json:"prices"`
		Contract      RPCFormContractParams  `json:"contract"`
		MinerFee      types.Currency         `json:"minerFee"`
		Basis         types.ChainIndex       `json:"basis"`
		RenterInputs  []types.SiacoinElement `json:"renterInputs"`
		RenterParents []types.V2Transaction  `json:"renterParents"`
	}

	// RPCFormContractResponse implements Object.
	RPCFormContractResponse struct {
		HostInputs []types.V2SiacoinInput `json:"hostInputs"`
	}

	// RPCFormContractSecondResponse implements Object.
	RPCFormContractSecondResponse struct {
		RenterContractSignature types.Signature         `json:"renterContractSignature"`
		RenterSatisfiedPolicies []types.SatisfiedPolicy `json:"renterSatisfiedPolicies"`
	}

	// RPCFormContractThirdResponse implements Object.
	RPCFormContractThirdResponse struct {
		Basis          types.ChainIndex      `json:"basis"`
		TransactionSet []types.V2Transaction `json:"transactionSet"`
	}

	// RPCRenewContractParams includes the contract details required to create
	// a renewal.
	RPCRenewContractParams struct {
		ContractID  types.FileContractID `json:"contractID"`
		Allowance   types.Currency       `json:"allowance"`
		Collateral  types.Currency       `json:"collateral"`
		ProofHeight uint64               `json:"proofHeight"`
	}

	// RPCRenewContractRequest implements Request.
	RPCRenewContractRequest struct {
		Prices             HostPrices             `json:"prices"`
		Renewal            RPCRenewContractParams `json:"renewal"`
		MinerFee           types.Currency         `json:"minerFee"`
		Basis              types.ChainIndex       `json:"basis"`
		RenterInputs       []types.SiacoinElement `json:"renterInputs"`
		RenterParents      []types.V2Transaction  `json:"renterParents"`
		ChallengeSignature types.Signature        `json:"challengeSignature"`
	}
	// RPCRenewContractResponse implements Object.
	RPCRenewContractResponse struct {
		HostInputs []types.V2SiacoinInput `json:"hostInputs"`
	}
	// RPCRenewContractSecondResponse implements Object.
	RPCRenewContractSecondResponse struct {
		RenterRenewalSignature  types.Signature         `json:"renterRenewalSignature"`
		RenterSatisfiedPolicies []types.SatisfiedPolicy `json:"renterSatisfiedPolicies"`
	}
	// RPCRenewContractThirdResponse implements Object.
	RPCRenewContractThirdResponse struct {
		Basis          types.ChainIndex      `json:"basis"`
		TransactionSet []types.V2Transaction `json:"transactionSet"`
	}

	// RPCModifySectorsRequest implements Request.
	RPCModifySectorsRequest struct {
		ContractID types.FileContractID `json:"contractID"`
		Prices     HostPrices           `json:"prices"`
		Actions    []WriteAction        `json:"actions"`
		// A ChallengeSignature proves the renter can modify the contract.
		ChallengeSignature types.Signature `json:"challengeSignature"`
	}
	// RPCModifySectorsResponse implements Object.
	RPCModifySectorsResponse struct {
		Proof []types.Hash256 `json:"proof"`
	}
	// RPCModifySectorsSecondResponse implements Object.
	RPCModifySectorsSecondResponse struct {
		RenterSignature types.Signature `json:"renterSignature"`
	}
	// RPCModifySectorsThirdResponse implements Object.
	RPCModifySectorsThirdResponse struct {
		HostSignature types.Signature `json:"hostSignature"`
	}

	// RPCLatestRevisionRequest implements Request.
	RPCLatestRevisionRequest struct {
		ContractID types.FileContractID `json:"contractID"`
	}
	// RPCLatestRevisionResponse implements Object.
	RPCLatestRevisionResponse struct {
		Contract types.V2FileContract `json:"contract"`
	}

	// RPCReadSectorRequest implements Request.
	RPCReadSectorRequest struct {
		Prices HostPrices    `json:"prices"`
		Token  AccountToken  `json:"token"`
		Root   types.Hash256 `json:"root"`
		Offset uint64        `json:"offset"`
		Length uint64        `json:"length"`
	}
	// RPCReadSectorResponse implements Object.
	RPCReadSectorResponse struct {
		Proof  []types.Hash256 `json:"proof"`
		Sector []byte          `json:"sector"`
	}

	// RPCReadSectorStreamedResponse implements Object.
	RPCReadSectorStreamedResponse struct {
		Proof      []types.Hash256 `json:"proof"`
		DataLength uint64          `json:"dataLength"`
	}

	// RPCWriteSectorStreamingRequest implements Request.
	RPCWriteSectorStreamingRequest struct {
		Prices     HostPrices   `json:"prices"`
		Token      AccountToken `json:"token"`
		Duration   uint64       `json:"duration"`
		DataLength uint64       `json:"dataLength"` // extended to SectorSize by host
	}

	// RPCWriteSectorRequest implements Request.
	RPCWriteSectorRequest struct {
		Prices   HostPrices   `json:"prices"`
		Token    AccountToken `json:"token"`
		Duration uint64       `json:"duration"`
		Sector   []byte       `json:"sector"` // extended to SectorSize by host
	}

	// RPCWriteSectorResponse implements Object.
	RPCWriteSectorResponse struct {
		Root types.Hash256 `json:"root"`
	}

	// RPCSectorRootsRequest implements Request.
	RPCSectorRootsRequest struct {
		Prices          HostPrices           `json:"prices"`
		ContractID      types.FileContractID `json:"contractID"`
		RenterSignature types.Signature      `json:"renterSignature"`
		Offset          uint64               `json:"offset"`
		Length          uint64               `json:"length"`
	}
	// RPCSectorRootsResponse implements Object.
	RPCSectorRootsResponse struct {
		Proof         []types.Hash256 `json:"proof"`
		Roots         []types.Hash256 `json:"roots"`
		HostSignature types.Signature `json:"hostSignature"`
	}

	// RPCAccountBalanceRequest implements Request.
	RPCAccountBalanceRequest struct {
		Account Account `json:"account"`
	}
	// RPCAccountBalanceResponse implements Object.
	RPCAccountBalanceResponse struct {
		Balance types.Currency `json:"balance"`
	}

	// An AccountDeposit represents a transfer into an account.
	AccountDeposit struct {
		Account Account        `json:"account"`
		Amount  types.Currency `json:"amount"`
	}

	// RPCFundAccountsRequest implements Request.
	RPCFundAccountsRequest struct {
		ContractID      types.FileContractID `json:"contractID"`
		Deposits        []AccountDeposit     `json:"deposits"`
		RenterSignature types.Signature      `json:"renterSignature"`
	}
	// RPCFundAccountsResponse implements Object.
	RPCFundAccountsResponse struct {
		Balances      []types.Currency `json:"balances"`
		HostSignature types.Signature  `json:"hostSignature"`
	}
)

// ChallengeSigHash returns the hash of the challenge signature used for
// signing.
func (r *RPCModifySectorsRequest) ChallengeSigHash(revisionNumber uint64) types.Hash256 {
	h := types.NewHasher()
	r.ContractID.EncodeTo(h.E)
	h.E.WriteUint64(revisionNumber)
	return h.Sum()
}

// ValidChallengeSignature checks the challenge signature for validity.
func (r *RPCModifySectorsRequest) ValidChallengeSignature(fc types.V2FileContract) bool {
	return fc.RenterPublicKey.VerifyHash(r.ChallengeSigHash(fc.RevisionNumber+1), r.ChallengeSignature)
}

// ChallengeSigHash returns the challenge sighash used for proving ownership
// of a contract for the renew RPC.
func (r *RPCRenewContractRequest) ChallengeSigHash(lastRevisionNumber uint64) types.Hash256 {
	h := types.NewHasher()
	r.Renewal.ContractID.EncodeTo(h.E)
	h.E.WriteUint64(lastRevisionNumber)
	return h.Sum()
}

// ValidChallengeSignature checks the challenge signature for validity.
func (r *RPCRenewContractRequest) ValidChallengeSignature(existing types.V2FileContract) bool {
	return existing.RenterPublicKey.VerifyHash(r.ChallengeSigHash(existing.RevisionNumber), r.ChallengeSignature)
}

// ValidateModifyActions checks the given actions for validity. It returns an
// error if the actions are invalid.
func ValidateModifyActions(actions []WriteAction, maxActions uint64) error {
	var actionCount uint64
	for _, action := range actions {
		switch action.Type {
		case ActionAppend, ActionSwap, ActionUpdate:
			actionCount++
		case ActionTrim:
			actionCount += action.N
		default:
			return fmt.Errorf("invalid action type: %v", action.Type)
		}
	}
	if actionCount > maxActions {
		return fmt.Errorf("too many actions: %v > %v", actionCount, maxActions)
	}
	return nil
}

// NewContract creates a new file contract with the given settings.
func NewContract(p HostPrices, cp RPCFormContractParams, hostKey types.PublicKey, hostAddress types.Address) types.V2FileContract {
	return types.V2FileContract{
		Filesize:         0,
		FileMerkleRoot:   types.Hash256{},
		ProofHeight:      cp.ProofHeight,
		ExpirationHeight: cp.ProofHeight + proofWindow,
		RenterOutput: types.SiacoinOutput{
			Value:   cp.Allowance,
			Address: cp.RenterAddress,
		},
		HostOutput: types.SiacoinOutput{
			Value:   cp.Collateral.Add(p.ContractPrice),
			Address: hostAddress,
		},
		MissedHostValue: cp.Collateral,
		TotalCollateral: cp.Collateral,
		RenterPublicKey: cp.RenterPublicKey,
		HostPublicKey:   hostKey,
		RevisionNumber:  0,
	}
}

// ContractCost calculates the cost to the renter for forming a contract.
func ContractCost(cs consensus.State, p HostPrices, fc types.V2FileContract, minerFee types.Currency) (renter, host types.Currency) {
	renter = fc.RenterOutput.Value.Add(p.ContractPrice).Add(minerFee).Add(cs.V2FileContractTax(fc))
	host = fc.TotalCollateral
	return
}

// RenewalCost calculates the cost to the renter for renewing a contract.
func RenewalCost(cs consensus.State, p HostPrices, r types.V2FileContractRenewal, minerFee types.Currency) (renter, host types.Currency) {
	renter = r.NewContract.RenterOutput.Value.Add(p.ContractPrice).Add(minerFee).Add(cs.V2FileContractTax(r.NewContract)).Sub(r.RenterRollover)
	host = r.NewContract.TotalCollateral.Sub(r.HostRollover)
	return
}

// PayWithContract modifies a contract to transfer the amount from the renter and
// deduct collateral from the host. It returns an RPC error if the contract does not
// have sufficient funds.
func PayWithContract(fc *types.V2FileContract, amount, collateral types.Currency) error {
	if fc.RenterOutput.Value.Cmp(amount) < 0 {
		return NewRPCError(ErrorCodePayment, fmt.Sprintf("insufficient renter funds: %v < %v", fc.RenterOutput.Value, amount))
	} else if fc.MissedHostValue.Cmp(collateral) < 0 {
		return NewRPCError(ErrorCodePayment, fmt.Sprintf("insufficient host collateral: %v < %v", fc.MissedHostValue, amount))
	}
	fc.RevisionNumber++
	fc.RenterOutput.Value = fc.RenterOutput.Value.Sub(amount)
	fc.HostOutput.Value = fc.HostOutput.Value.Add(amount)
	fc.MissedHostValue = fc.MissedHostValue.Sub(collateral)
	return nil
}

// ReviseForModifySectors creates a contract revision from a modify sectors request
// and response.
func ReviseForModifySectors(fc types.V2FileContract, req RPCModifySectorsRequest, resp RPCModifySectorsResponse) (types.V2FileContract, error) {
	old := fc.Filesize
	for _, action := range req.Actions {
		switch action.Type {
		case ActionAppend:
			fc.Filesize += SectorSize // NOTE: ingress cost paid via account
		case ActionTrim:
			fc.Filesize -= SectorSize * action.N
		}
	}
	if fc.Filesize > old {
		size := fc.Filesize - old
		duration := fc.ProofHeight - req.Prices.TipHeight
		err := PayWithContract(&fc, req.Prices.StoragePrice.Mul64(size).Mul64(duration), req.Prices.Collateral.Mul64(size).Mul64(duration))
		if err != nil {
			return fc, err
		}
	}
	fc.FileMerkleRoot = resp.Proof[len(resp.Proof)-1] // TODO get merkle root
	return fc, nil
}

// ReviseForSectorRoots creates a contract revision from a sector roots request
func ReviseForSectorRoots(fc types.V2FileContract, prices HostPrices, numRoots uint64) (types.V2FileContract, error) {
	err := PayWithContract(&fc, prices.EgressPrice.Mul64(round4KiB(32*numRoots)), types.ZeroCurrency)
	return fc, err
}

// ReviseForFundAccount creates a contract revision from a fund account request.
func ReviseForFundAccount(fc types.V2FileContract, amount types.Currency) (types.V2FileContract, error) {
	err := PayWithContract(&fc, amount, types.ZeroCurrency)
	return fc, err
}

// MinRenterAllowance returns the minimum allowance required to justify the given
// host collateral.
func MinRenterAllowance(hp HostPrices, duration uint64, collateral types.Currency) types.Currency {
	maxCollateralBytes := collateral.Div(hp.Collateral).Div64(duration)
	return hp.StoragePrice.Mul64(duration).Mul(maxCollateralBytes).Mul64(9).Div64(10) // 10% buffer
}

// NewRenewal creates a contract renewal from an existing contract revision
func NewRenewal(fc types.V2FileContract, prices HostPrices, rp RPCRenewContractParams) (renewal types.V2FileContractRenewal) {
	expirationHeight := rp.ProofHeight + proofWindow
	duration := expirationHeight - prices.TipHeight
	// collateral will always be risked for the full duration. Existing locked
	// collateral will be rolled into the new contract, so cost to the host
	// is not excessive.
	riskedCollateral := prices.Collateral.Mul64(fc.Filesize).Mul64(duration)

	var storage types.Currency
	if fc.ExpirationHeight < expirationHeight {
		// if the contract was extended, the renter must pay for the additional
		// storage duration
		additionalDuration := expirationHeight - fc.ExpirationHeight
		storage = prices.StoragePrice.Mul64(fc.Filesize).Mul64(additionalDuration)
	}

	// clear the old contract
	renewal.FinalRevision = fc
	renewal.FinalRevision.RevisionNumber = types.MaxRevisionNumber
	renewal.FinalRevision.Filesize = 0
	renewal.FinalRevision.FileMerkleRoot = types.Hash256{}
	renewal.FinalRevision.RenterSignature = types.Signature{}
	renewal.FinalRevision.HostSignature = types.Signature{}

	// create the new contract
	renewal.NewContract = fc
	renewal.NewContract.RevisionNumber = 0
	renewal.NewContract.RenterSignature = types.Signature{}
	renewal.NewContract.HostSignature = types.Signature{}
	renewal.NewContract.ExpirationHeight = expirationHeight
	renewal.NewContract.ProofHeight = rp.ProofHeight
	// the renter output value only needs to cover the new allowance
	renewal.NewContract.RenterOutput.Value = rp.Allowance

	// total collateral includes the additional requested collateral and
	// the risked collateral from the existing storage.
	renewal.NewContract.TotalCollateral = rp.Collateral.Add(riskedCollateral)
	// host output value includes the required collateral, the additional
	// storage cost, and the contract price.
	renewal.NewContract.HostOutput.Value = renewal.NewContract.TotalCollateral.Add(storage).Add(prices.ContractPrice)
	// missed host value should only includes the additional collateral
	renewal.NewContract.MissedHostValue = rp.Collateral

	// if the existing locked collateral is greater than the new required
	// collateral, the host will only lock the new required collateral. Otherwise,
	// roll over the existing locked collateral. The host will need to fund
	// the difference.
	if fc.TotalCollateral.Cmp(renewal.NewContract.TotalCollateral) > 0 {
		renewal.HostRollover = renewal.NewContract.TotalCollateral
	} else {
		renewal.HostRollover = fc.TotalCollateral
	}

	// if the remaining renter output is greater than the required allowance,
	// only roll over the new allowance. Otherwise, roll over the remaining
	// allowance. The renter will need to fund the difference.
	if fc.RenterOutput.Value.Cmp(rp.Allowance) > 0 {
		renewal.RenterRollover = rp.Allowance
	} else {
		renewal.RenterRollover = fc.RenterOutput.Value
	}
	return
}
