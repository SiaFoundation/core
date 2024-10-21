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
	RPCAccountBalanceID  = types.NewSpecifier("AccountBalance")
	RPCFormContractID    = types.NewSpecifier("FormContract")
	RPCFundAccountsID    = types.NewSpecifier("FundAccounts")
	RPCLatestRevisionID  = types.NewSpecifier("LatestRevision")
	RPCAppendSectorsID   = types.NewSpecifier("AppendSectors")
	RPCRemoveSectorsID   = types.NewSpecifier("RemoveSectors")
	RPCReadSectorID      = types.NewSpecifier("ReadSector")
	RPCRenewContractID   = types.NewSpecifier("RenewContract")
	RPCRefreshContractID = types.NewSpecifier("RefreshContract")
	RPCSectorRootsID     = types.NewSpecifier("SectorRoots")
	RPCSettingsID        = types.NewSpecifier("Settings")
	RPCWriteSectorID     = types.NewSpecifier("WriteSector")
	RPCVerifySectorID    = types.NewSpecifier("VerifySector")
)

func round4KiB(n uint64) uint64 {
	return (n + (1<<12 - 1)) &^ (1<<12 - 1)
}

// Usage contains the cost breakdown and collateral of executing an RPC.
type Usage struct {
	RPC            types.Currency `json:"rpc"`
	Storage        types.Currency `json:"storage"`
	Egress         types.Currency `json:"egress"`
	Ingress        types.Currency `json:"ingress"`
	AccountFunding types.Currency `json:"accountFunding"`
	Collateral     types.Currency `json:"collateral"`
}

// Cost returns the total cost of executing the RPC.
func (u Usage) RenterCost() types.Currency {
	return u.RPC.Add(u.Storage).Add(u.Egress).Add(u.Ingress).Add(u.AccountFunding)
}

// HostCollateral returns the amount of collateral the host must risk
func (u Usage) HostCollateral() types.Currency {
	return u.Collateral
}

// Add returns the sum of two Usages.
func (u Usage) Add(b Usage) Usage {
	return Usage{
		RPC:            u.RPC.Add(b.RPC),
		Storage:        u.Storage.Add(b.Storage),
		Egress:         u.Egress.Add(b.Egress),
		Ingress:        u.Ingress.Add(b.Ingress),
		AccountFunding: u.AccountFunding.Add(b.AccountFunding),
		Collateral:     u.Collateral.Add(b.Collateral),
	}
}

// HostPrices specify a time-bound set of parameters used to calculate the cost
// of various RPCs.
type HostPrices struct {
	ContractPrice     types.Currency `json:"contractPrice"`
	Collateral        types.Currency `json:"collateral"`
	StoragePrice      types.Currency `json:"storagePrice"`
	IngressPrice      types.Currency `json:"ingressPrice"`
	EgressPrice       types.Currency `json:"egressPrice"`
	RemoveSectorPrice types.Currency `json:"removeSectorPrice"`
	TipHeight         uint64         `json:"tipHeight"`
	ValidUntil        time.Time      `json:"validUntil"`

	// covers above fields
	Signature types.Signature `json:"signature"`
}

// RPCReadSectorCost returns the cost of reading a sector of the given length.
func (hp HostPrices) RPCReadSectorCost(length uint64) Usage {
	return Usage{
		Egress: hp.EgressPrice.Mul64(round4KiB(length)),
	}
}

// RPCWriteSectorCost returns the cost of executing the WriteSector RPC with the
// given sector length and duration.
func (hp HostPrices) RPCWriteSectorCost(sectorLength uint64, duration uint64) Usage {
	return hp.StoreSectorCost(duration).Add(Usage{
		Ingress: hp.IngressPrice.Mul64(round4KiB(sectorLength)),
	})
}

// StoreSectorCost returns the cost of storing a sector for the given duration.
func (hp HostPrices) StoreSectorCost(duration uint64) Usage {
	return Usage{
		Storage:    hp.StoragePrice.Mul64(SectorSize).Mul64(duration),
		Collateral: hp.Collateral.Mul64(SectorSize).Mul64(duration),
	}
}

// RPCSectorRootsCost returns the cost of fetching sector roots for the given length.
func (hp HostPrices) RPCSectorRootsCost(length uint64) Usage {
	return Usage{
		Egress: hp.EgressPrice.Mul64(round4KiB(32 * length)),
	}
}

// RPCVerifySectorCost returns the cost of building a proof for the specified
// sector.
func (hp HostPrices) RPCVerifySectorCost() Usage {
	return Usage{
		Egress: hp.EgressPrice.Mul64(SectorSize),
	}
}

// RPCRemoveSectorsCost returns the cost of removing sectors from a contract.
func (hp HostPrices) RPCRemoveSectorsCost(sectors int) Usage {
	return Usage{
		RPC: hp.RemoveSectorPrice.Mul64(uint64(sectors)),
	}
}

// RPCAppendSectorsCost returns the cost of appending sectors to a contract. The duration
// parameter is the number of blocks until the contract's expiration height.
func (hp HostPrices) RPCAppendSectorsCost(sectors, duration uint64) Usage {
	usage := hp.StoreSectorCost(duration)
	usage.Storage = usage.Storage.Mul64(sectors)
	usage.Collateral = usage.Collateral.Mul64(sectors)
	return usage
}

// SigHash returns the hash of the host settings used for signing.
func (hp HostPrices) SigHash() types.Hash256 {
	h := types.NewHasher()
	types.V2Currency(hp.ContractPrice).EncodeTo(h.E)
	types.V2Currency(hp.Collateral).EncodeTo(h.E)
	types.V2Currency(hp.StoragePrice).EncodeTo(h.E)
	types.V2Currency(hp.IngressPrice).EncodeTo(h.E)
	types.V2Currency(hp.EgressPrice).EncodeTo(h.E)
	types.V2Currency(hp.RemoveSectorPrice).EncodeTo(h.E)
	h.E.WriteUint64(hp.TipHeight)
	h.E.WriteTime(hp.ValidUntil)
	return h.Sum()
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

// HostSettings specify the settings of a host.
type HostSettings struct {
	ProtocolVersion     [3]uint8       `json:"protocolVersion"`
	Release             string         `json:"release"`
	WalletAddress       types.Address  `json:"walletAddress"`
	AcceptingContracts  bool           `json:"acceptingContracts"`
	MaxCollateral       types.Currency `json:"maxCollateral"`
	MaxContractDuration uint64         `json:"maxContractDuration"`
	MaxSectorDuration   uint64         `json:"maxSectorDuration"`
	MaxSectorBatchSize  uint64         `json:"maxSectorBatchSize"`
	RemainingStorage    uint64         `json:"remainingStorage"`
	TotalStorage        uint64         `json:"totalStorage"`
	Prices              HostPrices     `json:"prices"`
}

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
	// RPCSettingsRequest implements Object.
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

	// RPCFormContractRequest implements Object.
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

	// RPCRefreshContractParams includes the contract details required to refresh
	// a contract.
	RPCRefreshContractParams struct {
		ContractID types.FileContractID `json:"contractID"`
		Allowance  types.Currency       `json:"allowance"`
		Collateral types.Currency       `json:"collateral"`
	}

	// RPCRefreshContractRequest implements Object.
	RPCRefreshContractRequest struct {
		Prices             HostPrices               `json:"prices"`
		Refresh            RPCRefreshContractParams `json:"refresh"`
		MinerFee           types.Currency           `json:"minerFee"`
		Basis              types.ChainIndex         `json:"basis"`
		RenterInputs       []types.SiacoinElement   `json:"renterInputs"`
		RenterParents      []types.V2Transaction    `json:"renterParents"`
		ChallengeSignature types.Signature          `json:"challengeSignature"`
	}
	// RPCRefreshContractResponse implements Object.
	RPCRefreshContractResponse struct {
		HostInputs []types.V2SiacoinInput `json:"hostInputs"`
	}
	// RPCRefreshContractSecondResponse implements Object.
	RPCRefreshContractSecondResponse struct {
		RenterRenewalSignature  types.Signature         `json:"renterRenewalSignature"`
		RenterSatisfiedPolicies []types.SatisfiedPolicy `json:"renterSatisfiedPolicies"`
	}
	// RPCRefreshContractThirdResponse implements Object.
	RPCRefreshContractThirdResponse struct {
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

	// RPCRenewContractRequest implements Object.
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

	// RPCRemoveSectorsRequest implements Object.
	RPCRemoveSectorsRequest struct {
		ContractID types.FileContractID `json:"contractID"`
		Prices     HostPrices           `json:"prices"`
		Indices    []uint64             `json:"indices"`
		// A ChallengeSignature proves the renter can modify the contract.
		ChallengeSignature types.Signature `json:"challengeSignature"`
	}
	// RPCRemoveSectorsResponse implements Object.
	RPCRemoveSectorsResponse struct {
		OldSubtreeHashes []types.Hash256 `json:"oldSubtreeHashes"`
		OldLeafHashes    []types.Hash256 `json:"oldLeafHashes"`
		NewMerkleRoot    types.Hash256   `json:"newMerkleRoot"`
	}
	// RPCRemoveSectorsSecondResponse implements Object.
	RPCRemoveSectorsSecondResponse struct {
		RenterSignature types.Signature `json:"renterSignature"`
	}
	// RPCRemoveSectorsThirdResponse implements Object.
	RPCRemoveSectorsThirdResponse struct {
		HostSignature types.Signature `json:"hostSignature"`
	}

	// RPCLatestRevisionRequest implements Object.
	RPCLatestRevisionRequest struct {
		ContractID types.FileContractID `json:"contractID"`
	}
	// RPCLatestRevisionResponse implements Object.
	RPCLatestRevisionResponse struct {
		Contract types.V2FileContract `json:"contract"`
	}

	// RPCReadSectorRequest implements Object.
	RPCReadSectorRequest struct {
		Prices HostPrices    `json:"prices"`
		Token  AccountToken  `json:"token"`
		Root   types.Hash256 `json:"root"`
		Offset uint64        `json:"offset"`
		Length uint64        `json:"length"`
	}

	// RPCAppendSectorsRequest implements Object.
	RPCAppendSectorsRequest struct {
		Prices             HostPrices           `json:"prices"`
		Sectors            []types.Hash256      `json:"sectors"`
		ContractID         types.FileContractID `json:"contractID"`
		ChallengeSignature types.Signature      `json:"challengeSignature"`
	}
	// RPCAppendSectorsResponse implements Object.
	RPCAppendSectorsResponse struct {
		Accepted      []bool          `json:"accepted"`
		SubtreeRoots  []types.Hash256 `json:"subtreeRoots"`
		NewMerkleRoot types.Hash256   `json:"newMerkleRoot"`
	}
	// RPCAppendSectorsSecondResponse implements Object.
	RPCAppendSectorsSecondResponse struct {
		RenterSignature types.Signature `json:"renterSignature"`
	}
	// RPCAppendSectorsThirdResponse implements Object.
	RPCAppendSectorsThirdResponse struct {
		HostSignature types.Signature `json:"hostSignature"`
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

	// RPCWriteSectorStreamingRequest implements Object.
	RPCWriteSectorStreamingRequest struct {
		Prices     HostPrices   `json:"prices"`
		Token      AccountToken `json:"token"`
		Duration   uint64       `json:"duration"`
		DataLength uint64       `json:"dataLength"` // extended to SectorSize by host
	}

	// RPCWriteSectorRequest implements Object.
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

	// RPCSectorRootsRequest implements Object.
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

	// RPCAccountBalanceRequest implements Object.
	RPCAccountBalanceRequest struct {
		Account Account `json:"account"`
	}
	// RPCAccountBalanceResponse implements Object.
	RPCAccountBalanceResponse struct {
		Balance types.Currency `json:"balance"`
	}

	// RPCVerifySectorRequest implements Object.
	RPCVerifySectorRequest struct {
		Prices    HostPrices    `json:"prices"`
		Token     AccountToken  `json:"token"`
		Root      types.Hash256 `json:"root"`
		LeafIndex uint64        `json:"leafIndex"`
	}

	// RPCVerifySectorResponse implements Object.
	RPCVerifySectorResponse struct {
		Proof []types.Hash256 `json:"proof"`
		Leaf  [64]byte        `json:"leaf"`
	}

	// An AccountDeposit represents a transfer into an account.
	AccountDeposit struct {
		Account Account        `json:"account"`
		Amount  types.Currency `json:"amount"`
	}

	// RPCFundAccountsRequest implements Object.
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
func (r *RPCRemoveSectorsRequest) ChallengeSigHash(revisionNumber uint64) types.Hash256 {
	h := types.NewHasher()
	r.ContractID.EncodeTo(h.E)
	h.E.WriteUint64(revisionNumber)
	return h.Sum()
}

// ValidChallengeSignature checks the challenge signature for validity.
func (r *RPCRemoveSectorsRequest) ValidChallengeSignature(fc types.V2FileContract) bool {
	return fc.RenterPublicKey.VerifyHash(r.ChallengeSigHash(fc.RevisionNumber+1), r.ChallengeSignature)
}

// ChallengeSigHash returns the hash of the challenge signature used for
// signing.
func (r *RPCAppendSectorsRequest) ChallengeSigHash(revisionNumber uint64) types.Hash256 {
	h := types.NewHasher()
	r.ContractID.EncodeTo(h.E)
	h.E.WriteUint64(revisionNumber)
	return h.Sum()
}

// ValidChallengeSignature checks the challenge signature for validity.
func (r *RPCAppendSectorsRequest) ValidChallengeSignature(fc types.V2FileContract) bool {
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

// ChallengeSigHash returns the challenge sighash used for proving ownership
// of a contract for the renew RPC.
func (r *RPCRefreshContractRequest) ChallengeSigHash(lastRevisionNumber uint64) types.Hash256 {
	h := types.NewHasher()
	r.Refresh.ContractID.EncodeTo(h.E)
	h.E.WriteUint64(lastRevisionNumber)
	return h.Sum()
}

// ValidChallengeSignature checks the challenge signature for validity.
func (r *RPCRefreshContractRequest) ValidChallengeSignature(existing types.V2FileContract) bool {
	return existing.RenterPublicKey.VerifyHash(r.ChallengeSigHash(existing.RevisionNumber), r.ChallengeSignature)
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

// ContractCost calculates the cost to the host and renter for forming a contract.
func ContractCost(cs consensus.State, p HostPrices, fc types.V2FileContract, minerFee types.Currency) (renter, host types.Currency) {
	renter = fc.RenterOutput.Value.Add(p.ContractPrice).Add(minerFee).Add(cs.V2FileContractTax(fc))
	host = fc.TotalCollateral
	return
}

// RenewalCost calculates the cost to the host and renter for renewing a contract.
func RenewalCost(cs consensus.State, p HostPrices, r types.V2FileContractRenewal, minerFee types.Currency) (renter, host types.Currency) {
	renter = r.NewContract.RenterOutput.Value.Add(p.ContractPrice).Add(minerFee).Add(cs.V2FileContractTax(r.NewContract)).Sub(r.RenterRollover)
	host = r.NewContract.TotalCollateral.Sub(r.HostRollover)
	return
}

// RefreshCost calculates the cost to the host and renter for refreshing a contract.
func RefreshCost(cs consensus.State, p HostPrices, r types.V2FileContractRenewal, minerFee types.Currency) (renter, host types.Currency) {
	renter = r.NewContract.RenterOutput.Value.Add(p.ContractPrice).Add(minerFee).Add(cs.V2FileContractTax(r.NewContract)).Sub(r.RenterRollover)
	host = r.NewContract.HostOutput.Value.Sub(p.ContractPrice).Sub(r.HostRollover)
	return
}

// PayWithContract modifies a contract to transfer the amount from the renter and
// deduct collateral from the host. It returns an RPC error if the contract does not
// have sufficient funds.
func PayWithContract(fc *types.V2FileContract, usage Usage) error {
	amount, collateral := usage.RenterCost(), usage.HostCollateral()
	// verify the contract can pay the amount before modifying
	if fc.RenterOutput.Value.Cmp(amount) < 0 {
		return NewRPCError(ErrorCodePayment, fmt.Sprintf("insufficient renter funds: %v < %v", fc.RenterOutput.Value, amount))
	} else if fc.MissedHostValue.Cmp(collateral) < 0 {
		return NewRPCError(ErrorCodePayment, fmt.Sprintf("insufficient host collateral: %v < %v", fc.MissedHostValue, amount))
	}
	fc.RevisionNumber++
	fc.RenterOutput.Value = fc.RenterOutput.Value.Sub(amount)
	fc.HostOutput.Value = fc.HostOutput.Value.Add(amount)
	fc.MissedHostValue = fc.MissedHostValue.Sub(collateral)
	// clear signatures
	fc.RenterSignature = types.Signature{}
	fc.HostSignature = types.Signature{}
	return nil
}

// ReviseForRemoveSectors creates a contract revision from a modify sectors request
// and response.
func ReviseForRemoveSectors(fc types.V2FileContract, prices HostPrices, newRoot types.Hash256, deletions int) (types.V2FileContract, error) {
	fc.Filesize -= SectorSize * uint64(deletions)
	if err := PayWithContract(&fc, prices.RPCRemoveSectorsCost(deletions)); err != nil {
		return fc, err
	}
	fc.FileMerkleRoot = newRoot
	return fc, nil
}

// ReviseForAppendSectors creates a contract revision from an append sectors request
func ReviseForAppendSectors(fc types.V2FileContract, prices HostPrices, root types.Hash256, appended uint64) (types.V2FileContract, error) {
	sectors := fc.Filesize / SectorSize
	capacity := fc.Capacity / SectorSize
	appended -= capacity - sectors // capacity will always be >= sectors
	if err := PayWithContract(&fc, prices.RPCAppendSectorsCost(appended, fc.ExpirationHeight-prices.TipHeight)); err != nil {
		return fc, err
	}
	fc.Filesize += SectorSize * appended
	fc.FileMerkleRoot = root
	return fc, nil
}

// ReviseForSectorRoots creates a contract revision from a sector roots request
func ReviseForSectorRoots(fc types.V2FileContract, prices HostPrices, numRoots uint64) (types.V2FileContract, error) {
	err := PayWithContract(&fc, prices.RPCSectorRootsCost(numRoots))
	return fc, err
}

// ReviseForFundAccounts creates a contract revision from a fund account request.
func ReviseForFundAccounts(fc types.V2FileContract, amount types.Currency) (types.V2FileContract, error) {
	err := PayWithContract(&fc, Usage{AccountFunding: amount})
	return fc, err
}

// MinRenterAllowance returns the minimum allowance required to justify the given
// host collateral.
func MinRenterAllowance(hp HostPrices, duration uint64, collateral types.Currency) types.Currency {
	maxCollateralBytes := collateral.Div(hp.Collateral).Div64(duration)
	return hp.StoragePrice.Mul64(duration).Mul(maxCollateralBytes)
}

// RenewContract creates a contract renewal from an existing contract revision
func RenewContract(fc types.V2FileContract, prices HostPrices, rp RPCRenewContractParams) (renewal types.V2FileContractRenewal) {
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
	renewal.NewContract.ExpirationHeight = rp.ProofHeight + proofWindow
	renewal.NewContract.ProofHeight = rp.ProofHeight
	// the renter output value only needs to cover the new allowance
	renewal.NewContract.RenterOutput.Value = rp.Allowance

	// risked collateral must be calculated using the full duration to ensure the
	// host is incentivized to store the data. Existing locked collateral will be
	// rolled into the new contract, so cost to the host is not excessive.
	riskedCollateral := prices.Collateral.Mul64(fc.Filesize).Mul64(renewal.NewContract.ExpirationHeight - prices.TipHeight)

	// total collateral includes the additional requested collateral and
	// the risked collateral from the existing storage.
	renewal.NewContract.TotalCollateral = rp.Collateral.Add(riskedCollateral)
	// missed host value should only include the new collateral value
	renewal.NewContract.MissedHostValue = rp.Collateral

	// storage cost is the difference between the new and old contract since the old contract
	// already paid for the storage up to the current expiration height.
	storageCost := prices.StoragePrice.Mul64(fc.Filesize).Mul64(renewal.NewContract.ExpirationHeight - fc.ExpirationHeight)

	// host output value includes the locked + risked collateral, the additional
	// storage cost, and the contract price.
	renewal.NewContract.HostOutput.Value = renewal.NewContract.TotalCollateral.Add(storageCost).Add(prices.ContractPrice)

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

// RefreshContract creates a new contract renewal from an existing contract revision
func RefreshContract(fc types.V2FileContract, prices HostPrices, rp RPCRefreshContractParams) (renewal types.V2FileContractRenewal) {
	// clear the old contract
	renewal.FinalRevision = fc
	renewal.FinalRevision.RevisionNumber = types.MaxRevisionNumber
	renewal.FinalRevision.RenterSignature = types.Signature{}
	renewal.FinalRevision.HostSignature = types.Signature{}

	// create the new contract
	renewal.NewContract = fc
	renewal.NewContract.RevisionNumber = 0
	renewal.NewContract.RenterSignature = types.Signature{}
	renewal.NewContract.HostSignature = types.Signature{}
	// add the additional allowance and collateral
	renewal.NewContract.RenterOutput.Value = fc.RenterOutput.Value.Add(rp.Allowance)
	renewal.NewContract.HostOutput.Value = fc.HostOutput.Value.Add(rp.Collateral).Add(prices.ContractPrice)
	renewal.NewContract.MissedHostValue = fc.MissedHostValue.Add(rp.Collateral)
	// total collateral includes the additional requested collateral
	renewal.NewContract.TotalCollateral = fc.TotalCollateral.Add(rp.Collateral)
	// roll over everything from the existing contract
	renewal.HostRollover = fc.HostOutput.Value
	renewal.RenterRollover = fc.RenterOutput.Value
	return
}
