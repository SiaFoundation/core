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
	// ProofWindow is the number of blocks a host has to submit a proof after
	// the contract expires.
	ProofWindow = 144 // 24 hours

	// MinContractDuration is the minimum duration, in blocks, a host will
	// accept for a contract.
	MinContractDuration = 18 // 3 hours

	// TempSectorDuration is the number of blocks that temp sectors are expected to be stored
	// before being removed
	TempSectorDuration = 144 * 3

	// MaxSectorBatchSize is the number of sector operations that can be batched into a single RPC.
	// For example, the number of sectors appended to a contract within a single RPC append call or the
	// number of sectors removed in a single RPC free call.
	MaxSectorBatchSize = (1 << 40) / (SectorSize)

	// MaxAccountBatchSize is the number of account operations that can be batched into a single RPC.
	MaxAccountBatchSize = 1000

	// SectorSize is the size of one sector in bytes.
	SectorSize = 1 << 22 // 4 MiB
)

// RPC identifiers.
var (
	RPCAccountBalanceID    = types.NewSpecifier("AccountBalance")
	RPCFundAccountsID      = types.NewSpecifier("FundAccounts")
	RPCReplenishAccountsID = types.NewSpecifier("ReplAccounts")

	RPCAppendSectorsID = types.NewSpecifier("AppendSectors")
	RPCFreeSectorsID   = types.NewSpecifier("FreeSectors")
	RPCSectorRootsID   = types.NewSpecifier("SectorRoots")

	RPCFormContractID    = types.NewSpecifier("FormContract")
	RPCLatestRevisionID  = types.NewSpecifier("LatestRevision")
	RPCRefreshContractID = types.NewSpecifier("RefreshContract")
	RPCRefreshPartialID  = types.NewSpecifier("RefreshPartial")
	RPCRenewContractID   = types.NewSpecifier("RenewContract")

	RPCReadSectorID   = types.NewSpecifier("ReadSector")
	RPCWriteSectorID  = types.NewSpecifier("WriteSector")
	RPCVerifySectorID = types.NewSpecifier("VerifySector")
	RPCSettingsID     = types.NewSpecifier("Settings")
)

func round4KiB(n uint64) uint64 {
	return (n + (1<<12 - 1)) &^ (1<<12 - 1)
}

// Usage contains the cost breakdown and collateral of executing an RPC.
type Usage struct {
	RPC              types.Currency `json:"rpc"`
	Storage          types.Currency `json:"storage"`
	Egress           types.Currency `json:"egress"`
	Ingress          types.Currency `json:"ingress"`
	AccountFunding   types.Currency `json:"accountFunding"`
	RiskedCollateral types.Currency `json:"collateral"`
}

// RenterCost returns the total cost of executing the RPC.
func (u Usage) RenterCost() types.Currency {
	return u.RPC.Add(u.Storage).Add(u.Egress).Add(u.Ingress).Add(u.AccountFunding)
}

// HostRiskedCollateral returns the amount of collateral the host must risk
func (u Usage) HostRiskedCollateral() types.Currency {
	return u.RiskedCollateral
}

// Add returns the sum of two Usages.
func (u Usage) Add(b Usage) Usage {
	return Usage{
		RPC:              u.RPC.Add(b.RPC),
		Storage:          u.Storage.Add(b.Storage),
		Egress:           u.Egress.Add(b.Egress),
		Ingress:          u.Ingress.Add(b.Ingress),
		AccountFunding:   u.AccountFunding.Add(b.AccountFunding),
		RiskedCollateral: u.RiskedCollateral.Add(b.RiskedCollateral),
	}
}

// Mul returns the product of a Usage and a scalar.
func (u Usage) Mul(n uint64) Usage {
	return Usage{
		RPC:              u.RPC.Mul64(n),
		Storage:          u.Storage.Mul64(n),
		Egress:           u.Egress.Mul64(n),
		Ingress:          u.Ingress.Mul64(n),
		AccountFunding:   u.AccountFunding.Mul64(n),
		RiskedCollateral: u.RiskedCollateral.Mul64(n),
	}
}

// HostPrices specify a time-bound set of parameters used to calculate the cost
// of various RPCs.
type HostPrices struct {
	// ContractPrice is the base cost to the renter for forming,
	// renewing, or refreshing a contract. It is paid up front and
	// covers the cost of the revision and storage proof transaction
	// the host broadcasts at the end of the contract.
	ContractPrice types.Currency `json:"contractPrice"`
	// Collateral is the amount of Hastings the host will risk
	// per byte of storage per block. This is used by the renter
	// when revising a contract during RPCAppendSectors.
	Collateral types.Currency `json:"collateral"`
	// StoragePrice is the cost per byte of storage per block.
	// This is used by the renter when revising a contract during
	// RPCAppendSectors and RPCWriteSectors.
	StoragePrice types.Currency `json:"storagePrice"`
	// IngressPrice is the cost per byte of data uploaded to the host.
	// This is used by the renter to calculate the cost of bandwidth
	// when uploading to the host.
	IngressPrice types.Currency `json:"ingressPrice"`
	// EgressPrice is the cost per byte of data downloaded from the host.
	// This is used by the renter to calculate the cost of bandwidth
	// when downloading from the host.
	EgressPrice types.Currency `json:"egressPrice"`
	// FreeSectorPrice is the base cost to remove a single sector
	// from a contract. It is used by the renter to calculate the
	// cost of RPCFreeSectors.
	FreeSectorPrice types.Currency `json:"freeSectorPrice"`
	// TipHeight is the height the renter should use when calculating
	// the remaining duration of a contract. It is important that the
	// host and renter agree on the remaining duration so that cost
	// calculation is consistent for both parties.
	TipHeight uint64 `json:"tipHeight"`
	// ValidUntil is the time at which these prices will no longer
	// be honored. The renter should get an updated set of prices
	// before this time.
	ValidUntil time.Time `json:"validUntil"`

	// Signature is a signed hash of the above fields. The host will
	// check this signature before honoring any prices.
	Signature types.Signature `json:"signature"`
}

// RPCReadSectorCost returns the cost of reading a sector of the given length.
func (hp HostPrices) RPCReadSectorCost(length uint64) Usage {
	return Usage{
		Egress: hp.EgressPrice.Mul64(round4KiB(length)),
	}
}

// RPCWriteSectorCost returns the cost of executing the WriteSector RPC with the
// given sector length.
func (hp HostPrices) RPCWriteSectorCost(sectorLength uint64) Usage {
	return Usage{
		Storage: hp.StoragePrice.Mul64(SectorSize).Mul64(TempSectorDuration),
		Ingress: hp.IngressPrice.Mul64(round4KiB(sectorLength)),
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

// RPCFreeSectorsCost returns the cost of removing sectors from a contract.
func (hp HostPrices) RPCFreeSectorsCost(sectors int) Usage {
	return Usage{
		RPC: hp.FreeSectorPrice.Mul64(uint64(sectors)),
	}
}

// RPCAppendSectorsCost returns the cost of appending sectors to a contract. The duration
// parameter is the number of blocks until the contract's expiration height.
func (hp HostPrices) RPCAppendSectorsCost(sectors, duration uint64) Usage {
	return Usage{
		Storage:          hp.StoragePrice.Mul64(SectorSize).Mul64(sectors).Mul64(duration),
		Ingress:          hp.IngressPrice.Mul64(round4KiB(32 * sectors)),
		RiskedCollateral: hp.Collateral.Mul64(SectorSize).Mul64(sectors).Mul64(duration),
	}
}

// SigHash returns the hash of the host settings used for signing.
func (hp HostPrices) SigHash() types.Hash256 {
	h := types.NewHasher()
	types.V2Currency(hp.ContractPrice).EncodeTo(h.E)
	types.V2Currency(hp.Collateral).EncodeTo(h.E)
	types.V2Currency(hp.StoragePrice).EncodeTo(h.E)
	types.V2Currency(hp.IngressPrice).EncodeTo(h.E)
	types.V2Currency(hp.EgressPrice).EncodeTo(h.E)
	types.V2Currency(hp.FreeSectorPrice).EncodeTo(h.E)
	h.E.WriteUint64(hp.TipHeight)
	h.E.WriteTime(hp.ValidUntil)
	return h.Sum()
}

// HostSettings specify the settings of a host.
type HostSettings struct {
	// ProtocolVersion is the version of RHP4 the host supports
	ProtocolVersion [3]uint8 `json:"protocolVersion"`
	// Release identifies the software release of the host
	Release string `json:"release"`
	// WalletAddress is the address the host uses to receive payments.
	// It is used when forming and renewing contracts.
	WalletAddress types.Address `json:"walletAddress"`
	// AcceptingContracts indicates whether the host is currently accepting
	// new contracts.
	AcceptingContracts bool `json:"acceptingContracts"`
	// MaxCollateral is the maximum amount of collateral, in hastings, the host will allow
	// in a single contract.
	MaxCollateral types.Currency `json:"maxCollateral"`
	// MaxContractDuration is the maximum duration, in blocks, the host will
	// allow for a contract.
	MaxContractDuration uint64 `json:"maxContractDuration"`
	// RemainingStorage is the amount of storage, in sectors, the host has
	// remaining.
	RemainingStorage uint64 `json:"remainingStorage"`
	// TotalStorage is the total amount of storage, in sectors, the host has
	// available.
	TotalStorage uint64 `json:"totalStorage"`
	// Prices are a set of time-bound parameters used to calculate the cost
	// of various RPCs. The prices are signed by the host to prevent the renter
	// from tampering with them.
	Prices HostPrices `json:"prices"`
}

// An Account represents an ephemeral balance that can be funded via contract
// revision and spent to pay for RPCs.
type Account types.PublicKey

// String implements fmt.Stringer.
func (a Account) String() string { return hex.EncodeToString(a[:]) }

// MarshalText implements encoding.TextMarshaler.
func (a Account) MarshalText() ([]byte, error) { return []byte(a.String()), nil }

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

// NewAccountToken returns a signed account token authorizing spending from the
// account on the host.
func NewAccountToken(renterKey types.PrivateKey, hostKey types.PublicKey) AccountToken {
	token := AccountToken{
		HostKey:    hostKey,
		Account:    Account(renterKey.PublicKey()),
		ValidUntil: time.Now().Add(5 * time.Minute),
	}
	token.Signature = renterKey.SignHash(token.SigHash())
	return token
}

// An AccountToken authorizes an account action.
type AccountToken struct {
	HostKey    types.PublicKey `json:"hostKey"`
	Account    Account         `json:"account"`
	ValidUntil time.Time       `json:"validUntil"`
	Signature  types.Signature `json:"signature"`
}

// SigHash returns the hash of the account token used for signing.
func (at *AccountToken) SigHash() types.Hash256 {
	h := types.NewHasher()
	at.HostKey.EncodeTo(h.E)
	at.Account.EncodeTo(h.E)
	h.E.WriteTime(at.ValidUntil)
	return h.Sum()
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
		RenterContractSignature types.Signature         `json:"renterContractSignature"`
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
		RenterContractSignature types.Signature         `json:"renterContractSignature"`
		RenterSatisfiedPolicies []types.SatisfiedPolicy `json:"renterSatisfiedPolicies"`
	}
	// RPCRenewContractThirdResponse implements Object.
	RPCRenewContractThirdResponse struct {
		Basis          types.ChainIndex      `json:"basis"`
		TransactionSet []types.V2Transaction `json:"transactionSet"`
	}

	// RPCFreeSectorsRequest implements Object.
	RPCFreeSectorsRequest struct {
		ContractID types.FileContractID `json:"contractID"`
		Prices     HostPrices           `json:"prices"`
		Indices    []uint64             `json:"indices"`
		// A ChallengeSignature proves the renter can modify the contract.
		ChallengeSignature types.Signature `json:"challengeSignature"`
	}
	// RPCFreeSectorsResponse implements Object.
	RPCFreeSectorsResponse struct {
		OldSubtreeHashes []types.Hash256 `json:"oldSubtreeHashes"`
		OldLeafHashes    []types.Hash256 `json:"oldLeafHashes"`
		NewMerkleRoot    types.Hash256   `json:"newMerkleRoot"`
	}
	// RPCFreeSectorsSecondResponse implements Object.
	RPCFreeSectorsSecondResponse struct {
		RenterSignature types.Signature `json:"renterSignature"`
	}
	// RPCFreeSectorsThirdResponse implements Object.
	RPCFreeSectorsThirdResponse struct {
		HostSignature types.Signature `json:"hostSignature"`
	}

	// RPCLatestRevisionRequest implements Object.
	RPCLatestRevisionRequest struct {
		ContractID types.FileContractID `json:"contractID"`
	}
	// RPCLatestRevisionResponse implements Object.
	//
	// The `Revisable` field indicates whether the
	// host will accept further revisions to the contract. A host will not accept revisions too
	// close to the proof window or revisions on contracts that have already been resolved.
	// The `Renewed` field indicates whether the contract was renewed. If the contract was
	// renewed, the renter can use `FileContractID.V2RenewalID` to get the ID of the new contract.
	RPCLatestRevisionResponse struct {
		Contract  types.V2FileContract `json:"contract"`
		Revisable bool                 `json:"revisable"`
		Renewed   bool                 `json:"renewed"`
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
		Proof      []types.Hash256 `json:"proof"`
		DataLength uint64          `json:"dataLength"`
	}

	// RPCWriteSectorRequest implements Object.
	RPCWriteSectorRequest struct {
		Prices     HostPrices   `json:"prices"`
		Token      AccountToken `json:"token"`
		DataLength uint64       `json:"dataLength"` // extended to SectorSize by host
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

	// RPCReplenishAccountsRequest is the request type for RPCReplenishAccounts.
	RPCReplenishAccountsRequest struct {
		Accounts           []Account            `json:"accounts"`
		Target             types.Currency       `json:"target"`
		ContractID         types.FileContractID `json:"contractID"`
		ChallengeSignature types.Signature      `json:"challengeSignature"`
	}
	// RPCReplenishAccountsResponse is the response type for RPCReplenishAccounts.
	RPCReplenishAccountsResponse struct {
		Deposits []AccountDeposit `json:"deposits"`
	}
	// RPCReplenishAccountsSecondResponse is the second response type for RPCReplenishAccounts.
	RPCReplenishAccountsSecondResponse struct {
		RenterSignature types.Signature `json:"renterSignature"`
	}
	// RPCReplenishAccountsThirdResponse is the third response type for RPCReplenishAccounts.
	RPCReplenishAccountsThirdResponse struct {
		HostSignature types.Signature `json:"hostSignature"`
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
func (r *RPCFreeSectorsRequest) ChallengeSigHash(revisionNumber uint64) types.Hash256 {
	h := types.NewHasher()
	r.ContractID.EncodeTo(h.E)
	h.E.WriteUint64(revisionNumber)
	return h.Sum()
}

// ValidChallengeSignature checks the challenge signature for validity.
func (r *RPCFreeSectorsRequest) ValidChallengeSignature(fc types.V2FileContract) bool {
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

// ChallengeSigHash returns the hash of the challenge signature used for
// signing.
func (r *RPCReplenishAccountsRequest) ChallengeSigHash(revisionNumber uint64) types.Hash256 {
	h := types.NewHasher()
	types.EncodeSlice(h.E, r.Accounts)
	types.V2Currency(r.Target).EncodeTo(h.E)
	r.ContractID.EncodeTo(h.E)
	h.E.WriteUint64(revisionNumber)
	return h.Sum()
}

// ValidChallengeSignature checks the challenge signature for validity.
func (r *RPCReplenishAccountsRequest) ValidChallengeSignature(fc types.V2FileContract) bool {
	return fc.RenterPublicKey.VerifyHash(r.ChallengeSigHash(fc.RevisionNumber), r.ChallengeSignature)
}

// TotalCost returns the total cost to the renter of the replenish RPC.
func (r *RPCReplenishAccountsResponse) TotalCost() (total types.Currency) {
	for _, deposit := range r.Deposits {
		total = total.Add(deposit.Amount)
	}
	return
}

// NewContract creates a new file contract with the given settings.
func NewContract(p HostPrices, cp RPCFormContractParams, hostKey types.PublicKey, hostAddress types.Address) (types.V2FileContract, Usage) {
	return types.V2FileContract{
			Filesize:         0,
			FileMerkleRoot:   types.Hash256{},
			ProofHeight:      cp.ProofHeight,
			ExpirationHeight: cp.ProofHeight + ProofWindow,
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
		}, Usage{
			RPC: p.ContractPrice,
		}
}

// ContractCost calculates the cost to the host and renter for forming a contract.
func ContractCost(cs consensus.State, fc types.V2FileContract, minerFee types.Currency) (renter, host types.Currency) {
	contractCost := fc.HostOutput.Value.Sub(fc.TotalCollateral) // (contract price + locked collateral) - locked collateral
	renter = fc.RenterOutput.Value.Add(contractCost).Add(minerFee).Add(cs.V2FileContractTax(fc))
	host = fc.TotalCollateral
	return
}

// RenewalCost calculates the cost to the host and renter for renewing a contract.
func RenewalCost(cs consensus.State, r types.V2FileContractRenewal, minerFee types.Currency) (renter, host types.Currency) {
	contractCost := r.NewContract.HostOutput.Value.Sub(r.NewContract.TotalCollateral) // (contract price + storage cost + locked collateral) - locked collateral
	renter = r.NewContract.RenterOutput.Value.Add(contractCost).Add(minerFee).Add(cs.V2FileContractTax(r.NewContract)).Sub(r.RenterRollover)
	host = r.NewContract.TotalCollateral.Sub(r.HostRollover)
	return
}

// RefreshCost calculates the cost to the host and renter for refreshing a contract.
func RefreshCost(cs consensus.State, p HostPrices, r types.V2FileContractRenewal, minerFee types.Currency) (renter, host types.Currency) {
	// Unlike renewals, it is not possible to calculate the renter's cost of the contract during refreshes without the host's prices
	// because the existing renter and host outputs are rolled into the new contract to ensure the existing data
	// is still covered by collateral.
	renter = r.NewContract.RenterOutput.Value.Add(p.ContractPrice).Sub(r.RenterRollover).Add(minerFee).Add(cs.V2FileContractTax(r.NewContract))
	// new collateral = (contract price + new collateral + existing revenue + existing collateral) - contract price - (existing revenue + existing collateral)
	host = r.NewContract.HostOutput.Value.Sub(p.ContractPrice).Sub(r.HostRollover)
	return
}

// PayWithContract modifies a contract to transfer the amount from the renter and
// deduct collateral from the host. It returns an RPC error if the contract does not
// have sufficient funds.
func PayWithContract(fc *types.V2FileContract, usage Usage) error {
	amount, collateral := usage.RenterCost(), usage.HostRiskedCollateral()
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

// ReviseForFreeSectors creates a contract revision for the free sectors RPC
func ReviseForFreeSectors(fc types.V2FileContract, prices HostPrices, newRoot types.Hash256, deletions int) (types.V2FileContract, Usage, error) {
	fc.Filesize -= SectorSize * uint64(deletions)
	usage := prices.RPCFreeSectorsCost(deletions)
	if err := PayWithContract(&fc, usage); err != nil {
		return fc, Usage{}, err
	}
	fc.FileMerkleRoot = newRoot
	return fc, usage, nil
}

// ReviseForAppendSectors creates a contract revision for the append sectors RPC
func ReviseForAppendSectors(fc types.V2FileContract, prices HostPrices, root types.Hash256, appended uint64) (types.V2FileContract, Usage, error) {
	growth := appended - min(appended, (fc.Capacity-fc.Filesize)/SectorSize)
	fc.Filesize += SectorSize * appended
	fc.Capacity += SectorSize * growth
	fc.FileMerkleRoot = root
	usage := prices.RPCAppendSectorsCost(growth, fc.ExpirationHeight-prices.TipHeight)
	if err := PayWithContract(&fc, usage); err != nil {
		return fc, Usage{}, err
	}
	return fc, usage, nil
}

// ReviseForSectorRoots creates a contract revision for the sector roots RPC
func ReviseForSectorRoots(fc types.V2FileContract, prices HostPrices, numRoots uint64) (types.V2FileContract, Usage, error) {
	usage := prices.RPCSectorRootsCost(numRoots)
	err := PayWithContract(&fc, usage)
	return fc, usage, err
}

// ReviseForFundAccounts creates a contract revision for the fund accounts RPC
func ReviseForFundAccounts(fc types.V2FileContract, amount types.Currency) (types.V2FileContract, Usage, error) {
	usage := Usage{AccountFunding: amount}
	err := PayWithContract(&fc, usage)
	return fc, usage, err
}

// ReviseForReplenish creates a contract revision for the replenish accounts RPC
func ReviseForReplenish(fc types.V2FileContract, amount types.Currency) (types.V2FileContract, Usage, error) {
	usage := Usage{AccountFunding: amount}
	err := PayWithContract(&fc, usage)
	return fc, usage, err
}

// MinRenterAllowance returns the minimum allowance required to justify the given
// host collateral.
func MinRenterAllowance(hp HostPrices, collateral types.Currency) types.Currency {
	if hp.Collateral.IsZero() {
		return types.ZeroCurrency
	}
	maxCollateralBytes := collateral.Div(hp.Collateral)
	return hp.StoragePrice.Mul(maxCollateralBytes)
}

// MaxHostCollateral returns the maximum amount of collateral a host can justify
// to put into a contract for the given allowance.
func MaxHostCollateral(hp HostPrices, allowance types.Currency) types.Currency {
	if hp.StoragePrice.IsZero() {
		return types.MaxCurrency
	}
	maxCollateralBytes := allowance.Div(hp.StoragePrice)
	return hp.Collateral.Mul(maxCollateralBytes)
}

// RenewContract creates a contract renewal for the renew RPC
func RenewContract(fc types.V2FileContract, prices HostPrices, rp RPCRenewContractParams) (types.V2FileContractRenewal, Usage) {
	var renewal types.V2FileContractRenewal
	renewal.FinalRenterOutput = fc.RenterOutput
	renewal.FinalHostOutput = fc.HostOutput

	// create the new contract
	renewal.NewContract = fc
	renewal.NewContract.RevisionNumber = 0
	renewal.NewContract.Capacity = fc.Filesize
	renewal.NewContract.RenterSignature = types.Signature{}
	renewal.NewContract.HostSignature = types.Signature{}
	renewal.NewContract.ExpirationHeight = rp.ProofHeight + ProofWindow
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

	// storage cost is the difference between the new and old contract since the
	// old contract already paid for the storage up to the current expiration
	// height.
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
	renewal.FinalHostOutput.Value = renewal.FinalHostOutput.Value.Sub(renewal.HostRollover)

	// if the remaining renter output is greater than the required allowance,
	// only roll over the new allowance. Otherwise, roll over the remaining
	// allowance. The renter will need to fund the difference.
	if fc.RenterOutput.Value.Cmp(rp.Allowance) > 0 {
		renewal.RenterRollover = rp.Allowance
	} else {
		renewal.RenterRollover = fc.RenterOutput.Value
	}
	renewal.FinalRenterOutput.Value = renewal.FinalRenterOutput.Value.Sub(renewal.RenterRollover)

	return renewal, Usage{
		RPC:              prices.ContractPrice,
		Storage:          renewal.NewContract.HostOutput.Value.Sub(renewal.NewContract.TotalCollateral).Sub(prices.ContractPrice),
		RiskedCollateral: renewal.NewContract.RiskedCollateral(),
	}
}

// RefreshContractPartialRollover creates a contract renewal for the refresh RPC v1.
func RefreshContractPartialRollover(fc types.V2FileContract, prices HostPrices, rp RPCRefreshContractParams) (types.V2FileContractRenewal, Usage) {
	var renewal types.V2FileContractRenewal
	renewal.FinalRenterOutput = fc.RenterOutput
	renewal.FinalHostOutput = fc.HostOutput

	// create the new contract
	renewal.NewContract = fc
	renewal.NewContract.RevisionNumber = 0
	renewal.NewContract.RenterSignature = types.Signature{}
	renewal.NewContract.HostSignature = types.Signature{}

	// the host output needs to cover the existing risked collateral,
	// existing revenue, and the new collateral to ensure the existing data
	// is still protected.
	hostRevenueRisked := fc.RiskedHostRevenue()
	hostRiskedCollateral := fc.RiskedCollateral()
	// the valid output is the sum of the existing revenue, existing risked collateral,
	// the new collateral, and the contract price.
	renewal.NewContract.HostOutput.Value = hostRevenueRisked.Add(rp.Collateral).Add(prices.ContractPrice)
	// the missed host value only returns the new collateral since the
	// existing risked collateral and revenue should be burned on failure.
	renewal.NewContract.MissedHostValue = rp.Collateral
	// total collateral is the sum of the existing risked collateral and
	// the new locked collateral.
	renewal.NewContract.TotalCollateral = hostRiskedCollateral.Add(rp.Collateral)

	// if the existing host output is greater than the new contract's lock up,
	// only roll over the new required collateral. Otherwise, roll over the
	// existing host output. The host will need to fund the difference.
	hostFunds := renewal.NewContract.HostOutput.Value.Sub(prices.ContractPrice) // renter pays contract price
	if fc.HostOutput.Value.Cmp(hostFunds) > 0 {
		renewal.HostRollover = hostFunds
	} else {
		renewal.HostRollover = fc.HostOutput.Value
	}
	renewal.FinalHostOutput.Value = renewal.FinalHostOutput.Value.Sub(renewal.HostRollover)

	// the renter output value only needs to cover the new allowance
	renewal.NewContract.RenterOutput.Value = rp.Allowance
	// if the remaining renter output is greater than the required allowance,
	// only roll over the new allowance. Otherwise, roll over the remaining
	// allowance. The renter will need to fund the difference.
	renterFunds := rp.Allowance.Add(prices.ContractPrice)
	if fc.RenterOutput.Value.Cmp(renterFunds) > 0 {
		renewal.RenterRollover = renterFunds
	} else {
		renewal.RenterRollover = fc.RenterOutput.Value
	}
	renewal.FinalRenterOutput.Value = renewal.FinalRenterOutput.Value.Sub(renewal.RenterRollover)
	return renewal, Usage{
		// Refresh usage is only the contract price since duration is not increased
		RPC:              prices.ContractPrice,
		RiskedCollateral: hostRiskedCollateral,
	}
}

// RefreshContractFullRollover creates a contract renewal for the refresh RPC v0.
func RefreshContractFullRollover(fc types.V2FileContract, prices HostPrices, rp RPCRefreshContractParams) (types.V2FileContractRenewal, Usage) {
	var renewal types.V2FileContractRenewal
	// roll over everything from the existing contract
	renewal.FinalRenterOutput = fc.RenterOutput
	renewal.FinalHostOutput = fc.HostOutput
	renewal.FinalRenterOutput.Value = types.ZeroCurrency
	renewal.FinalHostOutput.Value = types.ZeroCurrency
	renewal.HostRollover = fc.HostOutput.Value
	renewal.RenterRollover = fc.RenterOutput.Value

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
	return renewal, Usage{
		// Refresh usage is only the contract price since duration is not increased
		RPC:              prices.ContractPrice,
		RiskedCollateral: renewal.NewContract.RiskedCollateral(),
	}
}
