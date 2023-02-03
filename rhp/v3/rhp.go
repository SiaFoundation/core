// Package rhp implements the Sia renter-host protocol, version 3.
package rhp

import (
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"lukechampine.com/frand"
)

// An Account is a public key used to identify an ephemeral account on a host.
type Account types.PublicKey

// ZeroAccount is a sentinel value that indicates the lack of an account.
var ZeroAccount Account

// A PaymentMethod is a way of paying for an arbitrary host operation.
type PaymentMethod interface {
	ProtocolObject
	isPaymentMethod()
}

func (PayByEphemeralAccountRequest) isPaymentMethod() {}
func (PayByContractRequest) isPaymentMethod()         {}

// SigHash returns the hash that is signed to authorize the account payment.
func (p PayByEphemeralAccountRequest) SigHash() types.Hash256 {
	h := types.NewHasher()
	p.Account.EncodeTo(h.E)
	h.E.WriteUint64(p.Expiry)
	p.Amount.EncodeTo(h.E)
	h.E.Write(p.Nonce[:])
	return h.Sum()
}

// SigHash returns the hash that is signed to authorize the contract payment.
func (p PayByContractRequest) SigHash(rev types.FileContractRevision) types.Hash256 {
	txn := types.Transaction{
		FileContractRevisions: []types.FileContractRevision{rev},
	}
	cs := consensus.State{Index: types.ChainIndex{Height: rev.WindowEnd}}
	return cs.PartialSigHash(txn, types.CoveredFields{FileContractRevisions: []uint64{0}})
}

// PayByEphemeralAccount creates a PayByEphemeralAccountRequest.
func PayByEphemeralAccount(account Account, amount types.Currency, expiry uint64, sk types.PrivateKey) PayByEphemeralAccountRequest {
	p := PayByEphemeralAccountRequest{
		Account:  account,
		Expiry:   expiry,
		Amount:   amount,
		Priority: 0, // TODO ???
	}
	frand.Read(p.Nonce[:])
	p.Signature = sk.SignHash(p.SigHash())
	return p
}

// PayByContract creates a PayByContractRequest by revising the supplied
// contract.
func PayByContract(rev *types.FileContractRevision, amount types.Currency, refundAcct Account, sk types.PrivateKey) (PayByContractRequest, bool) {
	if rev.ValidRenterPayout().Cmp(amount) < 0 || rev.MissedRenterPayout().Cmp(amount) < 0 {
		return PayByContractRequest{}, false
	}
	rev.ValidProofOutputs[0].Value = rev.ValidProofOutputs[0].Value.Sub(amount)
	rev.ValidProofOutputs[1].Value = rev.ValidProofOutputs[1].Value.Add(amount)
	rev.MissedProofOutputs[0].Value = rev.MissedProofOutputs[0].Value.Sub(amount)
	rev.MissedProofOutputs[1].Value = rev.MissedProofOutputs[1].Value.Add(amount)
	rev.RevisionNumber++

	newValid := make([]types.Currency, len(rev.ValidProofOutputs))
	for i, o := range rev.ValidProofOutputs {
		newValid[i] = o.Value
	}
	newMissed := make([]types.Currency, len(rev.MissedProofOutputs))
	for i, o := range rev.MissedProofOutputs {
		newMissed[i] = o.Value
	}
	p := PayByContractRequest{
		ContractID:        rev.ParentID,
		RevisionNumber:    rev.RevisionNumber,
		ValidProofValues:  newValid,
		MissedProofValues: newMissed,
		RefundAccount:     refundAcct,
	}
	p.Signature = sk.SignHash(p.SigHash(*rev))
	return p, true
}

// A SettingsID is a unique identifier for registered host settings used by renters
// when interacting with the host.
type SettingsID [16]byte

// An HostPriceTable contains the host's current prices for each RPC.
type HostPriceTable struct {
	// UID is a unique specifier that identifies this price table
	UID SettingsID `json:"uid"`

	// Validity is a duration that specifies how long the host guarantees these
	// prices for and are thus considered valid.
	Validity time.Duration `json:"validity"`

	// HostBlockHeight is the block height of the host. This allows the renter
	// to create valid withdrawal messages in case it is not synced yet.
	HostBlockHeight uint64 `json:"hostblockheight"`

	// UpdatePriceTableCost refers to the cost of fetching a new price table
	// from the host.
	UpdatePriceTableCost types.Currency `json:"updatepricetablecost"`

	// AccountBalanceCost refers to the cost of fetching the balance of an
	// ephemeral account.
	AccountBalanceCost types.Currency `json:"accountbalancecost"`

	// FundAccountCost refers to the cost of funding an ephemeral account on the
	// host.
	FundAccountCost types.Currency `json:"fundaccountcost"`

	// LatestRevisionCost refers to the cost of asking the host for the latest
	// revision of a contract.
	LatestRevisionCost types.Currency `json:"latestrevisioncost"`

	// SubscriptionMemoryCost is the cost of storing a byte of data for
	// SubscriptionPeriod time.
	SubscriptionMemoryCost types.Currency `json:"subscriptionmemorycost"`

	// SubscriptionNotificationCost is the cost of a single notification on top
	// of what is charged for bandwidth.
	SubscriptionNotificationCost types.Currency `json:"subscriptionnotificationcost"`

	// MDM related costs
	//
	// InitBaseCost is the amount of cost that is incurred when an MDM program
	// starts to run. This doesn't include the memory used by the program data.
	// The total cost to initialize a program is calculated as
	// InitCost = InitBaseCost + MemoryTimeCost * Time
	InitBaseCost types.Currency `json:"initbasecost"`

	// MemoryTimeCost is the amount of cost per byte per time that is incurred
	// by the memory consumption of the program.
	MemoryTimeCost types.Currency `json:"memorytimecost"`

	// Cost values specific to the bandwidth consumption.
	DownloadBandwidthCost types.Currency `json:"downloadbandwidthcost"`
	UploadBandwidthCost   types.Currency `json:"uploadbandwidthcost"`

	// Cost values specific to the DropSectors instruction.
	DropSectorsBaseCost types.Currency `json:"dropsectorsbasecost"`
	DropSectorsUnitCost types.Currency `json:"dropsectorsunitcost"`

	// Cost values specific to the HasSector command.
	HasSectorBaseCost types.Currency `json:"hassectorbasecost"`

	// Cost values specific to the Read instruction.
	ReadBaseCost   types.Currency `json:"readbasecost"`
	ReadLengthCost types.Currency `json:"readlengthcost"`

	// Cost values specific to the RenewContract instruction.
	RenewContractCost types.Currency `json:"renewcontractcost"`

	// Cost values specific to the Revision command.
	RevisionBaseCost types.Currency `json:"revisionbasecost"`

	// SwapSectorCost is the cost of swapping 2 full sectors by root.
	SwapSectorCost types.Currency `json:"swapsectorcost"`

	// Cost values specific to the Write instruction.
	WriteBaseCost   types.Currency `json:"writebasecost"`   // per write
	WriteLengthCost types.Currency `json:"writelengthcost"` // per byte written
	WriteStoreCost  types.Currency `json:"writestorecost"`  // per byte / block of additional storage

	// TxnFee estimations.
	TxnFeeMinRecommended types.Currency `json:"txnfeeminrecommended"`
	TxnFeeMaxRecommended types.Currency `json:"txnfeemaxrecommended"`

	// ContractPrice is the additional fee a host charges when forming/renewing
	// a contract to cover the miner fees when submitting the contract and
	// revision to the blockchain.
	ContractPrice types.Currency `json:"contractprice"`

	// CollateralCost is the amount of money per byte the host is promising to
	// lock away as collateral when adding new data to a contract. It's paid out
	// to the host regardless of the outcome of the storage proof.
	CollateralCost types.Currency `json:"collateralcost"`

	// MaxCollateral is the maximum amount of collateral the host is willing to
	// put into a single file contract.
	MaxCollateral types.Currency `json:"maxcollateral"`

	// MaxDuration is the max duration for which the host is willing to form a
	// contract.
	MaxDuration uint64 `json:"maxduration"`

	// WindowSize is the minimum time in blocks the host requests the
	// renewWindow of a new contract to be.
	WindowSize uint64 `json:"windowsize"`

	// Registry related fields.
	RegistryEntriesLeft  uint64 `json:"registryentriesleft"`
	RegistryEntriesTotal uint64 `json:"registryentriestotal"`
}

const registryEntrySize = 256

// UpdateRegistryCost is the cost of executing a 'UpdateRegistry'
// instruction on the MDM.
func (pt *HostPriceTable) UpdateRegistryCost() (writeCost, storeCost types.Currency) {
	// Cost is the same as uploading and storing a registry entry for 5 years.
	const blocksPerYear = 365 * 24 * time.Hour / (10 * time.Minute)
	writeCost = pt.writeCost(registryEntrySize)
	storeCost = pt.WriteStoreCost.Mul64(registryEntrySize).Mul64(uint64(5 * blocksPerYear))
	return writeCost.Add(storeCost), storeCost
}

// writeCost is the cost of executing a 'Write' instruction of a certain length
// on the MDM.
func (pt *HostPriceTable) writeCost(writeLength uint64) types.Currency {
	const atomicWriteSize = 1 << 12
	if mod := writeLength % atomicWriteSize; mod != 0 {
		writeLength += (atomicWriteSize - mod)
	}
	writeCost := pt.WriteLengthCost.Mul64(writeLength).Add(pt.WriteBaseCost)
	return writeCost
}

type (
	// PayByEphemeralAccountRequest represents a payment made using an ephemeral account.
	PayByEphemeralAccountRequest struct {
		Account   Account
		Expiry    uint64
		Amount    types.Currency
		Nonce     [8]byte
		Signature types.Signature
		Priority  int64
	}

	// PayByContractRequest represents a payment made using a contract revision.
	PayByContractRequest struct {
		ContractID        types.FileContractID
		RevisionNumber    uint64
		ValidProofValues  []types.Currency
		MissedProofValues []types.Currency
		RefundAccount     Account
		Signature         types.Signature
		HostSignature     types.Signature
	}
)

// RPC IDs
var (
	RPCAccountBalanceID       = types.NewSpecifier("AccountBalance")
	RPCExecuteProgramID       = types.NewSpecifier("ExecuteProgram")
	RPCUpdatePriceTableID     = types.NewSpecifier("UpdatePriceTable")
	RPCFundAccountID          = types.NewSpecifier("FundAccount")
	RPCLatestRevisionID       = types.NewSpecifier("LatestRevision")
	RPCRegistrySubscriptionID = types.NewSpecifier("Subscription")
	RPCFormContractID         = types.NewSpecifier("FormContract")
	RPCRenewContractID        = types.NewSpecifier("RenewContract")

	PaymentTypeContract         = types.NewSpecifier("PayByContract")
	PaymentTypeEphemeralAccount = types.NewSpecifier("PayByEphemAcc")
)

type (
	// PaymentResponse is the response to a payment request.
	PaymentResponse struct {
		Signature types.Signature
	}

	// RPCUpdatePriceTableResponse is the response object for the UpdatePriceTableResponse RPC.
	RPCUpdatePriceTableResponse struct {
		PriceTableJSON []byte
	}

	// RPCPriceTableResponse is the response object for the PriceTableResponse RPC.
	RPCPriceTableResponse struct{}

	// RPCFundAccountRequest is the request object for the FundAccountRequest RPC.
	RPCFundAccountRequest struct {
		Account Account
	}

	// A FundAccountReceipt is a receipt for a payment made to an account.
	FundAccountReceipt struct {
		Host      types.UnlockKey
		Account   Account
		Amount    types.Currency
		Timestamp time.Time
	}

	// RPCFundAccountResponse is the response object for the FundAccountResponse RPC.
	RPCFundAccountResponse struct {
		Balance   types.Currency
		Receipt   FundAccountReceipt
		Signature types.Signature
	}

	// RPCAccountBalanceRequest is the request object for the AccountBalanceRequest RPC.
	RPCAccountBalanceRequest struct {
		Account Account
	}

	// RPCAccountBalanceResponse is the response object for the AccountBalanceResponse RPC.
	RPCAccountBalanceResponse struct {
		Balance types.Currency
	}

	// RPCExecuteProgramRequest is the request object for the ExecuteProgramRequest RPC.
	RPCExecuteProgramRequest struct {
		FileContractID types.FileContractID
		Program        []Instruction
		ProgramData    []byte
	}

	// RPCExecuteProgramResponse is the response object for the ExecuteProgramResponse RPC.
	RPCExecuteProgramResponse struct {
		AdditionalCollateral types.Currency
		OutputLength         uint64
		NewMerkleRoot        types.Hash256
		NewSize              uint64
		Proof                []types.Hash256
		Error                error
		TotalCost            types.Currency
		FailureRefund        types.Currency
		Output               []byte
	}
)
