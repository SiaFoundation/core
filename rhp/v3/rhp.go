// Package rhp implements the Sia renter-host protocol, version 3.
package rhp

import (
	"time"

	"go.sia.tech/core/consensus"
	rhpv2 "go.sia.tech/core/rhp/v2"
	"go.sia.tech/core/types"
	"lukechampine.com/frand"
)

const (
	blocksPerYear     = 365 * 144
	registryEntrySize = 256
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
	types.V1Currency(p.Amount).EncodeTo(h.E)
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
	rev.ValidProofOutputs[types.RenterContractIndex].Value = rev.ValidProofOutputs[types.RenterContractIndex].Value.Sub(amount)
	rev.ValidProofOutputs[types.HostContractIndex].Value = rev.ValidProofOutputs[types.HostContractIndex].Value.Add(amount)
	rev.MissedProofOutputs[types.RenterContractIndex].Value = rev.MissedProofOutputs[types.RenterContractIndex].Value.Sub(amount)
	rev.MissedProofOutputs[types.HostContractIndex].Value = rev.MissedProofOutputs[types.HostContractIndex].Value.Add(amount)
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

type (
	// A SettingsID is a unique identifier for registered host settings used by renters
	// when interacting with the host.
	SettingsID [16]byte

	// ResourceCost is the cost of executing an instruction.
	ResourceCost struct {
		// Base is the cost to execute the instruction. It is not refunded if
		// the instruction fails.
		Base types.Currency
		// Storage is the cost to store the instruction's data. Storage is the
		// additional storage usage in bytes used. It is refunded if the
		// program fails.
		Storage types.Currency
		// Collateral is the amount of collateral that must be risked by the
		// host to execute the instruction. It is freed if the instruction
		// fails.
		Collateral types.Currency
		// Egress is the cost to send the instruction's output to the renter. It
		// is not refunded if the program fails.
		Egress types.Currency
		// Ingress is the cost to receive the instruction's input from the
		// renter. It is not refunded if the program fails.
		Ingress types.Currency
	}

	// An HostPriceTable contains the host's current prices for each RPC.
	HostPriceTable struct {
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

		// SwapSectorBaseCost is the cost of swapping 2 full sectors by root.
		SwapSectorBaseCost types.Currency `json:"swapsectorcost"`

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
)

// Add adds two ResourceCosts together.
func (a ResourceCost) Add(b ResourceCost) ResourceCost {
	return ResourceCost{
		Base:       a.Base.Add(b.Base),
		Storage:    a.Storage.Add(b.Storage),
		Collateral: a.Collateral.Add(b.Collateral),
		Egress:     a.Egress.Add(b.Egress),
		Ingress:    a.Ingress.Add(b.Ingress),
	}
}

// Total returns the total cost and collateral of a ResourceCost.
func (a ResourceCost) Total() (cost, collateral types.Currency) {
	cost = a.Base.Add(a.Storage).Add(a.Egress).Add(a.Ingress)
	collateral = a.Collateral
	return
}

// writeBaseCost is the cost of executing a 'Write' instruction of a certain length
// on the MDM.
func (pt *HostPriceTable) writeBaseCost(writeLength uint64) types.Currency {
	const atomicWriteSize = 1 << 12
	if mod := writeLength % atomicWriteSize; mod != 0 {
		writeLength += (atomicWriteSize - mod)
	}
	writeCost := pt.WriteLengthCost.Mul64(writeLength).Add(pt.WriteBaseCost)
	return writeCost
}

// AppendSectorCost returns the cost of executing the AppendSector instruction.
func (pt *HostPriceTable) AppendSectorCost(duration uint64) ResourceCost {
	return ResourceCost{
		// base cost is cost of writing 1 sector
		Base: pt.writeBaseCost(rhpv2.SectorSize),
		// storage cost is the cost of storing 1 sector for the remaining duration.
		Storage: pt.WriteStoreCost.Mul64(rhpv2.SectorSize).Mul64(duration),
		// collateral is the collateral the host is expected to put up per
		// sector per block.
		Collateral: pt.CollateralCost.Mul64(rhpv2.SectorSize).Mul64(duration),
		// note: bandwidth costs are now hardcoded to only include the
		// instruction data not the arguments.
		Ingress: pt.UploadBandwidthCost.Mul64(rhpv2.SectorSize),
	}
}

// AppendSectorRootCost returns the cost of executing the AppendSectorRoot
// instruction.
func (pt *HostPriceTable) AppendSectorRootCost(duration uint64) ResourceCost {
	return ResourceCost{
		// base cost is cost of 1 write
		Base: pt.WriteBaseCost,
		// storage cost is the cost of storing 1 sector for the remaining
		// duration.
		Storage: pt.WriteStoreCost.Mul64(rhpv2.SectorSize).Mul64(duration),
		// collateral is the collateral the host is expected to put up per
		// sector per block.
		Collateral: pt.CollateralCost.Mul64(rhpv2.SectorSize).Mul64(duration),
		Ingress:    pt.UploadBandwidthCost.Mul64(32), // sector root
	}
}

// DropSectorsCost returns the cost of executing the DropSector instruction.
func (pt *HostPriceTable) DropSectorsCost(n uint64) ResourceCost {
	return ResourceCost{
		Base:    pt.DropSectorsUnitCost.Mul64(n).Add(pt.DropSectorsBaseCost),
		Ingress: pt.UploadBandwidthCost.Mul64(8), // drop sector count
	}
}

// HasSectorCost returns the cost of executing the HasSector instruction.
func (pt *HostPriceTable) HasSectorCost() ResourceCost {
	return ResourceCost{
		Base:    pt.HasSectorBaseCost,
		Ingress: pt.UploadBandwidthCost.Mul64(32), // sector root
		Egress:  pt.DownloadBandwidthCost,         // boolean response
	}
}

// BaseCost is the cost of initialising an mdm program.
func (pt *HostPriceTable) BaseCost() ResourceCost {
	return ResourceCost{
		Base: pt.InitBaseCost,
	}
}

// ReadOffsetCost returns the cost of executing the ReadOffset instruction.
func (pt *HostPriceTable) ReadOffsetCost(length uint64) ResourceCost {
	return ResourceCost{
		Base:    pt.ReadLengthCost.Mul64(length).Add(pt.ReadBaseCost),
		Ingress: pt.UploadBandwidthCost.Mul64(8),        // sector root index
		Egress:  pt.DownloadBandwidthCost.Mul64(length), // response data
	}
}

// ReadSectorCost returns the cost of executing the ReadSector instruction.
func (pt *HostPriceTable) ReadSectorCost(length uint64) ResourceCost {
	return ResourceCost{
		Base:    pt.ReadLengthCost.Mul64(length).Add(pt.ReadBaseCost),
		Ingress: pt.UploadBandwidthCost.Mul64(32),       // sector root
		Egress:  pt.DownloadBandwidthCost.Mul64(length), // response data
	}
}

// SwapSectorCost returns the cost of executing the SwapSector instruction.
func (pt *HostPriceTable) SwapSectorCost() ResourceCost {
	return ResourceCost{
		Base:    pt.SwapSectorBaseCost,
		Ingress: pt.UploadBandwidthCost.Mul64(2 * 8), // 2 sector indices
	}
}

// UpdateSectorCost returns the cost of executing the UpdateSector instruction.
func (pt *HostPriceTable) UpdateSectorCost(length uint64) ResourceCost {
	return ResourceCost{
		// base cost is cost of writing 1 sector
		Base:    pt.writeBaseCost(rhpv2.SectorSize),
		Ingress: pt.UploadBandwidthCost.Mul64(length),
	}
}

// StoreSectorCost returns the cost of executing the StoreSector instruction.
func (pt *HostPriceTable) StoreSectorCost(duration uint64) ResourceCost {
	return ResourceCost{
		// base cost is cost of writing 1 sector.
		Base:    pt.writeBaseCost(rhpv2.SectorSize),
		Storage: pt.WriteStoreCost.Mul64(rhpv2.SectorSize).Mul64(duration),
		Ingress: pt.UploadBandwidthCost.Mul64(rhpv2.SectorSize),
	}
}

// RevisionCost returns the cost of executing the Revision instruction.
func (pt *HostPriceTable) RevisionCost() ResourceCost {
	return ResourceCost{
		Base: pt.RevisionBaseCost,
	}
}

// ReadRegistryCost returns the cost of executing the ReadRegistry instruction.
func (pt *HostPriceTable) ReadRegistryCost() ResourceCost {
	return ResourceCost{
		Base: pt.writeBaseCost(256),
		// increases the remaining duration of the registry entry and costs the
		// equivalent of storing 256 bytes for 10 years
		Storage: pt.WriteStoreCost.Mul64(256 * 10 * blocksPerYear),
		Egress:  pt.DownloadBandwidthCost.Mul64(256),
	}
}

// UpdateRegistryCost returns the cost of executing the UpdateRegistry
// instruction.
func (pt *HostPriceTable) UpdateRegistryCost() ResourceCost {
	return ResourceCost{
		Base: pt.writeBaseCost(256),
		// increases the remaining duration of the registry entry and costs the
		// equivalent of storing 256 bytes for 5 years
		Storage: pt.WriteStoreCost.Mul64(256 * 5 * blocksPerYear),
		Ingress: pt.UploadBandwidthCost.Mul64(256),
		// the updated entry is returned
		Egress: pt.DownloadBandwidthCost.Mul64(256),
	}
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

	// RPCFinalizeProgramRequest is the finalization request object for the
	// ExecuteProgram RPC.
	RPCFinalizeProgramRequest struct {
		Signature         types.Signature
		RevisionNumber    uint64
		ValidProofValues  []types.Currency
		MissedProofValues []types.Currency
	}

	// RPCFinalizeProgramResponse is the response object for finalizing the
	// ExecuteProgram RPC
	RPCFinalizeProgramResponse struct {
		Signature types.Signature
	}

	// RPCLatestRevisionRequest is the request object for the latest revision RPC.
	RPCLatestRevisionRequest struct {
		ContractID types.FileContractID
	}

	// RPCLatestRevisionResponse is the response object for the latest revision RPC.
	RPCLatestRevisionResponse struct {
		Revision types.FileContractRevision
	}

	// RPCRenewContractRequest is the request object for the renew contract RPC.
	RPCRenewContractRequest struct {
		TransactionSet         []types.Transaction
		RenterKey              types.UnlockKey
		FinalRevisionSignature types.Signature
	}

	// RPCRenewContractHostAdditions is a response object containing the host's
	// additions for the renew contract RPC.
	RPCRenewContractHostAdditions struct {
		Parents                []types.Transaction
		SiacoinInputs          []types.SiacoinInput
		SiacoinOutputs         []types.SiacoinOutput
		FinalRevisionSignature types.Signature
	}

	// RPCRenewSignatures is a response object for transferring signatures in
	// the renew contract RPC.
	RPCRenewSignatures struct {
		TransactionSignatures []types.TransactionSignature
		RevisionSignature     types.TransactionSignature
	}
)
