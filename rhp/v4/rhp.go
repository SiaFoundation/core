package rhp

import (
	"time"

	"go.sia.tech/core/types"
)

const (
	// SectorSize is the size of one sector in bytes.
	SectorSize = 1 << 22 // 4 MiB
	// SegmentSize is the size of one segment in bytes.
	SegmentSize = 64
)

// A NetAddress is a pair of protocol and address that a host may be reached on.
type NetAddress struct {
	Protocol string
	Address  string
}

// HostPrices specify a time-bound set of parameters used to calculate the cost
// of various RPCs.
type HostPrices struct {
	ContractPrice types.Currency
	Collateral    types.Currency
	StoragePrice  types.Currency
	IngressPrice  types.Currency
	EgressPrice   types.Currency
	TipHeight     uint64
	ValidUntil    time.Time

	// covers above fields
	Signature types.Signature
}

// HostSettings specify the settings of a host.
type HostSettings struct {
	Version            [3]uint8
	NetAddresses       []NetAddress
	WalletAddress      types.Address
	AcceptingContracts bool
	MaxCollateral      types.Currency
	MaxDuration        uint64
	RemainingStorage   uint64
	TotalStorage       uint64
	Prices             HostPrices
}

// Sign signs the host prices with the given key.
func (hs *HostSettings) Sign(sk types.PrivateKey) {
	// NOTE: this is a method on HostSettings (rather than HostPrices itself)
	// because that gives us access to the protocol version.
	h := types.NewHasher()
	hs.Prices.Signature = types.Signature{}
	hs.Prices.EncodeTo(h.E)
	hs.Prices.Signature = sk.SignHash(h.Sum())
}

// A WriteAction adds or modifies sectors within a contract.
type WriteAction struct {
	Type uint8
	Root types.Hash256 // Append
	A, B uint64        // Swap
	N    uint64        // Trim
}

// WriteAction types.
const (
	ActionAppend = iota + 1
	ActionSwap
	ActionTrim
	ActionUpdate // TODO: implement
)

type (
	// RPCSettingsRequest implements Object.
	RPCSettingsRequest struct{}

	// RPCSettingsResponse implements Object.
	RPCSettingsResponse struct {
		Settings HostSettings
	}

	// RPCSettings contains the request and response fields of the Settings
	// RPC.
	RPCSettings struct {
		Request  RPCSettingsRequest
		Response RPCSettingsResponse
	}

	// RPCFormContractRequest implements Object.
	RPCFormContractRequest struct {
		Prices       HostPrices
		Contract     types.V2FileContract
		RenterInputs []types.V2SiacoinInput
	}
	// RPCFormContractResponse implements Object.
	RPCFormContractResponse struct {
		HostInputs []types.V2SiacoinInput
	}

	// SignatureResponse implements Object.
	SignatureResponse types.Signature

	// RPCFormContract contains the request and response fields of the
	// FormContract RPC.
	RPCFormContract struct {
		Request  RPCFormContractRequest
		Response RPCFormContractResponse
		// second roundtrip
		RenterSignature SignatureResponse
		HostSignature   SignatureResponse
	}

	// RPCRenewContractRequest implements Object.
	RPCRenewContractRequest struct {
		Prices       HostPrices
		Renewal      types.V2FileContractRenewal
		RenterInputs []types.V2SiacoinInput
	}
	// RPCRenewContractResponse implements Object.
	RPCRenewContractResponse struct {
		HostInputs []types.V2SiacoinInput
	}

	// RPCRenewContract contains the request and response fields of the
	// RenewContract RPC.
	RPCRenewContract struct {
		Request  RPCRenewContractRequest
		Response RPCRenewContractResponse
		// second roundtrip
		RenterSignature SignatureResponse
		HostSignature   SignatureResponse
	}

	// RPCModifySectorsRequest implements Object.
	RPCModifySectorsRequest struct {
		Prices  HostPrices
		Actions []WriteAction
	}
	// RPCModifySectorsResponse implements Object.
	RPCModifySectorsResponse struct {
		Proof []types.Hash256
	}

	// RPCModifySectors contains the request and response fields of the
	// ModifySectors RPC.
	RPCModifySectors struct {
		Request  RPCModifySectorsRequest
		Response RPCModifySectorsResponse
		// second roundtrip
		RenterSignature types.Signature
		HostSignature   types.Signature
	}

	// RPCLatestRevisionRequest implements Object.
	RPCLatestRevisionRequest struct {
		ContractID types.FileContractID
	}
	// RPCLatestRevisionResponse implements Object.
	RPCLatestRevisionResponse struct {
		Contract types.V2FileContract
	}

	// RPCLatestRevision contains the request and response fields of the
	// LatestRevision RPC.
	RPCLatestRevision struct {
		Request  RPCLatestRevisionRequest
		Response RPCLatestRevisionResponse
	}

	// RPCReadSectorRequest implements Object.
	RPCReadSectorRequest struct {
		Prices HostPrices
		Root   types.Hash256
		Offset uint64
		Length uint64
	}
	// RPCReadSectorResponse implements Object.
	RPCReadSectorResponse struct {
		Proof  []types.Hash256
		Sector []byte
	}

	// RPCReadSector contains the request and response fields of the ReadSector
	// RPC.
	RPCReadSector struct {
		Request  RPCReadSectorRequest
		Response RPCReadSectorResponse
	}

	// RPCWriteSectorRequest implements Object.
	RPCWriteSectorRequest struct {
		Prices HostPrices
		Sector []byte // extended to SectorSize by host
	}
	// RPCWriteSectorResponse implements Object.
	RPCWriteSectorResponse struct {
		Root types.Hash256
	}

	// RPCWriteSector contains the request and response fields of the
	// WriteSector RPC.
	RPCWriteSector struct {
		Request  RPCWriteSectorRequest
		Response RPCWriteSectorResponse
	}

	// RPCSectorRootsRequest implements Object.
	RPCSectorRootsRequest struct {
		Prices HostPrices
		Offset uint64
		Length uint64
	}
	// RPCSectorRootsResponse implements Object.
	RPCSectorRootsResponse struct {
		Roots []types.Hash256
	}

	// RPCSectorRoots contains the request and response fields of the
	// SectorRoots RPC.
	RPCSectorRoots struct {
		Request  RPCSectorRootsRequest
		Response RPCSectorRootsResponse
	}

	// RPCAccountBalanceRequest implements Object.
	RPCAccountBalanceRequest struct {
		Account types.PublicKey
	}
	// RPCAccountBalanceResponse implements Object.
	RPCAccountBalanceResponse struct {
		Balance types.Currency
	}

	// RPCAccountBalance contains the request and response fields of the
	// AccountBalance RPC.
	RPCAccountBalance struct {
		Request  RPCAccountBalanceRequest
		Response RPCAccountBalanceResponse
	}

	// RPCFundAccountRequest implements Object.
	RPCFundAccountRequest struct {
		Account         types.PublicKey
		ContractID      types.FileContractID
		Amount          types.Currency
		RenterSignature types.Signature
	}
	// RPCFundAccountResponse implements Object.
	RPCFundAccountResponse struct {
		NewBalance    types.Currency
		HostSignature types.Signature
	}

	// RPCFundAccount contains the request and response fields of the
	// FundAccount RPC.
	RPCFundAccount struct {
		Request  RPCFundAccountRequest
		Response RPCFundAccountResponse
	}
)

// An RPC can be sent or received via a Transport.
type RPC interface {
	id() types.Specifier
}

func (RPCAccountBalance) id() types.Specifier { return types.NewSpecifier("AccountBalance") }
func (RPCFormContract) id() types.Specifier   { return types.NewSpecifier("FormContract") }
func (RPCFundAccount) id() types.Specifier    { return types.NewSpecifier("FundAccount") }
func (RPCLatestRevision) id() types.Specifier { return types.NewSpecifier("LatestRevision") }
func (RPCModifySectors) id() types.Specifier  { return types.NewSpecifier("ModifySectors") }
func (RPCReadSector) id() types.Specifier     { return types.NewSpecifier("ReadSector") }
func (RPCRenewContract) id() types.Specifier  { return types.NewSpecifier("RenewContract") }
func (RPCSectorRoots) id() types.Specifier    { return types.NewSpecifier("SectorRoots") }
func (RPCSettings) id() types.Specifier       { return types.NewSpecifier("Settings") }
func (RPCWriteSector) id() types.Specifier    { return types.NewSpecifier("WriteSector") }

var idMap = map[types.Specifier]func() RPC{
	(RPCAccountBalance{}).id(): func() RPC { return new(RPCAccountBalance) },
	(RPCFormContract{}).id():   func() RPC { return new(RPCFormContract) },
	(RPCFundAccount{}).id():    func() RPC { return new(RPCFundAccount) },
	(RPCLatestRevision{}).id(): func() RPC { return new(RPCLatestRevision) },
	(RPCModifySectors{}).id():  func() RPC { return new(RPCModifySectors) },
	(RPCReadSector{}).id():     func() RPC { return new(RPCReadSector) },
	(RPCRenewContract{}).id():  func() RPC { return new(RPCRenewContract) },
	(RPCSectorRoots{}).id():    func() RPC { return new(RPCSectorRoots) },
	(RPCSettings{}).id():       func() RPC { return new(RPCSettings) },
	(RPCWriteSector{}).id():    func() RPC { return new(RPCWriteSector) },
}

// RPCforID returns the RPC type corresponding to the given ID.
func RPCforID(id types.Specifier) RPC {
	return idMap[id]()
}
