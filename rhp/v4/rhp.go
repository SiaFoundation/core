package rhp

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"go.sia.tech/core/types"
	"lukechampine.com/frand"
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

// An AccountID represents a unique account identifier.
type AccountID [16]byte

// String implements fmt.Stringer.
func (id AccountID) String() string { return fmt.Sprintf("aid:%x", id[:]) }

// MarshalText implements encoding.TextMarshaler.
func (id AccountID) MarshalText() []byte { return []byte(id.String()) }

// UnmarshalText implements encoding.TextUnmarshaler.
func (id *AccountID) UnmarshalText(b []byte) error {
	n, err := hex.Decode(id[:], bytes.TrimPrefix(b, []byte("aid:")))
	if err != nil {
		return fmt.Errorf("decoding aid:<hex> failed: %w", err)
	} else if n < len(id) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// GenerateAccountID generates a new AccountID from a secure entropy source.
func GenerateAccountID() AccountID {
	return frand.Entropy128()
}

type (
	// RPCSettingsRequest implements Request.
	RPCSettingsRequest struct{}

	// RPCSettingsResponse implements Object.
	RPCSettingsResponse struct {
		Settings HostSettings
	}

	// RPCFormContractRequest implements Request.
	RPCFormContractRequest struct {
		Prices        HostPrices
		Contract      types.V2FileContract
		RenterInputs  []types.V2SiacoinInput
		RenterParents []types.V2Transaction
	}
	// RPCFormContractResponse implements Object.
	RPCFormContractResponse struct {
		HostInputs  []types.V2SiacoinInput
		HostParents []types.V2Transaction
	}
	// RPCFormContractSecondResponse implements Object.
	RPCFormContractSecondResponse struct {
		RenterContractSignature types.Signature
		RenterSatisfiedPolicies []types.SatisfiedPolicy
	}
	// RPCFormContractThirdResponse implements Object.
	RPCFormContractThirdResponse struct {
		HostContractSignature types.Signature
		HostSatisfiedPolicies []types.SatisfiedPolicy
	}

	// RPCRenewContractRequest implements Request.
	RPCRenewContractRequest struct {
		Prices        HostPrices
		Renewal       types.V2FileContractRenewal
		RenterInputs  []types.V2SiacoinInput
		RenterParents []types.V2Transaction
	}
	// RPCRenewContractResponse implements Object.
	RPCRenewContractResponse struct {
		HostInputs  []types.V2SiacoinInput
		HostParents []types.V2Transaction
	}
	// RPCRenewContractSecondResponse implements Object.
	RPCRenewContractSecondResponse struct {
		RenterContractSignature types.Signature
		RenterSatisfiedPolicies []types.SatisfiedPolicy
	}
	// RPCRenewContractThirdResponse implements Object.
	RPCRenewContractThirdResponse struct {
		HostContractSignature types.Signature
		HostSatisfiedPolicies []types.SatisfiedPolicy
	}

	// RPCModifySectorsRequest implements Request.
	RPCModifySectorsRequest struct {
		Prices  HostPrices
		Actions []WriteAction
	}
	// RPCModifySectorsResponse implements Object.
	RPCModifySectorsResponse struct {
		Proof []types.Hash256
	}
	// RPCModifySectorsSecondResponse implements Object.
	RPCModifySectorsSecondResponse struct {
		RenterSignature types.Signature
	}
	// RPCModifySectorsThirdResponse implements Object.
	RPCModifySectorsThirdResponse struct {
		HostSignature types.Signature
	}

	// RPCLatestRevisionRequest implements Request.
	RPCLatestRevisionRequest struct {
		ContractID types.FileContractID
	}
	// RPCLatestRevisionResponse implements Object.
	RPCLatestRevisionResponse struct {
		Contract types.V2FileContract
	}

	// RPCReadSectorRequest implements Request.
	RPCReadSectorRequest struct {
		Prices    HostPrices
		AccountID AccountID
		Root      types.Hash256
		Offset    uint64
		Length    uint64
	}
	// RPCReadSectorResponse implements Object.
	RPCReadSectorResponse struct {
		Proof  []types.Hash256
		Sector []byte
	}

	// RPCWriteSectorRequest implements Request.
	RPCWriteSectorRequest struct {
		Prices    HostPrices
		AccountID AccountID
		Sector    []byte // extended to SectorSize by host
	}
	// RPCWriteSectorResponse implements Object.
	RPCWriteSectorResponse struct {
		Root types.Hash256
	}

	// RPCSectorRootsRequest implements Request.
	RPCSectorRootsRequest struct {
		Prices          HostPrices
		RenterSignature types.Signature
		Offset          uint64
		Length          uint64
	}
	// RPCSectorRootsResponse implements Object.
	RPCSectorRootsResponse struct {
		Proof         []types.Hash256
		Roots         []types.Hash256
		HostSignature types.Signature
	}

	// RPCAccountBalanceRequest implements Request.
	RPCAccountBalanceRequest struct {
		AccountID AccountID
	}
	// RPCAccountBalanceResponse implements Object.
	RPCAccountBalanceResponse struct {
		Balance types.Currency
	}

	// An AccountDeposit represents a transfer into an account.
	AccountDeposit struct {
		AccountID AccountID
		Amount    types.Currency
	}

	// RPCFundAccountRequest implements Request.
	RPCFundAccountRequest struct {
		ContractID      types.FileContractID
		Deposits        []AccountDeposit
		RenterSignature types.Signature
	}
	// RPCFundAccountResponse implements Object.
	RPCFundAccountResponse struct {
		Balances      []types.Currency
		HostSignature types.Signature
	}
)

// A Request is the initial request object for an RPC.
type Request interface {
	Object
	ID() types.Specifier
}

func (RPCAccountBalanceRequest) ID() types.Specifier { return types.NewSpecifier("AccountBalance") }
func (RPCFormContractRequest) ID() types.Specifier   { return types.NewSpecifier("FormContract") }
func (RPCFundAccountRequest) ID() types.Specifier    { return types.NewSpecifier("FundAccount") }
func (RPCLatestRevisionRequest) ID() types.Specifier { return types.NewSpecifier("LatestRevision") }
func (RPCModifySectorsRequest) ID() types.Specifier  { return types.NewSpecifier("ModifySectors") }
func (RPCReadSectorRequest) ID() types.Specifier     { return types.NewSpecifier("ReadSector") }
func (RPCRenewContractRequest) ID() types.Specifier  { return types.NewSpecifier("RenewContract") }
func (RPCSectorRootsRequest) ID() types.Specifier    { return types.NewSpecifier("SectorRoots") }
func (RPCSettingsRequest) ID() types.Specifier       { return types.NewSpecifier("Settings") }
func (RPCWriteSectorRequest) ID() types.Specifier    { return types.NewSpecifier("WriteSector") }

var idMap = map[types.Specifier]func() Request{
	(RPCAccountBalanceRequest{}).ID(): func() Request { return new(RPCAccountBalanceRequest) },
	(RPCFormContractRequest{}).ID():   func() Request { return new(RPCFormContractRequest) },
	(RPCFundAccountRequest{}).ID():    func() Request { return new(RPCFundAccountRequest) },
	(RPCLatestRevisionRequest{}).ID(): func() Request { return new(RPCLatestRevisionRequest) },
	(RPCModifySectorsRequest{}).ID():  func() Request { return new(RPCModifySectorsRequest) },
	(RPCReadSectorRequest{}).ID():     func() Request { return new(RPCReadSectorRequest) },
	(RPCRenewContractRequest{}).ID():  func() Request { return new(RPCRenewContractRequest) },
	(RPCSectorRootsRequest{}).ID():    func() Request { return new(RPCSectorRootsRequest) },
	(RPCSettingsRequest{}).ID():       func() Request { return new(RPCSettingsRequest) },
	(RPCWriteSectorRequest{}).ID():    func() Request { return new(RPCWriteSectorRequest) },
}

// RequestforID returns the intial request object for a given ID.
func RequestforID(id types.Specifier) Request {
	return idMap[id]()
}
