package rhp

import (
	"time"

	"go.sia.tech/core/types"
)

// SectorSize is the size of one sector in bytes.
const SectorSize = 1 << 22 // 4 MiB

// A Protocol is a protocol supported by a host.
type Protocol struct {
	Name    string
	Address string
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
	Version            string
	Protocols          []Protocol
	WalletAddress      types.Address
	AcceptingContracts bool
	MaxCollateral      types.Currency
	MaxDuration        uint64
	RemainingStorage   uint64
	TotalStorage       uint64
	Prices             HostPrices
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
)

type (
	// RPCSettings contains the request and response fields of the Settings
	// RPC.
	RPCSettings struct {
		Settings HostSettings
	}

	// RPCFormContract contains the request and response fields of the
	// FormContract RPC.
	RPCFormContract struct {
		Prices       HostPrices
		Contract     types.V2FileContract
		RenterInputs []types.V2SiacoinInput
		HostInputs   []types.V2SiacoinInput
	}

	// RPCSignatures contains the request and response fields of the Signatures
	// RPC.
	RPCSignatures struct {
		RenterSignature types.Signature
		HostSignature   types.Signature
	}

	// RPCReviseContract contains the request and response fields of the
	// ReviseContract RPC.
	RPCReviseContract struct {
		Prices   HostPrices
		Revision types.V2FileContract
	}

	// RPCRenewContract contains the request and response fields of the
	// RenewContract RPC.
	RPCRenewContract struct {
		Prices  HostPrices
		Renewal types.V2FileContractRenewal
	}

	// RPCLatestRevision contains the request and response fields of the
	// LatestRevision RPC.
	RPCLatestRevision struct {
		ContractID types.FileContractID
		Contract   types.V2FileContract
	}

	// RPCReadSector contains the request and response fields of the ReadSector
	// RPC.
	RPCReadSector struct {
		Prices HostPrices
		Root   types.Hash256
		Offset uint64
		Length uint64
		Sector []byte
	}

	// RPCWriteSector contains the request and response fields of the
	// WriteSector RPC.
	RPCWriteSector struct {
		Prices HostPrices
		Sector []byte // extended to SectorSize by host
		Root   types.Hash256
	}

	// RPCModifySectors contains the request and response fields of the
	// ModifySectors RPC.
	RPCModifySectors struct {
		Actions []WriteAction
		Proof   []types.Hash256
	}

	// RPCSectorRoots contains the request and response fields of the
	// SectorRoots RPC.
	RPCSectorRoots struct {
		Prices HostPrices
		Offset uint64
		Length uint64
		Roots  []types.Hash256
	}

	// RPCAccountBalance contains the request and response fields of the
	// AccountBalance RPC.
	RPCAccountBalance struct {
		Account types.PublicKey
		Balance types.Currency
	}

	// RPCFundAccount contains the request and response fields of the
	// FundAccount RPC.
	RPCFundAccount struct {
		Account         types.PublicKey
		Revision        types.V2FileContract // TODO: only send relevant fields?
		RenterSignature types.Signature
		HostSignature   types.Signature
		NewBalance      types.Currency
	}
)

var _ = []RPC{
	(*RPCSettings)(nil),
	(*RPCFormContract)(nil),
	(*RPCSignatures)(nil),
	(*RPCReviseContract)(nil),
	(*RPCRenewContract)(nil),
	(*RPCLatestRevision)(nil),
	(*RPCReadSector)(nil),
	(*RPCWriteSector)(nil),
	(*RPCModifySectors)(nil),
	(*RPCSectorRoots)(nil),
	(*RPCAccountBalance)(nil),
	(*RPCFundAccount)(nil),
}
