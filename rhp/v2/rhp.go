// Package rhp implements the Sia renter-host protocol, version 2.
package rhp

import (
	"encoding/json"
	"fmt"
	"math/bits"
	"net"
	"strings"
	"time"

	"go.sia.tech/core/types"
)

func wrapErr(err *error, fnName string) {
	if *err != nil {
		*err = fmt.Errorf("%s: %w", fnName, *err)
	}
}

// A ContractRevision pairs a file contract with its signatures.
type ContractRevision struct {
	Revision   types.FileContractRevision
	Signatures [2]types.TransactionSignature
}

// EndHeight returns the height at which the host is no longer obligated to
// store contract data.
func (c ContractRevision) EndHeight() uint64 {
	return uint64(c.Revision.WindowStart)
}

// ID returns the ID of the original FileContract.
func (c ContractRevision) ID() types.FileContractID {
	return c.Revision.ParentID
}

// HostKey returns the public key of the host.
func (c ContractRevision) HostKey() (pk types.PublicKey) {
	copy(pk[:], c.Revision.UnlockConditions.PublicKeys[1].Key)
	return
}

// RenterFunds returns the funds remaining in the contract's Renter payout.
func (c ContractRevision) RenterFunds() types.Currency {
	return c.Revision.ValidRenterPayout()
}

// NumSectors returns the number of sectors covered by the contract.
func (c ContractRevision) NumSectors() uint64 {
	return c.Revision.Filesize / SectorSize
}

// HostSettings are the settings and prices used when interacting with a host.
type HostSettings struct {
	AcceptingContracts         bool           `json:"acceptingcontracts"`
	MaxDownloadBatchSize       uint64         `json:"maxdownloadbatchsize"`
	MaxDuration                uint64         `json:"maxduration"`
	MaxReviseBatchSize         uint64         `json:"maxrevisebatchsize"`
	NetAddress                 string         `json:"netaddress"`
	RemainingStorage           uint64         `json:"remainingstorage"`
	SectorSize                 uint64         `json:"sectorsize"`
	TotalStorage               uint64         `json:"totalstorage"`
	Address                    types.Address  `json:"unlockhash"`
	WindowSize                 uint64         `json:"windowsize"`
	Collateral                 types.Currency `json:"collateral"`
	MaxCollateral              types.Currency `json:"maxcollateral"`
	BaseRPCPrice               types.Currency `json:"baserpcprice"`
	ContractPrice              types.Currency `json:"contractprice"`
	DownloadBandwidthPrice     types.Currency `json:"downloadbandwidthprice"`
	SectorAccessPrice          types.Currency `json:"sectoraccessprice"`
	StoragePrice               types.Currency `json:"storageprice"`
	UploadBandwidthPrice       types.Currency `json:"uploadbandwidthprice"`
	EphemeralAccountExpiry     time.Duration  `json:"ephemeralaccountexpiry"`
	MaxEphemeralAccountBalance types.Currency `json:"maxephemeralaccountbalance"`
	RevisionNumber             uint64         `json:"revisionnumber"`
	Version                    string         `json:"version"`
	SiaMuxPort                 string         `json:"siamuxport"`
}

// MarshalJSON encodes the HostSettings as JSON. The Address field is overridden
// for compatibility with siad renters.
func (s HostSettings) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"acceptingcontracts":         s.AcceptingContracts,
		"maxdownloadbatchsize":       s.MaxDownloadBatchSize,
		"maxduration":                s.MaxDuration,
		"maxrevisebatchsize":         s.MaxReviseBatchSize,
		"netaddress":                 s.NetAddress,
		"remainingstorage":           s.RemainingStorage,
		"sectorsize":                 s.SectorSize,
		"totalstorage":               s.TotalStorage,
		"unlockhash":                 strings.TrimPrefix(s.Address.String(), "addr:"), // trim the "addr:" prefix for compatibility with siad
		"windowsize":                 s.WindowSize,
		"collateral":                 s.Collateral,
		"maxcollateral":              s.MaxCollateral,
		"baserpcprice":               s.BaseRPCPrice,
		"contractprice":              s.ContractPrice,
		"downloadbandwidthprice":     s.DownloadBandwidthPrice,
		"sectoraccessprice":          s.SectorAccessPrice,
		"storageprice":               s.StoragePrice,
		"uploadbandwidthprice":       s.UploadBandwidthPrice,
		"ephemeralaccountexpiry":     s.EphemeralAccountExpiry,
		"maxephemeralaccountbalance": s.MaxEphemeralAccountBalance,
		"revisionnumber":             s.RevisionNumber,
		"version":                    s.Version,
		"siamuxport":                 s.SiaMuxPort,
	})
}

// SiamuxAddr is a helper which returns an address that can be used to connect
// to the host's siamux.
func (s HostSettings) SiamuxAddr() string {
	host, _, err := net.SplitHostPort(s.NetAddress)
	if err != nil {
		return ""
	}
	return net.JoinHostPort(host, s.SiaMuxPort)
}

// RPC IDs
var (
	RPCFormContractID       = types.NewSpecifier("LoopFormContract")
	RPCLockID               = types.NewSpecifier("LoopLock")
	RPCReadID               = types.NewSpecifier("LoopRead")
	RPCRenewContractID      = types.NewSpecifier("LoopRenew")
	RPCRenewClearContractID = types.NewSpecifier("LoopRenewClear")
	RPCSectorRootsID        = types.NewSpecifier("LoopSectorRoots")
	RPCSettingsID           = types.NewSpecifier("LoopSettings")
	RPCUnlockID             = types.NewSpecifier("LoopUnlock")
	RPCWriteID              = types.NewSpecifier("LoopWrite")
)

// Read/Write actions
var (
	RPCWriteActionAppend = types.NewSpecifier("Append")
	RPCWriteActionTrim   = types.NewSpecifier("Trim")
	RPCWriteActionSwap   = types.NewSpecifier("Swap")
	RPCWriteActionUpdate = types.NewSpecifier("Update")

	RPCReadStop = types.NewSpecifier("ReadStop")
)

// RPC request/response objects
type (
	// RPCFormContractRequest contains the request parameters for the
	// FormContract and RenewContract RPCs.
	RPCFormContractRequest struct {
		Transactions []types.Transaction
		RenterKey    types.UnlockKey
	}

	// RPCRenewAndClearContractRequest contains the request parameters for the
	// RenewAndClearContract RPC.
	RPCRenewAndClearContractRequest struct {
		Transactions           []types.Transaction
		RenterKey              types.UnlockKey
		FinalValidProofValues  []types.Currency
		FinalMissedProofValues []types.Currency
	}

	// RPCFormContractAdditions contains the parent transaction, inputs, and
	// outputs added by the host when negotiating a file contract.
	RPCFormContractAdditions struct {
		Parents []types.Transaction
		Inputs  []types.SiacoinInput
		Outputs []types.SiacoinOutput
	}

	// RPCFormContractSignatures contains the signatures for a contract
	// transaction and initial revision. These signatures are sent by both the
	// renter and host during contract formation and renewal.
	RPCFormContractSignatures struct {
		ContractSignatures []types.TransactionSignature
		RevisionSignature  types.TransactionSignature
	}

	// RPCRenewAndClearContractSignatures contains the signatures for a contract
	// transaction, initial revision, and final revision of the contract being
	// renewed. These signatures are sent by both the renter and host during the
	// RenewAndClear RPC.
	RPCRenewAndClearContractSignatures struct {
		ContractSignatures     []types.TransactionSignature
		RevisionSignature      types.TransactionSignature
		FinalRevisionSignature types.Signature
	}

	// RPCLockRequest contains the request parameters for the Lock RPC.
	RPCLockRequest struct {
		ContractID types.FileContractID
		Signature  types.Signature
		Timeout    uint64
	}

	// RPCLockResponse contains the response data for the Lock RPC.
	RPCLockResponse struct {
		Acquired     bool
		NewChallenge [16]byte
		Revision     types.FileContractRevision
		Signatures   []types.TransactionSignature
	}

	// RPCReadRequestSection is a section requested in RPCReadRequest.
	RPCReadRequestSection struct {
		MerkleRoot types.Hash256
		Offset     uint64
		Length     uint64
	}

	// RPCReadRequest contains the request parameters for the Read RPC.
	RPCReadRequest struct {
		Sections    []RPCReadRequestSection
		MerkleProof bool

		RevisionNumber    uint64
		ValidProofValues  []types.Currency
		MissedProofValues []types.Currency
		Signature         types.Signature
	}

	// RPCReadResponse contains the response data for the Read RPC.
	RPCReadResponse struct {
		Signature   types.Signature
		Data        []byte
		MerkleProof []types.Hash256
	}

	// RPCSectorRootsRequest contains the request parameters for the SectorRoots RPC.
	RPCSectorRootsRequest struct {
		RootOffset uint64
		NumRoots   uint64

		RevisionNumber    uint64
		ValidProofValues  []types.Currency
		MissedProofValues []types.Currency
		Signature         types.Signature
	}

	// RPCSectorRootsResponse contains the response data for the SectorRoots RPC.
	RPCSectorRootsResponse struct {
		Signature   types.Signature
		SectorRoots []types.Hash256
		MerkleProof []types.Hash256
	}

	// RPCSettingsResponse contains the response data for the SettingsResponse RPC.
	RPCSettingsResponse struct {
		Settings []byte // JSON-encoded hostdb.HostSettings
	}

	// RPCWriteRequest contains the request parameters for the Write RPC.
	RPCWriteRequest struct {
		Actions     []RPCWriteAction
		MerkleProof bool

		RevisionNumber    uint64
		ValidProofValues  []types.Currency
		MissedProofValues []types.Currency
	}

	// RPCWriteAction is a generic Write action. The meaning of each field
	// depends on the Type of the action.
	RPCWriteAction struct {
		Type types.Specifier
		A, B uint64
		Data []byte
	}

	// RPCWriteMerkleProof contains the optional Merkle proof for response data
	// for the Write RPC.
	RPCWriteMerkleProof struct {
		OldSubtreeHashes []types.Hash256
		OldLeafHashes    []types.Hash256
		NewMerkleRoot    types.Hash256
	}

	// RPCWriteResponse contains the response data for the Write RPC.
	RPCWriteResponse struct {
		Signature types.Signature
	}
)

// RPCSectorRootsCost returns the price of a SectorRoots RPC.
func RPCSectorRootsCost(settings HostSettings, n uint64) types.Currency {
	roots, overflow := settings.DownloadBandwidthPrice.Mul64WithOverflow(n * 32)
	if overflow {
		return types.MaxCurrency
	}
	proof, overflow := settings.DownloadBandwidthPrice.Mul64WithOverflow(128 * 32)
	if overflow {
		return types.MaxCurrency
	}
	return settings.BaseRPCPrice.Add(roots).Add(proof)
}

// RPCReadCost returns the price of a Read RPC.
func RPCReadCost(settings HostSettings, sections []RPCReadRequestSection) types.Currency {
	sectorAccessPrice := settings.SectorAccessPrice.Mul64(uint64(len(sections)))
	var bandwidth uint64
	for _, sec := range sections {
		bandwidth += sec.Length
		bandwidth += 2 * uint64(bits.Len64(LeavesPerSector)) * 32 // proof
	}
	if bandwidth < minMessageSize {
		bandwidth = minMessageSize
	}
	bandwidthPrice, overflow := settings.DownloadBandwidthPrice.Mul64WithOverflow(bandwidth)
	if overflow {
		return types.MaxCurrency
	}
	return settings.BaseRPCPrice.Add(sectorAccessPrice).Add(bandwidthPrice)
}

// RPCAppendCost returns the price and collateral of a Write RPC with a single
// append operation.
func RPCAppendCost(settings HostSettings, storageDuration uint64) (price, collateral types.Currency) {
	storageCost, overflow := settings.StoragePrice.Mul64WithOverflow(SectorSize)
	if overflow {
		return types.MaxCurrency, types.MaxCurrency
	}
	storageCost, overflow = storageCost.Mul64WithOverflow(storageDuration)
	if overflow {
		return types.MaxCurrency, types.MaxCurrency
	}
	uploadCost, overflow := settings.UploadBandwidthPrice.Mul64WithOverflow(SectorSize)
	if overflow {
		return types.MaxCurrency, types.MaxCurrency
	}
	downloadCost, overflow := settings.DownloadBandwidthPrice.Mul64WithOverflow(128 * 32) // proof
	if overflow {
		return types.MaxCurrency, types.MaxCurrency
	}
	price = settings.BaseRPCPrice.Add(storageCost).Add(uploadCost).Add(downloadCost)
	collateral, overflow = settings.Collateral.Mul64WithOverflow(SectorSize)
	if overflow {
		return types.MaxCurrency, types.MaxCurrency
	}
	collateral, overflow = collateral.Mul64WithOverflow(storageDuration)
	if overflow {
		return types.MaxCurrency, types.MaxCurrency
	}
	// add some leeway to reduce chance of host rejecting
	price, overflow = price.Mul64WithOverflow(125)
	if overflow {
		return types.MaxCurrency, types.MaxCurrency
	}
	price = price.Div64(100)
	collateral, overflow = collateral.Mul64WithOverflow(95)
	if overflow {
		return types.MaxCurrency, types.MaxCurrency
	}
	collateral = collateral.Div64(100)
	return
}

// RPCDeleteCost returns the price of a Write RPC that deletes n sectors.
func RPCDeleteCost(settings HostSettings, n int) types.Currency {
	price, overflow := settings.DownloadBandwidthPrice.Mul64WithOverflow(128 * 32) // proof
	if overflow {
		return types.MaxCurrency
	}
	price = settings.BaseRPCPrice.Add(price)
	price, overflow = price.Mul64WithOverflow(105)
	if overflow {
		return types.MaxCurrency
	}
	return price.Div64(100)
}
