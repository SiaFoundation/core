// Package rhp implements the Sia renter-host protocol, version 2.
package rhp

import (
	"encoding/json"
	"errors"
	"fmt"
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
func (hs HostSettings) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"acceptingcontracts":         hs.AcceptingContracts,
		"maxdownloadbatchsize":       hs.MaxDownloadBatchSize,
		"maxduration":                hs.MaxDuration,
		"maxrevisebatchsize":         hs.MaxReviseBatchSize,
		"netaddress":                 hs.NetAddress,
		"remainingstorage":           hs.RemainingStorage,
		"sectorsize":                 hs.SectorSize,
		"totalstorage":               hs.TotalStorage,
		"unlockhash":                 strings.TrimPrefix(hs.Address.String(), "addr:"), // trim the "addr:" prefix for compatibility with siad
		"windowsize":                 hs.WindowSize,
		"collateral":                 hs.Collateral,
		"maxcollateral":              hs.MaxCollateral,
		"baserpcprice":               hs.BaseRPCPrice,
		"contractprice":              hs.ContractPrice,
		"downloadbandwidthprice":     hs.DownloadBandwidthPrice,
		"sectoraccessprice":          hs.SectorAccessPrice,
		"storageprice":               hs.StoragePrice,
		"uploadbandwidthprice":       hs.UploadBandwidthPrice,
		"ephemeralaccountexpiry":     hs.EphemeralAccountExpiry,
		"maxephemeralaccountbalance": hs.MaxEphemeralAccountBalance,
		"revisionnumber":             hs.RevisionNumber,
		"version":                    hs.Version,
		"siamuxport":                 hs.SiaMuxPort,
	})
}

// SiamuxAddr is a helper which returns an address that can be used to connect
// to the host's siamux.
func (hs HostSettings) SiamuxAddr() string {
	host, _, err := net.SplitHostPort(hs.NetAddress)
	if err != nil || host == "" {
		return ""
	}
	return net.JoinHostPort(host, hs.SiaMuxPort)
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

// RPC read/write errors
var (
	// ErrOffsetOutOfBounds is returned when the offset exceeds and length
	// exceed the sector size.
	ErrOffsetOutOfBounds = errors.New("update section is out of bounds")

	// ErrInvalidSectorLength is returned when a sector is not the correct
	// length.
	ErrInvalidSectorLength = errors.New("length of sector data must be exactly 4MiB")
	// ErrSwapOutOfBounds is returned when one of the swap indices exceeds the
	// total number of sectors
	ErrSwapOutOfBounds = errors.New("swap index is out of bounds")
	// ErrTrimOutOfBounds is returned when a trim operation exceeds the total
	// number of sectors
	ErrTrimOutOfBounds = errors.New("trim size exceeds number of sectors")
	// ErrUpdateOutOfBounds is returned when the update index exceeds the total
	// number of sectors
	ErrUpdateOutOfBounds = errors.New("update index is out of bounds")
	// ErrUpdateProofSize is returned when a proof is requested for an update
	// operation that is not a multiple of 64 bytes.
	ErrUpdateProofSize = errors.New("update section is not a multiple of the segment size")
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

// RPCCost represents the cost of an RPC based on a hosts settings.
type RPCCost struct {
	Base       types.Currency
	Storage    types.Currency
	Ingress    types.Currency
	Egress     types.Currency
	Collateral types.Currency
}

// Add adds two RPCCosts by adding each of the constituent costs together.
func (c RPCCost) Add(o RPCCost) RPCCost {
	return RPCCost{
		Base:       c.Base.Add(o.Base),
		Storage:    c.Storage.Add(o.Storage),
		Ingress:    c.Ingress.Add(o.Ingress),
		Egress:     c.Egress.Add(o.Egress),
		Collateral: c.Collateral.Add(o.Collateral),
	}
}

// Total returns the total cost and collateral required for an RPC call.
func (c RPCCost) Total() (cost, collateral types.Currency) {
	return c.Base.Add(c.Storage).Add(c.Ingress).Add(c.Egress), c.Collateral
}

// RPCReadCost returns the cost of a Read RPC.
func (hs HostSettings) RPCReadCost(sections []RPCReadRequestSection, proof bool) (RPCCost, error) {
	// validate the request sections and calculate the cost
	var bandwidth uint64
	for _, sec := range sections {
		switch {
		case uint64(sec.Offset)+uint64(sec.Length) > SectorSize:
			return RPCCost{}, ErrOffsetOutOfBounds
		case sec.Length == 0:
			return RPCCost{}, errors.New("length cannot be zero")
		case proof && (sec.Offset%LeafSize != 0 || sec.Length%LeafSize != 0):
			return RPCCost{}, errors.New("offset and length must be multiples of LeafSize when requesting a Merkle proof")
		}

		bandwidth += uint64(sec.Length)
		if proof {
			start := sec.Offset / LeafSize
			end := (sec.Offset + sec.Length) / LeafSize
			proofSize := RangeProofSize(LeavesPerSector, start, end)
			bandwidth += proofSize * 32
		}
	}

	return RPCCost{
		Base:   hs.BaseRPCPrice.Add(hs.SectorAccessPrice.Mul64(uint64(len(sections)))),
		Egress: hs.DownloadBandwidthPrice.Mul64(bandwidth),
	}, nil
}

// RPCSectorRootsCost returns the cost of a SectorRoots RPC.
func (hs HostSettings) RPCSectorRootsCost(rootOffset, numRoots uint64) RPCCost {
	proofSize := RangeProofSize(LeavesPerSector, rootOffset, rootOffset+numRoots)
	return RPCCost{
		Base:   hs.BaseRPCPrice,
		Egress: hs.DownloadBandwidthPrice.Mul64((numRoots + proofSize) * 32),
	}
}

// RPCWriteCost returns the cost of a Write RPC.
func (hs HostSettings) RPCWriteCost(actions []RPCWriteAction, oldSectors, remainingDuration uint64, proof bool) (RPCCost, error) {
	var uploadBytes uint64
	newSectors := oldSectors
	for _, action := range actions {
		switch action.Type {
		case RPCWriteActionAppend:
			if len(action.Data) != SectorSize {
				return RPCCost{}, fmt.Errorf("invalid sector size: %v: %w", len(action.Data), ErrInvalidSectorLength)
			}
			newSectors++
			uploadBytes += SectorSize
		case RPCWriteActionTrim:
			if action.A > newSectors {
				return RPCCost{}, ErrTrimOutOfBounds
			}
			newSectors -= action.A
		case RPCWriteActionSwap:
			if action.A >= newSectors || action.B >= newSectors {
				return RPCCost{}, ErrSwapOutOfBounds
			}
		case RPCWriteActionUpdate:
			idx, offset := action.A, action.B
			if idx >= newSectors {
				return RPCCost{}, ErrUpdateOutOfBounds
			} else if offset+uint64(len(action.Data)) > SectorSize {
				return RPCCost{}, ErrOffsetOutOfBounds
			} else if proof && (offset%LeafSize != 0) || len(action.Data)%LeafSize != 0 {
				return RPCCost{}, ErrUpdateProofSize
			}
		default:
			return RPCCost{}, fmt.Errorf("unknown write action type '%v'", action.Type)
		}
	}

	cost := RPCCost{
		Base:    hs.BaseRPCPrice,                            // base cost of the RPC
		Ingress: hs.UploadBandwidthPrice.Mul64(uploadBytes), // cost of uploading the new sectors
	}

	if newSectors > oldSectors {
		additionalSectors := (newSectors - oldSectors)
		cost.Storage = hs.StoragePrice.Mul64(SectorSize * additionalSectors * remainingDuration)  // cost of storing the new sectors
		cost.Collateral = hs.Collateral.Mul64(SectorSize * additionalSectors * remainingDuration) // collateral for the new sectors
	}

	if proof {
		// estimate cost of Merkle proof
		proofSize := DiffProofSize(actions, oldSectors)
		cost.Egress = hs.DownloadBandwidthPrice.Mul64(proofSize * 32)
	}
	return cost, nil
}
