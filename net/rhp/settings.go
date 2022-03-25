package rhp

import (
	"time"

	"go.sia.tech/core/types"
)

// A SettingsID is a unique identifier for registered host settings used by renters
// when interacting with the host.
type SettingsID [16]byte

// MaxLen returns the maximum length of an encoded object. Implements rpc.Object.
func (id *SettingsID) MaxLen() int {
	return 16
}

// EncodeTo encodes a SettingsID to an encoder. Implements types.EncoderTo.
func (id *SettingsID) EncodeTo(e *types.Encoder) {
	e.Write(id[:])
}

// DecodeFrom decodes a SettingsID from a decoder. Implements types.DecoderFrom.
func (id *SettingsID) DecodeFrom(d *types.Decoder) {
	d.Read(id[:])
}

// HostSettings are the settings and prices used when interacting with a host.
type HostSettings struct {
	AcceptingContracts         bool           `json:"acceptingContracts"`
	Address                    types.Address  `json:"address"`
	BlockHeight                uint64         `json:"blockHeight"`
	EphemeralAccountExpiry     time.Duration  `json:"ephemeralAccountExpiry"`
	MaxCollateral              types.Currency `json:"maxCollateral"`
	MaxDuration                uint64         `json:"maxDuration"`
	MaxEphemeralAccountBalance types.Currency `json:"maxEphemeralAccountBalance"`
	NetAddress                 string         `json:"netAddress"`
	RemainingRegistryEntries   uint64         `json:"remainingRegistryEntries"`
	RemainingStorage           uint64         `json:"remainingStorage"`
	SectorSize                 uint64         `json:"sectorSize"`
	TotalRegistryEntries       uint64         `json:"totalRegistryEntries"`
	TotalStorage               uint64         `json:"totalStorage"`
	ValidUntil                 time.Time      `json:"validUntil"`
	Version                    string         `json:"version"`
	WindowSize                 uint64         `json:"windowSize"`

	ContractFee types.Currency `json:"contractFee"`
	// Collateral is the amount of Hastings per byte per block that the host is willing to risk.
	Collateral types.Currency `json:"collateral"`
	// DownloadBandwidthPrice is the amount of Hastings per byte of download data charged to the renter.
	DownloadBandwidthPrice types.Currency `json:"downloadBandwidthPrice"`
	// UploadBandwidthPrice is the amount of Hastings per byte of upload data charged to the renter.
	UploadBandwidthPrice types.Currency `json:"uploadBandwidthPrice"`
	// StoragePrice is the amount of Hastings per byte per block to store data on the host.
	StoragePrice types.Currency `json:"storagePrice"`

	RPCAccountBalanceCost types.Currency `json:"rpcAccountBalanceCost"`
	RPCFundAccountCost    types.Currency `json:"rpcFundAccountCost"`
	RPCHostSettingsCost   types.Currency `json:"rpcHostSettingsCost"`
	RPCLatestRevisionCost types.Currency `json:"rpcLatestRevisionCost"`

	// ProgInitBaseCost is the cost in Hastings that is incurred when an MDM
	// program starts to run. This doesn't include the memory used by the
	// program data. The total cost to initialize a program is calculated as
	// InitCost = InitBaseCost + MemoryTimeCost * Time
	ProgInitBaseCost types.Currency `json:"progInitBaseCost"`
	// ProgMemoryTimeCost is the cost in Hastings per byte per time that is
	// incurred by the memory consumption of the program.
	ProgMemoryTimeCost types.Currency `json:"progMemorytimecost"`
	// ProgReadCost is the cost in Hastings per byte of data read from disk during program executions.
	ProgReadCost types.Currency `json:"progReadCost"`
	// ProgWriteCost is the cost in Hastings per byte, rounded up to the nearest multiple of 4KiB, of data written to
	// disk during program execution.
	ProgWriteCost types.Currency `json:"progWriteCost"`

	InstrAppendSectorBaseCost   types.Currency `json:"instrAppendSectorsBaseCost"`
	InstrDropSectorsBaseCost    types.Currency `json:"instrDropSectorsBaseCost"`
	InstrDropSectorsUnitCost    types.Currency `json:"instrDropSectorsUnitCost"`
	InstrHasSectorBaseCost      types.Currency `json:"instrHasSectorBaseCost"`
	InstrReadBaseCost           types.Currency `json:"instrReadBaseCost"`
	InstrReadRegistryBaseCost   types.Currency `json:"instrReadRegistryBaseCost"`
	InstrRevisionBaseCost       types.Currency `json:"instrRevisionBaseCost"`
	InstrSectorRootsBaseCost    types.Currency `json:"instrSectorRootsBaseCost"`
	InstrSwapSectorBaseCost     types.Currency `json:"instrSwapSectorCost"`
	InstrUpdateRegistryBaseCost types.Currency `json:"instrUpdateRegistryBaseCost"`
	InstrUpdateSectorBaseCost   types.Currency `json:"instrUpdateSectorBaseCost"`
	InstrWriteBaseCost          types.Currency `json:"instrWriteBaseCost"`
}

// EncodeTo encodes host settings to the encoder; implements types.EncoderTo.
func (p *HostSettings) EncodeTo(e *types.Encoder) {
	e.WriteTime(p.ValidUntil)
	e.WriteBool(p.AcceptingContracts)
	e.WriteUint64(p.BlockHeight)
	e.WriteUint64(uint64(p.EphemeralAccountExpiry))
	p.MaxCollateral.EncodeTo(e)
	e.WriteUint64(p.MaxDuration)
	p.MaxEphemeralAccountBalance.EncodeTo(e)
	e.WriteString(p.NetAddress)
	e.WriteUint64(p.RemainingStorage)
	e.WriteUint64(p.TotalStorage)
	e.WriteUint64(p.RemainingRegistryEntries)
	e.WriteUint64(p.TotalRegistryEntries)
	e.WriteUint64(p.SectorSize)
	p.Address.EncodeTo(e)
	e.WriteString(p.Version)
	e.WriteUint64(p.WindowSize)
	p.ContractFee.EncodeTo(e)
	p.Collateral.EncodeTo(e)
	p.DownloadBandwidthPrice.EncodeTo(e)
	p.UploadBandwidthPrice.EncodeTo(e)
	p.StoragePrice.EncodeTo(e)
	p.RPCAccountBalanceCost.EncodeTo(e)
	p.RPCFundAccountCost.EncodeTo(e)
	p.RPCLatestRevisionCost.EncodeTo(e)
	p.RPCHostSettingsCost.EncodeTo(e)
	p.ProgInitBaseCost.EncodeTo(e)
	p.ProgMemoryTimeCost.EncodeTo(e)
	p.ProgReadCost.EncodeTo(e)
	p.ProgWriteCost.EncodeTo(e)
	p.InstrDropSectorsBaseCost.EncodeTo(e)
	p.InstrDropSectorsUnitCost.EncodeTo(e)
	p.InstrHasSectorBaseCost.EncodeTo(e)
	p.InstrReadBaseCost.EncodeTo(e)
	p.InstrSwapSectorBaseCost.EncodeTo(e)
	p.InstrRevisionBaseCost.EncodeTo(e)
	p.InstrWriteBaseCost.EncodeTo(e)
}

// DecodeFrom decodes host settings from the decoder; implements types.DecoderFrom.
func (p *HostSettings) DecodeFrom(d *types.Decoder) {
	p.ValidUntil = d.ReadTime()
	p.AcceptingContracts = d.ReadBool()
	p.BlockHeight = d.ReadUint64()
	p.EphemeralAccountExpiry = time.Duration(d.ReadUint64())
	p.MaxCollateral.DecodeFrom(d)
	p.MaxDuration = d.ReadUint64()
	p.MaxEphemeralAccountBalance.DecodeFrom(d)
	p.NetAddress = d.ReadString()
	p.RemainingStorage = d.ReadUint64()
	p.TotalStorage = d.ReadUint64()
	p.RemainingRegistryEntries = d.ReadUint64()
	p.TotalRegistryEntries = d.ReadUint64()
	p.SectorSize = d.ReadUint64()
	p.Address.DecodeFrom(d)
	p.Version = d.ReadString()
	p.WindowSize = d.ReadUint64()
	p.ContractFee.DecodeFrom(d)
	p.Collateral.DecodeFrom(d)
	p.DownloadBandwidthPrice.DecodeFrom(d)
	p.UploadBandwidthPrice.DecodeFrom(d)
	p.StoragePrice.DecodeFrom(d)
	p.RPCAccountBalanceCost.DecodeFrom(d)
	p.RPCFundAccountCost.DecodeFrom(d)
	p.RPCLatestRevisionCost.DecodeFrom(d)
	p.RPCHostSettingsCost.DecodeFrom(d)
	p.ProgInitBaseCost.DecodeFrom(d)
	p.ProgMemoryTimeCost.DecodeFrom(d)
	p.ProgReadCost.DecodeFrom(d)
	p.ProgWriteCost.DecodeFrom(d)
	p.InstrDropSectorsBaseCost.DecodeFrom(d)
	p.InstrDropSectorsUnitCost.DecodeFrom(d)
	p.InstrHasSectorBaseCost.DecodeFrom(d)
	p.InstrReadBaseCost.DecodeFrom(d)
	p.InstrSwapSectorBaseCost.DecodeFrom(d)
	p.InstrRevisionBaseCost.DecodeFrom(d)
	p.InstrWriteBaseCost.DecodeFrom(d)
}

// MaxLen implements rpc.Object.
func (p *HostSettings) MaxLen() int {
	// UUID + bool + 25 types.Currency fields + 9 uint64 fields + version string + netaddress string
	// netaddress maximum is based on RFC 1035 https://www.freesoft.org/CIE/RFC/1035/9.htm.
	return 16 + 1 + (25 * 16) + (9 * 8) + 10 + 256
}
