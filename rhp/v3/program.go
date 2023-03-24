package rhp

import (
	"go.sia.tech/core/types"
)

type (
	// An Instruction is an MDM instruction.
	Instruction interface {
		ProtocolObject
		RequiresContract() bool
		RequiresFinalization() bool
	}

	// InstrAppendSector stores a sector on the host and appends its Merkle root
	// to a contract.
	InstrAppendSector struct {
		SectorDataOffset uint64
		ProofRequired    bool
	}

	// InstrAppendSectorRoot appends a sector root to a contract
	InstrAppendSectorRoot struct {
		MerkleRootOffset uint64
		ProofRequired    bool
	}

	// InstrDropSectors removes the last n sectors from a contract and deletes
	// them from the host.
	InstrDropSectors struct {
		SectorCountOffset uint64
		ProofRequired     bool
	}

	// InstrHasSector checks if a sector is present on the host.
	InstrHasSector struct {
		MerkleRootOffset uint64
	}

	// InstrReadOffset reads a range of bytes from an offset in the contract.
	InstrReadOffset struct {
		LengthOffset  uint64
		OffsetOffset  uint64
		ProofRequired bool
	}

	// InstrReadSector reads a range of bytes from a sector.
	InstrReadSector struct {
		LengthOffset     uint64
		OffsetOffset     uint64
		MerkleRootOffset uint64
		ProofRequired    bool
	}

	// InstrSwapSector swaps two sectors in a contract
	InstrSwapSector struct {
		Sector1Offset uint64
		Sector2Offset uint64
		ProofRequired bool
	}

	// InstrUpdateSector overwrites data in an existing sector.
	InstrUpdateSector struct {
		Offset        uint64
		Length        uint64
		DataOffset    uint64
		ProofRequired bool
	}

	// InstrStoreSector temporarily stores a sector on the host. The sector is
	// not associated with any contract and collateral is not risked.
	InstrStoreSector struct {
		DataOffset uint64
		Duration   uint64
	}

	// InstrRevision returns the latest revision of a contract
	InstrRevision struct{}

	// InstrReadRegistry reads a value from the registry
	InstrReadRegistry struct {
		PublicKeyOffset uint64
		PublicKeyLength uint64
		TweakOffset     uint64
		Version         uint8
	}

	// InstrReadRegistryNoVersion reads a pre-1.5.7 read registry Instruction
	// without the version byte
	InstrReadRegistryNoVersion struct {
		InstrReadRegistry
	}

	// InstrUpdateRegistry updates a registry value.
	InstrUpdateRegistry struct {
		TweakOffset     uint64
		RevisionOffset  uint64
		SignatureOffset uint64
		PublicKeyOffset uint64
		PublicKeyLength uint64
		DataOffset      uint64
		DataLength      uint64
		EntryType       uint8
	}

	// InstrUpdateRegistryNoType reads a pre-1.5.7 update registry Instruction
	// without the entry type byte
	InstrUpdateRegistryNoType struct {
		InstrUpdateRegistry
	}
)

var (
	idInstrAppendSector     = types.NewSpecifier("Append")
	idInstrAppendSectorRoot = types.NewSpecifier("AppendSectorRoot")
	idInstrDropSectors      = types.NewSpecifier("DropSectors")
	idInstrHasSector        = types.NewSpecifier("HasSector")
	idInstrStoreSector      = types.NewSpecifier("StoreSector")
	idInstrUpdateSector     = types.NewSpecifier("UpdateSector")
	idInstrReadOffset       = types.NewSpecifier("ReadOffset")
	idInstrReadSector       = types.NewSpecifier("ReadSector")
	idInstrContractRevision = types.NewSpecifier("Revision")
	idInstrSwapSector       = types.NewSpecifier("SwapSector")
	idInstrUpdateRegistry   = types.NewSpecifier("UpdateRegistry")
	idInstrReadRegistry     = types.NewSpecifier("ReadRegistry")
	idInstrReadRegistrySID  = types.NewSpecifier("ReadRegistrySID")
)

// RequiresContract implements Instruction.
func (i *InstrAppendSector) RequiresContract() bool {
	return true
}

// RequiresFinalization implements Instruction.
func (i *InstrAppendSector) RequiresFinalization() bool {
	return true
}

// EncodeTo implements Instruction.
func (i *InstrAppendSector) EncodeTo(e *types.Encoder) {
	e.WriteUint64(i.SectorDataOffset)
	e.WriteBool(i.ProofRequired)
}

// DecodeFrom implements Instruction.
func (i *InstrAppendSector) DecodeFrom(d *types.Decoder) {
	i.SectorDataOffset = d.ReadUint64()
	i.ProofRequired = d.ReadBool()
}

// RequiresContract implements Instruction.
func (i *InstrAppendSectorRoot) RequiresContract() bool {
	return true
}

// RequiresFinalization implements Instruction.
func (i *InstrAppendSectorRoot) RequiresFinalization() bool {
	return true
}

// EncodeTo implements Instruction.
func (i *InstrAppendSectorRoot) EncodeTo(e *types.Encoder) {
	e.WriteUint64(i.MerkleRootOffset)
	e.WriteBool(i.ProofRequired)
}

// DecodeFrom implements Instruction.
func (i *InstrAppendSectorRoot) DecodeFrom(d *types.Decoder) {
	i.MerkleRootOffset = d.ReadUint64()
	i.ProofRequired = d.ReadBool()
}

// RequiresContract implements Instruction.
func (i *InstrDropSectors) RequiresContract() bool {
	return true
}

// RequiresFinalization implements Instruction.
func (i *InstrDropSectors) RequiresFinalization() bool {
	return true
}

// EncodeTo implements Instruction.
func (i *InstrDropSectors) EncodeTo(e *types.Encoder) {
	e.WriteUint64(i.SectorCountOffset)
	e.WriteBool(i.ProofRequired)
}

// DecodeFrom implements Instruction.
func (i *InstrDropSectors) DecodeFrom(d *types.Decoder) {
	i.SectorCountOffset = d.ReadUint64()
	i.ProofRequired = d.ReadBool()
}

// RequiresContract implements Instruction.
func (i *InstrHasSector) RequiresContract() bool {
	return false
}

// RequiresFinalization implements Instruction.
func (i *InstrHasSector) RequiresFinalization() bool {
	return false
}

// EncodeTo implements Instruction.
func (i *InstrHasSector) EncodeTo(e *types.Encoder) {
	e.WriteUint64(i.MerkleRootOffset)
}

// DecodeFrom implements Instruction.
func (i *InstrHasSector) DecodeFrom(d *types.Decoder) {
	i.MerkleRootOffset = d.ReadUint64()
}

// RequiresContract implements Instruction.
func (i *InstrReadOffset) RequiresContract() bool {
	return true
}

// RequiresFinalization implements Instruction.
func (i *InstrReadOffset) RequiresFinalization() bool {
	return false
}

// EncodeTo implements Instruction.
func (i *InstrReadOffset) EncodeTo(e *types.Encoder) {
	e.WriteUint64(i.OffsetOffset)
	e.WriteUint64(i.LengthOffset)
	e.WriteBool(i.ProofRequired)
}

// DecodeFrom implements Instruction.
func (i *InstrReadOffset) DecodeFrom(d *types.Decoder) {
	i.OffsetOffset = d.ReadUint64()
	i.LengthOffset = d.ReadUint64()
	i.ProofRequired = d.ReadBool()
}

// RequiresContract implements Instruction.
func (i *InstrReadSector) RequiresContract() bool {
	return false
}

// RequiresFinalization implements Instruction.
func (i *InstrReadSector) RequiresFinalization() bool {
	return false
}

// EncodeTo implements Instruction.
func (i *InstrReadSector) EncodeTo(e *types.Encoder) {
	e.WriteUint64(i.MerkleRootOffset)
	e.WriteUint64(i.OffsetOffset)
	e.WriteUint64(i.LengthOffset)
	e.WriteBool(i.ProofRequired)
}

// DecodeFrom implements Instruction.
func (i *InstrReadSector) DecodeFrom(d *types.Decoder) {
	i.MerkleRootOffset = d.ReadUint64()
	i.OffsetOffset = d.ReadUint64()
	i.LengthOffset = d.ReadUint64()
	i.ProofRequired = d.ReadBool()
}

// RequiresContract implements Instruction.
func (i *InstrSwapSector) RequiresContract() bool {
	return true
}

// RequiresFinalization implements Instruction.
func (i *InstrSwapSector) RequiresFinalization() bool {
	return true
}

// EncodeTo implements Instruction.
func (i *InstrSwapSector) EncodeTo(e *types.Encoder) {
	e.WriteUint64(i.Sector1Offset)
	e.WriteUint64(i.Sector2Offset)
	e.WriteBool(i.ProofRequired)
}

// DecodeFrom implements Instruction.
func (i *InstrSwapSector) DecodeFrom(d *types.Decoder) {
	i.Sector1Offset = d.ReadUint64()
	i.Sector2Offset = d.ReadUint64()
	i.ProofRequired = d.ReadBool()
}

// RequiresContract implements Instruction.
func (i *InstrUpdateSector) RequiresContract() bool {
	return true
}

// RequiresFinalization implements Instruction.
func (i *InstrUpdateSector) RequiresFinalization() bool {
	return true
}

// EncodeTo implements Instruction.
func (i *InstrUpdateSector) EncodeTo(e *types.Encoder) {
	e.WriteUint64(i.Offset)
	e.WriteUint64(i.Length)
	e.WriteUint64(i.DataOffset)
	e.WriteBool(i.ProofRequired)
}

// DecodeFrom implements Instruction.
func (i *InstrUpdateSector) DecodeFrom(d *types.Decoder) {
	i.Offset = d.ReadUint64()
	i.Length = d.ReadUint64()
	i.DataOffset = d.ReadUint64()
	i.ProofRequired = d.ReadBool()
}

// RequiresContract implements Instruction.
func (i *InstrStoreSector) RequiresContract() bool {
	return false
}

// RequiresFinalization implements Instruction.
func (i *InstrStoreSector) RequiresFinalization() bool {
	return false
}

// EncodeTo implements Instruction.
func (i *InstrStoreSector) EncodeTo(e *types.Encoder) {
	e.WriteUint64(i.DataOffset)
	e.WriteUint64(i.Duration)
}

// DecodeFrom implements Instruction.
func (i *InstrStoreSector) DecodeFrom(d *types.Decoder) {
	i.DataOffset = d.ReadUint64()
	i.Duration = d.ReadUint64()
}

// RequiresContract implements Instruction.
func (i *InstrRevision) RequiresContract() bool {
	return true
}

// RequiresFinalization implements Instruction.
func (i *InstrRevision) RequiresFinalization() bool {
	return false
}

// EncodeTo implements Instruction.
func (i *InstrRevision) EncodeTo(e *types.Encoder) {
}

// DecodeFrom implements Instruction.
func (i *InstrRevision) DecodeFrom(d *types.Decoder) {
}

// RequiresContract implements Instruction.
func (i *InstrReadRegistry) RequiresContract() bool {
	return false
}

// RequiresFinalization implements Instruction.
func (i *InstrReadRegistry) RequiresFinalization() bool {
	return false
}

// EncodeTo implements Instruction.
func (i *InstrReadRegistry) EncodeTo(e *types.Encoder) {
	e.WriteUint64(i.PublicKeyOffset)
	e.WriteUint64(i.PublicKeyLength)
	e.WriteUint64(i.TweakOffset)
	e.WriteUint8(i.Version)
}

// DecodeFrom implements Instruction.
func (i *InstrReadRegistry) DecodeFrom(d *types.Decoder) {
	i.PublicKeyOffset = d.ReadUint64()
	i.PublicKeyLength = d.ReadUint64()
	i.TweakOffset = d.ReadUint64()
	i.Version = d.ReadUint8()
}

// EncodeTo implements Instruction.
func (i *InstrReadRegistryNoVersion) EncodeTo(e *types.Encoder) {
	e.WriteUint64(i.PublicKeyOffset)
	e.WriteUint64(i.PublicKeyLength)
	e.WriteUint64(i.TweakOffset)
}

// DecodeFrom implements Instruction.
func (i *InstrReadRegistryNoVersion) DecodeFrom(d *types.Decoder) {
	i.PublicKeyOffset = d.ReadUint64()
	i.PublicKeyLength = d.ReadUint64()
	i.TweakOffset = d.ReadUint64()
	i.Version = 1
}

// RequiresContract implements Instruction.
func (i *InstrUpdateRegistry) RequiresContract() bool {
	return false
}

// RequiresFinalization implements Instruction.
func (i *InstrUpdateRegistry) RequiresFinalization() bool {
	return false
}

// EncodeTo implements Instruction.
func (i *InstrUpdateRegistry) EncodeTo(e *types.Encoder) {
	e.WriteUint64(i.TweakOffset)
	e.WriteUint64(i.RevisionOffset)
	e.WriteUint64(i.SignatureOffset)
	e.WriteUint64(i.PublicKeyOffset)
	e.WriteUint64(i.PublicKeyLength)
	e.WriteUint64(i.DataOffset)
	e.WriteUint64(i.DataLength)
	e.WriteUint8(uint8(i.EntryType))
}

// DecodeFrom implements Instruction.
func (i *InstrUpdateRegistry) DecodeFrom(d *types.Decoder) {
	i.TweakOffset = d.ReadUint64()
	i.RevisionOffset = d.ReadUint64()
	i.SignatureOffset = d.ReadUint64()
	i.PublicKeyOffset = d.ReadUint64()
	i.PublicKeyLength = d.ReadUint64()
	i.DataOffset = d.ReadUint64()
	i.DataLength = d.ReadUint64()
	i.EntryType = d.ReadUint8()
}

// EncodeTo implements Instruction.
func (i *InstrUpdateRegistryNoType) EncodeTo(e *types.Encoder) {
	e.WriteUint64(i.TweakOffset)
	e.WriteUint64(i.RevisionOffset)
	e.WriteUint64(i.SignatureOffset)
	e.WriteUint64(i.PublicKeyOffset)
	e.WriteUint64(i.PublicKeyLength)
	e.WriteUint64(i.DataOffset)
	e.WriteUint64(i.DataLength)
}

// DecodeFrom implements Instruction.
func (i *InstrUpdateRegistryNoType) DecodeFrom(d *types.Decoder) {
	i.TweakOffset = d.ReadUint64()
	i.RevisionOffset = d.ReadUint64()
	i.SignatureOffset = d.ReadUint64()
	i.PublicKeyOffset = d.ReadUint64()
	i.PublicKeyLength = d.ReadUint64()
	i.DataOffset = d.ReadUint64()
	i.DataLength = d.ReadUint64()
	i.EntryType = EntryTypeArbitrary
}
