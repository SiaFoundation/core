package rhp

import (
	"bytes"
	"errors"
	"fmt"

	"go.sia.tech/core/types"
)

// A ProgramBuilder constructs MDM programs for the renter to execute on a host.
type ProgramBuilder struct {
	instructions         []Instruction
	requiresFinalization bool
	requiresContract     bool
	encoder              *types.Encoder
	data                 *bytes.Buffer
	offset               uint64
	usage                ResourceUsage

	duration uint64
	settings HostSettings
}

func (pb *ProgramBuilder) addUsage(usage ResourceUsage) {
	pb.usage = pb.usage.Add(usage)
}

func (pb *ProgramBuilder) appendInstruction(instr Instruction) {
	pb.requiresContract = pb.requiresContract || instr.RequiresContract()
	pb.requiresFinalization = pb.requiresFinalization || instr.RequiresFinalization()
	pb.instructions = append(pb.instructions, instr)
}

// AddAppendSectorInstruction adds an append sector instruction to the program.
func (pb *ProgramBuilder) AddAppendSectorInstruction(sector *[SectorSize]byte, proof bool) {
	instr := &InstrAppendSector{
		SectorDataOffset: pb.offset,
		ProofRequired:    proof,
	}
	pb.encoder.Write(sector[:])
	pb.offset += SectorSize
	pb.appendInstruction(instr)
	pb.addUsage(AppendSectorCost(pb.settings, pb.duration))
}

// AddDropSectorInstruction adds a drop sector instruction to the program.
func (pb *ProgramBuilder) AddDropSectorInstruction(sectors uint64, proof bool) {
	instr := &InstrDropSectors{
		SectorCountOffset: pb.offset,
		ProofRequired:     proof,
	}
	pb.encoder.WriteUint64(sectors)
	pb.offset += 8
	pb.appendInstruction(instr)
	pb.addUsage(DropSectorsCost(pb.settings, sectors))
}

// AddHasSectorInstruction adds a has sector instruction to the program.
func (pb *ProgramBuilder) AddHasSectorInstruction(root types.Hash256) {
	instr := &InstrHasSector{
		SectorRootOffset: pb.offset,
	}
	root.EncodeTo(pb.encoder)
	pb.offset += 32
	pb.appendInstruction(instr)
	pb.addUsage(HasSectorCost(pb.settings))
}

// AddReadSectorInstruction adds a read sector instruction to the program.
func (pb *ProgramBuilder) AddReadSectorInstruction(root types.Hash256, offset uint64, length uint64, proof bool) error {
	if offset+length > SectorSize {
		return errors.New("read offset + length exceeds sector size")
	}

	instr := &InstrReadSector{
		RootOffset:    pb.offset,
		SectorOffset:  pb.offset + 32,
		LengthOffset:  pb.offset + 40,
		ProofRequired: proof,
	}
	root.EncodeTo(pb.encoder)
	pb.encoder.WriteUint64(offset)
	pb.encoder.WriteUint64(length)
	pb.offset += 48
	pb.appendInstruction(instr)
	pb.addUsage(ReadCost(pb.settings, length))
	return nil
}

// AddReadOffsetInstruction adds a read offset instruction to the program.
func (pb *ProgramBuilder) AddReadOffsetInstruction(offset, length uint64, proof bool) {
	instr := &InstrReadOffset{
		DataOffset:    pb.offset,
		LengthOffset:  pb.offset + 8,
		ProofRequired: proof,
	}
	pb.encoder.WriteUint64(offset)
	pb.encoder.WriteUint64(length)
	pb.offset += 16
	pb.appendInstruction(instr)
	pb.addUsage(ReadCost(pb.settings, length))
}

// AddDropSectorsInstruction adds a drop sectors instruction to the program.
func (pb *ProgramBuilder) AddDropSectorsInstruction(sectors uint64, proof bool) {
	instr := &InstrDropSectors{
		SectorCountOffset: pb.offset,
		ProofRequired:     proof,
	}
	pb.encoder.WriteUint64(sectors)
	pb.offset += 8
	pb.appendInstruction(instr)
	pb.addUsage(DropSectorsCost(pb.settings, sectors))
}

// AddRevisionInstruction adds a revision instruction to the program.
func (pb *ProgramBuilder) AddRevisionInstruction() {
	pb.appendInstruction(&InstrContractRevision{})
	pb.addUsage(RevisionCost(pb.settings))
}

// AddSwapSectorInstruction adds a swap sector instruction to the program.
func (pb *ProgramBuilder) AddSwapSectorInstruction(i, j uint64, proof bool) {
	instr := &InstrSwapSector{
		RootAOffset:   pb.offset,
		RootBOffset:   pb.offset + 32,
		ProofRequired: proof,
	}
	pb.encoder.WriteUint64(i)
	pb.encoder.WriteUint64(j)
	pb.offset += 64
	pb.appendInstruction(instr)
	pb.addUsage(SwapSectorCost(pb.settings))
}

// AddUpdateRegistryInstruction adds an update registry instruction to the program.
func (pb *ProgramBuilder) AddUpdateRegistryInstruction(value RegistryValue) {
	instr := &InstrUpdateRegistry{
		EntryOffset: pb.offset,
	}
	value.EncodeTo(pb.encoder)
	// TODO: ?
	if err := pb.encoder.Flush(); err != nil {
		panic(err) // should never happen
	}
	pb.offset = uint64(pb.data.Len())
	pb.appendInstruction(instr)
	pb.addUsage(UpdateRegistryCost(pb.settings))
}

// AddReadRegistryInstruction adds a read registry instruction to the program.
func (pb *ProgramBuilder) AddReadRegistryInstruction(pub types.PublicKey, tweak types.Hash256) {
	instr := &InstrReadRegistry{
		PublicKeyOffset: pb.offset,
		TweakOffset:     pb.offset + 32,
	}
	pub.EncodeTo(pb.encoder)
	tweak.EncodeTo(pb.encoder)
	pb.offset += 64
	pb.appendInstruction(instr)
	pb.addUsage(ReadRegistryCost(pb.settings))
}

// Cost returns the estimated cost of executing the program, excluding bandwidth
// usage.
func (pb *ProgramBuilder) Cost() ResourceUsage {
	// use the initial cost as a base, then add the running total from the
	// program builder.
	return ExecutionCost(pb.settings, pb.offset, uint64(len(pb.instructions)), pb.requiresFinalization).Add(pb.usage)
}

// Program returns the program's instructions and a bool indicating if the
// program is read-only.
func (pb *ProgramBuilder) Program() (instructions []Instruction, requiresContract, requiresFinalization bool, err error) {
	if err := pb.encoder.Flush(); err != nil {
		return nil, false, false, fmt.Errorf("failed to flush program data: %w", err)
	}
	return pb.instructions, pb.requiresContract, pb.requiresFinalization, nil
}

// NewProgramBuilder initializes a new empty ProgramBuilder.
func NewProgramBuilder(settings HostSettings, data *bytes.Buffer, duration uint64) *ProgramBuilder {
	return &ProgramBuilder{
		encoder:  types.NewEncoder(data),
		data:     data,
		offset:   uint64(data.Len()),
		duration: duration,
		settings: settings,
	}
}
