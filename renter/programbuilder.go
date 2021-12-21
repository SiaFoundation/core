package renter

import (
	"bytes"
	"errors"
	"fmt"

	"go.sia.tech/core/net/rhp"
	"go.sia.tech/core/types"
)

// A ProgramBuilder constructs programs for the renter to execute on a host.
type ProgramBuilder struct {
	instructions         []rhp.Instruction
	requiresFinalization bool
	requiresContract     bool
	encoder              *types.Encoder
	data                 *bytes.Buffer
	offset               uint64
	usage                rhp.ResourceUsage

	duration uint64
	settings rhp.HostSettings
}

func (pb *ProgramBuilder) addUsage(usage rhp.ResourceUsage) {
	pb.usage = pb.usage.Add(usage)
}

func (pb *ProgramBuilder) appendInstruction(instr rhp.Instruction) {
	pb.requiresContract = pb.requiresContract || instr.RequiresContract()
	pb.requiresFinalization = pb.requiresFinalization || instr.RequiresFinalization()
	pb.instructions = append(pb.instructions, instr)
}

// AddAppendSectorInstruction adds an append sector instruction to the program.
func (pb *ProgramBuilder) AddAppendSectorInstruction(sector *[rhp.SectorSize]byte, proof bool) {
	instr := &rhp.InstrAppendSector{
		SectorDataOffset: pb.offset,
		ProofRequired:    proof,
	}
	pb.encoder.Write(sector[:])
	pb.offset += rhp.SectorSize
	pb.appendInstruction(instr)
	pb.addUsage(rhp.AppendSectorCost(pb.settings, pb.duration))
}

// AddDropSectorInstruction adds a drop sector instruction to the program.
func (pb *ProgramBuilder) AddDropSectorInstruction(sectors uint64, proof bool) {
	instr := &rhp.InstrDropSectors{
		SectorCountOffset: pb.offset,
		ProofRequired:     proof,
	}
	pb.encoder.WriteUint64(sectors)
	pb.offset += 8
	pb.appendInstruction(instr)
	pb.addUsage(rhp.DropSectorsCost(pb.settings, sectors))
}

// AddHasSectorInstruction adds a has sector instruction to the program.
func (pb *ProgramBuilder) AddHasSectorInstruction(root types.Hash256) {
	instr := &rhp.InstrHasSector{
		SectorRootOffset: pb.offset,
	}
	root.EncodeTo(pb.encoder)
	pb.offset += 32
	pb.appendInstruction(instr)
	pb.addUsage(rhp.HasSectorCost(pb.settings))
}

// AddReadSectorInstruction adds a read sector instruction to the program.
func (pb *ProgramBuilder) AddReadSectorInstruction(root types.Hash256, offset uint64, length uint64, proof bool) error {
	if offset+length > rhp.SectorSize {
		return errors.New("read offset + length exceeds sector size")
	}

	instr := &rhp.InstrReadSector{
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
	pb.addUsage(rhp.ReadCost(pb.settings, length))
	return nil
}

// AddReadOffsetInstruction adds a read offset instruction to the program.
func (pb *ProgramBuilder) AddReadOffsetInstruction(offset, length uint64, proof bool) {
	instr := &rhp.InstrReadOffset{
		DataOffset:    pb.offset,
		LengthOffset:  pb.offset + 8,
		ProofRequired: proof,
	}
	pb.encoder.WriteUint64(offset)
	pb.encoder.WriteUint64(length)
	pb.offset += 16
	pb.appendInstruction(instr)
	pb.addUsage(rhp.ReadCost(pb.settings, length))
}

// AddDropSectorsInstruction adds a drop sectors instruction to the program.
func (pb *ProgramBuilder) AddDropSectorsInstruction(sectors uint64, proof bool) {
	instr := &rhp.InstrDropSectors{
		SectorCountOffset: pb.offset,
		ProofRequired:     proof,
	}
	pb.encoder.WriteUint64(sectors)
	pb.offset += 8
	pb.appendInstruction(instr)
	pb.addUsage(rhp.DropSectorsCost(pb.settings, sectors))
}

// AddRevisionInstruction adds a revision instruction to the program.
func (pb *ProgramBuilder) AddRevisionInstruction() {
	pb.appendInstruction(&rhp.InstrContractRevision{})
	pb.addUsage(rhp.RevisionCost(pb.settings))
}

// AddSwapSectorInstruction adds a swap sector instruction to the program.
func (pb *ProgramBuilder) AddSwapSectorInstruction(i, j uint64, proof bool) {
	instr := &rhp.InstrSwapSector{
		RootAOffset:   pb.offset,
		RootBOffset:   pb.offset + 32,
		ProofRequired: proof,
	}
	pb.encoder.WriteUint64(i)
	pb.encoder.WriteUint64(j)
	pb.offset += 64
	pb.appendInstruction(instr)
	pb.addUsage(rhp.SwapSectorCost(pb.settings))
}

// AddUpdateRegistryInstruction adds an update registry instruction to the program.
func (pb *ProgramBuilder) AddUpdateRegistryInstruction(value rhp.RegistryValue) {
	instr := &rhp.InstrUpdateRegistry{
		EntryOffset: pb.offset,
	}
	value.EncodeTo(pb.encoder)
	// TODO: ?
	if err := pb.encoder.Flush(); err != nil {
		panic(err) // should never happen
	}
	pb.offset = uint64(pb.data.Len())
	pb.appendInstruction(instr)
	pb.addUsage(rhp.UpdateRegistryCost(pb.settings))
}

// AddReadRegistryInstruction adds a read registry instruction to the program.
func (pb *ProgramBuilder) AddReadRegistryInstruction(pub types.PublicKey, tweak types.Hash256) {
	instr := &rhp.InstrReadRegistry{
		PublicKeyOffset: pb.offset,
		TweakOffset:     pb.offset + 32,
	}
	pub.EncodeTo(pb.encoder)
	tweak.EncodeTo(pb.encoder)
	pb.offset += 64
	pb.appendInstruction(instr)
	pb.addUsage(rhp.ReadRegistryCost(pb.settings))
}

// Cost returns the estimated cost of executing the program, excluding bandwidth
// usage.
func (pb *ProgramBuilder) Cost() rhp.ResourceUsage {
	// use the initial cost as a base, then add the running total from the
	// program builder.
	return rhp.ExecutionCost(pb.settings, pb.offset, uint64(len(pb.instructions)), pb.requiresFinalization).Add(pb.usage)
}

// Program returns the program's instructions and a bool indicating if the
// program is read-only.
func (pb *ProgramBuilder) Program() (instructions []rhp.Instruction, requiresContract, requiresFinalization bool, err error) {
	if err := pb.encoder.Flush(); err != nil {
		return nil, false, false, fmt.Errorf("failed to flush program data: %w", err)
	}
	return pb.instructions, pb.requiresContract, pb.requiresFinalization, nil
}

// NewProgramBuilder initializes a new empty ProgramBuilder.
func NewProgramBuilder(settings rhp.HostSettings, data *bytes.Buffer, duration uint64) *ProgramBuilder {
	return &ProgramBuilder{
		encoder:  types.NewEncoder(data),
		data:     data,
		offset:   uint64(data.Len()),
		duration: duration,
		settings: settings,
	}
}
