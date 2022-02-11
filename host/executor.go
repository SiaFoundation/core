package host

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/net/rhp"
	"go.sia.tech/core/net/rpc"
	"go.sia.tech/core/types"
)

const (
	blocksPerYear = 144 * 365
)

// A ProgramExecutor executes an MDM program in the context of the current
// host session.
type ProgramExecutor struct {
	privkey types.PrivateKey

	newFileSize   uint64
	newMerkleRoot types.Hash256
	newRoots      []types.Hash256

	// gainedSectors counts the number of references a sector has gained
	// through append or update instructions. When a program is reverted all
	// references must be removed.
	gainedSectors map[types.Hash256]uint64
	// removedSectors counts the number of references a sector has lost through
	// update or drop instructions. When a program is committed all references
	// must be removed.
	removedSectors map[types.Hash256]uint64

	// output should not be written to directly, instead write to the encoder.
	output  bytes.Buffer
	encoder *types.Encoder

	budget               *Budget
	spent                types.Currency
	failureRefund        types.Currency
	additionalStorage    types.Currency
	additionalCollateral types.Currency

	sectors   SectorStore
	contracts ContractManager
	registry  *RegistryManager
	vc        consensus.ValidationContext
	settings  rhp.HostSettings
	duration  uint64
	contract  rhp.Contract

	committed bool
}

// payForExecution deducts the cost of the instruction from the budget.
func (pe *ProgramExecutor) payForExecution(usage rhp.ResourceUsage) error {
	cost := usage.BaseCost.Add(usage.StorageCost)

	// subtract the execution cost and additional storage costs from the budget.
	if err := pe.budget.Spend(cost); err != nil {
		return fmt.Errorf("failed to pay for execution: %w", err)
	}

	// add the additional spending to the program's state.
	pe.spent = pe.spent.Add(cost)
	pe.failureRefund = pe.failureRefund.Add(usage.StorageCost)
	pe.additionalCollateral = pe.additionalCollateral.Add(usage.AdditionalCollateral)
	pe.additionalStorage = pe.additionalStorage.Add(usage.StorageCost)
	return nil
}

// executeHasSector checks if the host is storing the sector.
func (pe *ProgramExecutor) executeHasSector(root types.Hash256) error {
	if err := pe.payForExecution(rhp.HasSectorCost(pe.settings)); err != nil {
		return fmt.Errorf("failed to pay instruction cost: %w", err)
	}

	// check if the sector exists in the sector store.
	exists, err := pe.sectors.Exists(root)
	if err != nil {
		return fmt.Errorf("failed to check sector existence: %w", err)
	}
	// output the boolean existence of the sector, 0 for false, 1 for true.
	pe.encoder.WriteBool(exists)
	return nil
}

// executeAppendSector appends a new sector to the executor's sector roots and
// adds it to the sector store.
func (pe *ProgramExecutor) executeAppendSector(root types.Hash256, sector *[rhp.SectorSize]byte, requiresProof bool) ([]types.Hash256, error) {
	if err := pe.payForExecution(rhp.AppendSectorCost(pe.settings, pe.duration)); err != nil {
		return nil, fmt.Errorf("failed to pay append sector cost: %w", err)
	}

	if err := pe.sectors.Add(root, sector); err != nil {
		return nil, fmt.Errorf("failed to add sector: %w", err)
	}

	// update the program's state
	pe.newRoots = append(pe.newRoots, root)
	pe.newMerkleRoot = rhp.MetaRoot(pe.newRoots)
	pe.newFileSize += rhp.SectorSize
	pe.gainedSectors[root]++
	// TODO: calculate optional proof.
	return nil, nil
}

// executeUpdateSector updates an existing sector.
func (pe *ProgramExecutor) executeUpdateSector(offset uint64, data []byte, requiresProof bool) ([]types.Hash256, error) {
	if err := pe.payForExecution(rhp.UpdateSectorCost(pe.settings, uint64(len(data)))); err != nil {
		return nil, fmt.Errorf("failed to pay instruction cost: %w", err)
	}

	index := offset / rhp.SectorSize
	if index >= uint64(len(pe.newRoots)) {
		return nil, fmt.Errorf("offset out of range: %d", index)
	}
	existingRoot := pe.newRoots[index]
	offset %= rhp.SectorSize

	// update the sector in the sector store.
	updatedRoot, err := pe.sectors.Update(existingRoot, offset, data)
	if err != nil {
		return nil, fmt.Errorf("failed to update sector: %w", err)
	}
	// update the program state
	pe.newRoots[index] = updatedRoot
	pe.newMerkleRoot = rhp.MetaRoot(pe.newRoots)
	pe.gainedSectors[updatedRoot]++
	pe.removedSectors[existingRoot]++
	// TODO: calculate optional proof.
	return nil, nil
}

// executeDropSectors drops the last n sectors from the executor's sector roots.
func (pe *ProgramExecutor) executeDropSectors(dropped uint64, requiresProof bool) ([]types.Hash256, error) {
	if err := pe.payForExecution(rhp.DropSectorsCost(pe.settings, dropped)); err != nil {
		return nil, fmt.Errorf("failed to pay instruction cost: %w", err)
	} else if uint64(len(pe.newRoots)) < dropped {
		return nil, errors.New("dropped sector index out of range")
	}

	// get the roots of the sectors to be dropped.
	i := len(pe.newRoots) - int(dropped)
	droppedRoots := pe.newRoots[i:]
	// update the program's contract state
	pe.newRoots = pe.newRoots[:i]
	pe.newMerkleRoot = rhp.MetaRoot(pe.newRoots)
	pe.newFileSize = uint64(len(pe.newRoots)) * rhp.SectorSize
	// remove a reference of each dropped sector.
	for _, root := range droppedRoots {
		pe.removedSectors[root]++
	}
	// TODO: calculate optional proof.
	return nil, nil
}

// executeSwapSectors swaps two sectors in the executor's sector roots.
func (pe *ProgramExecutor) executeSwapSectors(indexA, indexB uint64, requiresProof bool) ([]types.Hash256, error) {
	if err := pe.payForExecution(rhp.SwapSectorCost(pe.settings)); err != nil {
		return nil, fmt.Errorf("failed to pay instruction cost: %w", err)
	} else if indexA >= uint64(len(pe.newRoots)) {
		return nil, fmt.Errorf("sector 1 index out of range %v", indexA)
	} else if indexB >= uint64(len(pe.newRoots)) {
		return nil, fmt.Errorf("sector 2 index out of range %v", indexB)
	}

	// swap the sector roots.
	pe.newRoots[indexA], pe.newRoots[indexB] = pe.newRoots[indexB], pe.newRoots[indexA]
	// update the program's contract state
	pe.newMerkleRoot = rhp.MetaRoot(pe.newRoots)
	pe.newRoots[indexA].EncodeTo(pe.encoder)
	pe.newRoots[indexA].EncodeTo(pe.encoder)

	// TODO: calculate optional proof.
	return nil, nil
}

// executeReadSector reads a sector from the host. Returning the bytes read, an
// optional proof, or an error.
func (pe *ProgramExecutor) executeReadSector(root types.Hash256, offset, length uint64, requiresProof bool) ([]types.Hash256, error) {
	if err := pe.payForExecution(rhp.ReadCost(pe.settings, length)); err != nil {
		return nil, fmt.Errorf("failed to pay instruction cost: %w", err)
	} else if offset+length > rhp.SectorSize {
		return nil, errors.New("offset and length exceed sector size")
	}

	_, err := pe.sectors.Read(root, pe.encoder, offset, length)
	if err != nil {
		return nil, fmt.Errorf("failed to read sector: %w", err)
	}
	// TODO: calculate optional proof.
	return nil, nil
}

// executeContractRevision returns the latest revision of the contract before
// any instructions have been executed.
func (pe *ProgramExecutor) executeContractRevision() error {
	if err := pe.payForExecution(rhp.RevisionCost(pe.settings)); err != nil {
		return fmt.Errorf("failed to pay instruction cost: %w", err)
	} else if pe.contract.ID == (types.ElementID{}) {
		return errors.New("no contract revision set")
	}

	pe.contract.EncodeTo(pe.encoder)
	return nil
}

// executeSectorRoots returns the current sector roots of the program executor.
func (pe *ProgramExecutor) executeSectorRoots() error {
	if err := pe.payForExecution(rhp.SectorRootsCost(pe.settings, uint64(len(pe.newRoots)))); err != nil {
		return fmt.Errorf("failed to pay instruction cost: %w", err)
	} else if pe.contract.ID == (types.ElementID{}) {
		return errors.New("no contract revision set")
	}

	// write the sector roots to the encoder.
	pe.encoder.WritePrefix(len(pe.newRoots))
	for _, root := range pe.newRoots {
		root.EncodeTo(pe.encoder)
	}
	return nil
}

// executeReadRegistry reads a stored registry key and returns the value.
func (pe *ProgramExecutor) executeReadRegistry(key types.Hash256) error {
	if err := pe.payForExecution(rhp.ReadRegistryCost(pe.settings)); err != nil {
		return fmt.Errorf("failed to pay instruction cost: %w", err)
	}

	value, err := pe.registry.Get(key)
	if err != nil {
		return fmt.Errorf("failed to get registry value %v: %w", key, err)
	}
	value.EncodeTo(pe.encoder)
	return nil
}

// executeUpdateRegistry updates a stored registry key with a new value.
func (pe *ProgramExecutor) executeUpdateRegistry(value rhp.RegistryValue) error {
	err := pe.payForExecution(rhp.UpdateRegistryCost(pe.settings))
	if err != nil {
		return fmt.Errorf("failed to pay instruction cost: %w", err)
	} else if err := rhp.ValidateRegistryEntry(value); err != nil {
		return fmt.Errorf("invalid registry value: %w", err)
	}
	expirationHeight := pe.vc.Index.Height + blocksPerYear
	updated, err := pe.registry.Put(value, expirationHeight)
	// if err is nil the updated value is returned, otherwise the old value is
	// returned. Send the entry's current value to the renter.
	updated.EncodeTo(pe.encoder)
	return err
}

// SetContract sets the contract that read-write programs should use for
// finalization. The contract should be locked before calling this function.
func (pe *ProgramExecutor) SetContract(contract rhp.Contract) error {
	// set initial state of the program.
	pe.contract = contract
	pe.newFileSize = contract.Revision.Filesize
	// use height from price table to calculate remaining duration.
	pe.duration = contract.Revision.WindowStart - pe.settings.BlockHeight

	roots, err := pe.contracts.Roots(contract.ID)
	if err != nil {
		return fmt.Errorf("failed to get contract roots: %w", err)
	}
	pe.newMerkleRoot = rhp.MetaRoot(roots)
	pe.newRoots = append([]types.Hash256(nil), roots...)
	return nil
}

// ExecuteInstruction executes the given instruction, reading program data from
// r as needed, and writing the result of the instruction to w.
//
// note: Unlike siad's MDM, this implementation does not check the data offsets
// in the instruction arguments. It is assumed the program data is well-formed,
// meaning each argument appears in the program data in the order it is needed.
// Malformed programs may lead to unexpected behavior, but there is no need to
// buffer the program's data in memory during execution. Changing an
// instructions arguments would also cause programs to be unexecutable, so this
// seems like an acceptable trade-off. Should consider removing the offsets from
// the instruction arguments.
func (pe *ProgramExecutor) ExecuteInstruction(r io.Reader, w io.Writer, instruction rhp.Instruction) error {
	if pe.committed {
		panic("cannot modify a committed program")
	}

	// reset the output buffer
	pe.encoder.Flush()
	pe.output.Reset()

	proof, err := func() ([]types.Hash256, error) {
		switch instr := instruction.(type) {
		case *rhp.InstrAppendSector:
			// read the sector data.
			root, sector, err := rhp.ReadSector(r)
			if err != nil {
				return nil, fmt.Errorf("failed to read sector data: %w", err)
			}
			return pe.executeAppendSector(root, sector, instr.ProofRequired)
		case *rhp.InstrUpdateSector:
			if instr.Length > rhp.SectorSize {
				return nil, fmt.Errorf("data length exceeds sector size")
			}
			data := make([]byte, instr.Length)
			if _, err := io.ReadFull(r, data); err != nil {
				return nil, fmt.Errorf("failed to read update data: %w", err)
			}
			return pe.executeUpdateSector(instr.Offset, data, instr.ProofRequired)
		case *rhp.InstrDropSectors:
			var dropped uint64
			if err := binary.Read(r, binary.LittleEndian, &dropped); err != nil {
				return nil, fmt.Errorf("failed to read dropped sector count: %w", err)
			}
			return pe.executeDropSectors(dropped, instr.ProofRequired)
		case *rhp.InstrHasSector:
			// read the sector root from the program's data
			var root types.Hash256
			if _, err := io.ReadFull(r, root[:]); err != nil {
				return nil, fmt.Errorf("failed to read sector root: %w", err)
			}

			return nil, pe.executeHasSector(root)
		case *rhp.InstrReadSector:
			var root types.Hash256
			var offset, length uint64

			// read the root from the program's data
			if _, err := io.ReadFull(r, root[:]); err != nil {
				return nil, fmt.Errorf("failed to read sector root: %w", err)
			}

			// read the offset and length from the program's data
			if err := binary.Read(r, binary.LittleEndian, &offset); err != nil {
				return nil, fmt.Errorf("failed to read sector offset: %w", err)
			}
			if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
				return nil, fmt.Errorf("failed to read sector length: %w", err)
			}

			return pe.executeReadSector(root, offset, length, instr.ProofRequired)
		case *rhp.InstrReadOffset:
			var offset, length uint64

			if err := binary.Read(r, binary.LittleEndian, &offset); err != nil {
				return nil, fmt.Errorf("failed to read offset: %w", err)
			}

			if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
				return nil, fmt.Errorf("failed to read length: %w", err)
			}

			index := offset / rhp.SectorSize
			if index >= uint64(len(pe.newRoots)) {
				return nil, fmt.Errorf("offset out of range: %d", index)
			}

			root := pe.newRoots[index]
			offset %= rhp.SectorSize
			return pe.executeReadSector(root, offset, length, instr.ProofRequired)
		case *rhp.InstrSwapSector:
			var sectorA, sectorB uint64

			if err := binary.Read(r, binary.LittleEndian, &sectorA); err != nil {
				return nil, fmt.Errorf("failed to read sector A index: %w", err)
			}

			if err := binary.Read(r, binary.LittleEndian, &sectorB); err != nil {
				return nil, fmt.Errorf("failed to read sector B index: %w", err)
			}

			return pe.executeSwapSectors(sectorA, sectorB, instr.ProofRequired)
		case *rhp.InstrContractRevision:
			return nil, pe.executeContractRevision()
		case *rhp.InstrSectorRoots:
			return nil, pe.executeSectorRoots()
		case *rhp.InstrReadRegistry:
			// read the registry entry
			var pub types.PublicKey
			var tweak types.Hash256
			dec := types.NewDecoder(io.LimitedReader{R: r, N: 64})
			pub.DecodeFrom(dec)
			tweak.DecodeFrom(dec)
			if err := dec.Err(); err != nil {
				return nil, fmt.Errorf("failed to decode instruction: %w", dec.Err())
			}

			// read the registry value
			key := rhp.RegistryKey(pub, tweak)
			return nil, pe.executeReadRegistry(key)
		case *rhp.InstrUpdateRegistry:
			var value rhp.RegistryValue
			dec := types.NewDecoder(io.LimitedReader{R: r, N: int64(value.MaxLen())})
			value.DecodeFrom(dec)
			if err := dec.Err(); err != nil {
				return nil, fmt.Errorf("failed to decode instruction data: %w", dec.Err())
			}

			// update the registry value
			return nil, pe.executeUpdateRegistry(value)
		default:
			return nil, fmt.Errorf("unknown instruction: %s", instruction.Specifier())
		}
	}()

	if err := pe.encoder.Flush(); err != nil {
		return fmt.Errorf("failed to flush encoder: %w", err)
	}

	resp := &rhp.RPCExecuteInstrResponse{
		AdditionalCollateral: pe.additionalCollateral,
		AdditionalStorage:    pe.additionalStorage,
		TotalCost:            pe.spent,
		FailureRefund:        pe.failureRefund,

		NewDataSize:   pe.newFileSize,
		NewMerkleRoot: pe.newMerkleRoot,
		Proof:         proof,
		OutputLength:  uint64(pe.output.Len()),

		Error: err,
	}

	if err := rpc.WriteResponse(w, resp); err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	} else if _, err := pe.output.WriteTo(w); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	return resp.Error
}

// FinalizeContract updates the contract to reflect the final state of the
// program.
func (pe *ProgramExecutor) FinalizeContract(req rhp.RPCFinalizeProgramRequest) (rhp.Contract, error) {
	c := pe.contract
	c.Revision.RevisionNumber = req.NewRevisionNumber
	req.NewOutputs.Apply(&c.Revision)
	// update the contract's merkle root and file size.
	c.Revision.FileMerkleRoot = pe.newMerkleRoot
	c.Revision.Filesize = pe.newFileSize

	c.Revision.RenterSignature = req.Signature
	c.Revision.HostSignature = pe.privkey.SignHash(pe.vc.ContractSigHash(c.Revision))

	// validate that the renter's revision is valid and only transfers the
	// additional collateral and storage costs to the void. All other
	// costs have already been paid by the RPC budget.
	if err := rhp.ValidateProgramRevision(pe.vc, pe.contract, c, pe.additionalStorage, pe.additionalCollateral); err != nil {
		return rhp.Contract{}, fmt.Errorf("failed to verify contract revision: %w", err)
	} else if err := pe.contracts.Revise(c); err != nil {
		return rhp.Contract{}, fmt.Errorf("failed to revise contract: %w", err)
	} else if err := pe.contracts.SetRoots(c.ID, pe.newRoots); err != nil {
		return rhp.Contract{}, fmt.Errorf("failed to set new roots: %w", err)
	}
	return c, nil
}

// Revert removes the sectors that were added by the program. If
// commit has already been called, this function is a no-op.
func (pe *ProgramExecutor) Revert() error {
	if pe.committed {
		return nil
	}

	// delete the sectors added by the program.
	for root, refs := range pe.gainedSectors {
		if err := pe.sectors.Delete(root, refs); err != nil {
			return fmt.Errorf("failed to remove sector: %w", err)
		}
	}

	// increase the budget by the failure refund. This will refund the storage
	// costs from executing the program to the renter.
	pe.budget.Increase(pe.failureRefund)
	return nil
}

// Commit removes any sectors that were removed by the program and
// sets the failure refund to zero. If commit has already been called this
// function is a no-op.
func (pe *ProgramExecutor) Commit() error {
	if pe.committed {
		return nil
	}
	// delete sectors removed by the program.
	for root, refs := range pe.removedSectors {
		if err := pe.sectors.Delete(root, refs); err != nil {
			return fmt.Errorf("failed to remove sector: %w", err)
		}
	}

	// all program ops are now committed, set the failure refund to zero.
	pe.failureRefund = types.ZeroCurrency
	pe.committed = true
	return nil
}

// NewExecutor initializes the program's executor.
func NewExecutor(priv types.PrivateKey, ss SectorStore, cm ContractManager, rm *RegistryManager, vc consensus.ValidationContext, settings rhp.HostSettings, budget *Budget) *ProgramExecutor {
	pe := &ProgramExecutor{
		settings: settings,
		budget:   budget,
		duration: 1,

		privkey:   priv,
		sectors:   ss,
		registry:  rm,
		contracts: cm,
		vc:        vc,

		gainedSectors:  make(map[types.Hash256]uint64),
		removedSectors: make(map[types.Hash256]uint64),
	}
	pe.encoder = types.NewEncoder(&pe.output)

	return pe
}
