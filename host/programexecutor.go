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

// programExecutor executes an MDM program in the context of the current
// host session.
type programExecutor struct {
	privkey types.PrivateKey

	newFileSize   uint64
	newMerkleRoot types.Hash256
	newRoots      []types.Hash256

	gainedSectors  map[types.Hash256]struct{}
	removedSectors map[types.Hash256]struct{}

	// output should not be written to directly, instead write to the encoder.
	output  bytes.Buffer
	encoder *types.Encoder

	budget               *rpcBudget
	spent                types.Currency
	failureRefund        types.Currency
	additionalStorage    types.Currency
	additionalCollateral types.Currency

	sectors  SectorStore
	registry *registry
	vc       consensus.ValidationContext
	settings rhp.HostSettings
	duration uint64
	contract *types.FileContractRevision

	committed bool
}

// setContract sets the contract that read-write programs should use for
// finalization. The contract should be locked before calling this function.
func (pe *programExecutor) setContract(contract types.FileContractRevision) error {
	// set initial state of the program.
	pe.contract = &contract
	pe.newFileSize = contract.Revision.Filesize
	// use height from price table to calculate remaining duration.
	pe.duration = contract.Revision.WindowStart - pe.settings.BlockHeight

	roots, err := pe.sectors.ContractRoots(contract.Parent.ID)
	if err != nil {
		return fmt.Errorf("failed to get contract roots: %w", err)
	}
	pe.newMerkleRoot = rhp.MetaRoot(roots)
	pe.newRoots = append([]types.Hash256(nil), roots...)
	return nil
}

// payForExecution deducts the cost of the instruction from the budget.
func (pe *programExecutor) payForExecution(usage rhp.ResourceUsage) error {
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
func (pe *programExecutor) executeHasSector(root types.Hash256) error {
	err := pe.payForExecution(rhp.HasSectorCost(pe.settings))
	if err != nil {
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

// executeAppendSector stores a new sector on the host.
func (pe *programExecutor) executeAppendSector(sector *[rhp.SectorSize]byte, requiresProof bool) ([]types.Hash256, error) {
	err := pe.payForExecution(rhp.AppendSectorCost(pe.settings, pe.duration))
	if err != nil {
		return nil, fmt.Errorf("failed to pay append sector cost: %w", err)
	}

	// add the sector to the sector store.
	root := rhp.SectorRoot(sector)
	if err := pe.sectors.AddSector(root, sector); err != nil {
		return nil, fmt.Errorf("failed to add sector: %w", err)
	}
	// update the program's contract state
	pe.newRoots = append(pe.newRoots, root)
	pe.newMerkleRoot = rhp.MetaRoot(pe.newRoots)
	pe.newFileSize += rhp.SectorSize
	// add the sector to the gained sectors.
	pe.gainedSectors[root] = struct{}{}
	// delete the sector from the removed sectors.
	delete(pe.removedSectors, root)
	// TODO: calculate optional proof.
	return nil, nil
}

// executeReadSector reads a sector from the host. Returning the bytes read, an
// optional proof, or an error.
func (pe *programExecutor) executeReadSector(root types.Hash256, offset, length uint64, requiresProof bool) ([]types.Hash256, error) {
	if offset+length > rhp.SectorSize {
		return nil, errors.New("offset and length exceed sector size")
	}

	err := pe.payForExecution(rhp.ReadCost(pe.settings, length))
	if err != nil {
		return nil, fmt.Errorf("failed to pay instruction cost: %w", err)
	}

	_, err = pe.sectors.ReadSector(root, pe.encoder, offset, length)
	if err != nil {
		return nil, fmt.Errorf("failed to read sector: %w", err)
	}
	// TODO: calculate optional proof.
	return nil, nil
}

// executeDropSectors drops the last n sectors from the host and removes them
// from the contract.
func (pe *programExecutor) executeDropSectors(dropped uint64, requiresProof bool) ([]types.Hash256, error) {
	if uint64(len(pe.newRoots)) < dropped {
		return nil, errors.New("dropped sector index out of range")
	}

	err := pe.payForExecution(rhp.DropSectorsCost(pe.settings, dropped))
	if err != nil {
		return nil, fmt.Errorf("failed to pay instruction cost: %w", err)
	}

	// get the roots of the sectors to be dropped.
	i := len(pe.newRoots) - int(dropped)
	droppedRoots := pe.newRoots[i:]
	// update the program's contract state
	pe.newRoots = pe.newRoots[:i]
	pe.newMerkleRoot = rhp.MetaRoot(pe.newRoots)
	pe.newFileSize = uint64(len(pe.newRoots)) * rhp.SectorSize
	// remove each sector from the program's gained roots and add them to the
	// program's removed roots.
	for _, root := range droppedRoots {
		delete(pe.gainedSectors, root)
		pe.removedSectors[root] = struct{}{}
	}
	// TODO: calculate optional proof.
	return nil, nil
}

func (pe *programExecutor) executeSwapSectors(indexA, indexB uint64, requiresProof bool) ([]types.Hash256, error) {
	if indexA >= uint64(len(pe.newRoots)) {
		return nil, fmt.Errorf("sector 1 index out of range %v", indexA)
	} else if indexB >= uint64(len(pe.newRoots)) {
		return nil, fmt.Errorf("sector 2 index out of range %v", indexB)
	}

	err := pe.payForExecution(rhp.SwapSectorCost(pe.settings))
	if err != nil {
		return nil, fmt.Errorf("failed to pay instruction cost: %w", err)
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

func (pe *programExecutor) executeContractRevision() error {
	var contract types.FileContractRevision
	if pe.contract == nil {
		return errors.New("no contract revision set")
	}
	contract.EncodeTo(pe.encoder)
	return nil
}

func (pe *programExecutor) executeReadRegistry(key types.Hash256) error {
	value, err := pe.registry.Get(key)
	if err != nil {
		return fmt.Errorf("failed to get registry value %v: %w", key, err)
	}
	value.EncodeTo(pe.encoder)
	return nil
}

func (pe *programExecutor) executeUpdateRegistry(value rhp.RegistryValue) error {
	if err := validateRegistryEntry(value); err != nil {
		return fmt.Errorf("invalid registry value: %w", err)
	}
	expirationHeight := pe.vc.Index.Height + blocksPerYear
	updated, err := pe.registry.Put(value, expirationHeight)
	// if err is a registryValidationError, the old value should be returned
	if _, ok := err.(*registryValidationError); ok {
		updated.EncodeTo(pe.encoder)
		return err
	} else if err != nil {
		return fmt.Errorf("failed to update registry value: %w", err)
	}

	updated.EncodeTo(pe.encoder)
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
func (pe *programExecutor) ExecuteInstruction(r io.Reader, w io.Writer, instruction rhp.Instruction) error {
	if pe.committed {
		panic("cannot modify a committed program")
	}

	// reset the output buffer
	pe.encoder.Flush()
	pe.output.Reset()

	proof, err := func() ([]types.Hash256, error) {
		switch instr := instruction.(type) {
		case rhp.InstrAppendSector:
			// read the sector data.
			var sector [rhp.SectorSize]byte
			if _, err := io.ReadFull(r, sector[:]); err != nil {
				return nil, fmt.Errorf("failed to read append sector data: %w", err)
			}

			return pe.executeAppendSector(&sector, instr.ProofRequired)
		case rhp.InstrDropSectors:
			var dropped uint64
			if err := binary.Read(r, binary.LittleEndian, &dropped); err != nil {
				return nil, fmt.Errorf("failed to read dropped sector count: %w", err)
			}
			return pe.executeDropSectors(dropped, instr.ProofRequired)
		case rhp.InstrHasSector:
			// read the sector root from the program's data
			var root types.Hash256
			if _, err := io.ReadFull(r, root[:]); err != nil {
				return nil, fmt.Errorf("failed to read sector root: %w", err)
			}

			return nil, pe.executeHasSector(root)
		case rhp.InstrReadSector:
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
		case rhp.InstrReadOffset:
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
		case rhp.InstrSwapSector:
			var sectorA, sectorB uint64

			if err := binary.Read(r, binary.LittleEndian, &sectorA); err != nil {
				return nil, fmt.Errorf("failed to read sector A index: %w", err)
			}

			if err := binary.Read(r, binary.LittleEndian, &sectorB); err != nil {
				return nil, fmt.Errorf("failed to read sector B index: %w", err)
			}

			return pe.executeSwapSectors(sectorA, sectorB, instr.ProofRequired)
		case rhp.InstrContractRevision:
			return nil, pe.executeContractRevision()
		case rhp.InstrReadRegistry:
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
		case rhp.InstrUpdateRegistry:
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
func (pe *programExecutor) FinalizeContract(req rhp.RPCFinalizeProgramRequest) (types.FileContractRevision, error) {
	revision := *pe.contract
	revision.Revision.RevisionNumber = req.NewRevisionNumber
	req.NewOutputs.Apply(&revision.Revision)
	// update the contract's merkle root and file size.
	revision.Revision.FileMerkleRoot = pe.newMerkleRoot
	revision.Revision.Filesize = pe.newFileSize

	sigHash := pe.vc.ContractSigHash(revision.Revision)
	revision.HostSignature = pe.privkey.SignHash(sigHash)
	revision.RenterSignature = req.Signature

	// validate that the renter's revision is valid and only transfers the
	// additional collateral and storage costs to the void. All other
	// costs have already been paid by the RPC budget.
	if err := validateProgramRevision(pe.vc, *pe.contract, revision, pe.additionalStorage, pe.additionalCollateral); err != nil {
		return types.FileContractRevision{}, fmt.Errorf("failed to verify contract revision: %w", err)
	}

	return revision, nil
}

// Revert removes the sectors that were added by the program. If
// commit has already been called, this function is a no-op.
func (pe *programExecutor) Revert() error {
	if pe.committed {
		return nil
	}

	// delete the gained sectors.
	for root := range pe.gainedSectors {
		if err := pe.sectors.DeleteSector(root); err != nil {
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
func (pe *programExecutor) Commit() error {
	if pe.committed {
		return nil
	}
	// reset the gained sectors.
	pe.gainedSectors = make(map[types.Hash256]struct{})
	// delete the removed sectors.
	for root := range pe.removedSectors {
		if err := pe.sectors.DeleteSector(root); err != nil {
			return fmt.Errorf("failed to remove sector: %w", err)
		}
	}

	// all program ops are now committed, set the failure refund to zero.
	pe.failureRefund = types.ZeroCurrency
	return nil
}

// newExecutor initializes the program's executor.
func newExecutor(priv types.PrivateKey, ss SectorStore, reg *registry, vc consensus.ValidationContext, settings rhp.HostSettings, budget *rpcBudget) *programExecutor {
	pe := &programExecutor{
		settings: settings,
		budget:   budget,
		duration: 1,

		privkey:  priv,
		sectors:  ss,
		registry: reg,
		vc:       vc,

		gainedSectors:  make(map[types.Hash256]struct{}),
		removedSectors: make(map[types.Hash256]struct{}),
	}
	pe.encoder = types.NewEncoder(&pe.output)

	return pe
}
