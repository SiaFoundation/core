package rhp

import (
	"errors"
	"fmt"
	"time"

	"go.sia.tech/core/net/rpc"
	"go.sia.tech/core/types"
)

const defaultMaxLen = 10e3 // for revisions, proofs, etc.
const largeMaxLen = 1e6    // for transactions

// ContractOutputs contains the output values for a FileContract. Because the
// revisions negotiated by the renter and host typically do not modify the
// output recipients, we can save some space by only sending the new values.
type ContractOutputs struct {
	RenterValue     types.Currency
	HostValue       types.Currency
	MissedHostValue types.Currency
}

// Apply sets the output values of fc according to co.
func (co ContractOutputs) Apply(fc *types.FileContract) {
	fc.RenterOutput.Value = co.RenterValue
	fc.HostOutput.Value = co.HostValue
	fc.MissedHostValue = co.MissedHostValue
}

// RPC IDs
var (
	RPCLockID        = rpc.NewSpecifier("Lock")
	RPCReadID        = rpc.NewSpecifier("Read")
	RPCSectorRootsID = rpc.NewSpecifier("SectorRoots")
	RPCUnlockID      = rpc.NewSpecifier("Unlock")
	RPCWriteID       = rpc.NewSpecifier("Write")

	RPCAccountBalanceID = rpc.NewSpecifier("AccountBalance")
	RPCExecuteProgramID = rpc.NewSpecifier("ExecuteProgram")
	RPCFundAccountID    = rpc.NewSpecifier("FundAccount")
	RPCFormContractID   = rpc.NewSpecifier("FormContract")
	RPCLatestRevisionID = rpc.NewSpecifier("LatestRevision")
	RPCRenewContractID  = rpc.NewSpecifier("RenewContract")
	RPCSettingsID       = rpc.NewSpecifier("Settings")
)

// Read/Write actions
var (
	RPCWriteActionAppend = rpc.NewSpecifier("Append")
	RPCWriteActionTrim   = rpc.NewSpecifier("Trim")
	RPCWriteActionSwap   = rpc.NewSpecifier("Swap")
	RPCWriteActionUpdate = rpc.NewSpecifier("Update")

	RPCReadStop = rpc.NewSpecifier("ReadStop")
)

// RPC request/response objects
type (
	// RPCFormContractRequest contains the request parameters for the FormContract
	// RPC.
	RPCFormContractRequest struct {
		Inputs   []types.SiacoinInput
		Outputs  []types.SiacoinOutput
		MinerFee types.Currency
		Contract types.FileContract
	}

	// RPCRenewContractRequest contains the request parameters for the Renew
	// RPC. Resolution must contain a valid contract renewal.
	RPCRenewContractRequest struct {
		Inputs     []types.SiacoinInput
		Outputs    []types.SiacoinOutput
		MinerFee   types.Currency
		Resolution types.FileContractResolution
	}

	// RPCFormContractHostAdditions contains the parent transaction, inputs,
	// outputs and contract signature added by the host when negotiating a file
	// contract. It is expected that the inputs are not signed yet.
	RPCFormContractHostAdditions struct {
		Inputs            []types.SiacoinInput
		Outputs           []types.SiacoinOutput
		ContractSignature types.Signature
	}

	// RPCRenewContractHostAdditions contains the parent transaction, inputs,
	// outputs, finalization and renewal signatures added by the host when
	// negotiating a contract renewal. It is expected that the inputs are not
	// signed yet.
	RPCRenewContractHostAdditions struct {
		Inputs                []types.SiacoinInput
		Outputs               []types.SiacoinOutput
		HostRollover          types.Currency
		FinalizationSignature types.Signature
		InitialSignature      types.Signature
		RenewalSignature      types.Signature
	}

	// RPCContractSignatures contains the siacoin input signatures for a
	// transaction. These signatures are sent by the renter and host during
	// contract formation.
	RPCContractSignatures struct {
		SiacoinInputSignatures [][]types.Signature
	}

	// RPCRenewContractRenterSignatures contains the siacoin input and renewal
	// signature for a transaction. These signatures are sent by the renter
	// during contract renewal.
	RPCRenewContractRenterSignatures struct {
		SiacoinInputSignatures [][]types.Signature
		RenewalSignature       types.Signature
	}

	// RPCLockRequest contains the request parameters for the Lock RPC.
	RPCLockRequest struct {
		ContractID types.ElementID
		Signature  types.Signature
		Timeout    uint64
	}

	// RPCLockResponse contains the response data for the Lock RPC.
	RPCLockResponse struct {
		Acquired     bool
		NewChallenge [16]byte
		Revision     types.FileContractRevision
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

		NewRevisionNumber uint64
		NewOutputs        ContractOutputs
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

		NewRevisionNumber uint64
		NewOutputs        ContractOutputs
		Signature         types.Signature
	}

	// RPCSectorRootsResponse contains the response data for the SectorRoots RPC.
	RPCSectorRootsResponse struct {
		Signature   types.Signature
		SectorRoots []types.Hash256
		MerkleProof []types.Hash256
	}

	// RPCWriteRequest contains the request parameters for the Write RPC.
	RPCWriteRequest struct {
		Actions     []RPCWriteAction
		MerkleProof bool

		NewRevisionNumber uint64
		NewOutputs        ContractOutputs
	}

	// RPCWriteAction is a generic Write action. The meaning of each field
	// depends on the Type of the action.
	RPCWriteAction struct {
		Type rpc.Specifier
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

// ProtocolObject implementations

func writeMerkleProof(e *types.Encoder, proof []types.Hash256) {
	e.WritePrefix(len(proof))
	for i := range proof {
		proof[i].EncodeTo(e)
	}
}

func readMerkleProof(d *types.Decoder) (proof []types.Hash256) {
	proof = make([]types.Hash256, d.ReadPrefix())
	for i := range proof {
		proof[i].DecodeFrom(d)
	}
	return
}

func (co *ContractOutputs) encodeTo(e *types.Encoder) {
	co.RenterValue.EncodeTo(e)
	co.HostValue.EncodeTo(e)
	co.MissedHostValue.EncodeTo(e)
}

func (co *ContractOutputs) decodeFrom(d *types.Decoder) {
	co.RenterValue.DecodeFrom(d)
	co.HostValue.DecodeFrom(d)
	co.MissedHostValue.DecodeFrom(d)
}

func (ContractOutputs) maxLen() int {
	return 4 * 16
}

// EncodeTo implements rpc.Object.
func (r *RPCFormContractRequest) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.Inputs))
	for i := range r.Inputs {
		r.Inputs[i].EncodeTo(e)
	}
	e.WritePrefix(len(r.Outputs))
	for i := range r.Outputs {
		r.Outputs[i].EncodeTo(e)
	}
	r.MinerFee.EncodeTo(e)
	r.Contract.EncodeTo(e)
}

// DecodeFrom implements rpc.Object.
func (r *RPCFormContractRequest) DecodeFrom(d *types.Decoder) {
	r.Inputs = make([]types.SiacoinInput, d.ReadPrefix())
	for i := range r.Inputs {
		r.Inputs[i].DecodeFrom(d)
	}
	r.Outputs = make([]types.SiacoinOutput, d.ReadPrefix())
	for i := range r.Outputs {
		r.Outputs[i].DecodeFrom(d)
	}
	r.MinerFee.DecodeFrom(d)
	r.Contract.DecodeFrom(d)
}

// MaxLen implements rpc.Object.
func (r *RPCFormContractRequest) MaxLen() int {
	return defaultMaxLen
}

// EncodeTo implements rpc.Object.
func (r *RPCRenewContractRequest) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.Inputs))
	for i := range r.Inputs {
		r.Inputs[i].EncodeTo(e)
	}
	e.WritePrefix(len(r.Outputs))
	for i := range r.Outputs {
		r.Outputs[i].EncodeTo(e)
	}
	r.MinerFee.EncodeTo(e)
	r.Resolution.EncodeTo(e)
}

// DecodeFrom implements rpc.Object.
func (r *RPCRenewContractRequest) DecodeFrom(d *types.Decoder) {
	r.Inputs = make([]types.SiacoinInput, d.ReadPrefix())
	for i := range r.Inputs {
		r.Inputs[i].DecodeFrom(d)
	}
	r.Outputs = make([]types.SiacoinOutput, d.ReadPrefix())
	for i := range r.Outputs {
		r.Outputs[i].DecodeFrom(d)
	}
	r.MinerFee.DecodeFrom(d)
	r.Resolution.DecodeFrom(d)
}

// MaxLen implements rpc.Object.
func (r *RPCRenewContractRequest) MaxLen() int {
	return largeMaxLen
}

// EncodeTo implements rpc.Object.
func (r *RPCFormContractHostAdditions) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.Inputs))
	for i := range r.Inputs {
		r.Inputs[i].EncodeTo(e)
	}
	e.WritePrefix(len(r.Outputs))
	for i := range r.Outputs {
		r.Outputs[i].EncodeTo(e)
	}
	r.ContractSignature.EncodeTo(e)
}

// DecodeFrom implements rpc.Object.
func (r *RPCFormContractHostAdditions) DecodeFrom(d *types.Decoder) {
	r.Inputs = make([]types.SiacoinInput, d.ReadPrefix())
	for i := range r.Inputs {
		r.Inputs[i].DecodeFrom(d)
	}
	r.Outputs = make([]types.SiacoinOutput, d.ReadPrefix())
	for i := range r.Outputs {
		r.Outputs[i].DecodeFrom(d)
	}
	r.ContractSignature.DecodeFrom(d)
}

// MaxLen implements rpc.Object.
func (r *RPCFormContractHostAdditions) MaxLen() int {
	return largeMaxLen
}

// EncodeTo implements rpc.Object.
func (r *RPCRenewContractHostAdditions) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.Inputs))
	for i := range r.Inputs {
		r.Inputs[i].EncodeTo(e)
	}
	e.WritePrefix(len(r.Outputs))
	for i := range r.Outputs {
		r.Outputs[i].EncodeTo(e)
	}
	r.HostRollover.EncodeTo(e)
	r.FinalizationSignature.EncodeTo(e)
	r.InitialSignature.EncodeTo(e)
	r.RenewalSignature.EncodeTo(e)
}

// DecodeFrom implements rpc.Object.
func (r *RPCRenewContractHostAdditions) DecodeFrom(d *types.Decoder) {
	r.Inputs = make([]types.SiacoinInput, d.ReadPrefix())
	for i := range r.Inputs {
		r.Inputs[i].DecodeFrom(d)
	}
	r.Outputs = make([]types.SiacoinOutput, d.ReadPrefix())
	for i := range r.Outputs {
		r.Outputs[i].DecodeFrom(d)
	}
	r.HostRollover.DecodeFrom(d)
	r.FinalizationSignature.DecodeFrom(d)
	r.InitialSignature.DecodeFrom(d)
	r.RenewalSignature.DecodeFrom(d)
}

// MaxLen implements rpc.Object.
func (r *RPCRenewContractHostAdditions) MaxLen() int {
	return defaultMaxLen
}

// EncodeTo implements rpc.Object.
func (r *RPCContractSignatures) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.SiacoinInputSignatures))
	for i := range r.SiacoinInputSignatures {
		e.WritePrefix(len(r.SiacoinInputSignatures[i]))
		for j := range r.SiacoinInputSignatures[i] {
			r.SiacoinInputSignatures[i][j].EncodeTo(e)
		}
	}
}

// DecodeFrom implements rpc.Object.
func (r *RPCContractSignatures) DecodeFrom(d *types.Decoder) {
	r.SiacoinInputSignatures = make([][]types.Signature, d.ReadPrefix())
	for i := range r.SiacoinInputSignatures {
		r.SiacoinInputSignatures[i] = make([]types.Signature, d.ReadPrefix())
		for j := range r.SiacoinInputSignatures[i] {
			r.SiacoinInputSignatures[i][j].DecodeFrom(d)
		}
	}
}

// MaxLen implements rpc.Object.
func (r *RPCContractSignatures) MaxLen() int {
	return defaultMaxLen
}

// EncodeTo implements rpc.Object.
func (r *RPCRenewContractRenterSignatures) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.SiacoinInputSignatures))
	for i := range r.SiacoinInputSignatures {
		e.WritePrefix(len(r.SiacoinInputSignatures[i]))
		for j := range r.SiacoinInputSignatures[i] {
			r.SiacoinInputSignatures[i][j].EncodeTo(e)
		}
	}
	r.RenewalSignature.EncodeTo(e)
}

// DecodeFrom implements rpc.Object.
func (r *RPCRenewContractRenterSignatures) DecodeFrom(d *types.Decoder) {
	r.SiacoinInputSignatures = make([][]types.Signature, d.ReadPrefix())
	for i := range r.SiacoinInputSignatures {
		r.SiacoinInputSignatures[i] = make([]types.Signature, d.ReadPrefix())
		for j := range r.SiacoinInputSignatures[i] {
			r.SiacoinInputSignatures[i][j].DecodeFrom(d)
		}
	}
	r.RenewalSignature.DecodeFrom(d)
}

// MaxLen implements rpc.Object.
func (r *RPCRenewContractRenterSignatures) MaxLen() int {
	return defaultMaxLen
}

// EncodeTo implements rpc.Object.
func (r *RPCLockRequest) EncodeTo(e *types.Encoder) {
	r.ContractID.EncodeTo(e)
	r.Signature.EncodeTo(e)
	e.WriteUint64(r.Timeout)
}

// DecodeFrom implements rpc.Object.
func (r *RPCLockRequest) DecodeFrom(d *types.Decoder) {
	r.ContractID.DecodeFrom(d)
	r.Signature.DecodeFrom(d)
	r.Timeout = d.ReadUint64()
}

// MaxLen implements rpc.Object.
func (r *RPCLockRequest) MaxLen() int {
	return len(r.ContractID.Source) + 8 + len(r.Signature) + 8
}

// EncodeTo implements rpc.Object.
func (r *RPCLockResponse) EncodeTo(e *types.Encoder) {
	e.WriteBool(r.Acquired)
	e.Write(r.NewChallenge[:])
	r.Revision.EncodeTo(e)
}

// DecodeFrom implements rpc.Object.
func (r *RPCLockResponse) DecodeFrom(d *types.Decoder) {
	r.Acquired = d.ReadBool()
	d.Read(r.NewChallenge[:])
	r.Revision.DecodeFrom(d)
}

// MaxLen implements rpc.Object.
func (r *RPCLockResponse) MaxLen() int {
	return defaultMaxLen
}

// EncodeTo implements rpc.Object.
func (r *RPCReadRequest) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.Sections))
	for i := range r.Sections {
		r.Sections[i].MerkleRoot.EncodeTo(e)
		e.WriteUint64(r.Sections[i].Offset)
		e.WriteUint64(r.Sections[i].Length)
	}
	e.WriteBool(r.MerkleProof)
	e.WriteUint64(r.NewRevisionNumber)
	r.NewOutputs.encodeTo(e)
	r.Signature.EncodeTo(e)
}

// DecodeFrom implements rpc.Object.
func (r *RPCReadRequest) DecodeFrom(d *types.Decoder) {
	r.Sections = make([]RPCReadRequestSection, d.ReadPrefix())
	for i := range r.Sections {
		r.Sections[i].MerkleRoot.DecodeFrom(d)
		r.Sections[i].Offset = d.ReadUint64()
		r.Sections[i].Length = d.ReadUint64()
	}
	r.MerkleProof = d.ReadBool()
	r.NewRevisionNumber = d.ReadUint64()
	r.NewOutputs.decodeFrom(d)
	r.Signature.DecodeFrom(d)
}

// MaxLen implements rpc.Object.
func (r *RPCReadRequest) MaxLen() int {
	return defaultMaxLen
}

// EncodeTo implements rpc.Object.
func (r *RPCReadResponse) EncodeTo(e *types.Encoder) {
	r.Signature.EncodeTo(e)
	e.WriteBytes(r.Data)
	writeMerkleProof(e, r.MerkleProof)
}

// DecodeFrom implements rpc.Object.
func (r *RPCReadResponse) DecodeFrom(d *types.Decoder) {
	r.Signature.DecodeFrom(d)

	// r.Data will typically be large (4 MiB), so reuse the existing capacity if
	// possible.
	//
	// NOTE: for maximum efficiency, we should be doing this for every slice,
	// but in most cases the extra performance isn't worth the aliasing risk.
	dataLen := d.ReadPrefix()
	if cap(r.Data) < dataLen {
		r.Data = make([]byte, dataLen)
	}
	r.Data = r.Data[:dataLen]
	d.Read(r.Data)

	r.MerkleProof = readMerkleProof(d)
}

// MaxLen implements rpc.Object.
func (r *RPCReadResponse) MaxLen() int {
	return 16 * (1 << 20) // 16 MiB
}

// EncodeTo implements rpc.Object.
func (r *RPCSectorRootsRequest) EncodeTo(e *types.Encoder) {
	e.WriteUint64(r.RootOffset)
	e.WriteUint64(r.NumRoots)
	e.WriteUint64(r.NewRevisionNumber)
	r.NewOutputs.encodeTo(e)
	r.Signature.EncodeTo(e)
}

// DecodeFrom implements rpc.Object.
func (r *RPCSectorRootsRequest) DecodeFrom(d *types.Decoder) {
	r.RootOffset = d.ReadUint64()
	r.NumRoots = d.ReadUint64()
	r.NewRevisionNumber = d.ReadUint64()
	r.NewOutputs.decodeFrom(d)
	r.Signature.DecodeFrom(d)
}

// MaxLen implements rpc.Object.
func (r *RPCSectorRootsRequest) MaxLen() int {
	return 8 + 8 + 8 + r.NewOutputs.maxLen() + len(r.Signature)
}

// EncodeTo implements rpc.Object.
func (r *RPCSectorRootsResponse) EncodeTo(e *types.Encoder) {
	r.Signature.EncodeTo(e)
	writeMerkleProof(e, r.SectorRoots)
	writeMerkleProof(e, r.MerkleProof)
}

// DecodeFrom implements rpc.Object.
func (r *RPCSectorRootsResponse) DecodeFrom(d *types.Decoder) {
	r.Signature.DecodeFrom(d)
	r.SectorRoots = readMerkleProof(d)
	r.MerkleProof = readMerkleProof(d)
}

// MaxLen implements rpc.Object.
func (r *RPCSectorRootsResponse) MaxLen() int {
	return defaultMaxLen
}

// EncodeTo implements rpc.Object.
func (r *RPCWriteAction) EncodeTo(e *types.Encoder) {
	r.Type.EncodeTo(e)
	e.WriteUint64(r.A)
	e.WriteUint64(r.B)
	e.WriteBytes(r.Data)
}

// DecodeFrom implements rpc.Object.
func (r *RPCWriteAction) DecodeFrom(d *types.Decoder) {
	r.Type.DecodeFrom(d)
	r.A = d.ReadUint64()
	r.B = d.ReadUint64()
	r.Data = d.ReadBytes()
}

// EncodeTo implements rpc.Object.
func (r *RPCWriteRequest) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.Actions))
	for i := range r.Actions {
		r.Actions[i].EncodeTo(e)
	}
	e.WriteBool(r.MerkleProof)
	e.WriteUint64(r.NewRevisionNumber)
	r.NewOutputs.encodeTo(e)
}

// DecodeFrom implements rpc.Object.
func (r *RPCWriteRequest) DecodeFrom(d *types.Decoder) {
	r.Actions = make([]RPCWriteAction, d.ReadPrefix())
	for i := range r.Actions {
		r.Actions[i].DecodeFrom(d)
	}
	r.MerkleProof = d.ReadBool()
	r.NewRevisionNumber = d.ReadUint64()
	r.NewOutputs.decodeFrom(d)
}

// MaxLen implements rpc.Object.
func (r *RPCWriteRequest) MaxLen() int {
	return defaultMaxLen
}

// EncodeTo implements rpc.Object.
func (r *RPCWriteMerkleProof) EncodeTo(e *types.Encoder) {
	writeMerkleProof(e, r.OldSubtreeHashes)
	writeMerkleProof(e, r.OldLeafHashes)
	r.NewMerkleRoot.EncodeTo(e)
}

// DecodeFrom implements rpc.Object.
func (r *RPCWriteMerkleProof) DecodeFrom(d *types.Decoder) {
	r.OldSubtreeHashes = readMerkleProof(d)
	r.OldLeafHashes = readMerkleProof(d)
	r.NewMerkleRoot.DecodeFrom(d)
}

// MaxLen implements rpc.Object.
func (r *RPCWriteMerkleProof) MaxLen() int {
	return defaultMaxLen
}

// EncodeTo implements rpc.Object.
func (r *RPCWriteResponse) EncodeTo(e *types.Encoder) {
	r.Signature.EncodeTo(e)
}

// DecodeFrom implements rpc.Object.
func (r *RPCWriteResponse) DecodeFrom(d *types.Decoder) {
	r.Signature.DecodeFrom(d)
}

// MaxLen implements rpc.Object.
func (r *RPCWriteResponse) MaxLen() int {
	return 64
}

// RPCSettingsResponse contains the JSON-encoded settings for a host.
type RPCSettingsResponse struct {
	Settings []byte
}

// MaxLen returns the maximum encoded length of an object. Implements
// rpc.Object.
func (r *RPCSettingsResponse) MaxLen() int {
	return defaultMaxLen
}

// EncodeTo encodes a RPCSettingsResponse to an encoder. Implements
// types.EncoderTo.
func (r *RPCSettingsResponse) EncodeTo(e *types.Encoder) {
	e.WriteBytes(r.Settings)
}

// DecodeFrom decodes a RPCSettingsResponse from a decoder. Implements
// types.DecoderFrom.
func (r *RPCSettingsResponse) DecodeFrom(d *types.Decoder) {
	r.Settings = d.ReadBytes()
}

// RPCLatestRevisionRequest requests the host send the latest revision of the
// contract.
type RPCLatestRevisionRequest struct {
	ContractID types.ElementID
}

// MaxLen returns the maximum encoded length of an object. Implements
// rpc.Object.
func (r *RPCLatestRevisionRequest) MaxLen() int {
	return 40
}

// EncodeTo encodes a RPCLatestRevisionRequest to an encoder. Implements
// types.EncoderTo.
func (r *RPCLatestRevisionRequest) EncodeTo(e *types.Encoder) {
	r.ContractID.EncodeTo(e)
}

// DecodeFrom decodes a RPCLatestRevisionRequest from a decoder. Implements
// types.DecoderFrom.
func (r *RPCLatestRevisionRequest) DecodeFrom(d *types.Decoder) {
	r.ContractID.DecodeFrom(d)
}

// RPCLatestRevisionResponse contains the latest revision of a contract from the
// host.
type RPCLatestRevisionResponse struct {
	Revision Contract
}

// MaxLen returns the maximum encoded length of an object. Implements
// rpc.Object.
func (r *RPCLatestRevisionResponse) MaxLen() int {
	return defaultMaxLen
}

// EncodeTo encodes a RPCLatestRevisionResponse to an encoder. Implements
// types.EncoderTo.
func (r *RPCLatestRevisionResponse) EncodeTo(e *types.Encoder) {
	r.Revision.EncodeTo(e)
}

// DecodeFrom decodes a RPCLatestRevisionResponse from a decoder. Implements
// types.DecoderFrom.
func (r *RPCLatestRevisionResponse) DecodeFrom(d *types.Decoder) {
	r.Revision.DecodeFrom(d)
}

// RPCSettingsRegisteredResponse returns the settings ID to the renter to signal
// success.
type RPCSettingsRegisteredResponse struct {
	ID SettingsID
}

// MaxLen returns the maximum encoded length of an object. Implements
// rpc.Object.
func (r *RPCSettingsRegisteredResponse) MaxLen() int {
	return 16
}

// EncodeTo encodes a RPCSettingsRegisteredResponse to an encoder. Implements
// types.EncoderTo.
func (r *RPCSettingsRegisteredResponse) EncodeTo(e *types.Encoder) {
	e.Write(r.ID[:])
}

// DecodeFrom decodes a RPCSettingsRegisteredResponse from a decoder. Implements
// types.DecoderFrom.
func (r *RPCSettingsRegisteredResponse) DecodeFrom(d *types.Decoder) {
	d.Read(r.ID[:])
}

func writeInstruction(e *types.Encoder, instr Instruction) {
	specifier := instr.Specifier()
	e.Write(specifier[:])
	instr.EncodeTo(e)
}

func readInstruction(d *types.Decoder) (instr Instruction) {
	var spec rpc.Specifier
	d.Read(spec[:])

	switch spec {
	case SpecInstrAppendSector:
		instr = new(InstrAppendSector)
	case SpecInstrUpdateSector:
		instr = new(InstrUpdateSector)
	case SpecInstrDropSectors:
		instr = new(InstrDropSectors)
	case SpecInstrHasSector:
		instr = new(InstrHasSector)
	case SpecInstrReadOffset:
		instr = new(InstrReadOffset)
	case SpecInstrReadSector:
		instr = new(InstrReadSector)
	case SpecInstrContractRevision:
		instr = new(InstrContractRevision)
	case SpecInstrSwapSector:
		instr = new(InstrSwapSector)
	case SpecInstrUpdateRegistry:
		instr = new(InstrUpdateRegistry)
	case SpecInstrReadRegistry:
		instr = new(InstrReadRegistry)
	default:
		d.SetErr(fmt.Errorf("uknown instruction specifier, %v", spec))
		return
	}
	instr.DecodeFrom(d)
	return
}

// RPCExecuteProgramRequest is the request for the RPC method "execute".
type RPCExecuteProgramRequest struct {
	// FileContractID is the id of the filecontract we would like to modify.
	FileContractID types.ElementID
	// RenterSignature is the signature of the last revision of the file
	// contract.
	RenterSignature types.Signature
	// Instructions are the instructions to be executed.
	Instructions []Instruction
	// ProgramDataLength is the length of the programData following this
	// request.
	ProgramDataLength uint64
}

// MaxLen returns the maximum encoded length of an object. Implements
// rpc.Object.
func (req *RPCExecuteProgramRequest) MaxLen() int {
	return defaultMaxLen
}

// EncodeTo encodes a RPCExecuteProgramRequest to an encoder. Implements
// types.EncoderTo.
func (req *RPCExecuteProgramRequest) EncodeTo(e *types.Encoder) {
	req.FileContractID.EncodeTo(e)
	e.WritePrefix(len(req.Instructions))
	for _, instruction := range req.Instructions {
		writeInstruction(e, instruction)
	}
	e.WriteUint64(req.ProgramDataLength)
}

// DecodeFrom decodes a RPCExecuteProgramRequest from a decoder. Implements
// types.DecoderFrom.
func (req *RPCExecuteProgramRequest) DecodeFrom(d *types.Decoder) {
	req.FileContractID.DecodeFrom(d)
	req.Instructions = make([]Instruction, d.ReadPrefix())
	for i := range req.Instructions {
		req.Instructions[i] = readInstruction(d)
	}
	req.ProgramDataLength = d.ReadUint64()
}

// Payment specifiers are used to specify the payment type
var (
	PayByContract         = rpc.NewSpecifier("PayByContract")
	PayByEphemeralAccount = rpc.NewSpecifier("PayByEphemAcc")
)

// WithdrawalMessage is the amount of money to deduct from the account to create
// the RPC budget.
type WithdrawalMessage struct {
	AccountID types.PublicKey
	Expiry    uint64
	Amount    types.Currency

	// Nonce prevents duplicate withdrawals from being processed
	Nonce [8]byte
}

// SigHash computes the hash of the withdrawal message used for signing the
// pay by ephemeral account request.
func (wm *WithdrawalMessage) SigHash() types.Hash256 {
	h := types.NewHasher()
	wm.EncodeTo(h.E)
	return h.Sum()
}

// MaxLen implements rpc.Object.
func (wm *WithdrawalMessage) MaxLen() int {
	return 32 + 8 + 16 + 8
}

// EncodeTo implements types.EncoderTo.
func (wm *WithdrawalMessage) EncodeTo(e *types.Encoder) {
	wm.AccountID.EncodeTo(e)
	e.WriteUint64(wm.Expiry)
	wm.Amount.EncodeTo(e)
	e.Write(wm.Nonce[:])
}

// DecodeFrom implements types.DecoderFrom.
func (wm *WithdrawalMessage) DecodeFrom(d *types.Decoder) {
	wm.AccountID.DecodeFrom(d)
	wm.Expiry = d.ReadUint64()
	wm.Amount.DecodeFrom(d)
	d.Read(wm.Nonce[:])
}

// PayByEphemeralAccountRequest is a request to create an RPC budget using funds
// from an ephemeral account.
type PayByEphemeralAccountRequest struct {
	Message   WithdrawalMessage
	Signature types.Signature
	Priority  uint64
}

// MaxLen implements rpc.Object.
func (req *PayByEphemeralAccountRequest) MaxLen() int {
	return req.Message.MaxLen() + 64 + 8
}

// EncodeTo implements types.EncoderTo.
func (req *PayByEphemeralAccountRequest) EncodeTo(e *types.Encoder) {
	req.Message.EncodeTo(e)
	req.Signature.EncodeTo(e)
	e.WriteUint64(req.Priority)
}

// DecodeFrom implements types.DecoderFrom.
func (req *PayByEphemeralAccountRequest) DecodeFrom(d *types.Decoder) {
	req.Message.DecodeFrom(d)
	req.Signature.DecodeFrom(d)
	req.Priority = d.ReadUint64()
}

// PayByContractRequest is a request to create an RPC budget using funds from a
// file contract.
type PayByContractRequest struct {
	ContractID        types.ElementID
	RefundAccount     types.PublicKey
	Signature         types.Signature
	NewRevisionNumber uint64
	NewOutputs        ContractOutputs
}

// MaxLen implements rpc.Object.
func (req *PayByContractRequest) MaxLen() int {
	// contract ID + revision number + payouts + refund + signature
	return 40 + 8 + 64 + 32 + 64
}

// EncodeTo implements types.EncoderTo.
func (req *PayByContractRequest) EncodeTo(e *types.Encoder) {
	req.ContractID.EncodeTo(e)
	req.RefundAccount.EncodeTo(e)
	req.Signature.EncodeTo(e)
	e.WriteUint64(req.NewRevisionNumber)
	req.NewOutputs.encodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (req *PayByContractRequest) DecodeFrom(d *types.Decoder) {
	req.ContractID.DecodeFrom(d)
	req.RefundAccount.DecodeFrom(d)
	req.Signature.DecodeFrom(d)
	req.NewRevisionNumber = d.ReadUint64()
	req.NewOutputs.decodeFrom(d)
}

// RPCRevisionSigningResponse is returned by the host when finalizing a contract
// revision.
type RPCRevisionSigningResponse struct {
	Signature types.Signature
}

// MaxLen implements rpc.Object.
func (resp *RPCRevisionSigningResponse) MaxLen() int {
	return 64
}

// EncodeTo implements types.EncoderTo.
func (resp *RPCRevisionSigningResponse) EncodeTo(e *types.Encoder) {
	resp.Signature.EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (resp *RPCRevisionSigningResponse) DecodeFrom(d *types.Decoder) {
	resp.Signature.DecodeFrom(d)
}

// RPCAccountBalanceResponse is the returned response for RPCAccountBalance.
type RPCAccountBalanceResponse struct {
	Balance types.Currency
}

// MaxLen returns the maximum length of the encoded object. Implements
// rpc.Object.
func (resp *RPCAccountBalanceResponse) MaxLen() int {
	return 16
}

// EncodeTo encodes a RPCAccountBalanceResponse to an encoder. Implements
// types.EncoderTo.
func (resp *RPCAccountBalanceResponse) EncodeTo(e *types.Encoder) {
	resp.Balance.EncodeTo(e)
}

// DecodeFrom decodes a RPCAccountBalanceResponse from a decoder. Implements
// types.DecoderFrom.
func (resp *RPCAccountBalanceResponse) DecodeFrom(d *types.Decoder) {
	resp.Balance.DecodeFrom(d)
}

// RPCAccountBalanceRequest is a request for the balance of an account.
type RPCAccountBalanceRequest struct {
	AccountID types.PublicKey
}

// MaxLen returns the maximum length of the encoded object. Implements
// rpc.Object.
func (resp *RPCAccountBalanceRequest) MaxLen() int {
	return 32
}

// EncodeTo encodes a RPCAccountBalanceRequest to an encoder. Implements
// types.EncoderTo.
func (resp *RPCAccountBalanceRequest) EncodeTo(e *types.Encoder) {
	resp.AccountID.EncodeTo(e)
}

// DecodeFrom decodes a RPCAccountBalanceRequest from a decoder. Implements
// types.DecoderFrom.
func (resp *RPCAccountBalanceRequest) DecodeFrom(d *types.Decoder) {
	resp.AccountID.DecodeFrom(d)
}

// RPCFundAccountRequest is a request to fund an account.
type RPCFundAccountRequest struct {
	AccountID types.PublicKey
}

// MaxLen returns the maximum length of the encoded object. Implements
// rpc.Object.
func (resp *RPCFundAccountRequest) MaxLen() int {
	return 32
}

// EncodeTo encodes a RPCFundAccountRequest to an encoder. Implements
// types.EncoderTo.
func (resp *RPCFundAccountRequest) EncodeTo(e *types.Encoder) {
	resp.AccountID.EncodeTo(e)
}

// DecodeFrom decodes a RPCFundAccountRequest from a decoder. Implements
// types.DecoderFrom.
func (resp *RPCFundAccountRequest) DecodeFrom(d *types.Decoder) {
	resp.AccountID.DecodeFrom(d)
}

// A Receipt is returned as part of funding an ephemeral account. It shows the
// amount deposited and the account.
type Receipt struct {
	Account   types.PublicKey
	Host      types.PublicKey
	Amount    types.Currency
	Timestamp time.Time
}

// SigHash computes the hash of the receipt. Used for signing the
// pay by ephemeral account response.
func (r *Receipt) SigHash() types.Hash256 {
	h := types.NewHasher()
	r.EncodeTo(h.E)
	return h.Sum()
}

// MaxLen returns the maximum length of the encoded object. Implements
// rpc.Object.
func (r *Receipt) MaxLen() int {
	return 32 + 32 + 16 + 8
}

// EncodeTo encodes a Receipt to an encoder. Implements
// types.EncoderTo.
func (r *Receipt) EncodeTo(e *types.Encoder) {
	r.Account.EncodeTo(e)
	r.Host.EncodeTo(e)
	r.Amount.EncodeTo(e)
	e.WriteTime(r.Timestamp)
}

// DecodeFrom decodes a Receipt from a decoder. Implements
// types.DecoderFrom.
func (r *Receipt) DecodeFrom(d *types.Decoder) {
	r.Account.DecodeFrom(d)
	r.Host.DecodeFrom(d)
	r.Amount.DecodeFrom(d)
	r.Timestamp = d.ReadTime()
}

// RPCFundAccountResponse is the response to a RPCFundAccountRequest. It returns
// the current balance of the account and a signed receipt from the host.
type RPCFundAccountResponse struct {
	Balance   types.Currency
	Receipt   Receipt
	Signature types.Signature
}

// MaxLen returns the maximum length of the encoded object. Implements
// rpc.Object.
func (resp *RPCFundAccountResponse) MaxLen() int {
	return 16 + resp.Receipt.MaxLen() + 8 + 64
}

// EncodeTo encodes a RPCFundAccountResponse to an encoder. Implements
// types.EncoderTo.
func (resp *RPCFundAccountResponse) EncodeTo(e *types.Encoder) {
	resp.Balance.EncodeTo(e)
	resp.Receipt.EncodeTo(e)
	resp.Signature.EncodeTo(e)
}

// DecodeFrom decodes a RPCFundAccountResponse from a decoder. Implements
// types.DecoderFrom.
func (resp *RPCFundAccountResponse) DecodeFrom(d *types.Decoder) {
	resp.Balance.DecodeFrom(d)
	resp.Receipt.DecodeFrom(d)
	resp.Signature.DecodeFrom(d)
}

// RPCExecuteInstrResponse is sent to the renter by the host for each
// successfully executed instruction during program execution. The
// final response is used to determine the final contract state.
type RPCExecuteInstrResponse struct {
	AdditionalCollateral types.Currency
	AdditionalStorage    types.Currency
	FailureRefund        types.Currency
	TotalCost            types.Currency
	OutputLength         uint64
	NewDataSize          uint64
	NewMerkleRoot        types.Hash256
	Proof                []types.Hash256
	Error                error
}

// MaxLen returns the maximum length of the encoded object. Implements
// rpc.Object.
func (resp *RPCExecuteInstrResponse) MaxLen() int {
	return defaultMaxLen
}

// EncodeTo encodes a RPCExecuteInstrResponse to an encoder. Implements
// types.EncoderTo.
func (resp *RPCExecuteInstrResponse) EncodeTo(e *types.Encoder) {
	resp.AdditionalCollateral.EncodeTo(e)
	resp.AdditionalStorage.EncodeTo(e)
	resp.FailureRefund.EncodeTo(e)
	resp.TotalCost.EncodeTo(e)
	e.WriteUint64(resp.OutputLength)
	e.WriteUint64(resp.NewDataSize)
	resp.NewMerkleRoot.EncodeTo(e)
	e.WritePrefix(len(resp.Proof))
	for _, h := range resp.Proof {
		h.EncodeTo(e)
	}
	var errStr string
	if resp.Error != nil {
		errStr = resp.Error.Error()
	}
	e.WriteString(errStr)
}

// DecodeFrom decodes a RPCExecuteInstrResponse from a decoder. Implements
// types.DecoderFrom.
func (resp *RPCExecuteInstrResponse) DecodeFrom(d *types.Decoder) {
	resp.AdditionalCollateral.DecodeFrom(d)
	resp.AdditionalStorage.DecodeFrom(d)
	resp.FailureRefund.DecodeFrom(d)
	resp.TotalCost.DecodeFrom(d)
	resp.OutputLength = d.ReadUint64()
	resp.NewDataSize = d.ReadUint64()
	resp.NewMerkleRoot.DecodeFrom(d)
	resp.Proof = make([]types.Hash256, d.ReadUint64())
	for i := range resp.Proof {
		resp.Proof[i].DecodeFrom(d)
	}
	if str := d.ReadString(); len(str) != 0 {
		resp.Error = errors.New(str)
	}
}

// RPCFinalizeProgramRequest is a request sent by the renter after execution
// of a read-write program to update the contract with the new collateral
// and storage burn.
type RPCFinalizeProgramRequest struct {
	Signature         types.Signature
	NewRevisionNumber uint64
	NewOutputs        ContractOutputs
}

// MaxLen returns the maximum encoded size of the object; implements rpc.Object.
func (req *RPCFinalizeProgramRequest) MaxLen() int {
	return 64 + 8 + 16*4
}

// EncodeTo encodes the RPCFinalizeProgramRequest to the encoder. Implements
// types.EncoderTo.
func (req *RPCFinalizeProgramRequest) EncodeTo(e *types.Encoder) {
	req.Signature.EncodeTo(e)
	e.WriteUint64(req.NewRevisionNumber)
	req.NewOutputs.encodeTo(e)
}

// DecodeFrom decodes the RPCFinalizeProgramRequest from the decoder. Implements
// types.DecoderFrom.
func (req *RPCFinalizeProgramRequest) DecodeFrom(d *types.Decoder) {
	req.Signature.DecodeFrom(d)
	req.NewRevisionNumber = d.ReadUint64()
	req.NewOutputs.decodeFrom(d)
}
