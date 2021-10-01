package rhp

import (
	"bytes"
	"strings"

	"go.sia.tech/core/types"
)

// A ProtocolObject is an object that can be serialized for transport in the
// renter-host protocol.
type ProtocolObject interface {
	encodeTo(e *types.Encoder)
	decodeFrom(d *types.Decoder)
}

// A Specifier is a generic identification tag.
type Specifier [16]byte

func (s Specifier) String() string { return string(bytes.Trim(s[:], "\x00")) }

func newSpecifier(str string) Specifier {
	if len(str) > 16 {
		panic("specifier is too long")
	}
	var s Specifier
	copy(s[:], str)
	return s
}

// An RPCError may be sent instead of a response object to any RPC.
type RPCError struct {
	Type        Specifier
	Data        []byte // structure depends on Type
	Description string // human-readable error string
}

// Error implements the error interface.
func (err *RPCError) Error() string {
	return err.Description
}

// Is reports whether this error matches target.
func (err *RPCError) Is(target error) bool {
	return strings.Contains(err.Description, target.Error())
}

// rpcResponse is a helper type for encoding and decoding RPC response messages,
// which can represent either valid data or an error.
type rpcResponse struct {
	err  *RPCError
	data ProtocolObject
}

// ContractOutputs contains the output values for a FileContractState.
// Because the revisions negotiated by the renter and host typically do not
// modify the output recipients, we can save some space by only sending the
// new values.
type ContractOutputs struct {
	ValidRenterValue  types.Currency
	ValidHostValue    types.Currency
	MissedRenterValue types.Currency
	MissedHostValue   types.Currency
}

// Apply sets the output values of fc according to co.
func (co ContractOutputs) Apply(fc *types.FileContractState) {
	fc.ValidRenterOutput.Value = co.ValidRenterValue
	fc.ValidHostOutput.Value = co.ValidHostValue
	fc.MissedRenterOutput.Value = co.MissedRenterValue
	fc.MissedHostOutput.Value = co.MissedHostValue
}

// Handshake specifiers
var (
	loopEnter = newSpecifier("LoopEnter")
	loopExit  = newSpecifier("LoopExit")
)

// RPC IDs
var (
	RPCFormContractID       = newSpecifier("LoopFormContract")
	RPCLockID               = newSpecifier("LoopLock")
	RPCReadID               = newSpecifier("LoopRead")
	RPCRenewContractID      = newSpecifier("LoopRenew")
	RPCRenewClearContractID = newSpecifier("LoopRenewClear")
	RPCSectorRootsID        = newSpecifier("LoopSectorRoots")
	RPCSettingsID           = newSpecifier("LoopSettings")
	RPCUnlockID             = newSpecifier("LoopUnlock")
	RPCWriteID              = newSpecifier("LoopWrite")
)

// Read/Write actions
var (
	RPCWriteActionAppend = newSpecifier("Append")
	RPCWriteActionTrim   = newSpecifier("Trim")
	RPCWriteActionSwap   = newSpecifier("Swap")
	RPCWriteActionUpdate = newSpecifier("Update")

	RPCReadStop = newSpecifier("ReadStop")
)

// RPC request/response objects
type (
	// RPCFormContractRequest contains the request parameters for the
	// FormContract and RenewContract RPCs.
	RPCFormContractRequest struct {
		Transactions []types.Transaction
		RenterKey    types.PublicKey
	}

	// RPCRenewAndClearContractRequest contains the request parameters for the
	// RenewAndClearContract RPC.
	RPCRenewAndClearContractRequest struct {
		Transactions []types.Transaction
		RenterKey    types.PublicKey
		FinalOutputs ContractOutputs
	}

	// RPCFormContractAdditions contains the parent transaction, inputs, and
	// outputs added by the host when negotiating a file contract.
	RPCFormContractAdditions struct {
		Parents []types.Transaction
		Inputs  []types.SiacoinInput
		Outputs []types.Beneficiary
	}

	// RPCFormContractSignatures contains the signatures for a contract
	// transaction and initial revision. These signatures are sent by both the
	// renter and host during contract formation and renewal.
	RPCFormContractSignatures struct {
		ContractSignatures []types.InputSignature
		RevisionSignature  types.Signature
	}

	// RPCRenewAndClearContractSignatures contains the signatures for a contract
	// transaction, initial revision, and final revision of the contract being
	// renewed. These signatures are sent by both the renter and host during the
	// RenewAndClear RPC.
	RPCRenewAndClearContractSignatures struct {
		ContractSignatures     []types.InputSignature
		RevisionSignature      types.Signature
		FinalRevisionSignature types.InputSignature
	}

	// RPCLockRequest contains the request parameters for the Lock RPC.
	RPCLockRequest struct {
		ContractID types.OutputID
		Signature  types.InputSignature
		Timeout    uint64
	}

	// RPCLockResponse contains the response data for the Lock RPC.
	RPCLockResponse struct {
		Acquired     bool
		NewChallenge [16]byte
		Revision     types.FileContractRevision
		Signatures   [2]types.Signature
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

	// RPCSettingsResponse contains the response data for the SettingsResponse RPC.
	RPCSettingsResponse struct {
		Settings []byte // JSON-encoded hostdb.HostSettings
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
		Type Specifier
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

func writePrefixedBytes(e *types.Encoder, b []byte) {
	e.WritePrefix(len(b))
	e.Write(b)
}

func readPrefixedBytes(d *types.Decoder) []byte {
	b := make([]byte, d.ReadPrefix())
	d.Read(b)
	return b
}

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

func (s *Specifier) encodeTo(e *types.Encoder)   { e.Write(s[:]) }
func (s *Specifier) decodeFrom(d *types.Decoder) { d.Read(s[:]) }

func (co *ContractOutputs) encodeTo(e *types.Encoder) {
	co.ValidRenterValue.EncodeTo(e)
	co.ValidHostValue.EncodeTo(e)
	co.MissedRenterValue.EncodeTo(e)
	co.MissedHostValue.EncodeTo(e)
}

func (co *ContractOutputs) decodeFrom(d *types.Decoder) {
	co.ValidRenterValue.DecodeFrom(d)
	co.ValidHostValue.DecodeFrom(d)
	co.MissedRenterValue.DecodeFrom(d)
	co.MissedHostValue.DecodeFrom(d)
}

func (err *RPCError) encodeTo(e *types.Encoder) {
	err.Type.encodeTo(e)
	writePrefixedBytes(e, err.Data)
	writePrefixedBytes(e, []byte(err.Description))
}

func (err *RPCError) decodeFrom(d *types.Decoder) {
	err.Type.decodeFrom(d)
	err.Data = readPrefixedBytes(d)
	err.Description = string(readPrefixedBytes(d))
}

func (resp *rpcResponse) encodeTo(e *types.Encoder) {
	e.WriteBool(resp.err != nil)
	if resp.err != nil {
		resp.err.encodeTo(e)
	} else {
		resp.data.encodeTo(e)
	}
}

func (resp *rpcResponse) decodeFrom(d *types.Decoder) {
	if isErr := d.ReadBool(); isErr {
		resp.err = new(RPCError)
		resp.err.decodeFrom(d)
	} else {
		resp.data.decodeFrom(d)
	}
}

func (r *RPCFormContractRequest) encodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.Transactions))
	for i := range r.Transactions {
		r.Transactions[i].EncodeTo(e)
	}
	r.RenterKey.EncodeTo(e)
}

func (r *RPCFormContractRequest) decodeFrom(d *types.Decoder) {
	r.Transactions = make([]types.Transaction, d.ReadPrefix())
	for i := range r.Transactions {
		r.Transactions[i].DecodeFrom(d)
	}
	r.RenterKey.DecodeFrom(d)
}

func (r *RPCFormContractAdditions) encodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.Parents))
	for i := range r.Parents {
		r.Parents[i].EncodeTo(e)
	}
	e.WritePrefix(len(r.Inputs))
	for i := range r.Inputs {
		r.Inputs[i].EncodeTo(e)
	}
	e.WritePrefix(len(r.Outputs))
	for i := range r.Outputs {
		r.Outputs[i].EncodeTo(e)
	}
}

func (r *RPCFormContractAdditions) decodeFrom(d *types.Decoder) {
	r.Parents = make([]types.Transaction, d.ReadPrefix())
	for i := range r.Parents {
		r.Parents[i].DecodeFrom(d)
	}
	r.Inputs = make([]types.SiacoinInput, d.ReadPrefix())
	for i := range r.Inputs {
		r.Inputs[i].DecodeFrom(d)
	}
	r.Outputs = make([]types.Beneficiary, d.ReadPrefix())
	for i := range r.Outputs {
		r.Outputs[i].DecodeFrom(d)
	}
}

func (r *RPCFormContractSignatures) encodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.ContractSignatures))
	for i := range r.ContractSignatures {
		r.ContractSignatures[i].EncodeTo(e)
	}
	r.RevisionSignature.EncodeTo(e)
}

func (r *RPCFormContractSignatures) decodeFrom(d *types.Decoder) {
	r.ContractSignatures = make([]types.InputSignature, d.ReadPrefix())
	for i := range r.ContractSignatures {
		r.ContractSignatures[i].DecodeFrom(d)
	}
	r.RevisionSignature.DecodeFrom(d)
}

func (r *RPCRenewAndClearContractRequest) encodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.Transactions))
	for i := range r.Transactions {
		r.Transactions[i].EncodeTo(e)
	}
	r.RenterKey.EncodeTo(e)
	r.FinalOutputs.encodeTo(e)
}

func (r *RPCRenewAndClearContractRequest) decodeFrom(d *types.Decoder) {
	r.Transactions = make([]types.Transaction, d.ReadPrefix())
	for i := range r.Transactions {
		r.Transactions[i].DecodeFrom(d)
	}
	r.RenterKey.DecodeFrom(d)
	r.FinalOutputs.decodeFrom(d)
}

func (r *RPCRenewAndClearContractSignatures) encodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.ContractSignatures))
	for i := range r.ContractSignatures {
		r.ContractSignatures[i].EncodeTo(e)
	}
	r.RevisionSignature.EncodeTo(e)
	r.FinalRevisionSignature.EncodeTo(e)
}

func (r *RPCRenewAndClearContractSignatures) decodeFrom(d *types.Decoder) {
	r.ContractSignatures = make([]types.InputSignature, d.ReadPrefix())
	for i := range r.ContractSignatures {
		r.ContractSignatures[i].DecodeFrom(d)
	}
	r.RevisionSignature.DecodeFrom(d)
	r.FinalRevisionSignature.DecodeFrom(d)
}

func (r *RPCLockRequest) encodeTo(e *types.Encoder) {
	r.ContractID.EncodeTo(e)
	r.Signature.EncodeTo(e)
	e.WriteUint64(r.Timeout)
}

func (r *RPCLockRequest) decodeFrom(d *types.Decoder) {
	r.ContractID.DecodeFrom(d)
	r.Signature.DecodeFrom(d)
	r.Timeout = d.ReadUint64()
}

func (r *RPCLockResponse) encodeTo(e *types.Encoder) {
	e.WriteBool(r.Acquired)
	e.Write(r.NewChallenge[:])
	r.Revision.EncodeTo(e)
	r.Signatures[0].EncodeTo(e)
	r.Signatures[1].EncodeTo(e)
}

func (r *RPCLockResponse) decodeFrom(d *types.Decoder) {
	r.Acquired = d.ReadBool()
	d.Read(r.NewChallenge[:])
	r.Revision.DecodeFrom(d)
	r.Signatures[0].DecodeFrom(d)
	r.Signatures[1].DecodeFrom(d)
}

func (r *RPCReadRequest) encodeTo(e *types.Encoder) {
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

func (r *RPCReadRequest) decodeFrom(d *types.Decoder) {
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

func (r *RPCReadResponse) encodeTo(e *types.Encoder) {
	r.Signature.EncodeTo(e)
	writePrefixedBytes(e, r.Data)
	writeMerkleProof(e, r.MerkleProof)
}

func (r *RPCReadResponse) decodeFrom(d *types.Decoder) {
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

func (r *RPCSectorRootsRequest) encodeTo(e *types.Encoder) {
	e.WriteUint64(r.RootOffset)
	e.WriteUint64(r.NumRoots)
	e.WriteUint64(r.NewRevisionNumber)
	r.NewOutputs.encodeTo(e)
	r.Signature.EncodeTo(e)
}

func (r *RPCSectorRootsRequest) decodeFrom(d *types.Decoder) {
	r.RootOffset = d.ReadUint64()
	r.NumRoots = d.ReadUint64()
	r.NewRevisionNumber = d.ReadUint64()
	r.NewOutputs.decodeFrom(d)
	r.Signature.DecodeFrom(d)
}

func (r *RPCSectorRootsResponse) encodeTo(e *types.Encoder) {
	r.Signature.EncodeTo(e)
	writeMerkleProof(e, r.SectorRoots)
	writeMerkleProof(e, r.MerkleProof)
}

func (r *RPCSectorRootsResponse) decodeFrom(d *types.Decoder) {
	r.Signature.DecodeFrom(d)
	r.SectorRoots = readMerkleProof(d)
	r.MerkleProof = readMerkleProof(d)
}

func (r *RPCSettingsResponse) encodeTo(e *types.Encoder) {
	writePrefixedBytes(e, r.Settings)
}

func (r *RPCSettingsResponse) decodeFrom(d *types.Decoder) {
	r.Settings = readPrefixedBytes(d)
}

func (r *RPCWriteAction) encodeTo(e *types.Encoder) {
	r.Type.encodeTo(e)
	e.WriteUint64(r.A)
	e.WriteUint64(r.B)
	writePrefixedBytes(e, r.Data)
}

func (r *RPCWriteAction) decodeFrom(d *types.Decoder) {
	r.Type.decodeFrom(d)
	r.A = d.ReadUint64()
	r.B = d.ReadUint64()
	r.Data = readPrefixedBytes(d)
}

func (r *RPCWriteRequest) encodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.Actions))
	for i := range r.Actions {
		r.Actions[i].encodeTo(e)
	}
	e.WriteBool(r.MerkleProof)
	e.WriteUint64(r.NewRevisionNumber)
	r.NewOutputs.encodeTo(e)
}

func (r *RPCWriteRequest) decodeFrom(d *types.Decoder) {
	r.Actions = make([]RPCWriteAction, d.ReadPrefix())
	for i := range r.Actions {
		r.Actions[i].decodeFrom(d)
	}
	r.MerkleProof = d.ReadBool()
	r.NewRevisionNumber = d.ReadUint64()
	r.NewOutputs.decodeFrom(d)
}

func (r *RPCWriteMerkleProof) encodeTo(e *types.Encoder) {
	writeMerkleProof(e, r.OldSubtreeHashes)
	writeMerkleProof(e, r.OldLeafHashes)
	r.NewMerkleRoot.EncodeTo(e)
}

func (r *RPCWriteMerkleProof) decodeFrom(d *types.Decoder) {
	r.OldSubtreeHashes = readMerkleProof(d)
	r.OldLeafHashes = readMerkleProof(d)
	r.NewMerkleRoot.DecodeFrom(d)
}

func (r *RPCWriteResponse) encodeTo(e *types.Encoder) {
	r.Signature.EncodeTo(e)
}

func (r *RPCWriteResponse) decodeFrom(d *types.Decoder) {
	r.Signature.DecodeFrom(d)
}
