package rhp

import (
	"go.sia.tech/core/net/rpc"
	"go.sia.tech/core/types"
)

// ContractOutputs contains the output values for a FileContract. Because the
// revisions negotiated by the renter and host typically do not modify the
// output recipients, we can save some space by only sending the new values.
type ContractOutputs struct {
	ValidRenterValue  types.Currency
	ValidHostValue    types.Currency
	MissedRenterValue types.Currency
	MissedHostValue   types.Currency
}

// Apply sets the output values of fc according to co.
func (co ContractOutputs) Apply(fc *types.FileContract) {
	fc.ValidRenterOutput.Value = co.ValidRenterValue
	fc.ValidHostOutput.Value = co.ValidHostValue
	fc.MissedRenterOutput.Value = co.MissedRenterValue
	fc.MissedHostOutput.Value = co.MissedHostValue
}

// RPC IDs
var (
	RPCFormContractID       = rpc.NewSpecifier("FormContract")
	RPCLockID               = rpc.NewSpecifier("Lock")
	RPCReadID               = rpc.NewSpecifier("Read")
	RPCRenewContractID      = rpc.NewSpecifier("Renew")
	RPCRenewClearContractID = rpc.NewSpecifier("RenewClear")
	RPCSectorRootsID        = rpc.NewSpecifier("SectorRoots")
	RPCSettingsID           = rpc.NewSpecifier("Settings")
	RPCUnlockID             = rpc.NewSpecifier("Unlock")
	RPCWriteID              = rpc.NewSpecifier("Write")
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
		Outputs []types.SiacoinOutput
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
		ContractID types.ElementID
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

// EncodeTo implements types.EncoderTo.
func (co *ContractOutputs) EncodeTo(e *types.Encoder) {
	co.ValidRenterValue.EncodeTo(e)
	co.ValidHostValue.EncodeTo(e)
	co.MissedRenterValue.EncodeTo(e)
	co.MissedHostValue.EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (co *ContractOutputs) DecodeFrom(d *types.Decoder) {
	co.ValidRenterValue.DecodeFrom(d)
	co.ValidHostValue.DecodeFrom(d)
	co.MissedRenterValue.DecodeFrom(d)
	co.MissedHostValue.DecodeFrom(d)
}

// EncodeTo implements types.EncoderTo.
func (r *RPCFormContractRequest) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.Transactions))
	for i := range r.Transactions {
		r.Transactions[i].EncodeTo(e)
	}
	r.RenterKey.EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (r *RPCFormContractRequest) DecodeFrom(d *types.Decoder) {
	r.Transactions = make([]types.Transaction, d.ReadPrefix())
	for i := range r.Transactions {
		r.Transactions[i].DecodeFrom(d)
	}
	r.RenterKey.DecodeFrom(d)
}

// EncodeTo implements types.EncoderTo.
func (r *RPCFormContractAdditions) EncodeTo(e *types.Encoder) {
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

// DecodeFrom implements types.DecoderFrom.
func (r *RPCFormContractAdditions) DecodeFrom(d *types.Decoder) {
	r.Parents = make([]types.Transaction, d.ReadPrefix())
	for i := range r.Parents {
		r.Parents[i].DecodeFrom(d)
	}
	r.Inputs = make([]types.SiacoinInput, d.ReadPrefix())
	for i := range r.Inputs {
		r.Inputs[i].DecodeFrom(d)
	}
	r.Outputs = make([]types.SiacoinOutput, d.ReadPrefix())
	for i := range r.Outputs {
		r.Outputs[i].DecodeFrom(d)
	}
}

// EncodeTo implements types.EncoderTo.
func (r *RPCFormContractSignatures) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.ContractSignatures))
	for i := range r.ContractSignatures {
		r.ContractSignatures[i].EncodeTo(e)
	}
	r.RevisionSignature.EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (r *RPCFormContractSignatures) DecodeFrom(d *types.Decoder) {
	r.ContractSignatures = make([]types.InputSignature, d.ReadPrefix())
	for i := range r.ContractSignatures {
		r.ContractSignatures[i].DecodeFrom(d)
	}
	r.RevisionSignature.DecodeFrom(d)
}

// EncodeTo implements types.EncoderTo.
func (r *RPCRenewAndClearContractRequest) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.Transactions))
	for i := range r.Transactions {
		r.Transactions[i].EncodeTo(e)
	}
	r.RenterKey.EncodeTo(e)
	r.FinalOutputs.EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (r *RPCRenewAndClearContractRequest) DecodeFrom(d *types.Decoder) {
	r.Transactions = make([]types.Transaction, d.ReadPrefix())
	for i := range r.Transactions {
		r.Transactions[i].DecodeFrom(d)
	}
	r.RenterKey.DecodeFrom(d)
	r.FinalOutputs.DecodeFrom(d)
}

// EncodeTo implements types.EncoderTo.
func (r *RPCRenewAndClearContractSignatures) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.ContractSignatures))
	for i := range r.ContractSignatures {
		r.ContractSignatures[i].EncodeTo(e)
	}
	r.RevisionSignature.EncodeTo(e)
	r.FinalRevisionSignature.EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (r *RPCRenewAndClearContractSignatures) DecodeFrom(d *types.Decoder) {
	r.ContractSignatures = make([]types.InputSignature, d.ReadPrefix())
	for i := range r.ContractSignatures {
		r.ContractSignatures[i].DecodeFrom(d)
	}
	r.RevisionSignature.DecodeFrom(d)
	r.FinalRevisionSignature.DecodeFrom(d)
}

// EncodeTo implements types.EncoderTo.
func (r *RPCLockRequest) EncodeTo(e *types.Encoder) {
	r.ContractID.EncodeTo(e)
	r.Signature.EncodeTo(e)
	e.WriteUint64(r.Timeout)
}

// DecodeFrom implements types.DecoderFrom.
func (r *RPCLockRequest) DecodeFrom(d *types.Decoder) {
	r.ContractID.DecodeFrom(d)
	r.Signature.DecodeFrom(d)
	r.Timeout = d.ReadUint64()
}

// EncodeTo implements types.EncoderTo.
func (r *RPCLockResponse) EncodeTo(e *types.Encoder) {
	e.WriteBool(r.Acquired)
	e.Write(r.NewChallenge[:])
	r.Revision.EncodeTo(e)
	r.Signatures[0].EncodeTo(e)
	r.Signatures[1].EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (r *RPCLockResponse) DecodeFrom(d *types.Decoder) {
	r.Acquired = d.ReadBool()
	d.Read(r.NewChallenge[:])
	r.Revision.DecodeFrom(d)
	r.Signatures[0].DecodeFrom(d)
	r.Signatures[1].DecodeFrom(d)
}

// EncodeTo implements types.EncoderTo.
func (r *RPCReadRequest) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.Sections))
	for i := range r.Sections {
		r.Sections[i].MerkleRoot.EncodeTo(e)
		e.WriteUint64(r.Sections[i].Offset)
		e.WriteUint64(r.Sections[i].Length)
	}
	e.WriteBool(r.MerkleProof)
	e.WriteUint64(r.NewRevisionNumber)
	r.NewOutputs.EncodeTo(e)
	r.Signature.EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (r *RPCReadRequest) DecodeFrom(d *types.Decoder) {
	r.Sections = make([]RPCReadRequestSection, d.ReadPrefix())
	for i := range r.Sections {
		r.Sections[i].MerkleRoot.DecodeFrom(d)
		r.Sections[i].Offset = d.ReadUint64()
		r.Sections[i].Length = d.ReadUint64()
	}
	r.MerkleProof = d.ReadBool()
	r.NewRevisionNumber = d.ReadUint64()
	r.NewOutputs.DecodeFrom(d)
	r.Signature.DecodeFrom(d)
}

// EncodeTo implements types.EncoderTo.
func (r *RPCReadResponse) EncodeTo(e *types.Encoder) {
	r.Signature.EncodeTo(e)
	writePrefixedBytes(e, r.Data)
	writeMerkleProof(e, r.MerkleProof)
}

// DecodeFrom implements types.DecoderFrom.
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

// EncodeTo implements types.EncoderTo.
func (r *RPCSectorRootsRequest) EncodeTo(e *types.Encoder) {
	e.WriteUint64(r.RootOffset)
	e.WriteUint64(r.NumRoots)
	e.WriteUint64(r.NewRevisionNumber)
	r.NewOutputs.EncodeTo(e)
	r.Signature.EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (r *RPCSectorRootsRequest) DecodeFrom(d *types.Decoder) {
	r.RootOffset = d.ReadUint64()
	r.NumRoots = d.ReadUint64()
	r.NewRevisionNumber = d.ReadUint64()
	r.NewOutputs.DecodeFrom(d)
	r.Signature.DecodeFrom(d)
}

// EncodeTo implements types.EncoderTo.
func (r *RPCSectorRootsResponse) EncodeTo(e *types.Encoder) {
	r.Signature.EncodeTo(e)
	writeMerkleProof(e, r.SectorRoots)
	writeMerkleProof(e, r.MerkleProof)
}

// DecodeFrom implements types.DecoderFrom.
func (r *RPCSectorRootsResponse) DecodeFrom(d *types.Decoder) {
	r.Signature.DecodeFrom(d)
	r.SectorRoots = readMerkleProof(d)
	r.MerkleProof = readMerkleProof(d)
}

// EncodeTo implements types.EncoderTo.
func (r *RPCSettingsResponse) EncodeTo(e *types.Encoder) {
	writePrefixedBytes(e, r.Settings)
}

// DecodeFrom implements types.DecoderFrom.
func (r *RPCSettingsResponse) DecodeFrom(d *types.Decoder) {
	r.Settings = readPrefixedBytes(d)
}

// EncodeTo implements types.EncoderTo.
func (r *RPCWriteAction) EncodeTo(e *types.Encoder) {
	r.Type.EncodeTo(e)
	e.WriteUint64(r.A)
	e.WriteUint64(r.B)
	writePrefixedBytes(e, r.Data)
}

// DecodeFrom implements types.DecoderFrom.
func (r *RPCWriteAction) DecodeFrom(d *types.Decoder) {
	r.Type.DecodeFrom(d)
	r.A = d.ReadUint64()
	r.B = d.ReadUint64()
	r.Data = readPrefixedBytes(d)
}

// EncodeTo implements types.EncoderTo.
func (r *RPCWriteRequest) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.Actions))
	for i := range r.Actions {
		r.Actions[i].EncodeTo(e)
	}
	e.WriteBool(r.MerkleProof)
	e.WriteUint64(r.NewRevisionNumber)
	r.NewOutputs.EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (r *RPCWriteRequest) DecodeFrom(d *types.Decoder) {
	r.Actions = make([]RPCWriteAction, d.ReadPrefix())
	for i := range r.Actions {
		r.Actions[i].DecodeFrom(d)
	}
	r.MerkleProof = d.ReadBool()
	r.NewRevisionNumber = d.ReadUint64()
	r.NewOutputs.DecodeFrom(d)
}

// EncodeTo implements types.EncoderTo.
func (r *RPCWriteMerkleProof) EncodeTo(e *types.Encoder) {
	writeMerkleProof(e, r.OldSubtreeHashes)
	writeMerkleProof(e, r.OldLeafHashes)
	r.NewMerkleRoot.EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (r *RPCWriteMerkleProof) DecodeFrom(d *types.Decoder) {
	r.OldSubtreeHashes = readMerkleProof(d)
	r.OldLeafHashes = readMerkleProof(d)
	r.NewMerkleRoot.DecodeFrom(d)
}

// EncodeTo implements types.EncoderTo.
func (r *RPCWriteResponse) EncodeTo(e *types.Encoder) {
	r.Signature.EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (r *RPCWriteResponse) DecodeFrom(d *types.Decoder) {
	r.Signature.DecodeFrom(d)
}
