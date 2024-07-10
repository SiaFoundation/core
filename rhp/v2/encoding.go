package rhp

import (
	"go.sia.tech/core/types"
)

// A ProtocolObject is an object that can be serialized for transport in the
// renter-host protocol.
type ProtocolObject interface {
	types.EncoderTo
	types.DecoderFrom
}

// EncodeTo implements ProtocolObject.
func (c *Challenge) EncodeTo(e *types.Encoder) { e.Write(c[:]) }

// DecodeFrom implements ProtocolObject.
func (c *Challenge) DecodeFrom(d *types.Decoder) { d.Read(c[:]) }

// EncodeTo implements ProtocolObject.
func (r *RPCError) EncodeTo(e *types.Encoder) {
	r.Type.EncodeTo(e)
	e.WriteBytes(r.Data)
	e.WriteString(r.Description)
}

// DecodeFrom implements ProtocolObject.
func (r *RPCError) DecodeFrom(d *types.Decoder) {
	r.Type.DecodeFrom(d)
	r.Data = d.ReadBytes()
	r.Description = d.ReadString()
}

// EncodeTo implements ProtocolObject.
func (resp *rpcResponse) EncodeTo(e *types.Encoder) {
	e.WriteBool(resp.err != nil)
	if resp.err != nil {
		resp.err.EncodeTo(e)
		return
	}
	resp.data.EncodeTo(e)
}

// DecodeFrom implements ProtocolObject.
func (resp *rpcResponse) DecodeFrom(d *types.Decoder) {
	if d.ReadBool() {
		resp.err = new(RPCError)
		resp.err.DecodeFrom(d)
		return
	}
	resp.data.DecodeFrom(d)
}

// EncodeTo implements ProtocolObject.
func (r *loopKeyExchangeRequest) EncodeTo(e *types.Encoder) {
	loopEnter.EncodeTo(e)
	e.Write(r.PublicKey[:])
	types.EncodeSlice(e, r.Ciphers)
}

// DecodeFrom implements ProtocolObject.
func (r *loopKeyExchangeRequest) DecodeFrom(d *types.Decoder) {
	new(types.Specifier).DecodeFrom(d) // loopEnter
	d.Read(r.PublicKey[:])
	types.DecodeSlice(d, &r.Ciphers)
}

// EncodeTo implements ProtocolObject.
func (r *loopKeyExchangeResponse) EncodeTo(e *types.Encoder) {
	e.Write(r.PublicKey[:])
	e.WriteBytes(r.Signature[:])
	r.Cipher.EncodeTo(e)
}

// DecodeFrom implements ProtocolObject.
func (r *loopKeyExchangeResponse) DecodeFrom(d *types.Decoder) {
	d.Read(r.PublicKey[:])
	copy(r.Signature[:], d.ReadBytes())
	r.Cipher.DecodeFrom(d)
}

// RPCFormContract

// EncodeTo implements ProtocolObject.
func (r *RPCFormContractRequest) EncodeTo(e *types.Encoder) {
	types.EncodeSlice(e, r.Transactions)
	r.RenterKey.EncodeTo(e)
}

// DecodeFrom implements ProtocolObject.
func (r *RPCFormContractRequest) DecodeFrom(d *types.Decoder) {
	types.DecodeSlice(d, &r.Transactions)
	r.RenterKey.DecodeFrom(d)
}

// EncodeTo implements ProtocolObject.
func (r *RPCFormContractAdditions) EncodeTo(e *types.Encoder) {
	types.EncodeSlice(e, r.Parents)
	types.EncodeSlice(e, r.Inputs)
	types.EncodeSliceCast[types.V1SiacoinOutput](e, r.Outputs)
}

// DecodeFrom implements ProtocolObject.
func (r *RPCFormContractAdditions) DecodeFrom(d *types.Decoder) {
	types.DecodeSlice(d, &r.Parents)
	types.DecodeSlice(d, &r.Inputs)
	types.DecodeSliceCast[types.V1SiacoinOutput](d, &r.Outputs)
}

// EncodeTo implements ProtocolObject.
func (r *RPCFormContractSignatures) EncodeTo(e *types.Encoder) {
	types.EncodeSlice(e, r.ContractSignatures)
	r.RevisionSignature.EncodeTo(e)
}

// DecodeFrom implements ProtocolObject.
func (r *RPCFormContractSignatures) DecodeFrom(d *types.Decoder) {
	types.DecodeSlice(d, &r.ContractSignatures)
	r.RevisionSignature.DecodeFrom(d)
}

// RPCRenewAndClear

// EncodeTo implements ProtocolObject.
func (r *RPCRenewAndClearContractRequest) EncodeTo(e *types.Encoder) {
	types.EncodeSlice(e, r.Transactions)
	r.RenterKey.EncodeTo(e)
	types.EncodeSliceCast[types.V1Currency](e, r.FinalValidProofValues)
	types.EncodeSliceCast[types.V1Currency](e, r.FinalMissedProofValues)
}

// DecodeFrom implements ProtocolObject.
func (r *RPCRenewAndClearContractRequest) DecodeFrom(d *types.Decoder) {
	types.DecodeSlice(d, &r.Transactions)
	r.RenterKey.DecodeFrom(d)
	types.DecodeSliceCast[types.V1Currency](d, &r.FinalValidProofValues)
	types.DecodeSliceCast[types.V1Currency](d, &r.FinalMissedProofValues)
}

// EncodeTo implements ProtocolObject.
func (r *RPCRenewAndClearContractSignatures) EncodeTo(e *types.Encoder) {
	types.EncodeSlice(e, r.ContractSignatures)
	r.RevisionSignature.EncodeTo(e)
	e.WriteBytes(r.FinalRevisionSignature[:])
}

// DecodeFrom implements ProtocolObject.
func (r *RPCRenewAndClearContractSignatures) DecodeFrom(d *types.Decoder) {
	types.DecodeSlice(d, &r.ContractSignatures)
	r.RevisionSignature.DecodeFrom(d)
	copy(r.FinalRevisionSignature[:], d.ReadBytes())
}

// RPCLock

// EncodeTo implements ProtocolObject.
func (r *RPCLockRequest) EncodeTo(e *types.Encoder) {
	r.ContractID.EncodeTo(e)
	e.WriteBytes(r.Signature[:])
	e.WriteUint64(r.Timeout)
}

// DecodeFrom implements ProtocolObject.
func (r *RPCLockRequest) DecodeFrom(d *types.Decoder) {
	r.ContractID.DecodeFrom(d)
	copy(r.Signature[:], d.ReadBytes())
	r.Timeout = d.ReadUint64()
}

// EncodeTo implements ProtocolObject.
func (r *RPCLockResponse) EncodeTo(e *types.Encoder) {
	e.WriteBool(r.Acquired)
	r.NewChallenge.EncodeTo(e)
	r.Revision.EncodeTo(e)
	types.EncodeSlice(e, r.Signatures)
}

// DecodeFrom implements ProtocolObject.
func (r *RPCLockResponse) DecodeFrom(d *types.Decoder) {
	r.Acquired = d.ReadBool()
	r.NewChallenge.DecodeFrom(d)
	r.Revision.DecodeFrom(d)
	types.DecodeSlice(d, &r.Signatures)
}

// RPCRead

// EncodeTo implements ProtocolObject.
func (r *RPCReadRequest) EncodeTo(e *types.Encoder) {
	types.EncodeSliceFn(e, r.Sections, func(e *types.Encoder, s RPCReadRequestSection) {
		s.MerkleRoot.EncodeTo(e)
		e.WriteUint64(uint64(s.Offset))
		e.WriteUint64(uint64(s.Length))
	})
	e.WriteBool(r.MerkleProof)
	e.WriteUint64(r.RevisionNumber)
	types.EncodeSliceCast[types.V1Currency](e, r.ValidProofValues)
	types.EncodeSliceCast[types.V1Currency](e, r.MissedProofValues)
	e.WriteBytes(r.Signature[:])
}

// DecodeFrom implements ProtocolObject.
func (r *RPCReadRequest) DecodeFrom(d *types.Decoder) {
	types.DecodeSliceFn(d, &r.Sections, func(d *types.Decoder) (s RPCReadRequestSection) {
		s.MerkleRoot.DecodeFrom(d)
		s.Offset = d.ReadUint64()
		s.Length = d.ReadUint64()
		return
	})
	r.MerkleProof = d.ReadBool()
	r.RevisionNumber = d.ReadUint64()
	types.DecodeSliceCast[types.V1Currency](d, &r.ValidProofValues)
	types.DecodeSliceCast[types.V1Currency](d, &r.MissedProofValues)
	copy(r.Signature[:], d.ReadBytes())
}

// EncodeTo implements ProtocolObject.
func (r *RPCReadResponse) EncodeTo(e *types.Encoder) {
	e.WriteBytes(r.Signature[:])
	e.WriteBytes(r.Data)
	types.EncodeSlice(e, r.MerkleProof)
}

// DecodeFrom implements ProtocolObject.
func (r *RPCReadResponse) DecodeFrom(d *types.Decoder) {
	copy(r.Signature[:], d.ReadBytes())

	// r.Data will typically be large (4 MiB), so reuse the existing capacity if
	// possible.
	//
	// NOTE: for maximum efficiency, we should be doing this for every slice,
	// but in most cases the extra performance isn't worth the aliasing issues.
	dataLen := int(d.ReadUint64())
	if cap(r.Data) < dataLen {
		r.Data = make([]byte, dataLen)
	}
	r.Data = r.Data[:dataLen]
	d.Read(r.Data)

	types.DecodeSlice(d, &r.MerkleProof)
}

// RPCSectorRoots

// EncodeTo implements ProtocolObject.
func (r *RPCSectorRootsRequest) EncodeTo(e *types.Encoder) {
	e.WriteUint64(r.RootOffset)
	e.WriteUint64(r.NumRoots)
	e.WriteUint64(r.RevisionNumber)
	types.EncodeSliceCast[types.V1Currency](e, r.ValidProofValues)
	types.EncodeSliceCast[types.V1Currency](e, r.MissedProofValues)
	e.WriteBytes(r.Signature[:])
}

// DecodeFrom implements ProtocolObject.
func (r *RPCSectorRootsRequest) DecodeFrom(d *types.Decoder) {
	r.RootOffset = d.ReadUint64()
	r.NumRoots = d.ReadUint64()
	r.RevisionNumber = d.ReadUint64()
	types.DecodeSliceCast[types.V1Currency](d, &r.ValidProofValues)
	types.DecodeSliceCast[types.V1Currency](d, &r.MissedProofValues)
	copy(r.Signature[:], d.ReadBytes())
}

// EncodeTo implements ProtocolObject.
func (r *RPCSectorRootsResponse) EncodeTo(e *types.Encoder) {
	e.WriteBytes(r.Signature[:])
	types.EncodeSlice(e, r.SectorRoots)
	types.EncodeSlice(e, r.MerkleProof)
}

// DecodeFrom implements ProtocolObject.
func (r *RPCSectorRootsResponse) DecodeFrom(d *types.Decoder) {
	copy(r.Signature[:], d.ReadBytes())
	types.DecodeSlice(d, &r.SectorRoots)
	types.DecodeSlice(d, &r.MerkleProof)
}

// RPCSettings

// EncodeTo implements ProtocolObject.
func (r *RPCSettingsResponse) EncodeTo(e *types.Encoder) {
	e.WriteBytes(r.Settings)
}

// DecodeFrom implements ProtocolObject.
func (r *RPCSettingsResponse) DecodeFrom(d *types.Decoder) {
	r.Settings = d.ReadBytes()
}

// RPCWrite

// EncodeTo implements ProtocolObject.
func (r *RPCWriteRequest) EncodeTo(e *types.Encoder) {
	types.EncodeSliceFn(e, r.Actions, func(e *types.Encoder, a RPCWriteAction) {
		a.Type.EncodeTo(e)
		e.WriteUint64(a.A)
		e.WriteUint64(a.B)
		e.WriteBytes(a.Data)
	})
	e.WriteBool(r.MerkleProof)
	e.WriteUint64(r.RevisionNumber)
	types.EncodeSliceCast[types.V1Currency](e, r.ValidProofValues)
	types.EncodeSliceCast[types.V1Currency](e, r.MissedProofValues)
}

// DecodeFrom implements ProtocolObject.
func (r *RPCWriteRequest) DecodeFrom(d *types.Decoder) {
	types.DecodeSliceFn(d, &r.Actions, func(d *types.Decoder) (a RPCWriteAction) {
		a.Type.DecodeFrom(d)
		a.A = d.ReadUint64()
		a.B = d.ReadUint64()
		a.Data = d.ReadBytes()
		return
	})
	r.MerkleProof = d.ReadBool()
	r.RevisionNumber = d.ReadUint64()
	types.DecodeSliceCast[types.V1Currency](d, &r.ValidProofValues)
	types.DecodeSliceCast[types.V1Currency](d, &r.MissedProofValues)
}

// EncodeTo implements ProtocolObject.
func (r *RPCWriteMerkleProof) EncodeTo(e *types.Encoder) {
	types.EncodeSlice(e, r.OldSubtreeHashes)
	types.EncodeSlice(e, r.OldLeafHashes)
	r.NewMerkleRoot.EncodeTo(e)
}

// DecodeFrom implements ProtocolObject.
func (r *RPCWriteMerkleProof) DecodeFrom(d *types.Decoder) {
	types.DecodeSlice(d, &r.OldSubtreeHashes)
	types.DecodeSlice(d, &r.OldLeafHashes)
	r.NewMerkleRoot.DecodeFrom(d)
}

// EncodeTo implements ProtocolObject.
func (r *RPCWriteResponse) EncodeTo(e *types.Encoder) {
	e.WriteBytes(r.Signature[:])
}

// DecodeFrom implements ProtocolObject.
func (r *RPCWriteResponse) DecodeFrom(d *types.Decoder) {
	copy(r.Signature[:], d.ReadBytes())
}
