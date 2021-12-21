package rhp

import (
	"encoding/binary"

	"go.sia.tech/core/types"
)

const (
	// RegistryValueArbitrary is a registry value where all data is arbitrary.
	RegistryValueArbitrary = iota + 1
	// RegistryValuePubKey is a registry value where the first 20 bytes of data
	// corresponds to the hash of a host's public key.
	RegistryValuePubKey
)

const (
	// MaxRegistryValueDataSize is the maximum size of a RegistryValue's Data
	// field.
	MaxRegistryValueDataSize = 113
)

// A RegistryValue is a value stored in the registry.
type RegistryValue struct {
	Tweak    types.Hash256
	Data     []byte
	Revision uint64
	Type     uint8

	PublicKey types.PublicKey
	Signature types.Signature
}

// Key returns the key for the registry value.
func (r *RegistryValue) Key() types.Hash256 {
	return RegistryKey(r.PublicKey, r.Tweak)
}

// Hash returns the hash of the RegistryValue used for signing
// the entry.
func (r *RegistryValue) Hash() types.Hash256 {
	h := types.NewHasher()

	h.E.Write(r.Tweak[:])
	h.E.WriteBytes(r.Data)
	h.E.WriteUint64(r.Revision)
	h.E.WriteUint64(uint64(r.Type))

	return h.Sum()
}

// Work returns the work of a RegistryValue.
func (r *RegistryValue) Work() types.Work {
	var data []byte
	switch r.Type {
	case RegistryValuePubKey:
		data = r.Data[20:]
	default:
		data = r.Data
	}

	h := types.NewHasher()

	h.E.Write(r.Tweak[:])
	h.E.WriteBytes(data)
	h.E.WriteUint64(r.Revision)

	return types.WorkRequiredForHash(types.BlockID(h.Sum()))
}

// MaxLen returns the maximum length of an encoded RegistryValue. Implements
// rpc.Object.
func (r *RegistryValue) MaxLen() int {
	return 32 + 8 + MaxRegistryValueDataSize + 8 + 1 + 32 + 64
}

// EncodeTo encodes a RegistryValue to an Encoder. Implements types.EncoderTo.
func (r *RegistryValue) EncodeTo(e *types.Encoder) {
	r.Tweak.EncodeTo(e)
	e.WriteBytes(r.Data)
	e.WriteUint64(r.Revision)
	e.WriteUint8(r.Type)
	r.PublicKey.EncodeTo(e)
	r.Signature.EncodeTo(e)
}

// DecodeFrom decodes a RegistryValue from a Decoder. Implements types.DecoderFrom.
func (r *RegistryValue) DecodeFrom(d *types.Decoder) {
	r.Tweak.DecodeFrom(d)
	r.Data = make([]byte, d.ReadPrefix())
	d.Read(r.Data)
	r.Revision = d.ReadUint64()
	r.Type = d.ReadUint8()
	r.PublicKey.DecodeFrom(d)
	r.Signature.DecodeFrom(d)
}

// RegistryKey is the unique key for a RegistryValue.
func RegistryKey(pub types.PublicKey, tweak types.Hash256) types.Hash256 {
	// ed25519 specifier + LE uint64 pub key length + public key + tweak
	buf := make([]byte, 16+8+32+32)
	copy(buf, "ed25519")
	binary.LittleEndian.PutUint64(buf[16:], 32)
	copy(buf[24:], pub[:])
	copy(buf[56:], tweak[:])
	return types.HashBytes(buf)
}
