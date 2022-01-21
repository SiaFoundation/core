package rhp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"go.sia.tech/core/types"
)

const (
	// EntryTypeArbitrary is a registry value where all data is arbitrary.
	EntryTypeArbitrary = iota + 1
	// EntryTypePubKey is a registry value where the first 20 bytes of data
	// corresponds to the hash of a host's public key.
	EntryTypePubKey
)

const (
	// MaxValueDataSize is the maximum size of a Value's Data
	// field.
	MaxValueDataSize = 113
)

// A RegistryValue is stored in the host registry.
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

// Hash returns the hash of the Value used for signing
// the entry.
func (r *RegistryValue) Hash() types.Hash256 {
	h := types.NewHasher()

	h.E.Write(r.Tweak[:])
	h.E.WriteBytes(r.Data)
	h.E.WriteUint64(r.Revision)
	h.E.WriteUint64(uint64(r.Type))

	return h.Sum()
}

// Work returns the work of a Value.
func (r *RegistryValue) Work() types.Work {
	var data []byte
	switch r.Type {
	case EntryTypePubKey:
		// for public key entries the first 20 bytes represent the
		// public key of the host, ignore it for work calculations.
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

// MaxLen returns the maximum length of an encoded Value. Implements
// rpc.Object.
func (r *RegistryValue) MaxLen() int {
	return 32 + 8 + MaxValueDataSize + 8 + 1 + 32 + 64
}

// EncodeTo encodes a Value to an Encoder. Implements types.EncoderTo.
func (r *RegistryValue) EncodeTo(e *types.Encoder) {
	r.Tweak.EncodeTo(e)
	e.WriteBytes(r.Data)
	e.WriteUint64(r.Revision)
	e.WriteUint8(r.Type)
	r.PublicKey.EncodeTo(e)
	r.Signature.EncodeTo(e)
}

// DecodeFrom decodes a Value from a Decoder. Implements types.DecoderFrom.
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
	// v1 compat registry key
	// ed25519 specifier + LE uint64 pub key length + public key + tweak
	buf := make([]byte, 16+8+32+32)
	copy(buf, "ed25519")
	binary.LittleEndian.PutUint64(buf[16:], 32)
	copy(buf[24:], pub[:])
	copy(buf[56:], tweak[:])
	return types.HashBytes(buf)
}

// RegistryHostID returns the ID hash of the host for primary registry entries.
func RegistryHostID(pub types.PublicKey) types.Hash256 {
	// v1 compat host public key hash
	// ed25519 specifier + LE uint64 pub key length + public key
	buf := make([]byte, 16+8+32)
	copy(buf, "ed25519")
	binary.LittleEndian.PutUint64(buf[16:], 32)
	copy(buf[24:], pub[:])
	return types.HashBytes(buf)
}

// ValidateRegistryEntry validates the fields of a registry entry.
func ValidateRegistryEntry(value RegistryValue) (err error) {
	switch value.Type {
	case EntryTypeArbitrary:
		break // no extra validation required
	case EntryTypePubKey:
		// pub key entries have the first 20 bytes of the host's pub key hash
		// prefixed to the data.
		if len(value.Data) < 20 {
			return errors.New("expected host public key hash")
		}
	default:
		return fmt.Errorf("invalid registry value type: %d", value.Type)
	}

	switch {
	case !value.PublicKey.VerifyHash(value.Hash(), value.Signature):
		return errors.New("registry value signature invalid")
	case len(value.Data) > MaxValueDataSize:
		return fmt.Errorf("registry value too large: %d", len(value.Data))
	}

	return nil
}

// ValidateRegistryUpdate validates a registry update against the current entry.
// An updated registry entry must have a greater revision number, more work, or
// be replacing a non-primary registry entry.
func ValidateRegistryUpdate(old, update RegistryValue, hostID types.Hash256) error {
	// if the new revision is greater than the current revision, the update is
	// valid.
	if update.Revision > old.Revision {
		return nil
	} else if update.Revision < old.Revision {
		return errors.New("update revision must be greater than current revision")
	}

	// if the revision number is the same, but the work is greater, the update
	// is valid.
	if w := update.Work().Cmp(old.Work()); w > 0 {
		return nil
	} else if w < 0 {
		return errors.New("update must have greater work or greater revision number than current entry")
	}

	// if the update entry is an arbitrary value entry, the update is invalid.
	if update.Type == EntryTypeArbitrary {
		return errors.New("update must be a primary entry or have a greater revision number")
	}

	// if the updated entry is not a primary entry, it is invalid.
	if !bytes.Equal(update.Data[:20], hostID[:20]) {
		return errors.New("update must be a primary entry or have a greater revision number")
	}

	// if the update and current entry are both primary, the update is invalid
	if old.Type == EntryTypePubKey && bytes.Equal(old.Data[:20], hostID[:20]) {
		return errors.New("update revision must be greater than current revision")
	}

	return nil
}
