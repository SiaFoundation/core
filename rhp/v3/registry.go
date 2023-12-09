package rhp

import (
	"bytes"
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

// A RegistryKey uniquely identifies a value in the host's registry.
type RegistryKey struct {
	PublicKey types.PublicKey
	Tweak     types.Hash256
}

// A RegistryValue is a value associated with a key and a tweak in a host's
// registry.
type RegistryValue struct {
	Data      []byte
	Revision  uint64
	Type      uint8
	Signature types.Signature
}

// A RegistryEntry contains the data stored by a host for each registry value.
type RegistryEntry struct {
	RegistryKey
	RegistryValue
}

// Hash returns the hash of the key.
func (rk *RegistryKey) Hash() types.Hash256 {
	h := types.NewHasher()
	rk.PublicKey.UnlockKey().EncodeTo(h.E)
	rk.Tweak.EncodeTo(h.E)
	return h.Sum()
}

// Hash returns the hash used for signing the entry.
func (re *RegistryEntry) Hash() types.Hash256 {
	h := types.NewHasher()
	re.Tweak.EncodeTo(h.E)
	h.E.WriteBytes(re.Data)
	h.E.WriteUint64(re.Revision)
	if re.Type == EntryTypePubKey {
		h.E.WriteUint8(re.Type)
	}
	return h.Sum()
}

// Work returns the work of an entry.
func (re *RegistryEntry) Work() types.Hash256 {
	data := re.Data
	if re.Type == EntryTypePubKey {
		data = re.Data[20:]
	}
	h := types.NewHasher()
	re.Tweak.EncodeTo(h.E)
	h.E.WriteBytes(data)
	h.E.WriteUint64(re.Revision)
	return h.Sum()
}

// CompareRegistryWork compares the work of two registry entries.
func CompareRegistryWork(r1, r2 RegistryEntry) int {
	r1w, r2w := r1.Work(), r2.Work()
	return bytes.Compare(r1w[:], r2w[:])
}

// RegistryHostID returns the ID hash of the host for primary registry entries.
func RegistryHostID(pk types.PublicKey) types.Hash256 {
	h := types.NewHasher()
	pk.UnlockKey().EncodeTo(h.E)
	return h.Sum()
}

// ValidateRegistryEntry validates the fields of a registry entry.
func ValidateRegistryEntry(re RegistryEntry) (err error) {
	switch re.Type {
	case EntryTypeArbitrary:
		// no extra validation required
	case EntryTypePubKey:
		// pub key entries have the first 20 bytes of the host's pub key hash
		// prefixed to the data.
		if len(re.Data) < 20 {
			return errors.New("expected host public key hash")
		}
	default:
		return fmt.Errorf("invalid registry value type: %d", re.Type)
	}
	if !re.PublicKey.VerifyHash(re.Hash(), re.Signature) {
		return errors.New("invalid signature")
	} else if len(re.Data) > MaxValueDataSize {
		return fmt.Errorf("data size exceeds maximum: %d > %d", len(re.Data), MaxValueDataSize)
	}
	return nil
}

// ValidateRegistryUpdate validates a registry update against the current entry.
// An updated registry entry must have a greater revision number, more work, or
// be replacing a non-primary registry entry.
func ValidateRegistryUpdate(old, update RegistryEntry, hostID types.Hash256) error {
	// if the new revision is greater than the current revision, the update is
	// valid.
	if update.Revision > old.Revision {
		return nil
	} else if update.Revision < old.Revision {
		return errors.New("update revision must be greater than current revision")
	}

	// if the revision number is the same, but the work is greater, the update
	// is valid.
	if w := CompareRegistryWork(update, old); w > 0 {
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
