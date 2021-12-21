package host

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.sia.tech/core/net/rhp"
	"go.sia.tech/core/types"
)

type (
	registryValidationError struct {
		err error
	}
)

// Error implements the error interface.
func (e *registryValidationError) Error() string {
	return e.err.Error()
}

type registry struct {
	hostID types.Hash256
	store  RegistryStore

	// registry entries must be locked while they are being modified
	mu    sync.Mutex
	locks map[types.Hash256]*locker
}

// lockKey locks the registry key with the provided key preventing
// updates. The context can be used to interrupt if the registry key lock cannot
// be acquired quickly.
func (r *registry) lockKey(key types.Hash256, timeout time.Duration) error {
	// cannot defer unlock to prevent deadlock
	r.mu.Lock()
	_, exists := r.locks[key]
	if !exists {
		r.locks[key] = &locker{
			c:       make(chan struct{}, 1),
			waiters: 1,
		}
		r.mu.Unlock()
		return nil
	}
	r.locks[key].waiters++
	c := r.locks[key].c
	// mutex must be unlocked before waiting on the channel.
	r.mu.Unlock()
	select {
	case <-c:
		return nil
	case <-time.After(timeout):
		return errors.New("registry key lock timeout")
	}
}

// unlockKey unlocks the registry key with the provided key.
func (r *registry) unlockKey(key types.Hash256) {
	r.mu.Lock()
	defer r.mu.Unlock()
	lock, exists := r.locks[key]
	if !exists {
		return
	} else if lock.waiters <= 0 {
		delete(r.locks, key)
		return
	}
	lock.waiters--
	lock.c <- struct{}{}
}

// Get returns the registry value for the provided key.
func (r *registry) Get(key types.Hash256) (rhp.RegistryValue, error) {
	r.lockKey(key, time.Second)
	defer r.unlockKey(key)
	return r.store.Get(key)
}

// Put creates or updates the registry value for the provided key. If err is
// nil, the new value is returned. If err is not nil and is assignable to
// registryUpdateError, the old value is returned.
func (r *registry) Put(value rhp.RegistryValue, expirationHeight uint64) (rhp.RegistryValue, error) {
	key := value.Key()
	r.lockKey(key, time.Second)
	defer r.unlockKey(key)

	if err := validateRegistryEntry(value); err != nil {
		return rhp.RegistryValue{}, fmt.Errorf("invalid registry entry: %w", err)
	}

	// get the current value.
	old, err := r.store.Get(key)
	// if the key doesn't exist, we don't need to validate it further.
	if errors.Is(err, ErrEntryNotFound) {
		if _, err = r.store.Set(key, value, expirationHeight); err != nil {
			return value, fmt.Errorf("failed to create registry key: %w", err)
		}
		return value, nil
	} else if err != nil {
		return old, fmt.Errorf("failed to get registry value: %w", err)
	}

	if err := validateRegistryUpdate(old, value, r.hostID); err != nil {
		return old, &registryValidationError{fmt.Errorf("invalid registry update: %w", err)}
	}

	return r.store.Set(key, value, expirationHeight)
}

// validateRegistryEntry validates the fields of a registry entry.
func validateRegistryEntry(value rhp.RegistryValue) error {
	switch value.Type {
	case rhp.RegistryValueArbitrary:
		break // no extra validation required
	case rhp.RegistryValuePubKey:
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
	case len(value.Data) > rhp.RegistryDataSize:
		return fmt.Errorf("registry value too large: %d", len(value.Data))
	}

	return nil
}

// validateRegistryUpdate validates a registry update against the current entry.
// An updated registry entry must have a greater revision number, more work, or
// be replacing a non-primary registry entry.
func validateRegistryUpdate(old, update rhp.RegistryValue, hostID types.Hash256) error {
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
	if update.Type == rhp.RegistryValueArbitrary {
		return errors.New("update must be a primary entry or have a greater revision number")
	}

	// if the updated entry is not a primary entry, it is invalid.
	if !bytes.Equal(update.Data[:20], hostID[:20]) {
		return errors.New("update must be a primary entry or have a greater revision number")
	}

	// if the update and current entry are both primary, the update is invalid
	if old.Type == rhp.RegistryValuePubKey && bytes.Equal(old.Data[:20], hostID[:20]) {
		return errors.New("update revision must be greater than current revision")
	}

	return nil
}
