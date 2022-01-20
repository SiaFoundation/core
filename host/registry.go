package host

import (
	"errors"
	"fmt"
	"sync"

	"go.sia.tech/core/net/rhp"
	"go.sia.tech/core/types"
)

// A RegistryManager manages registry entries stored in a RegistryStore.
type RegistryManager struct {
	hostID types.Hash256
	store  RegistryStore

	// registry entries must be locked while they are being modified
	mu sync.Mutex
}

// Get returns the registry value for the provided key.
func (r *RegistryManager) Get(key types.Hash256) (rhp.RegistryValue, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.store.Get(key)
}

// Put creates or updates the registry value for the provided key. If err is nil
// the new value is returned, otherwise the previous value is returned.
func (r *RegistryManager) Put(value rhp.RegistryValue, expirationHeight uint64) (rhp.RegistryValue, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := rhp.ValidateRegistryEntry(value); err != nil {
		return rhp.RegistryValue{}, fmt.Errorf("invalid registry entry: %w", err)
	}

	// get the current value.
	key := value.Key()
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

	if err := rhp.ValidateRegistryUpdate(old, value, r.hostID); err != nil {
		return old, fmt.Errorf("invalid registry update: %w", err)
	}

	return r.store.Set(key, value, expirationHeight)
}

// NewRegistryManager returns a new registry manager.
func NewRegistryManager(privkey types.PrivateKey, store RegistryStore) *RegistryManager {
	return &RegistryManager{
		hostID: rhp.RegistryHostID(privkey.PublicKey()),
		store:  store,
	}
}
