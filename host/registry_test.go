package host

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"go.sia.tech/core/net/rhp"
	"go.sia.tech/core/types"
	"lukechampine.com/frand"
)

type ephemeralRegistryStore struct {
	mu sync.Mutex

	cap    uint64
	values map[types.Hash256]rhp.RegistryValue
}

// Get returns the registry value for the given key. If the key is not found
// should return rhp.ErrNotFound.
func (er *ephemeralRegistryStore) Get(key types.Hash256) (rhp.RegistryValue, error) {
	er.mu.Lock()
	defer er.mu.Unlock()

	val, exists := er.values[key]
	if !exists {
		return rhp.RegistryValue{}, ErrEntryNotFound
	}
	return val, nil
}

// Set sets the registry value for the given key.
func (er *ephemeralRegistryStore) Set(key types.Hash256, value rhp.RegistryValue, expiration uint64) (rhp.RegistryValue, error) {
	er.mu.Lock()
	defer er.mu.Unlock()

	if _, exists := er.values[key]; !exists && uint64(len(er.values)) >= er.cap {
		return rhp.RegistryValue{}, errors.New("capacity exceeded")
	}

	er.values[key] = value
	return value, nil
}

// Len returns the number of entries in the registry.
func (er *ephemeralRegistryStore) Len() uint64 {
	er.mu.Lock()
	defer er.mu.Unlock()

	return uint64(len(er.values))
}

// Cap returns the maximum number of entries the registry can hold.
func (er *ephemeralRegistryStore) Cap() uint64 {
	return er.cap
}

func newEphemeralRegistryStore(limit uint64) *ephemeralRegistryStore {
	return &ephemeralRegistryStore{
		cap:    limit,
		values: make(map[types.Hash256]rhp.RegistryValue),
	}
}

func TestRegistryLock(t *testing.T) {
	r := registry{
		locks: make(map[types.Hash256]*locker),
	}

	key := types.Hash256(frand.Entropy256())

	// lock the registry key
	if err := r.lockKey(key, time.Second*10); err != nil {
		t.Fatal(err)
	}

	// test locking the registry key again with a timeout; should fail.
	if err := r.lockKey(key, time.Millisecond*100); err == nil {
		t.Fatal("expected context error")
	}

	// test locking a second registry key
	{
		key := types.Hash256(frand.Entropy256())
		if err := r.lockKey(key, time.Millisecond*100); err != nil {
			t.Fatal("unexpected error:", err)
		}

		r.unlockKey(key)
	}

	// unlock the first registry key
	r.unlockKey(key)

	// test locking a second time
	if err := r.lockKey(key, time.Millisecond*100); err != nil {
		t.Fatal(err)
	}
	r.unlockKey(key)
}

func randomRegistryValue(key types.PrivateKey) (value rhp.RegistryValue) {
	value.Tweak = frand.Entropy256()
	value.Data = frand.Bytes(32)
	value.Type = rhp.RegistryValueArbitrary
	value.PublicKey = key.PublicKey()
	value.Signature = key.SignHash(value.Hash())
	return
}

func testRegistry(hostID types.Hash256, limit uint64) *registry {
	return &registry{
		hostID: hostID,
		store:  newEphemeralRegistryStore(limit),
		locks:  make(map[types.Hash256]*locker),
	}
}

func TestRegistryPut(t *testing.T) {
	const registryCap = 10

	hostID := types.Hash256(frand.Entropy256())
	reg := testRegistry(hostID, 10)

	key := types.NewPrivateKeyFromSeed(frand.Entropy256())

	// store a random value in the registry
	original := randomRegistryValue(key)
	updated, err := reg.Put(original, registryCap)
	if err != nil {
		t.Fatal(err)
	} else if !reflect.DeepEqual(original, updated) {
		t.Fatal("expected returned value to match")
	}

	// test storing the same value again; should fail and return the original
	// value
	updated, err = reg.Put(original, 10)
	if _, ok := err.(*registryValidationError); !ok {
		t.Fatalf("expected a validation error, got %s", err)
	} else if !reflect.DeepEqual(original, updated) {
		t.Fatal("expected returned value to match")
	}

	// test updating the value's revision number and data; should succeed
	value := rhp.RegistryValue{
		Tweak:     original.Tweak,
		Data:      original.Data,
		Revision:  1,
		Type:      rhp.RegistryValueArbitrary,
		PublicKey: key.PublicKey(),
	}
	value.Signature = key.SignHash(value.Hash())
	updated, err = reg.Put(value, 10)
	if err != nil {
		t.Fatalf("expected update to succeed, got %s", err)
	} else if !reflect.DeepEqual(value, updated) {
		t.Fatal("expected returned value to match new value")
	}

	// test updating the value's work; should succeed
	value = rhp.RegistryValue{
		Tweak:     original.Tweak,
		Data:      make([]byte, 32),
		Revision:  1,
		Type:      rhp.RegistryValueArbitrary,
		PublicKey: key.PublicKey(),
	}
	var i int
	for i = 0; i < 1e6; i++ {
		frand.Read(value.Data)
		if value.Work().Cmp(updated.Work()) > 0 {
			break
		}
	}
	value.Signature = key.SignHash(value.Hash())
	updated, err = reg.Put(value, 10)
	if err != nil {
		t.Fatalf("expected update to succeed, got %s", err)
	} else if !reflect.DeepEqual(value, updated) {
		t.Fatal("expected returned value to match new value")
	}

	// test setting the value to a primary value; should succeed
	value = rhp.RegistryValue{
		Tweak:     original.Tweak,
		Data:      append([]byte(hostID[:20]), updated.Data...),
		Revision:  1,
		Type:      rhp.RegistryValuePubKey,
		PublicKey: key.PublicKey(),
	}
	value.Signature = key.SignHash(value.Hash())
	updated, err = reg.Put(value, 10)
	if err != nil {
		t.Fatalf("expected update to succeed, got %s", err)
	} else if !reflect.DeepEqual(value, updated) {
		t.Fatal("expected returned value to match new value")
	}

	// fill the registry
	for i := 0; i < registryCap-1; i++ {
		_, err := reg.Put(randomRegistryValue(key), 10)
		if err != nil {
			t.Fatalf("failed on entry %d: %s", i, err)
		}
	}

	// test storing a value that would exceed the registry capacity; should fail
	_, err = reg.Put(randomRegistryValue(key), 10)
	if err == nil {
		t.Fatalf("expected cap error")
	}
}
