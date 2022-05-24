package host

import (
	"errors"
	"reflect"
	"sync"
	"testing"

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
// should return renterhost.ErrNotFound.
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

func randomRegistryValue(key types.PrivateKey) (value rhp.RegistryValue) {
	value.Tweak = frand.Entropy256()
	value.Data = frand.Bytes(32)
	value.Type = rhp.EntryTypeArbitrary
	value.PublicKey = key.PublicKey()
	value.Signature = key.SignHash(value.Hash())
	return
}

func testRegistry(priKey types.PrivateKey, limit uint64) *RegistryManager {
	return NewRegistryManager(priKey, newEphemeralRegistryStore(limit))
}

func TestRegistryPut(t *testing.T) {
	const registryCap = 10
	hostPriv := types.GeneratePrivateKey()
	renterPriv := types.GeneratePrivateKey()
	reg := testRegistry(hostPriv, registryCap)

	// store a random value in the registry
	original := randomRegistryValue(renterPriv)
	updated, err := reg.Put(original, registryCap)
	if err != nil {
		t.Fatal(err)
	} else if !reflect.DeepEqual(original, updated) {
		t.Fatal("expected returned value to match")
	}

	// test storing the same value again; should fail and return the original
	// value
	updated, err = reg.Put(original, 10)
	if err == nil {
		t.Fatalf("expected validation error")
	} else if !reflect.DeepEqual(original, updated) {
		t.Fatal("expected returned value to match")
	}

	// test updating the value's revision number and data; should succeed
	value := rhp.RegistryValue{
		Tweak:     original.Tweak,
		Data:      original.Data,
		Revision:  1,
		Type:      rhp.EntryTypeArbitrary,
		PublicKey: renterPriv.PublicKey(),
	}
	value.Signature = renterPriv.SignHash(value.Hash())
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
		Type:      rhp.EntryTypeArbitrary,
		PublicKey: renterPriv.PublicKey(),
	}
	var i int
	for i = 0; i < 1e6; i++ {
		frand.Read(value.Data)
		if value.Work().Cmp(updated.Work()) > 0 {
			break
		}
	}
	value.Signature = renterPriv.SignHash(value.Hash())
	updated, err = reg.Put(value, 10)
	if err != nil {
		t.Fatalf("expected update to succeed, got %s", err)
	} else if !reflect.DeepEqual(value, updated) {
		t.Fatal("expected returned value to match new value")
	}

	// test setting the value to a primary value; should succeed
	hostID := rhp.RegistryHostID(hostPriv.PublicKey())
	value = rhp.RegistryValue{
		Tweak:     original.Tweak,
		Data:      append([]byte(hostID[:20]), updated.Data...),
		Revision:  1,
		Type:      rhp.EntryTypePubKey,
		PublicKey: renterPriv.PublicKey(),
	}
	value.Signature = renterPriv.SignHash(value.Hash())
	updated, err = reg.Put(value, 10)
	if err != nil {
		t.Fatalf("expected update to succeed, got %s", err)
	} else if !reflect.DeepEqual(value, updated) {
		t.Fatal("expected returned value to match new value")
	}

	// fill the registry
	for i := 0; i < registryCap-1; i++ {
		_, err := reg.Put(randomRegistryValue(renterPriv), 10)
		if err != nil {
			t.Fatalf("failed on entry %d: %s", i, err)
		}
	}

	// test storing a value that would exceed the registry capacity; should fail
	_, err = reg.Put(randomRegistryValue(renterPriv), 10)
	if err == nil {
		t.Fatalf("expected cap error")
	}
}
