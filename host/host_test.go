package host

import (
	"testing"
	"time"

	"go.sia.tech/core/chain"
	"go.sia.tech/core/types"

	"lukechampine.com/frand"
)

type testStubContractStore struct {
}

func (cs *testStubContractStore) ProcessChainApplyUpdate(cau *chain.ApplyUpdate, mayCommit bool) error {
	return nil
}

func (cs *testStubContractStore) ProcessChainRevertUpdate(cru *chain.RevertUpdate) error {
	return nil
}

// Contract returns the contract with the specified ID.
func (cs *testStubContractStore) Contract(id types.ElementID) (contract Contract, _ error) {
	contract.Parent.ID = id
	return
}

// AddContract stores the provided contract, overwriting any previous
// contract with the same ID.
func (cs *testStubContractStore) AddContract(c Contract) error {
	return nil
}

// ReviseContract updates the current revision associated with a contract.
func (cs *testStubContractStore) ReviseContract(revision types.FileContractRevision) error {
	return nil
}

// UpdateContractTransactions updates the contract's various transactions.
//
// This method does not return an error. If a contract cannot be saved to
// the store, the method should panic or exit with an error.
func (cs *testStubContractStore) UpdateContractTransactions(id types.ElementID, finalization, proof []types.Transaction, err error) {
}

// ActionableContracts returns all of the store's contracts for which
// ContractIsActionable returns true (as of the current block height).
//
// This method does not return an error. If contracts cannot be loaded from
// the store, the method should panic or exit with an error.
func (cs *testStubContractStore) ActionableContracts() []Contract {
	return nil
}

func TestContractLock(t *testing.T) {
	h := NewSessionHandler([]byte{31: 0}, nil, nil, new(testStubContractStore), nil, nil, nil, nil, nil, nil)

	id := types.ElementID{
		Source: frand.Entropy256(),
		Index:  frand.Uint64n(1000),
	}

	// lock the contract
	contract, err := h.lockContract(id, time.Second*10)
	if err != nil {
		t.Fatal(err)
	}

	if contract.Parent.ID != id {
		t.Fatalf("unexpected contract id %v, expected %v", contract.Parent.ID, id)
	}

	// test locking the contract again with a timeout; should fail.
	if _, err = h.lockContract(id, time.Millisecond*100); err == nil {
		t.Fatal("expected context error")
	}

	// test locking a second contract
	{
		id := types.ElementID{
			Source: frand.Entropy256(),
			Index:  frand.Uint64n(1000),
		}

		if _, err := h.lockContract(id, time.Millisecond*100); err != nil {
			t.Fatal("unexpected error:", err)
		}

		h.unlockContract(id)
	}

	// unlock the first contract
	h.unlockContract(id)

	// test locking a second time
	if _, err := h.lockContract(id, time.Millisecond*100); err != nil {
		t.Fatal(err)
	}
	h.unlockContract(id)
}

func BenchmarkContractLock(b *testing.B) {
	b.Run("single lock unlock", func(b *testing.B) {
		h := NewSessionHandler([]byte{31: 0}, nil, nil, new(testStubContractStore), nil, nil, nil, nil, nil, nil)

		id := types.ElementID{
			Source: frand.Entropy256(),
			Index:  frand.Uint64n(1000),
		}

		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := h.lockContract(id, time.Millisecond*100); err != nil {
				b.Fatal(err)
			}
			h.unlockContract(id)
		}
	})

	b.Run("multi lock", func(b *testing.B) {
		h := NewSessionHandler([]byte{31: 0}, nil, nil, new(testStubContractStore), nil, nil, nil, nil, nil, nil)

		contracts := make([]types.ElementID, b.N)
		for i := range contracts {
			contracts[i].Source = frand.Entropy256()
			contracts[i].Index = frand.Uint64n(1000)
		}

		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := h.lockContract(contracts[i], time.Millisecond*100); err != nil {
				b.Fatal(err)
			}
		}
	})
}