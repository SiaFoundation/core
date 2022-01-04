package host

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"go.sia.tech/core/chain"
	"go.sia.tech/core/types"
)

// A contractManager manages contracts on the host and handles lifecycle actions
// TODO: should this logic be moved to siad and provided via interface instead?
// It would simplify core and allow for more flexibility in the future.
type contractManager struct {
	store ContractStore

	mu    sync.Mutex
	locks map[types.ElementID]*locker
}

func (cm *contractManager) lock(id types.ElementID, timeout time.Duration) (Contract, error) {
	// cannot defer unlock to prevent deadlock
	cm.mu.Lock()

	contract, err := cm.store.Get(id)
	if err != nil {
		cm.mu.Unlock()
		return Contract{}, fmt.Errorf("failed to get contract: %w", err)
	} else if contract.FatalError != nil {
		cm.mu.Unlock()
		return Contract{}, fmt.Errorf("contract is no longer usable: %w", contract.FatalError)
	}

	_, exists := cm.locks[id]
	if !exists {
		cm.locks[id] = &locker{
			c:       make(chan struct{}, 1),
			waiters: 0,
		}
		cm.mu.Unlock()
		return contract, nil
	}
	cm.locks[id].waiters++
	c := cm.locks[id].c
	// mutex must be unlocked before waiting on the channel to prevent deadlock.
	cm.mu.Unlock()
	select {
	case <-c:
		contract, err := cm.store.Get(id)
		if err != nil {
			return Contract{}, fmt.Errorf("failed to get contract: %w", err)
		}
		return contract, nil
	case <-time.After(timeout):
		return Contract{}, errors.New("contract lock timeout")
	}
}

func (cm *contractManager) unlock(id types.ElementID) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	lock, exists := cm.locks[id]
	if !exists {
		return
	} else if lock.waiters <= 0 {
		delete(cm.locks, id)
		return
	}
	lock.waiters--
	lock.c <- struct{}{}
}

func (cm *contractManager) add(contract Contract) error {
	return cm.store.Add(contract)
}

func (cm *contractManager) revise(revision types.FileContractRevision) error {
	return cm.store.Revise(revision)
}

// ProcessChainApplyUpdate processes a chain update.
//
// TODO: contract proofs need to be updated and revisions need to be submitted.
func (cm *contractManager) ProcessChainApplyUpdate(cau *chain.ApplyUpdate, mayCommit bool) error {
	return nil

}

// ProcessChainRevertUpdate processes a chain revert.
//
// TODO: contract proofs need to be updated, contract transactions may need to
// be resubmitted, and invalid contracts need to be pruned.
func (cm *contractManager) ProcessChainRevertUpdate(cru *chain.RevertUpdate) error {
	return nil
}
