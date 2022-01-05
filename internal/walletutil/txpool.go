package walletutil

import (
	"errors"
	"fmt"
	"sync"

	"go.sia.tech/core/chain"
	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

// A TxPool stores transactions that will eventually be included in a block.
type TxPool struct {
	mu             sync.Mutex
	txns           map[types.TransactionID]types.Transaction
	feeMin, feeMax types.Currency
	vc             consensus.ValidationContext
	prevVC         consensus.ValidationContext
	prevUpdate     consensus.ApplyUpdate
}

func (tp *TxPool) validateTransaction(txn types.Transaction) error {
	if err := tp.vc.ValidateTransaction(txn); err != nil {
		return fmt.Errorf("failed to validate transaction: %w", err)
	}

	// validate ephemeral outputs
	available := make(map[types.ElementID]bool)
	for _, txn := range tp.txns {
		for i := range txn.SiacoinOutputs {
			available[txn.SiacoinOutputID(uint64(i))] = true
		}
	}
	for _, in := range txn.SiacoinInputs {
		if in.Parent.LeafIndex == types.EphemeralLeafIndex {
			if !available[in.Parent.ID] {
				return errors.New("transaction references an unknown ephemeral output")
			}
			delete(available, in.Parent.ID)
		}
	}
	return nil
}

func (tp *TxPool) transactionDependencies(txn types.Transaction, poolTxns map[types.TransactionID]types.Transaction) (dependencies []types.Transaction) {
	added := make(map[types.TransactionID]bool)
	var addDeps func(txn types.Transaction)
	addDeps = func(txn types.Transaction) {
		added[txn.ID()] = true
		for _, in := range txn.SiacoinInputs {
			parentID := types.TransactionID(in.Parent.ID.Source)
			if parent, inPool := poolTxns[parentID]; inPool && !added[parentID] {
				addDeps(parent)
				dependencies = append(dependencies, parent)
			}
		}
	}
	addDeps(txn)
	return
}

// AddTransaction validates a transaction and adds it to the pool. If the
// transaction references ephemeral parent outputs, those outputs must be
// created by other transactions already in the pool. The transaction's proofs
// must be up-to-date.
func (tp *TxPool) AddTransaction(txn types.Transaction) error {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	txid := txn.ID()
	if _, ok := tp.txns[txid]; ok {
		return nil // already in pool
	}
	txn = txn.DeepCopy()
	if err := tp.validateTransaction(txn); err != nil {
		return err
	}
	tp.txns[txid] = txn
	return nil
}

// AcceptTransactionSet validates a transaction set and adds it to the pool. If
// the transaction references ephemeral parent outputs, those outputs must be
// created by other transactions already in the pool. The transaction's proofs
// must be up-to-date.
func (tp *TxPool) AcceptTransactionSet(txns []types.Transaction) error {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	if err := tp.vc.ValidateTransactionSet(txns); err != nil {
		return fmt.Errorf("failed to validate transaction set: %w", err)
	}

	for i, txn := range txns {
		txid := txn.ID()
		if _, ok := tp.txns[txid]; ok {
			return nil // already in pool
		}
		txn = txn.DeepCopy()
		if err := tp.validateTransaction(txn); err != nil {
			return fmt.Errorf("failed to validate transaction %v: %w", i, err)
		}
		tp.txns[txid] = txn
	}
	return nil
}

// FeeEstimate returns the estimated fees for a transaction.
func (tp *TxPool) FeeEstimate() (min, max types.Currency, err error) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return tp.feeMin, tp.feeMax, nil
}

// UnconfirmedParents returns the parents of the transaction in the pool.
func (tp *TxPool) UnconfirmedParents(txn types.Transaction) ([]types.Transaction, error) {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	poolTxns := make(map[types.TransactionID]types.Transaction)
	for _, txn := range tp.txns {
		poolTxns[txn.ID()] = txn
	}

	return tp.transactionDependencies(txn, poolTxns), nil
}

// Transaction returns the transaction with the specified ID, if it is currently
// in the pool.
func (tp *TxPool) Transaction(id types.TransactionID) (types.Transaction, bool) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	txn, ok := tp.txns[id]
	return txn, ok
}

// Transactions returns the transactions currently in the pool.
func (tp *TxPool) Transactions() []types.Transaction {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	txns := make([]types.Transaction, 0, len(tp.txns))
	for _, txn := range tp.txns {
		txns = append(txns, txn.DeepCopy())
	}
	return txns
}

// TransactionsForBlock returns the pool transactions ordered so that all
// parents are included before their dependent children.
func (tp *TxPool) TransactionsForBlock() (txns []types.Transaction) {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	poolTxns := make(map[types.TransactionID]types.Transaction)
	for _, txn := range tp.txns {
		poolTxns[txn.ID()] = txn
	}

	capacity := tp.vc.MaxBlockWeight()
	for _, txn := range poolTxns {
		// prepend the txn with its dependencies
		group := append(tp.transactionDependencies(txn, poolTxns), txn)
		// if the weight of the group exceeds the remaining capacity of the
		// block, skip it
		groupWeight := tp.vc.BlockWeight(group)
		if groupWeight > capacity {
			continue
		}
		// add the group to the block
		txns = append(txns, group...)
		capacity -= groupWeight
		for _, txn := range group {
			delete(poolTxns, txn.ID())
		}
	}
	return
}

// ProcessChainApplyUpdate implements chain.Subscriber.
func (tp *TxPool) ProcessChainApplyUpdate(cau *chain.ApplyUpdate, _ bool) error {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	// delete confirmed txns
	for _, txn := range cau.Block.Transactions {
		delete(tp.txns, txn.ID())
	}

	// update unconfirmed txns
outer:
	for id, txn := range tp.txns {
		// if any of the inputs were spent, the txn is now invalid; delete it
		for i := range txn.SiacoinInputs {
			if cau.SiacoinElementWasSpent(txn.SiacoinInputs[i].Parent) {
				delete(tp.txns, id)
				continue outer
			}
		}
		// all inputs still unspent; update proofs
		for i := range txn.SiacoinInputs {
			cau.UpdateElementProof(&txn.SiacoinInputs[i].Parent.StateElement)
		}

		if err := cau.Context.ValidateTransaction(txn); err != nil {
			delete(tp.txns, id)
			continue
		}

		tp.txns[id] = txn
	}

	// update the current and previous validation contexts
	tp.prevVC, tp.vc = tp.vc, cau.Context
	tp.prevUpdate = cau.ApplyUpdate
	return nil
}

// ProcessChainRevertUpdate implements chain.Subscriber.
func (tp *TxPool) ProcessChainRevertUpdate(cru *chain.RevertUpdate) error {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	// put reverted txns back in the pool
	for _, txn := range cru.Block.Transactions {
		tp.txns[txn.ID()] = txn
	}

	// update unconfirmed txns
outer:
	for id, txn := range tp.txns {
		// if any of the inputs no longer exist, the txn is now invalid; delete it
		for i := range txn.SiacoinInputs {
			if cru.SiacoinElementWasRemoved(txn.SiacoinInputs[i].Parent) {
				delete(tp.txns, id)
				continue outer
			}
		}
		// all inputs still unspent; update proofs
		for i := range txn.SiacoinInputs {
			cru.UpdateElementProof(&txn.SiacoinInputs[i].Parent.StateElement)
		}

		// verify that the transaction is still valid
		if err := cru.Context.ValidateTransaction(txn); err != nil {
			delete(tp.txns, id)
			continue
		}

		tp.txns[id] = txn
	}

	// update validation context
	tp.vc = cru.Context
	return nil
}

// NewTxPool creates a new transaction pool.
func NewTxPool(vc consensus.ValidationContext) *TxPool {
	return &TxPool{
		txns:   make(map[types.TransactionID]types.Transaction),
		vc:     vc,
		prevVC: vc,
	}
}
