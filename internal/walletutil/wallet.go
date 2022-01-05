// Package walletutil implements an ephemeral wallet and txpool useful for
// testing.
package walletutil

import (
	"errors"
	"sync"

	"go.sia.tech/core/chain"
	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

// An EphemeralWallet is an in-memory implementation of a Wallet.
type EphemeralWallet struct {
	privKey types.PrivateKey

	mu      sync.Mutex
	unspent []types.SiacoinElement
	spent   map[types.ElementID]bool
}

func (w *EphemeralWallet) spendPolicy() types.SpendPolicy {
	return types.PolicyPublicKey(w.privKey.PublicKey())
}

// ProcessChainApplyUpdate applies a block
func (w *EphemeralWallet) ProcessChainApplyUpdate(cau *chain.ApplyUpdate, mayCommit bool) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// remove any spent outputs and update proofs for any remaining outputs
	remaining := w.unspent[:0]
	for _, o := range w.unspent {
		if cau.SiacoinElementWasSpent(o) {
			delete(w.spent, o.ID)
			continue
		}
		cau.UpdateElementProof(&o.StateElement)
		remaining = append(remaining, o)
	}
	w.unspent = remaining

	// add any new siacoin outputs
	for _, o := range cau.NewSiacoinElements {
		if o.Address == w.Address() {
			w.unspent = append(w.unspent, o)
		}
	}
	return nil
}

// ProcessChainRevertUpdate reverts a block
func (w *EphemeralWallet) ProcessChainRevertUpdate(cru *chain.RevertUpdate) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	addr := w.Address()
	// re-add any outputs that were spent
	for _, o := range cru.SpentSiacoins {
		if o.Address == addr {
			w.unspent = append(w.unspent, o)
		}
	}

	// remove any outputs that were removed by this change.
	remaining := w.unspent[:0]
	for _, o := range w.unspent {
		if cru.SiacoinElementWasRemoved(o) {
			continue
		}

		cru.UpdateElementProof(&o.StateElement)
		remaining = append(remaining, o)
	}
	w.unspent = remaining
	return nil
}

// Balance returns the balance of all unspent outputs of the wallet.
func (w *EphemeralWallet) Balance() (balance types.Currency) {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, o := range w.unspent {
		if w.spent[o.ID] {
			continue
		}
		balance = balance.Add(o.Value)
	}
	return
}

// Address returns the address of the wallet.
func (w *EphemeralWallet) Address() types.Address {
	return types.PolicyAddress(w.spendPolicy())
}

// NextAddress returns the address of the wallet.
func (w *EphemeralWallet) NextAddress() types.Address {
	return w.Address()
}

// Addresses returns the addresses of the wallet.
func (w *EphemeralWallet) Addresses() []types.Address {
	return []types.Address{w.Address()}
}

// FundTransaction adds outputs to the transaction.
func (w *EphemeralWallet) FundTransaction(txn *types.Transaction, amount types.Currency, pool []types.Transaction) ([]types.ElementID, func(), error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	var added []types.ElementID
	var input types.Currency
	for _, o := range w.unspent {
		if w.spent[o.ID] {
			continue
		}
		w.spent[o.ID] = true
		added = append(added, o.ID)
		txn.SiacoinInputs = append(txn.SiacoinInputs, types.SiacoinInput{
			Parent:      o,
			SpendPolicy: w.spendPolicy(),
		})
		input = input.Add(o.Value)
		if input.Cmp(amount) >= 0 {
			break
		}
	}
	if input.Cmp(amount) < 0 {
		return nil, nil, errors.New("not enough funds")
	} else if input.Cmp(amount) > 0 {
		txn.SiacoinOutputs = append(txn.SiacoinOutputs, types.SiacoinOutput{
			Value:   input.Sub(amount),
			Address: w.Address(),
		})
	}
	return added, func() {
		// cleanup the added outputs
		w.mu.Lock()
		defer w.mu.Unlock()
		for _, id := range added {
			delete(w.spent, id)
		}
	}, nil
}

// SignTransaction signs inputs in the transaction.
func (w *EphemeralWallet) SignTransaction(vc consensus.ValidationContext, txn *types.Transaction, toSign []types.ElementID) error {
	sigMap := make(map[types.ElementID]bool)
	for _, id := range toSign {
		sigMap[id] = true
	}
	sigHash := vc.SigHash(*txn)
	for i, sci := range txn.SiacoinInputs {
		if !sigMap[sci.Parent.ID] {
			continue
		}
		txn.SiacoinInputs[i].Signatures = append(txn.SiacoinInputs[i].Signatures, types.InputSignature(w.privKey.SignHash(sigHash)))
	}
	return nil
}

// NewEphemeralWallet creates a new ephemeral wallet and applies the genesis
// update to its state.
func NewEphemeralWallet(privKey types.PrivateKey, genesis *chain.ApplyUpdate) *EphemeralWallet {
	w := &EphemeralWallet{
		privKey: privKey,
		spent:   make(map[types.ElementID]bool),
	}
	w.ProcessChainApplyUpdate(genesis, true)
	return w
}
