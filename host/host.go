package host

import (
	"errors"
	"io"
	"time"

	"go.sia.tech/core/chain"
	"go.sia.tech/core/consensus"
	"go.sia.tech/core/net/rhp"
	"go.sia.tech/core/types"
)

var (
	// ErrEntryNotFound should be returned when a registry key does not exist
	// in the registry.
	ErrEntryNotFound = errors.New("entry not found")
)

type (
	// A SectorStore stores contract sector data. Implementations are expected
	// to handle multiple references to a sector for add and delete operations.
	SectorStore interface {
		// Add adds the sector with the specified root to the store.
		Add(root types.Hash256, sector *[rhp.SectorSize]byte) error
		// Delete removes a number of references to a sector from the store.
		// If a sector has no more references, it should be removed from the
		// store.
		Delete(root types.Hash256, references uint64) error
		// Exists checks if the sector exists in the store.
		Exists(root types.Hash256) (bool, error)
		// Read reads the sector with the given root, offset and length
		// into w. Returns the number of bytes read or an error.
		Read(root types.Hash256, w io.Writer, offset, length uint64) (n uint64, err error)
		// Update copies an existing sector with the specified root and adds a
		// new sector to the store with the data at offset overwritten,
		// returning the Merkle root of the new sector.
		Update(root types.Hash256, offset uint64, data []byte) (types.Hash256, error)
	}

	// An EphemeralAccountStore manages ephemeral account balances.
	EphemeralAccountStore interface {
		// Balance returns the balance of the account with the given ID.
		Balance(accountID types.PublicKey) (types.Currency, error)
		// Credit adds the specified amount to the account with the given ID.
		// May be limited by MaxEphemeralAccountBalance setting.
		Credit(accountID types.PublicKey, amount types.Currency) (types.Currency, error)
		// Debit subtracts the specified amount from the account with the given
		// ID. requestID may be used to uniquely identify and prevent duplicate
		// debit requests. Returns the remaining balance of the account.
		Debit(accountID types.PublicKey, requestID types.Hash256, amount types.Currency) (types.Currency, error)
		// Refund refunds the specified amount to the account with the given ID,
		// should not be limited by MaxEphemeralAccountBalance setting.
		Refund(accountID types.PublicKey, amount types.Currency) error
	}

	// RegistryStore stores host registry entries. The registry is a key/value
	// store for small data.
	RegistryStore interface {
		// Get returns the registry value for the given key. If the key is not
		// found should return ErrEntryNotFound.
		Get(types.Hash256) (rhp.RegistryValue, error)
		// Set sets the registry value for the given key.
		Set(key types.Hash256, value rhp.RegistryValue, expiration uint64) (rhp.RegistryValue, error)
		// Len returns the number of entries in the registry.
		Len() uint64
		// Cap returns the maximum number of entries the registry can hold.
		Cap() uint64
	}

	// A ContractStore stores contracts, metadata, and proofs for the host.
	ContractStore interface {
		chain.Subscriber

		// Exists returns true if the contract is in the store.
		Exists(types.ElementID) bool
		// Get returns the contract with the given ID.
		Get(types.ElementID) (rhp.Contract, error)
		// Add stores the provided contract, overwriting any previous contract
		// with the same ID.
		Add(rhp.Contract, types.Transaction) error
		// ReviseContract updates the current revision associated with a contract.
		Revise(rhp.Contract) error

		// Roots returns the roots of all sectors stored by the contract.
		Roots(types.ElementID) ([]types.Hash256, error)
		// SetRoots sets the stored roots of the contract.
		SetRoots(types.ElementID, []types.Hash256) error
	}

	// A ContractManager manages a hosts active contracts.
	ContractManager interface {
		// Lock locks a contract for modification.
		Lock(types.ElementID, time.Duration) (rhp.Contract, error)
		// Unlock unlocks a locked contract.
		Unlock(types.ElementID)
		// Add stores the provided contract, overwriting any previous contract
		// with the same ID.
		Add(rhp.Contract, types.Transaction) error
		// ReviseContract updates the current revision associated with a contract.
		Revise(rhp.Contract) error

		// Roots returns the roots of all sectors stored by the contract.
		Roots(types.ElementID) ([]types.Hash256, error)
		// SetRoots updates the roots of the contract.
		SetRoots(types.ElementID, []types.Hash256) error
	}

	// A SettingsReporter returns the host's current settings.
	SettingsReporter interface {
		Settings() rhp.HostSettings
	}

	// A TransactionPool broadcasts transaction sets to miners for inclusion in
	// an upcoming block.
	TransactionPool interface {
		AddTransaction(txn types.Transaction) error
		RecommendedFee() types.Currency
	}

	// A Wallet provides addresses and funds and signs transactions.
	Wallet interface {
		Address() types.Address
		SpendPolicy(types.Address) (types.SpendPolicy, bool)
		FundTransaction(txn *types.Transaction, amount types.Currency, pool []types.Transaction) ([]types.ElementID, func(), error)
		SignTransaction(cs consensus.State, txn *types.Transaction, toSign []types.ElementID) error
	}
)
