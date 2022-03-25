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

	// A SettingsReporter returns the host's current settings.
	SettingsReporter interface {
		Settings() rhp.HostSettings
	}

	// A TransactionPool broadcasts transaction sets to miners for inclusion in
	// an upcoming block.
	TransactionPool interface {
		AddTransaction(txn types.Transaction) error
		RecommendedFee() types.Currency
		Transactions() []types.Transaction
	}

	// A Wallet provides addresses and funds and signs transactions.
	Wallet interface {
		Address() types.Address
		FundTransaction(txn *types.Transaction, amount types.Currency, pool []types.Transaction) ([]types.ElementID, func(), error)
		SignTransaction(vc consensus.ValidationContext, txn *types.Transaction, toSign []types.ElementID) error
	}
)

type (
	// ContractState is the current lifecycle stage of a contract.
	ContractState string

	// A Contract contains metadata on the current lifecycle stage of a file
	// contract.
	Contract struct {
		rhp.Contract
		Parent types.FileContractElement
		// FormationTransaction is the transaction created by the host and
		// renter during contract formation. A reference is kept in case it
		// needs to be rebroadcast. Transaction proofs should be updated by the
		// contract store if the transaction is not confirmed.
		Confirmed            bool
		FormationTransaction types.Transaction

		// StorageProof is the future storage proof for the contract.
		// WindowStart and WindowProof are expected to be kept updated by the
		// contract store.
		StorageProof types.StorageProof

		// ResolutionHeight is the height the contract was resolved, or 0 if the
		// contract is unresolved.
		ResolutionHeight uint64
		// State is the current lifecycle state of the contract.
		State ContractState
	}

	// A ContractStore stores contracts and manages proofs for the host.
	ContractStore interface {
		chain.Subscriber

		// Exists returns true if the contract is in the store.
		Exists(types.ElementID) bool
		// Get returns the contract with the given ID.
		Get(types.ElementID) (rhp.Contract, error)
		// Add stores the provided contract, should error if the contract
		// already exists in the store.
		Add(rhp.Contract, types.Transaction) error
		// Delete removes the contract with the given ID from the store.
		Delete(types.ElementID) error
		// ReviseContract updates the current revision associated with a contract.
		Revise(rhp.Contract) error

		// Roots returns the roots of all sectors stored by the contract.
		Roots(types.ElementID) ([]types.Hash256, error)
		// SetRoots sets the stored roots of the contract.
		SetRoots(types.ElementID, []types.Hash256) error

		// ContractAction calls contractFn on every contract in the store that
		// needs a lifecycle action performed.
		ContractAction(vc consensus.ValidationContext, contractFn func(consensus.ValidationContext, Contract)) error
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
)

var (
	// ContractStateUnresolved is a contract that has not yet been resolved.
	ContractStateUnresolved ContractState = "unresolved"
	// ContractStateFinalized is a contract that has been finalized early.
	ContractStateFinalized ContractState = "finalized"
	// ContractStateRenewed is a contract that has been renewed.
	ContractStateRenewed ContractState = "renewed"
	// ContractStateValid is a contract with a successfully confirmed storage proof.
	ContractStateValid ContractState = "valid"
	// ContractStateMissed is a contract that was resolved after the proof window
	// ended.
	ContractStateMissed ContractState = "missed"
)

// ShouldSubmitRevision returns true if the host should broadcast the final
// revision. The final revision should be broadcast if the height is within 6
// blocks of the proof window and the host's current revision number is higher
// than the parent's.
func (c *Contract) ShouldSubmitRevision(index types.ChainIndex) bool {
	return index.Height >= c.Parent.WindowStart-6 && index.Height < c.Parent.WindowStart && c.Revision.RevisionNumber > c.Parent.RevisionNumber
}

// ShouldSubmitResolution returns true if the host should broadcast a contract
// resolution. The contract resolution should be broadcast if the contract is in
// the proof window and has not already been resolved.
func (c *Contract) ShouldSubmitResolution(index types.ChainIndex) bool {
	// if the current index is past window start and the contract has not been resolved, attempt to resolve it. If the
	// resolution fails, retry every 6 blocks.
	return c.ResolutionHeight == 0 && c.Parent.WindowStart <= index.Height && (index.Height-c.Parent.WindowStart)%6 == 0
}
