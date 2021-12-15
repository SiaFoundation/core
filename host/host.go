package host

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"go.sia.tech/core/chain"
	"go.sia.tech/core/consensus"
	"go.sia.tech/core/net/mux"
	"go.sia.tech/core/net/rhp"
	"go.sia.tech/core/net/rpc"
	"go.sia.tech/core/types"
)

var (
	// ErrEntryNotFound should be returned when a registry key does not exist
	// in the registry.
	ErrEntryNotFound = errors.New("entry not found")
)

type (
	// A Logger logs messages to a location.
	Logger interface {
		Scope(scope string) Logger

		Errorf(f string, v ...interface{})
		Errorln(v ...interface{})

		Infof(f string, v ...interface{})
		Infoln(v ...interface{})

		Warnf(f string, v ...interface{})
		Warnln(v ...interface{})
	}

	// A ChainManager manages the chain state.
	ChainManager interface {
		Tip() types.ChainIndex
		TipContext() (consensus.ValidationContext, error)
	}

	// A SectorStore stores contract sector data.
	SectorStore interface {
		// ContractRoots returns the roots of all sectors belonging to the
		// specified file contract.
		ContractRoots(id types.ElementID) ([]types.Hash256, error)
		// DeleteSector removes a sector from the store.
		DeleteSector(root types.Hash256) error
		// Exists checks if the sector exists in the store.
		Exists(root types.Hash256) (bool, error)
		// SetContractRoots updates the sector roots of the file contract.
		SetContractRoots(id types.ElementID, roots []types.Hash256) error

		// AddSector adds the sector with the specified root to the store.
		AddSector(root types.Hash256, sector *[rhp.SectorSize]byte) error
		// ReadSector reads the sector with the given root, offset and length
		// into w. Returns the number of bytes read or an error.
		ReadSector(root types.Hash256, w io.Writer, offset, length uint64) (n uint64, err error)
	}

	// An EphemeralAccountStore manages ephemeral account balances.
	EphemeralAccountStore interface {
		// Balance returns the balance of the account with the given ID.
		Balance(accountID types.PublicKey) (types.Currency, error)
		// Credit adds the specified amount to the account with the given ID.
		// May be limited by MaxEphemeralAccountBalance setting.
		Credit(accountID types.PublicKey, amount types.Currency) (types.Currency, error)
		// Refund refunds the specified amount to the account with the given ID,
		// should not be limited by MaxEphemeralAccountBalance setting.
		Refund(accountID types.PublicKey, amount types.Currency) error
		// Debit subtracts the specified amount from the account with the given
		// ID. requestID may be used to uniquely identify and prevent duplicate
		// debit requests. Returns the remaining balance of the account.
		Debit(accountID types.PublicKey, requestID types.Hash256, amount types.Currency) (types.Currency, error)
	}

	// A ContractStore stores file contracts, along with some chain metadata.
	ContractStore interface {
		chain.Subscriber

		// Contract returns the contract with the specified ID.
		Contract(id types.ElementID) (Contract, error)

		// AddContract stores the provided contract, overwriting any previous
		// contract with the same ID.
		AddContract(c Contract) error
		// ReviseContract updates the current revision associated with a contract.
		ReviseContract(revision types.FileContractRevision) error
		// UpdateContractTransactions updates the contract's various
		// transactions.
		//
		// This method does not return an error. If a contract cannot be saved
		// to the store, the method should panic or exit with an error.
		UpdateContractTransactions(id types.ElementID, finalization, proof []types.Transaction, err error)
		// ActionableContracts returns all of the store's contracts for which
		// ContractIsActionable returns true (as of the current block height).
		//
		// This method does not return an error. If contracts cannot be loaded
		// from the store, the method should panic or exit with an error.
		ActionableContracts() []Contract
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

	// A Wallet provides addresses and funds and signs transactions.
	Wallet interface {
		Balance() types.Currency
		NextAddress() types.Address
		Addresses() []types.Address
		FundTransaction(txn *types.Transaction, amount types.Currency, pool []types.Transaction) ([]types.ElementID, func(), error)
		SignTransaction(vc consensus.ValidationContext, txn *types.Transaction, toSign []types.ElementID) error
	}

	// A SettingsReporter returns the host's current settings.
	SettingsReporter interface {
		Settings() rhp.HostSettings
	}

	// A TransactionPool broadcasts tßransaction sets to miners for inclusion in
	// an upcoming block.
	TransactionPool interface {
		AcceptTransactionSet(txns []types.Transaction) error
		FeeEstimate() (min, max types.Currency, err error)
		UnconfirmedParents(txn types.Transaction) ([]types.Transaction, error)
		BroadcastTransaction(txn types.Transaction, dependsOn []types.Transaction)
	}
)

type locker struct {
	c       chan struct{}
	waiters int
}

// A Contract is a file contract paired with various metadata.
type Contract struct {
	types.FileContractRevision

	FormationSet    []types.Transaction
	FinalizationSet []types.Transaction
	ProofSet        []types.Transaction

	FormationConfirmed    bool
	FinalizationConfirmed bool
	ResolutionConfirmed   bool

	FormationHeight    uint64
	FinalizationHeight uint64
	ProofHeight        uint64
	ProofSegment       uint64

	// Non-nil, with explanatory error message, if it is no longer possible to
	// submit a valid storage proof for the Contract.
	FatalError error
}

// A SessionHandler handles the host side of a renter-host session.
type SessionHandler struct {
	privkey types.PrivateKey

	cm     ChainManager
	tpool  TransactionPool
	wallet Wallet

	sectors   SectorStore
	contracts ContractStore
	accounts  EphemeralAccountStore
	settings  SettingsReporter

	registry *registry

	log Logger

	rpcs map[rpc.Specifier]func(*mux.Stream)

	settingsMu     sync.Mutex
	activeSettings map[rhp.SettingsID]rhp.HostSettings

	// contracts must be locked while they are being modified
	contractMu    sync.Mutex
	contractLocks map[types.ElementID]*locker
}

// validSettings returns the settings with the given UID, if they exist.
func (sh *SessionHandler) validSettings(id rhp.SettingsID) (rhp.HostSettings, error) {
	sh.settingsMu.Lock()
	defer sh.settingsMu.Unlock()
	settings, exists := sh.activeSettings[id]
	if !exists {
		return rhp.HostSettings{}, errors.New("settings not found")
	}
	return settings, nil
}

// registerSettings registers the setting's UID with the session handler for
// renters to reference in other RPC.
func (sh *SessionHandler) registerSettings(id rhp.SettingsID, settings rhp.HostSettings) {
	sh.settingsMu.Lock()
	defer sh.settingsMu.Unlock()
	sh.activeSettings[id] = settings
	time.AfterFunc(time.Until(settings.ValidUntil), func() {
		sh.settingsMu.Lock()
		delete(sh.activeSettings, id)
		sh.settingsMu.Unlock()
	})
}

// lockContract locks the contract with the provided ID preventing use in other
// RPC. The context can be used to interrupt if the contract lock cannot be
// acquired quickly.
func (sh *SessionHandler) lockContract(id types.ElementID, timeout time.Duration) (Contract, error) {
	// cannot defer unlock to prevent deadlock
	sh.contractMu.Lock()

	contract, err := sh.contracts.Contract(id)
	if err != nil {
		sh.contractMu.Unlock()
		return Contract{}, fmt.Errorf("failed to get contract: %w", err)
	} else if contract.FatalError != nil {
		sh.contractMu.Unlock()
		return Contract{}, fmt.Errorf("contract is no longer usable: %w", contract.FatalError)
	}

	_, exists := sh.contractLocks[id]
	if !exists {
		sh.contractLocks[id] = &locker{
			c:       make(chan struct{}, 1),
			waiters: 0,
		}
		sh.contractMu.Unlock()
		return contract, nil
	}
	sh.contractLocks[id].waiters++
	c := sh.contractLocks[id].c
	// mutex must be unlocked before waiting on the channel to prevent deadlock.
	sh.contractMu.Unlock()
	select {
	case <-c:
		contract, err := sh.contracts.Contract(id)
		if err != nil {
			return Contract{}, fmt.Errorf("failed to get contract: %w", err)
		}
		return contract, nil
	case <-time.After(timeout):
		return Contract{}, errors.New("contract lock timeout")
	}
}

// unlockContract unlocks the contract with the provided ID.
func (sh *SessionHandler) unlockContract(id types.ElementID) {
	sh.contractMu.Lock()
	defer sh.contractMu.Unlock()
	lock, exists := sh.contractLocks[id]
	if !exists {
		return
	} else if lock.waiters <= 0 {
		delete(sh.contractLocks, id)
		return
	}
	lock.waiters--
	lock.c <- struct{}{}
}

// Serve starts a new renter-host session on the provided conn.
func (sh *SessionHandler) Serve(conn net.Conn) error {
	s, err := rhp.AcceptSession(conn, sh.privkey)
	if err != nil {
		return fmt.Errorf("failed to start session: %w", err)
	}

	for {
		stream, err := s.AcceptStream()
		if errors.Is(err, mux.ErrClosedConn) || errors.Is(err, mux.ErrPeerClosedConn) {
			return nil
		} else if err != nil {
			return fmt.Errorf("failed to accept stream: %w", err)
		}
		go func() {
			defer stream.Close()

			log := sh.log.Scope("host rpc")

			var specifier rpc.Specifier
			if err := rpc.ReadRequest(stream, &specifier); err != nil {
				log.Warnln("failed to read specifier:", err)
				return
			}

			rpcFn, exists := sh.rpcs[specifier]
			if !exists {
				log.Warnln("unrecognized RPC:", specifier)
				if err := rpc.WriteResponseErr(stream, fmt.Errorf("unknown rpc: %v", specifier)); err != nil {
					log.Warnln("failed to write unknown rpc response:", err)
				}
				return
			}
			rpcFn(stream)
		}()
	}
}

// NewSessionHandler initializes a new host session manager.
func NewSessionHandler(privkey types.PrivateKey, cm ChainManager, ss SectorStore, cs ContractStore, as EphemeralAccountStore, rs RegistryStore, w Wallet, sr SettingsReporter, tp TransactionPool, log Logger) *SessionHandler {
	h := types.NewHasher()
	privkey.PublicKey().EncodeTo(h.E)
	hostID := h.Sum()

	sh := &SessionHandler{
		privkey: privkey,

		cm:        cm,
		accounts:  as,
		sectors:   ss,
		contracts: cs,
		wallet:    w,
		settings:  sr,
		tpool:     tp,
		log:       log,

		registry: &registry{
			hostID:        hostID,
			store:         rs,
			registryLocks: make(map[types.Hash256]*locker),
		},

		activeSettings: make(map[rhp.SettingsID]rhp.HostSettings),
		contractLocks:  make(map[types.ElementID]*locker),
	}

	sh.rpcs = map[rpc.Specifier]func(*mux.Stream){
		rhp.RPCAccountBalanceID: sh.handleRPCAccountBalance,
		rhp.RPCExecuteProgramID: sh.handleRPCExecuteProgram,
		rhp.RPCFormContractID:   sh.handleRPCFormContract,
		rhp.RPCFundAccountID:    sh.handleRPCFundAccount,
		rhp.RPCLatestRevisionID: sh.handleRPCLatestRevision,
		rhp.RPCRenewContractID:  sh.handleRPCRenewContract,
		rhp.RPCSettingsID:       sh.handleRPCSettings,
	}

	return sh
}
