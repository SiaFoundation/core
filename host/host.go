package host

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

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
		// AddSector adds the sector with the specified root to the store.
		AddSector(root types.Hash256, sector *[rhp.SectorSize]byte) error
		// DeleteSector removes a sector from the store.
		DeleteSector(root types.Hash256) error
		// Exists checks if the sector exists in the store.
		Exists(root types.Hash256) (bool, error)
		// ReadSector reads the sector with the given root, offset and length
		// into w. Returns the number of bytes read or an error.
		ReadSector(root types.Hash256, w io.Writer, offset, length uint64) (n uint64, err error)

		// ContractRoots returns the roots of all sectors belonging to the
		// specified file contract.
		ContractRoots(id types.ElementID) ([]types.Hash256, error)
		// SetContractRoots updates the sector roots of the file contract.
		SetContractRoots(id types.ElementID, roots []types.Hash256) error
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

	// A ContractStore stores a hosts contracts
	ContractStore interface {
		// Get returns the contract with the specified ID.
		Get(types.ElementID) (Contract, error)
		// Add stores the provided contract, overwriting any previous contract
		// with the same ID.
		Add(c Contract) error
		// ReviseContract updates the current revision associated with a contract.
		Revise(revision types.FileContractRevision) error
		// UpdateContractTransactions updates the contract's various
		// transactions.
		//
		// This method does not return an error. If a contract cannot be saved
		// to the store, the method should panic or exit with an error.
		UpdateTransactions(id types.ElementID, finalization, proof []types.Transaction, err error)
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
		Addresses() []types.Address
		Balance() types.Currency
		Address() types.Address
		FundTransaction(txn *types.Transaction, amount types.Currency, pool []types.Transaction) ([]types.ElementID, func(), error)
		SignTransaction(vc consensus.ValidationContext, txn *types.Transaction, toSign []types.ElementID) error
	}

	// A SettingsReporter returns the host's current settings.
	SettingsReporter interface {
		Settings() rhp.HostSettings
	}

	// A TransactionPool broadcasts transaction sets to miners for inclusion in
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

	accounts  EphemeralAccountStore
	contracts *contractManager
	log       Logger
	registry  *registry
	sectors   SectorStore
	settings  SettingsReporter

	rpcs map[rpc.Specifier]func(*mux.Stream)

	settingsMu     sync.Mutex
	activeSettings map[rhp.SettingsID]rhp.HostSettings
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

// Serve starts a new renter-host session on the provided conn.
func (sh *SessionHandler) Serve(conn net.Conn) error {
	defer conn.Close()

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
	hostID := types.HashObject(privkey.PublicKey())
	sh := &SessionHandler{
		privkey: privkey,

		cm:       cm,
		accounts: as,
		sectors:  ss,
		contracts: &contractManager{
			store: cs,
			locks: make(map[types.ElementID]*locker),
		},
		wallet:   w,
		settings: sr,
		tpool:    tp,
		log:      log,

		registry: &registry{
			hostID: hostID,
			store:  rs,
			locks:  make(map[types.Hash256]*locker),
		},

		activeSettings: make(map[rhp.SettingsID]rhp.HostSettings),
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
