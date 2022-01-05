// Package ghost implements a barebones, reference, ephemeral Sia host. It is
// used for testing purposes only.
package ghost

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"go.sia.tech/core/host"
	"go.sia.tech/core/net/rhp"
	"go.sia.tech/core/types"
)

var (
	// DefaultSettings are the default settings for a ghost host.
	DefaultSettings = rhp.HostSettings{
		AcceptingContracts:     true,
		ContractFee:            types.Siacoins(1),
		Collateral:             types.Siacoins(1).Div64(1 << 22).Div64(4320), // 1 SC per sector per block per month
		MaxCollateral:          types.Siacoins(5000),
		MaxDuration:            4960,
		StoragePrice:           types.Siacoins(1).Div64(1 << 22).Div64(4320), // 1 SC per sector per block per month
		DownloadBandwidthPrice: types.Siacoins(1).Div64(1 << 22),             // 1 SC per sector
		UploadBandwidthPrice:   types.Siacoins(1).Div64(1 << 22),             // 1 SC per sector
		SectorSize:             1 << 22,
		WindowSize:             144,

		RPCFundAccountCost:    types.NewCurrency64(1),
		RPCAccountBalanceCost: types.NewCurrency64(1),
		RPCRenewContractCost:  types.NewCurrency64(1),
		RPCHostSettingsCost:   types.NewCurrency64(1),
		RPCLatestRevisionCost: types.NewCurrency64(1),
	}

	// FreeSettings are the cheapest possible host settings.
	FreeSettings = rhp.HostSettings{
		AcceptingContracts: true,
		MaxCollateral:      types.Siacoins(100),
		MaxDuration:        4960,
		SectorSize:         1 << 22,
		WindowSize:         144,
	}
)

// A MemEphemeralAccountStore is an in-memory implementation of the ephemeral
// account store. Implements host.EphemeralAccountStore.
type MemEphemeralAccountStore struct {
	mu       sync.Mutex
	balances map[types.PublicKey]types.Currency
}

// Balance returns the balance of the ephemeral account.
func (ms *MemEphemeralAccountStore) Balance(accountID types.PublicKey) (types.Currency, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	return ms.balances[accountID], nil
}

// Credit adds the specified amount to the account, returning the current
// balance.
func (ms *MemEphemeralAccountStore) Credit(accountID types.PublicKey, amount types.Currency) (types.Currency, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.balances[accountID] = ms.balances[accountID].Add(amount)
	return ms.balances[accountID], nil
}

// Refund returns the amount to the ephemeral account.
func (ms *MemEphemeralAccountStore) Refund(accountID types.PublicKey, amount types.Currency) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.balances[accountID] = ms.balances[accountID].Add(amount)
	return nil
}

// Debit subtracts the specified amount from the account, returning the current
// balance.
func (ms *MemEphemeralAccountStore) Debit(accountID types.PublicKey, requestID types.Hash256, amount types.Currency) (types.Currency, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	bal, exists := ms.balances[accountID]
	if !exists || bal.Cmp(amount) < 0 {
		return bal, errors.New("insufficient funds")
	}

	ms.balances[accountID] = ms.balances[accountID].Sub(amount)
	return ms.balances[accountID], nil
}

// NewMemAccountStore intializes a new AccountStore.
func NewMemAccountStore() *MemEphemeralAccountStore {
	return &MemEphemeralAccountStore{
		balances: make(map[types.PublicKey]types.Currency),
	}
}

// EphemeralSectorStore implements an ephemeral sector store. Implements
// host.SectorStore.
type EphemeralSectorStore struct {
	mu            sync.Mutex
	sectors       map[types.Hash256]*[rhp.SectorSize]byte
	contractRoots map[types.ElementID][]types.Hash256
}

// ContractRoots returns the roots of all sectors belonging to the
// specified file contract.
func (es *EphemeralSectorStore) ContractRoots(id types.ElementID) ([]types.Hash256, error) {
	es.mu.Lock()
	defer es.mu.Unlock()
	return es.contractRoots[id], nil
}

// DeleteSector removes a sector from the store.
func (es *EphemeralSectorStore) DeleteSector(root types.Hash256) error {
	es.mu.Lock()
	defer es.mu.Unlock()
	delete(es.sectors, root)
	return nil
}

// Exists checks if the sector exists in the store.
func (es *EphemeralSectorStore) Exists(root types.Hash256) (bool, error) {
	es.mu.Lock()
	defer es.mu.Unlock()
	_, exists := es.sectors[root]
	return exists, nil
}

// SetContractRoots updates the sector roots of the file contract.
func (es *EphemeralSectorStore) SetContractRoots(id types.ElementID, roots []types.Hash256) error {
	es.mu.Lock()
	defer es.mu.Unlock()
	es.contractRoots[id] = append([]types.Hash256(nil), roots...)
	return nil
}

// AddSector adds the sector with the specified root to the store.
func (es *EphemeralSectorStore) AddSector(root types.Hash256, sector *[rhp.SectorSize]byte) error {
	es.mu.Lock()
	defer es.mu.Unlock()
	es.sectors[root] = sector
	return nil
}

// ReadSector reads the sector with the given root, offset and length
// into w. Returns the number of bytes read or an error.
func (es *EphemeralSectorStore) ReadSector(root types.Hash256, w io.Writer, offset, length uint64) (uint64, error) {
	es.mu.Lock()
	defer es.mu.Unlock()
	sector, exists := es.sectors[root]
	if !exists {
		return 0, errors.New("sector not found")
	}
	if offset+length > rhp.SectorSize {
		return 0, errors.New("read out of bounds")
	}
	n, err := w.Write(sector[offset : offset+length])
	return uint64(n), err
}

// NewEphemeralSectorStore initializes a new EphemeralSectorStore.
func NewEphemeralSectorStore() *EphemeralSectorStore {
	return &EphemeralSectorStore{
		sectors:       make(map[types.Hash256]*[rhp.SectorSize]byte),
		contractRoots: make(map[types.ElementID][]types.Hash256),
	}
}

// EphemeralContractStore implements an ephemeral contract store.
type EphemeralContractStore struct {
	key types.PrivateKey

	mu        sync.Mutex
	height    uint64
	contracts map[types.ElementID]*host.Contract
}

// Get returns the contract with the specified ID.
func (es *EphemeralContractStore) Get(id types.ElementID) (host.Contract, error) {
	es.mu.Lock()
	defer es.mu.Unlock()

	if _, exists := es.contracts[id]; !exists {
		return host.Contract{}, errors.New("contract not found")
	}

	return *es.contracts[id], nil
}

// Add stores the provided contract, overwriting any previous
// contract with the same ID.
func (es *EphemeralContractStore) Add(c host.Contract) error {
	es.mu.Lock()
	defer es.mu.Unlock()

	es.contracts[c.Parent.ID] = &c
	return nil
}

// Revise updates the current revision associated with a contract.
func (es *EphemeralContractStore) Revise(revision types.FileContractRevision) error {
	es.mu.Lock()
	defer es.mu.Unlock()

	if _, exists := es.contracts[revision.Parent.ID]; !exists {
		return errors.New("contract not found")
	}

	es.contracts[revision.Parent.ID].FileContractRevision = revision
	return nil
}

// UpdateTransactions updates the contract's various transactions.
//
// This method does not return an error. If a contract cannot be saved to
// the store, the method should panic or exit with an error.
func (es *EphemeralContractStore) UpdateTransactions(contractID types.ElementID, final, proof []types.Transaction, err error) {
	es.mu.Lock()
	defer es.mu.Unlock()

	if _, exists := es.contracts[contractID]; !exists {
		panic("contract not found")
	}

	es.contracts[contractID].FinalizationSet = final
	es.contracts[contractID].ProofSet = proof
}

// ActionableContracts returns all of the store's contracts that are ready,
// as of the current height, for a lifecycle action to be performed on them.
//
// This method does not return an error. If contracts cannot be loaded from
// the store, the method should panic or exit with an error.
func (es *EphemeralContractStore) ActionableContracts() (actionable []types.ElementID) {
	es.mu.Lock()
	defer es.mu.Unlock()

	for _, contract := range es.contracts {
		if (!contract.ResolutionConfirmed && es.height < contract.ProofHeight) ||
			(contract.FatalError == nil && (!contract.FormationConfirmed ||
				(!contract.FinalizationConfirmed && es.height >= contract.FinalizationHeight))) {
			actionable = append(actionable, contract.Parent.ID)
		}
	}
	return
}

// NewEphemeralContractStore initializes a new EphemeralContractStore.
func NewEphemeralContractStore(key types.PrivateKey, initialHeight uint64) *EphemeralContractStore {
	return &EphemeralContractStore{
		key:       key,
		height:    initialHeight,
		contracts: make(map[types.ElementID]*host.Contract),
	}
}

// EphemeralSettingsReporter reports the current settings of the host.
// Implements host.SettingsReporter.
type EphemeralSettingsReporter struct {
	settings rhp.HostSettings
}

// Update updates the host's settings.
func (es *EphemeralSettingsReporter) Update(settings rhp.HostSettings) {
	es.settings = settings
}

// Settings returns the host's current settings.
func (es *EphemeralSettingsReporter) Settings() (settings rhp.HostSettings) {
	settings = es.settings
	settings.ValidUntil = time.Now().Add(time.Minute * 10)
	return
}

// NewEphemeralSettingsReporter initializes a new settings reporter.
func NewEphemeralSettingsReporter(settings rhp.HostSettings) *EphemeralSettingsReporter {
	return &EphemeralSettingsReporter{
		settings: settings,
	}
}

// EphemeralRegistryStore implements an in-memory registry key-value store.
// Implements host.RegistryStore.
type EphemeralRegistryStore struct {
	mu sync.Mutex

	cap    uint64
	values map[types.Hash256]rhp.RegistryValue
}

// Get returns the registry value for the given key. If the key is not found
// should return rhp.ErrNotFound.
func (es *EphemeralRegistryStore) Get(key types.Hash256) (rhp.RegistryValue, error) {
	es.mu.Lock()
	defer es.mu.Unlock()

	val, exists := es.values[key]
	if !exists {
		return rhp.RegistryValue{}, host.ErrEntryNotFound
	}
	return val, nil
}

// Set sets the registry value for the given key.
func (es *EphemeralRegistryStore) Set(key types.Hash256, value rhp.RegistryValue, expiration uint64) (rhp.RegistryValue, error) {
	es.mu.Lock()
	defer es.mu.Unlock()

	if _, exists := es.values[key]; !exists && uint64(len(es.values)) >= es.cap {
		return rhp.RegistryValue{}, errors.New("capacity exceeded")
	}

	es.values[key] = value
	return value, nil
}

// Len returns the number of entries in the registry.
func (es *EphemeralRegistryStore) Len() uint64 {
	es.mu.Lock()
	defer es.mu.Unlock()

	return uint64(len(es.values))
}

// Cap returns the maximum number of entries the registry can hold.
func (es *EphemeralRegistryStore) Cap() uint64 {
	return es.cap
}

// NewEphemeralRegistryStore initializes a new EphemeralRegistryStore.
func NewEphemeralRegistryStore(limit uint64) *EphemeralRegistryStore {
	return &EphemeralRegistryStore{
		cap:    limit,
		values: make(map[types.Hash256]rhp.RegistryValue),
	}
}

// A Host is an ephemeral host that can be used for testing.
type Host struct {
	pubKey   types.PublicKey
	settings rhp.HostSettings

	l net.Listener
}

// PublicKey returns the host's public key.
func (h *Host) PublicKey() types.PublicKey {
	return h.pubKey
}

// UpdateSettings updates the host's settings.
func (h *Host) UpdateSettings(settings rhp.HostSettings) {
	h.settings = settings
}

// Settings returns the host's current settings. Implements
// host.SettingsReporter.
func (h *Host) Settings() (settings rhp.HostSettings) {
	settings = h.settings
	settings.ValidUntil = time.Now().Add(time.Minute * 10)
	return
}

// Close closes the host.
func (h *Host) Close() error {
	return h.l.Close()
}

// New initializes a new host.
func New(privKey types.PrivateKey, settings rhp.HostSettings, cm host.ChainManager, wallet host.Wallet, tpool host.TransactionPool, log host.Logger) (*Host, error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, fmt.Errorf("failed to start listener: %w", err)
	}
	settings.NetAddress = l.Addr().String()
	settings.Address = wallet.Address()

	cs := NewEphemeralContractStore(privKey, cm.Tip().Height)
	ss := NewEphemeralSectorStore()
	as := NewMemAccountStore()
	rs := NewEphemeralRegistryStore(100)
	h := &Host{
		pubKey:   privKey.PublicKey(),
		settings: settings,
		l:        l,
	}
	sh := host.NewSessionHandler(privKey, cm, ss, cs, as, rs, wallet, h, tpool, log)
	// start listening for incoming RHP connections
	go func() {
		for {
			conn, err := l.Accept()
			if errors.Is(err, net.ErrClosed) {
				return
			} else if err != nil {
				panic(err)
			}
			go sh.Serve(conn)
		}
	}()
	return h, nil
}
