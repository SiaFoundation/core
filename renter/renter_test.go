package renter

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"go.sia.tech/core/chain"
	"go.sia.tech/core/consensus"
	"go.sia.tech/core/host"
	"go.sia.tech/core/net/rhp"
	"go.sia.tech/core/types"

	"lukechampine.com/frand"
)

var (
	testSettings = rhp.HostSettings{
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
)

type memEphemeralAccountStore struct {
	mu       sync.Mutex
	balances map[types.PublicKey]types.Currency
}

func (ms *memEphemeralAccountStore) Balance(accountID types.PublicKey) (types.Currency, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	return ms.balances[accountID], nil
}

func (ms *memEphemeralAccountStore) Credit(accountID types.PublicKey, amount types.Currency) (types.Currency, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.balances[accountID] = ms.balances[accountID].Add(amount)
	return ms.balances[accountID], nil
}

func (ms *memEphemeralAccountStore) Refund(accountID types.PublicKey, amount types.Currency) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.balances[accountID] = ms.balances[accountID].Add(amount)
	return nil
}

func (ms *memEphemeralAccountStore) Debit(accountID types.PublicKey, requestID types.Hash256, amount types.Currency) (types.Currency, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	bal, exists := ms.balances[accountID]
	if !exists || bal.Cmp(amount) < 0 {
		return bal, errors.New("insufficient funds")
	}

	ms.balances[accountID] = ms.balances[accountID].Sub(amount)
	return ms.balances[accountID], nil
}

func newMemAccountStore() *memEphemeralAccountStore {
	return &memEphemeralAccountStore{
		balances: make(map[types.PublicKey]types.Currency),
	}
}

type ephemeralSectorStore struct {
	mu            sync.Mutex
	sectors       map[types.Hash256]*[rhp.SectorSize]byte
	contractRoots map[types.ElementID][]types.Hash256
}

// ContractRoots returns the roots of all sectors belonging to the
// specified file contract.
func (es *ephemeralSectorStore) ContractRoots(id types.ElementID) ([]types.Hash256, error) {
	es.mu.Lock()
	defer es.mu.Unlock()
	return es.contractRoots[id], nil
}

// DeleteSector removes a sector from the store.
func (es *ephemeralSectorStore) DeleteSector(root types.Hash256) error {
	es.mu.Lock()
	defer es.mu.Unlock()
	delete(es.sectors, root)
	return nil
}

// Exists checks if the sector exists in the store.
func (es *ephemeralSectorStore) Exists(root types.Hash256) (bool, error) {
	es.mu.Lock()
	defer es.mu.Unlock()
	_, exists := es.sectors[root]
	return exists, nil
}

// SetContractRoots updates the sector roots of the file contract.
func (es *ephemeralSectorStore) SetContractRoots(id types.ElementID, roots []types.Hash256) error {
	es.mu.Lock()
	defer es.mu.Unlock()
	es.contractRoots[id] = append([]types.Hash256(nil), roots...)
	return nil
}

// AddSector adds the sector with the specified root to the store.
func (es *ephemeralSectorStore) AddSector(root types.Hash256, sector *[rhp.SectorSize]byte) error {
	es.mu.Lock()
	defer es.mu.Unlock()
	es.sectors[root] = sector
	return nil
}

// ReadSector reads the sector with the given root, offset and length
// into w. Returns the number of bytes read or an error.
func (es *ephemeralSectorStore) ReadSector(root types.Hash256, w io.Writer, offset, length uint64) (uint64, error) {
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

func newEphemeralSectorStore() *ephemeralSectorStore {
	return &ephemeralSectorStore{
		sectors:       make(map[types.Hash256]*[rhp.SectorSize]byte),
		contractRoots: make(map[types.ElementID][]types.Hash256),
	}
}

type ephemeralContractStore struct {
	key types.PrivateKey

	mu        sync.Mutex
	height    uint64
	contracts map[types.ElementID]*host.Contract
}

// Contract returns the contract with the specified ID.
func (es *ephemeralContractStore) Contract(id types.ElementID) (host.Contract, error) {
	es.mu.Lock()
	defer es.mu.Unlock()

	if _, exists := es.contracts[id]; !exists {
		return host.Contract{}, errors.New("contract not found")
	}

	return *es.contracts[id], nil
}

// AddContract stores the provided contract, overwriting any previous
// contract with the same ID.
func (es *ephemeralContractStore) AddContract(c host.Contract) error {
	es.mu.Lock()
	defer es.mu.Unlock()

	es.contracts[c.Parent.ID] = &c
	return nil
}

// ReviseContract updates the current revision associated with a contract.
func (es *ephemeralContractStore) ReviseContract(revision types.FileContractRevision) error {
	es.mu.Lock()
	defer es.mu.Unlock()

	if _, exists := es.contracts[revision.Parent.ID]; !exists {
		return errors.New("contract not found")
	}

	es.contracts[revision.Parent.ID].FileContractRevision = revision
	return nil
}

// UpdateContractTransactions updates the contract's various transactions.
//
// This method does not return an error. If a contract cannot be saved to
// the store, the method should panic or exit with an error.
func (es *ephemeralContractStore) UpdateContractTransactions(contractID types.ElementID, final, proof []types.Transaction, err error) {
	es.mu.Lock()
	defer es.mu.Unlock()

	if _, exists := es.contracts[contractID]; !exists {
		panic("contract not found")
	}

	es.contracts[contractID].FinalizationSet = final
	es.contracts[contractID].ProofSet = proof
}

// ProcessChainApplyUpdate is called when a new block is applied to the consensus.
func (es *ephemeralContractStore) ProcessChainApplyUpdate(cau *chain.ApplyUpdate, mayCommit bool) error {
	es.mu.Lock()
	defer es.mu.Unlock()

	es.height = cau.Context.Index.Height

	for _, fc := range cau.NewFileContracts {
		if _, exists := es.contracts[fc.ID]; exists {
			es.contracts[fc.ID].FormationConfirmed = true
		}
	}

	for _, fc := range cau.RevisedFileContracts {
		if _, exists := es.contracts[fc.ID]; exists {
			es.contracts[fc.ID].FinalizationConfirmed = true
		}
	}

	for _, fc := range cau.ResolvedFileContracts {
		if _, exists := es.contracts[fc.ID]; exists {
			es.contracts[fc.ID].ResolutionConfirmed = true
		}
	}
	return nil
}

// ProcessChainRevertUpdate is called when a block is reverted.
func (es *ephemeralContractStore) ProcessChainRevertUpdate(cru *chain.RevertUpdate) error {
	es.mu.Lock()
	defer es.mu.Unlock()

	es.height = cru.Context.Index.Height

	for _, fc := range cru.NewFileContracts {
		if _, exists := es.contracts[fc.ID]; exists {
			es.contracts[fc.ID].FormationConfirmed = false
		}
	}

	for _, fc := range cru.RevisedFileContracts {
		if _, exists := es.contracts[fc.ID]; exists {
			es.contracts[fc.ID].FinalizationConfirmed = false
		}
	}

	for _, fc := range cru.ResolvedFileContracts {
		if _, exists := es.contracts[fc.ID]; exists {
			es.contracts[fc.ID].ResolutionConfirmed = false
		}
	}

	return nil
}

// ActionableContracts returns all of the store's contracts that are ready,
// as of the current height, for a lifecycle action to be performed on them.
//
// This method does not return an error. If contracts cannot be loaded from
// the store, the method should panic or exit with an error.
func (es *ephemeralContractStore) ActionableContracts() (actionable []host.Contract) {
	es.mu.Lock()
	defer es.mu.Unlock()

	for _, contract := range es.contracts {
		if (!contract.ResolutionConfirmed && es.height < contract.ProofHeight) ||
			(contract.FatalError == nil && (!contract.FormationConfirmed ||
				(!contract.FinalizationConfirmed && es.height >= contract.FinalizationHeight))) {
			actionable = append(actionable, *contract)
		}
	}
	return
}

func newStubContractStore(key types.PrivateKey, initialHeight uint64) *ephemeralContractStore {
	return &ephemeralContractStore{
		key:       key,
		height:    initialHeight,
		contracts: make(map[types.ElementID]*host.Contract),
	}
}

type ephemeralSettingsReporter struct {
	settings rhp.HostSettings
}

func (es *ephemeralSettingsReporter) Settings() (settings rhp.HostSettings) {
	settings = es.settings
	settings.ValidUntil = time.Now().Add(time.Minute * 10)
	return
}

func newEphemeralSettingsReporter(settings rhp.HostSettings) *ephemeralSettingsReporter {
	return &ephemeralSettingsReporter{
		settings: settings,
	}
}

type stubChainManager struct{}

func (cm *stubChainManager) TipContext() (consensus.ValidationContext, error) {
	return consensus.ValidationContext{}, nil
}

func (cm *stubChainManager) Tip() types.ChainIndex {
	return types.ChainIndex{}
}

type ephemeralRegistryStore struct {
	mu sync.Mutex

	cap    uint64
	values map[types.Hash256]rhp.RegistryValue
}

// Get returns the registry value for the given key. If the key is not found
// should return rhp.ErrNotFound.
func (es *ephemeralRegistryStore) Get(key types.Hash256) (rhp.RegistryValue, error) {
	es.mu.Lock()
	defer es.mu.Unlock()

	val, exists := es.values[key]
	if !exists {
		return rhp.RegistryValue{}, host.ErrEntryNotFound
	}
	return val, nil
}

// Set sets the registry value for the given key.
func (es *ephemeralRegistryStore) Set(key types.Hash256, value rhp.RegistryValue, expiration uint64) (rhp.RegistryValue, error) {
	es.mu.Lock()
	defer es.mu.Unlock()

	if _, exists := es.values[key]; !exists && uint64(len(es.values)) >= es.cap {
		return rhp.RegistryValue{}, errors.New("capacity exceeded")
	}

	es.values[key] = value
	return value, nil
}

// Len returns the number of entries in the registry.
func (es *ephemeralRegistryStore) Len() uint64 {
	es.mu.Lock()
	defer es.mu.Unlock()

	return uint64(len(es.values))
}

// Cap returns the maximum number of entries the registry can hold.
func (es *ephemeralRegistryStore) Cap() uint64 {
	return es.cap
}

func newEphemeralRegistryStore(limit uint64) *ephemeralRegistryStore {
	return &ephemeralRegistryStore{
		cap:    limit,
		values: make(map[types.Hash256]rhp.RegistryValue),
	}
}

type stubWallet struct {
	key     types.PublicKey
	balance types.Currency
}

func (w *stubWallet) Balance() types.Currency {
	return w.balance
}

func (w *stubWallet) Address() types.Address {
	return types.PolicyAddress(types.PolicyPublicKey(w.key))
}

func (w *stubWallet) NextAddress() types.Address {
	return types.PolicyAddress(types.PolicyPublicKey(w.key))
}

func (w *stubWallet) Addresses() []types.Address {
	return []types.Address{w.Address()}
}

func (w *stubWallet) FundTransaction(txn *types.Transaction, amount types.Currency, pool []types.Transaction) ([]types.ElementID, func(), error) {
	return nil, func() {}, nil
}

func (w *stubWallet) SignTransaction(vc consensus.ValidationContext, txn *types.Transaction, toSign []types.ElementID) error {
	return nil
}

func newStubWallet(initialBalance types.Currency, key types.PublicKey) *stubWallet {
	return &stubWallet{
		key:     key,
		balance: initialBalance,
	}
}

type stubTpool struct {
}

func (tp *stubTpool) AcceptTransactionSet(txns []types.Transaction) error {
	return nil
}

func (tp *stubTpool) FeeEstimate() (min, max types.Currency, err error) {
	return
}

func (tp *stubTpool) UnconfirmedParents(txn types.Transaction) ([]types.Transaction, error) {
	return nil, nil
}

func (tp *stubTpool) BroadcastTransaction(txn types.Transaction, dependsOn []types.Transaction) {
}

func newStubTpool() *stubTpool {
	return &stubTpool{}
}

type stdOutLogger struct {
	scope string
}

func (l *stdOutLogger) logf(prefix, f string, v ...interface{}) {
	l.logln(prefix, fmt.Sprintf(f, v...))
}

func (l *stdOutLogger) Scope(scope string) host.Logger {
	if len(l.scope) != 0 {
		return &stdOutLogger{scope: fmt.Sprintf("%s: %s", l.scope, scope)}
	}
	return &stdOutLogger{scope: scope}
}

func (l *stdOutLogger) logln(prefix string, v ...interface{}) {
	if len(l.scope) != 0 {
		prefix = fmt.Sprintf("[%s][%s] %s:", prefix, time.Now().Format(time.RFC822), l.scope)
	} else {
		prefix = fmt.Sprintf("[%s][%s]:", prefix, time.Now().Format(time.RFC822))
	}
	os.Stdout.WriteString(fmt.Sprintln(append([]interface{}{prefix}, v...)))
}

func (l *stdOutLogger) Errorf(f string, v ...interface{}) {
	l.logf("ERROR", f, v...)
}

func (l *stdOutLogger) Warnf(f string, v ...interface{}) {
	l.logf("WARN", f, v...)
}

func (l *stdOutLogger) Infof(f string, v ...interface{}) {
	l.logf("INFO", f, v...)
}

func (l *stdOutLogger) Errorln(v ...interface{}) {
	l.logln("ERROR", v...)
}

func (l *stdOutLogger) Warnln(v ...interface{}) {
	l.logln("WARN", v...)
}

func (l *stdOutLogger) Infoln(v ...interface{}) {
	l.logln("INFO", v...)
}

func initTestHost(tb testing.TB, cm host.ChainManager, settings rhp.HostSettings) (types.PublicKey, types.PrivateKey, string) {
	priv := types.NewPrivateKeyFromSeed(frand.Entropy256())
	pub := priv.PublicKey()

	cs := newStubContractStore(priv, 0)
	ss := newEphemeralSectorStore()
	as := newMemAccountStore()
	sr := newEphemeralSettingsReporter(settings)
	r := newEphemeralRegistryStore(100)
	w := newStubWallet(types.NewCurrency64(0), pub)
	tp := newStubTpool()

	h := host.NewSessionHandler(priv, cm, ss, cs, as, r, w, sr, tp, new(stdOutLogger))

	listener, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		tb.Fatal(err)
	}

	addr := listener.Addr().String()

	tb.Cleanup(func() {
		listener.Close()
	})

	go func() {
		for {
			conn, err := listener.Accept()
			if errors.Is(err, net.ErrClosed) {
				return
			} else if err != nil {
				panic(err)
			}
			go h.Serve(conn)
		}
	}()

	return pub, priv, addr
}

func randSettings() rhp.HostSettings {
	return rhp.HostSettings{
		NetAddress: "localhost:98123",
		Address:    types.PolicyAddress(types.AnyoneCanSpend()),
		Version:    "v2.0.0",

		EphemeralAccountExpiry: time.Duration(frand.Intn(int(time.Hour))),

		BlockHeight:              frand.Uint64n(math.MaxUint64),
		MaxDuration:              frand.Uint64n(math.MaxUint64),
		RemainingRegistryEntries: frand.Uint64n(math.MaxUint64),
		RemainingStorage:         frand.Uint64n(math.MaxUint64),
		SectorSize:               frand.Uint64n(math.MaxUint64),
		TotalRegistryEntries:     frand.Uint64n(math.MaxUint64),
		TotalStorage:             frand.Uint64n(math.MaxUint64),
		WindowSize:               frand.Uint64n(math.MaxUint64),

		Collateral:                 types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
		DownloadBandwidthPrice:     types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
		InstrDropSectorsBaseCost:   types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
		InstrDropSectorsUnitCost:   types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
		InstrHasSectorBaseCost:     types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
		InstrReadBaseCost:          types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
		InstrRevisionBaseCost:      types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
		InstrSwapSectorBaseCost:    types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
		InstrWriteBaseCost:         types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
		MaxCollateral:              types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
		MaxEphemeralAccountBalance: types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
		ProgInitBaseCost:           types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
		ProgMemoryTimeCost:         types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
		ProgReadCost:               types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
		ProgWriteCost:              types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
		RPCAccountBalanceCost:      types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
		ContractFee:                types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
		RPCFundAccountCost:         types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
		RPCHostSettingsCost:        types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
		RPCLatestRevisionCost:      types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
		RPCRenewContractCost:       types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
		StoragePrice:               types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
		TxnFeeMaxRecommended:       types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
		TxnFeeMinRecommended:       types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
		UploadBandwidthPrice:       types.NewCurrency64(frand.Uint64n(math.MaxUint64)),
	}
}

func TestRPCSettings(t *testing.T) {
	expectedSettings := randSettings()
	hostKey, _, hostAddr := initTestHost(t, new(stubChainManager), expectedSettings)
	session, err := NewSession(hostAddr, hostKey, nil, nil, new(stubChainManager))
	if err != nil {
		t.Fatal(err)
	}

	retrievedSettings, err := session.ScanSettings()
	if err != nil {
		t.Fatal(err)
	}

	// ID should be empty since no payment method was specified.
	if !retrievedSettings.ValidUntil.After(time.Now()) {
		t.Fatal("expected ValidUntil to be in the future")
	}

	retrievedSettings.ValidUntil = time.Time{}

	if !reflect.DeepEqual(expectedSettings, retrievedSettings) {
		t.Fatalf("expected settings %+v, got %+v", expectedSettings, retrievedSettings)
	}
}

func TestRPCLatestRevision(t *testing.T) {
	renterKey := types.NewPrivateKeyFromSeed(frand.Entropy256())
	renterPub := renterKey.PublicKey()

	wallet := newStubWallet(types.Siacoins(10), renterPub)
	tpool := newStubTpool()

	hostKey, _, hostAddr := initTestHost(t, new(stubChainManager), testSettings)
	session, err := NewSession(hostAddr, hostKey, wallet, tpool, new(stubChainManager))
	if err != nil {
		t.Fatal(err)
	}

	renterFunds := types.Siacoins(5)
	hostFunds := types.Siacoins(10)

	fcr, _, err := session.FormContract(renterKey, hostFunds, renterFunds, 200)
	if err != nil {
		t.Fatal(err)
	}

	payment := session.PayByContract(&fcr, renterKey, renterPub)
	_, err = session.RegisterSettings(payment)
	if err != nil {
		t.Fatal(err)
	}

	_, err = session.FundAccount(renterPub, types.Siacoins(1), payment)
	if err != nil {
		t.Fatal(err)
	}

	payment = session.PayByEphemeralAccount(renterPub, renterKey, 20)
	latest, err := session.LatestRevision(fcr.Parent.ID, payment)
	if err != nil {
		t.Fatal(err)
	}

	if reflect.DeepEqual(latest, fcr.Parent) {
		t.Fatal("expected latest revision match")
	}
}

func TestRPCFormContract(t *testing.T) {
	renterPriv := types.NewPrivateKeyFromSeed(frand.Entropy256())
	renterPub := renterPriv.PublicKey()

	wallet := newStubWallet(types.Siacoins(10), renterPub)
	tpool := newStubTpool()

	hostPub, _, hostAddr := initTestHost(t, new(stubChainManager), testSettings)
	session, err := NewSession(hostAddr, hostPub, wallet, tpool, new(stubChainManager))
	if err != nil {
		t.Fatal(err)
	}

	settings, err := session.ScanSettings()
	if err != nil {
		t.Fatal(err)
	}

	renterFunds := types.Siacoins(5)
	hostFunds := types.Siacoins(10)

	fcr, _, err := session.FormContract(renterPriv, hostFunds, renterFunds, 200)
	if err != nil {
		t.Fatal(err)
	}

	switch {
	case fcr.Revision.RevisionNumber != 0:
		t.Fatal("expected revision number to be 0")
	case fcr.Revision.ValidRenterOutput.Address != wallet.Address():
		t.Fatal("expected valid renter address to be the renter's address")
	case fcr.Revision.MissedRenterOutput.Address != wallet.Address():
		t.Fatal("expected missed renter address to be the renter's address")
	case fcr.Revision.ValidRenterOutput.Value != renterFunds.Sub(settings.ContractFee):
		t.Fatal("expected valid renter output to be renter funds minus contract fee")
	case fcr.Revision.ValidHostOutput.Value != hostFunds.Add(settings.ContractFee):
		t.Fatal("expected valid host output to be host funds plus contract fee")
	case fcr.Revision.MissedRenterOutput.Value != fcr.Revision.ValidRenterOutput.Value:
		t.Fatal("expected valid and missed renter outputs to match")
	case fcr.Revision.MissedHostOutput.Value != fcr.Revision.ValidHostOutput.Value:
		t.Fatal("expected valid and missed host outputs to match")
	}
}

func TestRPCFundAccount(t *testing.T) {
	renterPriv := types.NewPrivateKeyFromSeed(frand.Entropy256())
	renterPub := renterPriv.PublicKey()

	wallet := newStubWallet(types.Siacoins(10), renterPub)
	tpool := newStubTpool()

	hostPub, _, hostAddr := initTestHost(t, new(stubChainManager), testSettings)
	session, err := NewSession(hostAddr, hostPub, wallet, tpool, new(stubChainManager))
	if err != nil {
		t.Fatal(err)
	}

	renterFunds := types.Siacoins(5)
	hostFunds := types.Siacoins(10)

	fcr, _, err := session.FormContract(renterPriv, hostFunds, renterFunds, 200)
	if err != nil {
		t.Fatal(err)
	}

	originalAllowance := fcr.Revision.ValidRenterOutput.Value
	payment := session.PayByContract(&fcr, renterPriv, renterPub)
	settings, err := session.RegisterSettings(payment)
	if err != nil {
		t.Fatal(err)
	}

	balance, err := session.FundAccount(renterPub, types.Siacoins(100), payment)
	if err == nil {
		t.Fatal("expected fund to fail")
	}

	fundAmount := types.Siacoins(2)
	balance, err = session.FundAccount(renterPub, fundAmount, payment)
	if err != nil {
		t.Fatal(err)
	}

	remainingAllowance := originalAllowance.Sub(fundAmount).Sub(settings.RPCFundAccountCost).Sub(settings.RPCHostSettingsCost)

	if balance != fundAmount {
		t.Fatalf("expected balance to be %v, got %v", fundAmount, balance)
	} else if fcr.Revision.ValidRenterOutput.Value != remainingAllowance {
		t.Fatalf("expected remaining allowance to be %v, got %v", remainingAllowance, fcr.Revision.ValidRenterOutput.Value)
	}
}

func TestRPCAccountBalance(t *testing.T) {
	renterPriv := types.NewPrivateKeyFromSeed(frand.Entropy256())
	renterPub := renterPriv.PublicKey()

	wallet := newStubWallet(types.Siacoins(10), renterPub)
	tpool := newStubTpool()
	cm := new(stubChainManager)

	hostPub, _, hostAddr := initTestHost(t, cm, testSettings)
	session, err := NewSession(hostAddr, hostPub, wallet, tpool, cm)
	if err != nil {
		t.Fatal(err)
	}

	renterFunds := types.Siacoins(5)
	hostFunds := types.Siacoins(10)

	fcr, _, err := session.FormContract(renterPriv, hostFunds, renterFunds, 200)
	if err != nil {
		t.Fatal(err)
	}

	remainingAllowance := fcr.Revision.ValidRenterOutput.Value
	payment := session.PayByContract(&fcr, renterPriv, renterPub)
	// get usable settings.
	settings, err := session.RegisterSettings(payment)
	if err != nil {
		t.Fatal(err)
	}

	// make sure the remaining renter allowance is correct.
	remainingAllowance = remainingAllowance.Sub(settings.RPCHostSettingsCost)
	if fcr.Revision.ValidRenterOutput.Value.Cmp(remainingAllowance) != 0 {
		t.Fatalf("expected remaining allowance to be %v, got %v", remainingAllowance, fcr.Revision.ValidRenterOutput.Value)
	}

	// fund an ephemeral account with 2 SC.
	fundAmount := types.Siacoins(2)
	balance, err := session.FundAccount(renterPub, fundAmount, payment)
	if err != nil {
		t.Fatal(err)
	}

	// subtract the costs from the remaining allowance.
	remainingAllowance = remainingAllowance.Sub(settings.RPCFundAccountCost).Sub(fundAmount)

	// check the fund amount and renter allowance is correct.
	if balance != fundAmount {
		t.Fatalf("expected balance to be %v, got %v", fundAmount, balance)
	} else if fcr.Revision.ValidRenterOutput.Value != remainingAllowance {
		t.Fatalf("expected remaining allowance to be %v, got %v", remainingAllowance, fcr.Revision.ValidRenterOutput.Value)
	}

	balance, err = session.AccountBalance(renterPub, payment)
	if err != nil {
		t.Fatal(err)
	}

	// subtract the costs from the remaining allowance.
	remainingAllowance = remainingAllowance.Sub(settings.RPCAccountBalanceCost)

	// check the account balance and renter allowance is correct.
	if balance.Cmp(fundAmount) != 0 {
		t.Fatalf("expected balance to be %v, got %v", fundAmount, balance)
	} else if fcr.Revision.ValidRenterOutput.Value.Cmp(remainingAllowance) != 0 {
		t.Fatalf("expected remaining allowance to be %v, got %v", remainingAllowance, fcr.Revision.ValidRenterOutput.Value)
	}

	// check the account balance, paying with an ephemeral account.
	payment = session.PayByEphemeralAccount(renterPub, renterPriv, 10)
	balance, err = session.AccountBalance(renterPub, payment)
	if err != nil {
		t.Fatal(err)
	}

	if balance.Cmp(fundAmount.Sub(settings.RPCAccountBalanceCost)) != 0 {
		t.Fatalf("expected balance to be %v, got %v", fundAmount.Sub(settings.RPCAccountBalanceCost), balance)
	} else if fcr.Revision.ValidRenterOutput.Value.Cmp(remainingAllowance) != 0 {
		t.Fatalf("expected remaining allowance to be %v, got %v", remainingAllowance, fcr.Revision.ValidRenterOutput.Value)
	}
}

func TestReadWriteProgram(t *testing.T) {
	renterPriv := types.NewPrivateKeyFromSeed(frand.Entropy256())
	renterPub := renterPriv.PublicKey()

	wallet := newStubWallet(types.Siacoins(10), renterPub)
	tpool := newStubTpool()

	hostPub, _, hostAddr := initTestHost(t, new(stubChainManager), testSettings)
	session, err := NewSession(hostAddr, hostPub, wallet, tpool, new(stubChainManager))
	if err != nil {
		t.Fatal(err)
	}

	renterFunds := types.Siacoins(50)
	hostFunds := types.Siacoins(100)

	fcr, _, err := session.FormContract(renterPriv, hostFunds, renterFunds, 200)
	if err != nil {
		t.Fatal(err)
	}

	payment := session.PayByContract(&fcr, renterPriv, renterPub)
	settings, err := session.RegisterSettings(payment)
	if err != nil {
		t.Fatal(err)
	}

	var sector [rhp.SectorSize]byte
	frand.Read(sector[:16])
	expectedRoot := rhp.SectorRoot(&sector)

	duration := fcr.Revision.WindowStart - settings.BlockHeight
	inputBuf := bytes.NewBuffer(make([]byte, 0, rhp.SectorSize))
	builder := NewProgramBuilder(settings, inputBuf, duration)
	builder.AddAppendSectorInstruction(&sector, true)

	instructions, requiresContract, requiresFinalization, err := builder.Program()
	if err != nil {
		t.Fatal(err)
	} else if !requiresContract {
		t.Fatal("expected append program to require contract")
	} else if !requiresFinalization {
		t.Fatal("expected append program to require finalization")
	} else if len(instructions) != 1 {
		t.Fatal("expected append program to have 1 instruction")
	} else if _, ok := instructions[0].(rhp.InstrAppendSector); !ok {
		t.Fatal("expected append program to have append sector instruction")
	}

	programCost := builder.Cost()
	budget := settings.UploadBandwidthPrice.Mul64(settings.SectorSize + 1<<12).
		Add(settings.DownloadBandwidthPrice.Mul64(1 << 10)).
		Add(programCost.BaseCost).
		Add(programCost.StorageCost)

	err = session.ExecuteProgram(Program{
		Instructions: instructions,
		Budget:       budget,

		RequiresContract:     requiresContract,
		RequiresFinalization: requiresFinalization,
		ContractRevision:     &fcr,
		RenterKey:            renterPriv,
	}, inputBuf.Bytes(), payment, func(resp rhp.RPCExecuteInstrResponse, r io.Reader) error {
		switch {
		case resp.NewDataSize != rhp.SectorSize:
			t.Fatalf("expected new data size to be %v, got %v", rhp.SectorSize, resp.NewDataSize)
		case resp.NewMerkleRoot != expectedRoot:
			t.Fatalf("expected new merkle root to be %v, got %v", expectedRoot, resp.NewMerkleRoot)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	switch {
	case fcr.Revision.RevisionNumber != 3:
		// settings revision, payment revision, program execution revision
		t.Fatalf("expected revision number to be 3, got %v", fcr.Revision.RevisionNumber)
	case fcr.Revision.Filesize != rhp.SectorSize:
		t.Fatalf("expected filesize to be %v, got %v", rhp.SectorSize, fcr.Revision.Filesize)
	}

	inputBuf.Reset()
	builder = NewProgramBuilder(settings, inputBuf, duration)
	if err := builder.AddReadSectorInstruction(expectedRoot, 0, rhp.SectorSize, true); err != nil {
		t.Fatal(err)
	}

	budget = settings.UploadBandwidthPrice.Mul64(1 << 10).
		Add(settings.DownloadBandwidthPrice.Mul64(settings.SectorSize)).
		Add(programCost.BaseCost).
		Add(programCost.StorageCost)

	instructions, requiresContract, requiresFinalization, err = builder.Program()
	if err != nil {
		t.Fatal(err)
	} else if requiresContract {
		t.Fatal("expected read program to not require contract")
	} else if requiresFinalization {
		t.Fatal("expected read program to not require finalization")
	} else if len(instructions) != 1 {
		t.Fatal("expected read program to have 1 instruction")
	} else if _, ok := instructions[0].(rhp.InstrReadSector); !ok {
		t.Fatal("expected read program to have read sector instruction")
	}

	err = session.ExecuteProgram(Program{
		Instructions: instructions,
		Budget:       budget,

		RequiresContract:     requiresContract,
		RequiresFinalization: requiresFinalization,
		ContractRevision:     &fcr,
		RenterKey:            renterPriv,
	}, inputBuf.Bytes(), payment, func(rir rhp.RPCExecuteInstrResponse, r io.Reader) error {
		var sector [rhp.SectorSize]byte
		if _, err := io.ReadFull(r, sector[:]); err != nil {
			return fmt.Errorf("failed to read sector data: %w", err)
		}

		if expectedRoot != rhp.SectorRoot(&sector) {
			return fmt.Errorf("sector root mismatch")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func BenchmarkWrite(b *testing.B) {
	renterPriv := types.NewPrivateKeyFromSeed(frand.Entropy256())
	renterPub := renterPriv.PublicKey()

	wallet := newStubWallet(types.Siacoins(10), renterPub)
	tpool := newStubTpool()

	hostPub, _, hostAddr := initTestHost(b, new(stubChainManager), testSettings)
	session, err := NewSession(hostAddr, hostPub, wallet, tpool, new(stubChainManager))
	if err != nil {
		b.Fatal(err)
	}

	renterFunds := types.Siacoins(50)
	hostFunds := types.Siacoins(100)

	fcr, _, err := session.FormContract(renterPriv, hostFunds, renterFunds, 200)
	if err != nil {
		b.Fatal(err)
	}

	payment := session.PayByContract(&fcr, renterPriv, renterPub)
	settings, err := session.RegisterSettings(payment)
	if err != nil {
		b.Fatal(err)
	}

	var sector [rhp.SectorSize]byte
	frand.Read(sector[:16])

	duration := fcr.Revision.WindowEnd - settings.BlockHeight
	inputBuf := bytes.NewBuffer(make([]byte, 0, rhp.SectorSize))

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(int64(rhp.SectorSize))
	for i := 0; i < b.N; i++ {
		inputBuf.Reset()

		builder := NewProgramBuilder(settings, inputBuf, duration)
		builder.AddAppendSectorInstruction(&sector, true)

		instructions, requiresContract, requiresFinalization, err := builder.Program()
		if err != nil {
			b.Fatal(err)
		}

		programCost := builder.Cost()
		budget := settings.UploadBandwidthPrice.Mul64(settings.SectorSize).
			Add(settings.DownloadBandwidthPrice.Mul64(1 << 10)).
			Add(programCost.BaseCost).
			Add(programCost.StorageCost)

		// append sector does not return any output
		err = session.ExecuteProgram(Program{
			Instructions: instructions,
			Budget:       budget,

			RequiresContract:     requiresContract,
			RequiresFinalization: requiresFinalization,
			ContractRevision:     &fcr,
			RenterKey:            renterPriv,
		}, inputBuf.Bytes(), payment, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRead(b *testing.B) {
	renterPriv := types.NewPrivateKeyFromSeed(frand.Entropy256())
	renterPub := renterPriv.PublicKey()

	wallet := newStubWallet(types.Siacoins(10), renterPub)
	tpool := newStubTpool()

	hostPub, _, hostAddr := initTestHost(b, new(stubChainManager), testSettings)
	session, err := NewSession(hostAddr, hostPub, wallet, tpool, new(stubChainManager))
	if err != nil {
		b.Fatal(err)
	}

	renterFunds := types.Siacoins(1000)
	hostFunds := types.Siacoins(2000)

	fcr, _, err := session.FormContract(renterPriv, hostFunds, renterFunds, 200)
	if err != nil {
		b.Fatal(err)
	}

	payment := session.PayByContract(&fcr, renterPriv, renterPub)
	settings, err := session.RegisterSettings(payment)
	if err != nil {
		b.Fatal(err)
	}

	var sector [rhp.SectorSize]byte
	frand.Read(sector[:16])
	root := rhp.SectorRoot(&sector)

	duration := fcr.Revision.WindowEnd - settings.BlockHeight
	inputBuf := bytes.NewBuffer(make([]byte, 0, rhp.SectorSize))

	inputBuf.Reset()

	builder := NewProgramBuilder(settings, inputBuf, duration)
	builder.AddAppendSectorInstruction(&sector, true)

	instructions, requiresContract, requiresFinalization, err := builder.Program()
	if err != nil {
		b.Fatal(err)
	}

	programCost := builder.Cost()
	budget := settings.UploadBandwidthPrice.Mul64(settings.SectorSize).
		Add(settings.DownloadBandwidthPrice.Mul64(1 << 10)).
		Add(programCost.BaseCost).
		Add(programCost.StorageCost)

	// append sector does not return any output
	err = session.ExecuteProgram(Program{
		Instructions: instructions,
		Budget:       budget,

		RequiresContract:     requiresContract,
		RequiresFinalization: requiresFinalization,
		ContractRevision:     &fcr,
		RenterKey:            renterPriv,
	}, inputBuf.Bytes(), payment, nil)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(int64(rhp.SectorSize))
	for i := 0; i < b.N; i++ {
		builder = NewProgramBuilder(settings, inputBuf, duration)
		if err := builder.AddReadSectorInstruction(root, 0, rhp.SectorSize, true); err != nil {
			b.Fatal(err)
		}

		instructions, requiresContract, requiresFinalization, err = builder.Program()
		if err != nil {
			b.Fatal(err)
		}

		programCost = builder.Cost()
		budget = settings.UploadBandwidthPrice.Mul64(1 << 10).
			Add(settings.DownloadBandwidthPrice.Mul64(settings.SectorSize)).
			Add(programCost.BaseCost).
			Add(programCost.StorageCost)

		// safe to ignore the read sector output
		err = session.ExecuteProgram(Program{
			Instructions: instructions,
			Budget:       budget,

			RequiresContract:     requiresContract,
			RequiresFinalization: requiresFinalization,
			ContractRevision:     &fcr,
			RenterKey:            renterPriv,
		}, inputBuf.Bytes(), payment, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}
