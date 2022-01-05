package renter

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"testing"
	"time"

	"go.sia.tech/core/chain"
	"go.sia.tech/core/consensus"
	"go.sia.tech/core/host"
	"go.sia.tech/core/internal/chainutil"
	"go.sia.tech/core/internal/ghost"
	"go.sia.tech/core/internal/walletutil"
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

func mineBlock(vc consensus.ValidationContext, txns ...types.Transaction) types.Block {
	b := types.Block{
		Header: types.BlockHeader{
			Height:    vc.Index.Height + 1,
			ParentID:  vc.Index.ID,
			Timestamp: time.Now(),
		},
		Transactions: txns,
	}
	b.Header.Commitment = vc.Commitment(b.Header.MinerAddress, b.Transactions)
	chainutil.FindBlockNonce(&b.Header, types.HashRequiringWork(vc.Difficulty))
	return b
}

// initTestChain initializes a new testing chain with a genesis block including
// siacoin outputs.
func initTestChain(tb testing.TB, outputs []types.SiacoinOutput) (*chain.ApplyUpdate, *chain.Manager) {
	block := types.Block{
		Header:       types.BlockHeader{Timestamp: time.Unix(734600000, 0)},
		Transactions: []types.Transaction{{SiacoinOutputs: outputs}},
	}
	genesisUpdate := consensus.GenesisUpdate(block, types.Work{NumHashes: [32]byte{30: 1}})
	store := chainutil.NewEphemeralStore(consensus.Checkpoint{
		Block:   block,
		Context: genesisUpdate.Context,
	})
	cm := chain.NewManager(store, genesisUpdate.Context)
	tb.Cleanup(func() {
		cm.Close()
	})
	return &chain.ApplyUpdate{
		ApplyUpdate: genesisUpdate,
		Block:       block,
	}, cm
}

// initTestHost initializes a new test host and returns it's listening address. The host will
// be closed when the test completes.
func initTestHost(tb testing.TB, privKey types.PrivateKey, cm host.ChainManager, w host.Wallet, tp host.TransactionPool, settings rhp.HostSettings) string {
	h, err := ghost.New(privKey, settings, cm, w, tp, new(stdOutLogger))
	if err != nil {
		tb.Fatal(err)
	}

	tb.Cleanup(func() {
		h.Close()
	})

	return h.Settings().NetAddress
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
	privKey := types.NewPrivateKeyFromSeed(frand.Entropy256())
	genesisUpdate, cm := initTestChain(t, nil)
	hostWallet := walletutil.NewEphemeralWallet(privKey, genesisUpdate)
	vc, err := cm.TipContext()
	if err != nil {
		t.Fatal(err)
	}
	tp := walletutil.NewTxPool(vc)
	hostAddr := initTestHost(t, privKey, cm, hostWallet, tp, expectedSettings)
	hostKey := privKey.PublicKey()
	session, err := NewSession(hostAddr, hostKey, nil, nil, cm)
	if err != nil {
		t.Fatal(err)
	}

	expectedSettings.NetAddress = hostAddr
	expectedSettings.Address = hostWallet.Address()
	retrievedSettings, err := session.ScanSettings()
	if err != nil {
		t.Fatal(err)
	} else if retrievedSettings.NetAddress != hostAddr {
		// the host's net address should be the same as the generated one
		t.Fatal("retrieved settings address does not match host address")
	} else if retrievedSettings.Address != hostWallet.Address() {
		// the host's wallet address should be the same as the generated one
		t.Fatal("retrieved settings wallet address does not match host wallet address")
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
	renterPriv := types.NewPrivateKeyFromSeed(frand.Entropy256())
	renterPub := renterPriv.PublicKey()
	hostPriv := types.NewPrivateKeyFromSeed(frand.Entropy256())
	hostPub := hostPriv.PublicKey()
	genesisUpdate, cm := initTestChain(t, []types.SiacoinOutput{
		{Value: types.Siacoins(100), Address: types.PolicyAddress(types.PolicyPublicKey(renterPub))},
		{Value: types.Siacoins(100), Address: types.PolicyAddress(types.PolicyPublicKey(hostPub))},
	})
	vc, err := cm.TipContext()
	if err != nil {
		t.Fatal(err)
	}
	hostWallet := walletutil.NewEphemeralWallet(hostPriv, genesisUpdate)
	renterWallet := walletutil.NewEphemeralWallet(renterPriv, genesisUpdate)
	tp := walletutil.NewTxPool(vc)
	if err := cm.AddSubscriber(tp, cm.Tip()); err != nil {
		t.Fatal(err)
	} else if err := cm.AddSubscriber(hostWallet, cm.Tip()); err != nil {
		t.Fatal(err)
	} else if err := cm.AddSubscriber(renterWallet, cm.Tip()); err != nil {
		t.Fatal(err)
	}
	hostAddr := initTestHost(t, hostPriv, cm, hostWallet, tp, ghost.DefaultSettings)
	session, err := NewSession(hostAddr, hostPub, renterWallet, tp, cm)
	if err != nil {
		t.Fatal(err)
	}

	renterFunds := types.Siacoins(5)
	hostFunds := types.Siacoins(10)

	contract, _, err := session.FormContract(renterPriv, hostFunds, renterFunds, 200)
	if err != nil {
		t.Fatal(err)
	}

	// check that the contract transaction made it into the transaction pool and
	// attempt to mine a block to confirm it.
	if len(tp.Transactions()) != 1 {
		t.Fatalf("expected 1 transaction in the transaction pool, got %v", len(tp.Transactions()))
	} else if err := cm.AddTipBlock(mineBlock(vc, tp.TransactionsForBlock()...)); err != nil {
		t.Fatal(err)
	}

	payment := session.PayByContract(&contract, renterPriv, renterPub)
	_, err = session.RegisterSettings(payment)
	if err != nil {
		t.Fatal(err)
	}

	_, err = session.FundAccount(renterPub, types.Siacoins(1), payment)
	if err != nil {
		t.Fatal(err)
	}

	payment = session.PayByEphemeralAccount(renterPub, renterPriv, 20)
	latest, err := session.LatestRevision(contract.ID, payment)
	if err != nil {
		t.Fatal(err)
	}

	if reflect.DeepEqual(latest, contract.Revision) {
		t.Fatal("expected latest revision match")
	}
}

func TestRPCFormContract(t *testing.T) {
	renterPriv := types.NewPrivateKeyFromSeed(frand.Entropy256())
	renterPub := renterPriv.PublicKey()
	hostPriv := types.NewPrivateKeyFromSeed(frand.Entropy256())
	hostPub := hostPriv.PublicKey()
	genesisUpdate, cm := initTestChain(t, []types.SiacoinOutput{
		{Value: types.Siacoins(100), Address: types.PolicyAddress(types.PolicyPublicKey(renterPub))},
		{Value: types.Siacoins(100), Address: types.PolicyAddress(types.PolicyPublicKey(hostPub))},
	})
	vc, err := cm.TipContext()
	if err != nil {
		t.Fatal(err)
	}
	hostWallet := walletutil.NewEphemeralWallet(hostPriv, genesisUpdate)
	renterWallet := walletutil.NewEphemeralWallet(renterPriv, genesisUpdate)
	tp := walletutil.NewTxPool(vc)
	if err := cm.AddSubscriber(tp, cm.Tip()); err != nil {
		t.Fatal(err)
	} else if err := cm.AddSubscriber(hostWallet, cm.Tip()); err != nil {
		t.Fatal(err)
	} else if err := cm.AddSubscriber(renterWallet, cm.Tip()); err != nil {
		t.Fatal(err)
	}
	hostAddr := initTestHost(t, hostPriv, cm, hostWallet, tp, ghost.DefaultSettings)
	session, err := NewSession(hostAddr, hostPub, renterWallet, tp, cm)
	if err != nil {
		t.Fatal(err)
	}

	settings, err := session.ScanSettings()
	if err != nil {
		t.Fatal(err)
	}

	renterFunds := types.Siacoins(5)
	hostFunds := types.Siacoins(10)

	contract, txnset, err := session.FormContract(renterPriv, hostFunds, renterFunds, 200)
	if err != nil {
		t.Fatal(err)
	}

	// check that the contract transaction made it into the transaction pool and
	// attempt to mine a block to confirm it.
	if len(tp.Transactions()) != len(txnset) {
		t.Fatalf("expected %v transaction in the transaction pool, got %v", len(txnset), len(tp.Transactions()))
	} else if err := cm.AddTipBlock(mineBlock(vc, tp.TransactionsForBlock()...)); err != nil {
		t.Fatal(err)
	}

	// calculate the expected remaining balance for each wallet
	hostNewBalance := types.Siacoins(100).Sub(hostFunds)
	renterNewBalance := types.Siacoins(100).Sub(renterFunds).Sub(txnset[0].MinerFee).Sub(vc.FileContractTax(contract.Revision))

	switch {
	case hostWallet.Balance() != hostNewBalance:
		t.Fatalf("expected host wallet balance to be %v SC, got %v SC", hostNewBalance, hostWallet.Balance())
	case renterWallet.Balance() != renterNewBalance:
		t.Fatalf("expected renter wallet balance to be %v SC, got %v SC", renterNewBalance, renterWallet.Balance())
	case contract.Revision.RevisionNumber != 0:
		t.Fatal("expected revision number to be 0")
	case contract.Revision.ValidRenterOutput.Address != renterWallet.Address():
		t.Fatal("expected valid renter address to be the renter's address")
	case contract.Revision.MissedRenterOutput.Address != renterWallet.Address():
		t.Fatal("expected missed renter address to be the renter's address")
	case contract.Revision.ValidRenterOutput.Value != renterFunds.Sub(settings.ContractFee):
		t.Fatal("expected valid renter output to be renter funds minus contract fee")
	case contract.Revision.ValidHostOutput.Value != hostFunds.Add(settings.ContractFee):
		t.Fatal("expected valid host output to be host funds plus contract fee")
	case contract.Revision.MissedRenterOutput.Value != contract.Revision.ValidRenterOutput.Value:
		t.Fatal("expected valid and missed renter outputs to match")
	case contract.Revision.MissedHostOutput.Value != contract.Revision.ValidHostOutput.Value:
		t.Fatal("expected valid and missed host outputs to match")
	}
}

func TestRPCFundAccount(t *testing.T) {
	renterPriv := types.NewPrivateKeyFromSeed(frand.Entropy256())
	renterPub := renterPriv.PublicKey()
	hostPriv := types.NewPrivateKeyFromSeed(frand.Entropy256())
	hostPub := hostPriv.PublicKey()
	genesisUpdate, cm := initTestChain(t, []types.SiacoinOutput{
		{Value: types.Siacoins(100), Address: types.PolicyAddress(types.PolicyPublicKey(renterPub))},
		{Value: types.Siacoins(100), Address: types.PolicyAddress(types.PolicyPublicKey(hostPub))},
	})
	vc, err := cm.TipContext()
	if err != nil {
		t.Fatal(err)
	}
	hostWallet := walletutil.NewEphemeralWallet(hostPriv, genesisUpdate)
	renterWallet := walletutil.NewEphemeralWallet(renterPriv, genesisUpdate)
	tp := walletutil.NewTxPool(vc)
	if err := cm.AddSubscriber(tp, cm.Tip()); err != nil {
		t.Fatal(err)
	} else if err := cm.AddSubscriber(hostWallet, cm.Tip()); err != nil {
		t.Fatal(err)
	} else if err := cm.AddSubscriber(renterWallet, cm.Tip()); err != nil {
		t.Fatal(err)
	}
	hostAddr := initTestHost(t, hostPriv, cm, hostWallet, tp, ghost.DefaultSettings)
	session, err := NewSession(hostAddr, hostPub, renterWallet, tp, cm)
	if err != nil {
		t.Fatal(err)
	}

	renterFunds := types.Siacoins(5)
	hostFunds := types.Siacoins(10)

	contract, _, err := session.FormContract(renterPriv, hostFunds, renterFunds, 200)
	if err != nil {
		t.Fatal(err)
	}

	// check that the contract transaction made it into the transaction pool and
	// attempt to mine a block to confirm it.
	if len(tp.Transactions()) != 1 {
		t.Fatalf("expected 1 transaction in the transaction pool, got %v", len(tp.Transactions()))
	} else if err := cm.AddTipBlock(mineBlock(vc, tp.TransactionsForBlock()...)); err != nil {
		t.Fatal(err)
	}

	originalAllowance := contract.Revision.ValidRenterOutput.Value
	payment := session.PayByContract(&contract, renterPriv, renterPub)
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
	} else if contract.Revision.ValidRenterOutput.Value != remainingAllowance {
		t.Fatalf("expected remaining allowance to be %v, got %v", remainingAllowance, contract.Revision.ValidRenterOutput.Value)
	}
}

func TestRPCAccountBalance(t *testing.T) {
	renterPriv := types.NewPrivateKeyFromSeed(frand.Entropy256())
	renterPub := renterPriv.PublicKey()
	hostPriv := types.NewPrivateKeyFromSeed(frand.Entropy256())
	hostPub := hostPriv.PublicKey()
	genesisUpdate, cm := initTestChain(t, []types.SiacoinOutput{
		{Value: types.Siacoins(100), Address: types.PolicyAddress(types.PolicyPublicKey(renterPub))},
		{Value: types.Siacoins(100), Address: types.PolicyAddress(types.PolicyPublicKey(hostPub))},
	})
	vc, err := cm.TipContext()
	if err != nil {
		t.Fatal(err)
	}
	hostWallet := walletutil.NewEphemeralWallet(hostPriv, genesisUpdate)
	renterWallet := walletutil.NewEphemeralWallet(renterPriv, genesisUpdate)
	tp := walletutil.NewTxPool(vc)
	if err := cm.AddSubscriber(tp, cm.Tip()); err != nil {
		t.Fatal(err)
	} else if err := cm.AddSubscriber(hostWallet, cm.Tip()); err != nil {
		t.Fatal(err)
	} else if err := cm.AddSubscriber(renterWallet, cm.Tip()); err != nil {
		t.Fatal(err)
	}
	hostAddr := initTestHost(t, hostPriv, cm, hostWallet, tp, ghost.DefaultSettings)
	session, err := NewSession(hostAddr, hostPub, renterWallet, tp, cm)
	if err != nil {
		t.Fatal(err)
	}

	renterFunds := types.Siacoins(5)
	hostFunds := types.Siacoins(10)

	contract, _, err := session.FormContract(renterPriv, hostFunds, renterFunds, 200)
	if err != nil {
		t.Fatal(err)
	}

	// check that the contract transaction made it into the transaction pool and
	// attempt to mine a block to confirm it.
	if len(tp.Transactions()) != 1 {
		t.Fatalf("expected 1 transaction in the transaction pool, got %v", len(tp.Transactions()))
	} else if err := cm.AddTipBlock(mineBlock(vc, tp.TransactionsForBlock()...)); err != nil {
		t.Fatal(err)
	}

	remainingAllowance := contract.Revision.ValidRenterOutput.Value
	payment := session.PayByContract(&contract, renterPriv, renterPub)
	// get usable settings.
	settings, err := session.RegisterSettings(payment)
	if err != nil {
		t.Fatal(err)
	}

	// make sure the remaining renter allowance is correct.
	remainingAllowance = remainingAllowance.Sub(settings.RPCHostSettingsCost)
	if contract.Revision.ValidRenterOutput.Value.Cmp(remainingAllowance) != 0 {
		t.Fatalf("expected remaining allowance to be %v, got %v", remainingAllowance, contract.Revision.ValidRenterOutput.Value)
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
	} else if contract.Revision.ValidRenterOutput.Value != remainingAllowance {
		t.Fatalf("expected remaining allowance to be %v, got %v", remainingAllowance, contract.Revision.ValidRenterOutput.Value)
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
	} else if contract.Revision.ValidRenterOutput.Value.Cmp(remainingAllowance) != 0 {
		t.Fatalf("expected remaining allowance to be %v, got %v", remainingAllowance, contract.Revision.ValidRenterOutput.Value)
	}

	// check the account balance, paying with an ephemeral account.
	payment = session.PayByEphemeralAccount(renterPub, renterPriv, 10)
	balance, err = session.AccountBalance(renterPub, payment)
	if err != nil {
		t.Fatal(err)
	}

	if balance.Cmp(fundAmount.Sub(settings.RPCAccountBalanceCost)) != 0 {
		t.Fatalf("expected balance to be %v, got %v", fundAmount.Sub(settings.RPCAccountBalanceCost), balance)
	} else if contract.Revision.ValidRenterOutput.Value.Cmp(remainingAllowance) != 0 {
		t.Fatalf("expected remaining allowance to be %v, got %v", remainingAllowance, contract.Revision.ValidRenterOutput.Value)
	}
}

func TestReadWriteProgram(t *testing.T) {
	renterPriv := types.NewPrivateKeyFromSeed(frand.Entropy256())
	renterPub := renterPriv.PublicKey()
	hostPriv := types.NewPrivateKeyFromSeed(frand.Entropy256())
	hostPub := hostPriv.PublicKey()
	genesisUpdate, cm := initTestChain(t, []types.SiacoinOutput{
		{Value: types.Siacoins(100), Address: types.PolicyAddress(types.PolicyPublicKey(renterPub))},
		{Value: types.Siacoins(100), Address: types.PolicyAddress(types.PolicyPublicKey(hostPub))},
	})
	vc, err := cm.TipContext()
	if err != nil {
		t.Fatal(err)
	}
	hostWallet := walletutil.NewEphemeralWallet(hostPriv, genesisUpdate)
	renterWallet := walletutil.NewEphemeralWallet(renterPriv, genesisUpdate)
	tp := walletutil.NewTxPool(vc)
	if err := cm.AddSubscriber(tp, cm.Tip()); err != nil {
		t.Fatal(err)
	} else if err := cm.AddSubscriber(hostWallet, cm.Tip()); err != nil {
		t.Fatal(err)
	} else if err := cm.AddSubscriber(renterWallet, cm.Tip()); err != nil {
		t.Fatal(err)
	}
	hostAddr := initTestHost(t, hostPriv, cm, hostWallet, tp, ghost.DefaultSettings)
	session, err := NewSession(hostAddr, hostPub, renterWallet, tp, cm)
	if err != nil {
		t.Fatal(err)
	}

	renterFunds := types.Siacoins(50)
	hostFunds := types.Siacoins(100)

	contract, _, err := session.FormContract(renterPriv, hostFunds, renterFunds, 200)
	if err != nil {
		t.Fatal(err)
	}

	// check that the contract transaction made it into the transaction pool and
	// attempt to mine a block to confirm it.
	if len(tp.Transactions()) != 1 {
		t.Fatalf("expected 1 transaction in the transaction pool, got %v", len(tp.Transactions()))
	} else if err := cm.AddTipBlock(mineBlock(vc, tp.TransactionsForBlock()...)); err != nil {
		t.Fatal(err)
	}

	payment := session.PayByContract(&contract, renterPriv, renterPub)
	settings, err := session.RegisterSettings(payment)
	if err != nil {
		t.Fatal(err)
	}

	var sector [rhp.SectorSize]byte
	frand.Read(sector[:16])
	expectedRoot := rhp.SectorRoot(&sector)

	duration := contract.Revision.WindowStart - settings.BlockHeight
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
	} else if _, ok := instructions[0].(*rhp.InstrAppendSector); !ok {
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
		Contract:             &contract,
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
	case contract.Revision.RevisionNumber != 3:
		// settings revision, payment revision, program execution revision
		t.Fatalf("expected revision number to be 3, got %v", contract.Revision.RevisionNumber)
	case contract.Revision.Filesize != rhp.SectorSize:
		t.Fatalf("expected filesize to be %v, got %v", rhp.SectorSize, contract.Revision.Filesize)
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
	} else if _, ok := instructions[0].(*rhp.InstrReadSector); !ok {
		t.Fatal("expected read program to have read sector instruction")
	}

	err = session.ExecuteProgram(Program{
		Instructions: instructions,
		Budget:       budget,

		RequiresContract:     requiresContract,
		RequiresFinalization: requiresFinalization,
		Contract:             &contract,
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
	hostPriv := types.NewPrivateKeyFromSeed(frand.Entropy256())
	hostPub := hostPriv.PublicKey()
	genesisUpdate, cm := initTestChain(b, []types.SiacoinOutput{
		{Value: types.Siacoins(100), Address: types.PolicyAddress(types.PolicyPublicKey(renterPub))},
		{Value: types.Siacoins(100), Address: types.PolicyAddress(types.PolicyPublicKey(hostPub))},
	})
	vc, err := cm.TipContext()
	if err != nil {
		b.Fatal(err)
	}
	hostWallet := walletutil.NewEphemeralWallet(hostPriv, genesisUpdate)
	renterWallet := walletutil.NewEphemeralWallet(renterPriv, genesisUpdate)
	tp := walletutil.NewTxPool(vc)
	if err := cm.AddSubscriber(tp, cm.Tip()); err != nil {
		b.Fatal(err)
	} else if err := cm.AddSubscriber(hostWallet, cm.Tip()); err != nil {
		b.Fatal(err)
	} else if err := cm.AddSubscriber(renterWallet, cm.Tip()); err != nil {
		b.Fatal(err)
	}
	hostAddr := initTestHost(b, hostPriv, cm, hostWallet, tp, ghost.DefaultSettings)
	session, err := NewSession(hostAddr, hostPub, renterWallet, tp, cm)
	if err != nil {
		b.Fatal(err)
	}

	renterFunds := types.Siacoins(100)
	hostFunds := types.Siacoins(100)

	contract, _, err := session.FormContract(renterPriv, hostFunds, renterFunds, 200)
	if err != nil {
		b.Fatal(err)
	}

	// check that the contract transaction made it into the transaction pool and
	// attempt to mine a block to confirm it.
	if len(tp.Transactions()) != 1 {
		b.Fatalf("expected 1 transaction in the transaction pool, got %v", len(tp.Transactions()))
	} else if err := cm.AddTipBlock(mineBlock(vc, tp.TransactionsForBlock()...)); err != nil {
		b.Fatal(err)
	}

	payment := session.PayByContract(&contract, renterPriv, renterPub)
	settings, err := session.RegisterSettings(payment)
	if err != nil {
		b.Fatal(err)
	}

	var sector [rhp.SectorSize]byte
	frand.Read(sector[:16])

	duration := contract.Revision.WindowEnd - settings.BlockHeight
	inputBuf := bytes.NewBuffer(make([]byte, 0, rhp.SectorSize))
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

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(int64(rhp.SectorSize))
	for i := 0; i < b.N; i++ {
		// append sector does not return any output
		err = session.ExecuteProgram(Program{
			Instructions: instructions,
			Budget:       budget,

			RequiresContract:     requiresContract,
			RequiresFinalization: requiresFinalization,
			Contract:             &contract,
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
	hostPriv := types.NewPrivateKeyFromSeed(frand.Entropy256())
	hostPub := hostPriv.PublicKey()
	genesisUpdate, cm := initTestChain(b, []types.SiacoinOutput{
		{Value: types.Siacoins(100), Address: types.PolicyAddress(types.PolicyPublicKey(renterPub))},
		{Value: types.Siacoins(100), Address: types.PolicyAddress(types.PolicyPublicKey(hostPub))},
	})
	vc, err := cm.TipContext()
	if err != nil {
		b.Fatal(err)
	}
	hostWallet := walletutil.NewEphemeralWallet(hostPriv, genesisUpdate)
	renterWallet := walletutil.NewEphemeralWallet(renterPriv, genesisUpdate)
	tp := walletutil.NewTxPool(vc)
	if err := cm.AddSubscriber(tp, cm.Tip()); err != nil {
		b.Fatal(err)
	} else if err := cm.AddSubscriber(hostWallet, cm.Tip()); err != nil {
		b.Fatal(err)
	} else if err := cm.AddSubscriber(renterWallet, cm.Tip()); err != nil {
		b.Fatal(err)
	}
	hostAddr := initTestHost(b, hostPriv, cm, hostWallet, tp, ghost.FreeSettings)
	session, err := NewSession(hostAddr, hostPub, renterWallet, tp, cm)
	if err != nil {
		b.Fatal(err)
	}

	renterFunds := types.Siacoins(100)
	hostFunds := types.Siacoins(100)

	contract, _, err := session.FormContract(renterPriv, hostFunds, renterFunds, 200)
	if err != nil {
		b.Fatal(err)
	}

	// check that the contract transaction made it into the transaction pool and
	// attempt to mine a block to confirm it.
	if len(tp.Transactions()) != 1 {
		b.Fatalf("expected 1 transaction in the transaction pool, got %v", len(tp.Transactions()))
	} else if err := cm.AddTipBlock(mineBlock(vc, tp.TransactionsForBlock()...)); err != nil {
		b.Fatal(err)
	}

	payment := session.PayByContract(&contract, renterPriv, renterPub)
	settings, err := session.RegisterSettings(payment)
	if err != nil {
		b.Fatal(err)
	}

	var sector [rhp.SectorSize]byte
	frand.Read(sector[:16])
	root := rhp.SectorRoot(&sector)

	duration := contract.Revision.WindowEnd - settings.BlockHeight
	inputBuf := bytes.NewBuffer(make([]byte, 0, rhp.SectorSize))
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
		Contract:             &contract,
		RenterKey:            renterPriv,
	}, inputBuf.Bytes(), payment, nil)
	if err != nil {
		b.Fatal(err)
	}

	inputBuf.Reset()
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

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(int64(rhp.SectorSize))
	for i := 0; i < b.N; i++ {
		// safe to ignore the read sector output
		err = session.ExecuteProgram(Program{
			Instructions: instructions,
			Budget:       budget,

			RequiresContract:     requiresContract,
			RequiresFinalization: requiresFinalization,
			Contract:             &contract,
			RenterKey:            renterPriv,
		}, inputBuf.Bytes(), payment, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}
