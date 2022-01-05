package renter

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/net/rhp"
	"go.sia.tech/core/net/rpc"
	"go.sia.tech/core/types"
)

type (
	// ChainManager manages the chain state.
	ChainManager interface {
		// ValidationContext returns the current ValidationContext
		TipContext() (consensus.ValidationContext, error)
	}

	// A TransactionPool broadcasts transaction sets to miners for inclusion in an
	// upcoming block.
	TransactionPool interface {
		FeeEstimate() (min, max types.Currency, err error)
	}

	// A Wallet provides addresses and funds and signs transactions.
	Wallet interface {
		Balance() types.Currency
		Address() types.Address
		Addresses() []types.Address
		FundTransaction(txn *types.Transaction, amount types.Currency, pool []types.Transaction) ([]types.ElementID, func(), error)
		SignTransaction(vc consensus.ValidationContext, txn *types.Transaction, toSign []types.ElementID) error
	}
)

var (
	// ErrPaymentRequired is returned when a payment method is required but not
	// provided.
	ErrPaymentRequired = errors.New("payment method is required")
)

// A Session is an implementation of the renter side of the renter-host protocol.
type Session struct {
	hostKey types.PublicKey

	wallet  Wallet
	tpool   TransactionPool
	cm      ChainManager
	session *rhp.Session

	settings   rhp.HostSettings
	settingsID rhp.SettingsID
}

func (s *Session) currentSettings() (rhp.SettingsID, rhp.HostSettings, error) {
	if s.settings.ValidUntil.Before(time.Now()) {
		return rhp.SettingsID{}, rhp.HostSettings{}, fmt.Errorf("settings expired")
	}
	return s.settingsID, s.settings, nil
}

// AccountBalance returns the current balance of an ephemeral account.
func (s *Session) AccountBalance(accountID types.PublicKey, payment PaymentMethod) (types.Currency, error) {
	if payment == nil {
		return types.ZeroCurrency, ErrPaymentRequired
	}

	stream, err := s.session.DialStream()
	if err != nil {
		return types.ZeroCurrency, fmt.Errorf("failed to open new stream: %w", err)
	}
	defer stream.Close()

	id, settings, err := s.currentSettings()
	if err != nil {
		return types.ZeroCurrency, errors.New("price table invalid or expired")
	}

	err = rpc.WriteRequest(stream, rhp.RPCAccountBalanceID, &id)
	if err != nil {
		return types.ZeroCurrency, fmt.Errorf("failed to write account balance request: %w", err)
	}

	if err := payment.Pay(stream, settings.RPCAccountBalanceCost); err != nil {
		return types.ZeroCurrency, fmt.Errorf("failed to pay for account balance: %w", err)
	}

	req := &rhp.RPCAccountBalanceRequest{
		AccountID: accountID,
	}
	if err = rpc.WriteResponse(stream, req); err != nil {
		return types.ZeroCurrency, fmt.Errorf("failed to write account balance request: %w", err)
	}

	var resp rhp.RPCAccountBalanceResponse
	if err := rpc.ReadResponse(stream, &resp); err != nil {
		return types.ZeroCurrency, fmt.Errorf("failed to read account balance response: %w", err)
	}

	return resp.Balance, nil
}

// FundAccount funds an ephemeral account with the given amount. The ephemeral
// account's balance can be used as the payment method for other RPC calls.
func (s *Session) FundAccount(accountID types.PublicKey, amount types.Currency, payment PaymentMethod) (types.Currency, error) {
	if payment == nil {
		return types.ZeroCurrency, ErrPaymentRequired
	} else if _, ok := payment.(*payByContract); !ok {
		return types.ZeroCurrency, errors.New("ephemeral accounts must be funded by a contract")
	}

	stream, err := s.session.DialStream()
	if err != nil {
		return types.ZeroCurrency, fmt.Errorf("failed to open new stream: %w", err)
	}
	defer stream.Close()

	id, settings, err := s.currentSettings()
	if err != nil {
		return types.ZeroCurrency, errors.New("price table invalid or expired")
	}

	err = rpc.WriteRequest(stream, rhp.RPCFundAccountID, &id)
	if err != nil {
		return types.ZeroCurrency, fmt.Errorf("failed to write account balance request: %w", err)
	}

	if err := payment.Pay(stream, settings.RPCFundAccountCost.Add(amount)); err != nil {
		return types.ZeroCurrency, fmt.Errorf("failed to pay for account balance: %w", err)
	}

	err = rpc.WriteResponse(stream, &rhp.RPCFundAccountRequest{
		AccountID: accountID,
	})
	if err != nil {
		return types.ZeroCurrency, fmt.Errorf("failed to write account balance request: %w", err)
	}

	var resp rhp.RPCFundAccountResponse
	if err := rpc.ReadResponse(stream, &resp); err != nil {
		return types.ZeroCurrency, fmt.Errorf("failed to read account balance response: %w", err)
	}

	return resp.Balance, nil
}

// LatestRevision returns the latest revision of a contract.
func (s *Session) LatestRevision(contractID types.ElementID, payment PaymentMethod) (types.FileContractRevision, error) {
	if payment == nil {
		return types.FileContractRevision{}, ErrPaymentRequired
	}

	stream, err := s.session.DialStream()
	if err != nil {
		return types.FileContractRevision{}, fmt.Errorf("failed to open new stream: %w", err)
	}
	defer stream.Close()

	id, settings, err := s.currentSettings()
	if err != nil {
		return types.FileContractRevision{}, fmt.Errorf("failed to load price table: %w", err)
	}

	if err := rpc.WriteRequest(stream, rhp.RPCLatestRevisionID, &id); err != nil {
		return types.FileContractRevision{}, fmt.Errorf("failed to write latest revision request: %w", err)
	}

	if err := payment.Pay(stream, settings.RPCLatestRevisionCost); err != nil {
		return types.FileContractRevision{}, fmt.Errorf("failed to pay for latest revision: %w", err)
	}

	req := &rhp.RPCLatestRevisionRequest{
		ContractID: contractID,
	}
	if err := rpc.WriteResponse(stream, req); err != nil {
		return types.FileContractRevision{}, fmt.Errorf("failed to write latest revision request: %w", err)
	}

	var resp rhp.RPCLatestRevisionResponse
	if err := rpc.ReadResponse(stream, &resp); err != nil {
		return types.FileContractRevision{}, fmt.Errorf("failed to read latest revision response: %w", err)
	}
	return resp.Revision, nil
}

// RegisterSettings returns the current settings from the host and registers
// them for use in other RPC.
func (s *Session) RegisterSettings(payment PaymentMethod) (settings rhp.HostSettings, _ error) {
	if payment == nil {
		return rhp.HostSettings{}, ErrPaymentRequired
	}

	stream, err := s.session.DialStream()
	if err != nil {
		return rhp.HostSettings{}, fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	if err := rpc.WriteRequest(stream, rhp.RPCSettingsID, nil); err != nil {
		return rhp.HostSettings{}, fmt.Errorf("failed to write settings request: %w", err)
	}

	var resp rhp.RPCSettingsResponse
	if err := rpc.ReadResponse(stream, &resp); err != nil {
		return rhp.HostSettings{}, fmt.Errorf("failed to read settings response: %w", err)
	}

	if err := json.Unmarshal(resp.Settings, &settings); err != nil {
		return rhp.HostSettings{}, fmt.Errorf("failed to decode settings: %w", err)
	}

	if err := payment.Pay(stream, settings.RPCHostSettingsCost); err != nil {
		return rhp.HostSettings{}, fmt.Errorf("failed to pay for settings: %w", err)
	}

	var registerResp rhp.RPCSettingsRegisteredResponse
	if err = rpc.ReadResponse(stream, &registerResp); err != nil {
		return rhp.HostSettings{}, fmt.Errorf("failed to read tracking response: %w", err)
	}

	s.settings = settings
	s.settingsID = registerResp.ID
	return
}

// ScanSettings returns the current settings for the host.
func (s *Session) ScanSettings() (settings rhp.HostSettings, _ error) {
	stream, err := s.session.DialStream()
	if err != nil {
		return rhp.HostSettings{}, fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	if err := rpc.WriteRequest(stream, rhp.RPCSettingsID, nil); err != nil {
		return rhp.HostSettings{}, fmt.Errorf("failed to write settings request: %w", err)
	}

	var resp rhp.RPCSettingsResponse
	if err := rpc.ReadResponse(stream, &resp); err != nil {
		return rhp.HostSettings{}, fmt.Errorf("failed to read settings response: %w", err)
	}

	if err := json.Unmarshal(resp.Settings, &settings); err != nil {
		return rhp.HostSettings{}, fmt.Errorf("failed to decode settings: %w", err)
	}
	return
}

// NewSession initiates a new RHP session with the host.
func NewSession(netaddress string, theirKey types.PublicKey, w Wallet, tp TransactionPool, cm ChainManager) (*Session, error) {
	conn, err := net.Dial("tcp", netaddress)
	if err != nil {
		return nil, fmt.Errorf("failed to open connection: %w", err)
	}

	s := &Session{
		hostKey: theirKey,

		cm:     cm,
		wallet: w,
		tpool:  tp,
	}

	s.session, err = rhp.DialSession(conn, theirKey)
	if err != nil {
		return nil, fmt.Errorf("failed to start session: %w", err)
	}

	return s, nil
}
