package host

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"go.sia.tech/core/v2/net/rhp"
	"go.sia.tech/core/v2/types"

	"lukechampine.com/frand"
)

type stubEphemeralAccountStore struct {
	mu       sync.Mutex
	balances map[types.PublicKey]types.Currency
}

func (s *stubEphemeralAccountStore) Balance(accountID types.PublicKey) (types.Currency, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.balances[accountID], nil
}

func (s *stubEphemeralAccountStore) Deposit(accountID types.PublicKey, amount types.Currency) (types.Currency, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.balances[accountID] = s.balances[accountID].Add(amount)
	return s.balances[accountID], nil
}

func (s *stubEphemeralAccountStore) Refund(accountID types.PublicKey, amount types.Currency) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.balances[accountID] = s.balances[accountID].Add(amount)
	return nil
}

func (s *stubEphemeralAccountStore) Withdraw(accountID types.PublicKey, requestID types.Hash256, amount types.Currency) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	bal, exists := s.balances[accountID]
	if !exists || bal.Cmp(amount) < 0 {
		return errors.New("insufficient funds")
	}

	s.balances[accountID] = s.balances[accountID].Sub(amount)
	return nil
}

func newStubAccountStore() *stubEphemeralAccountStore {
	return &stubEphemeralAccountStore{
		balances: make(map[types.PublicKey]types.Currency),
	}
}

func TestRPCBudget(t *testing.T) {
	eas := newStubAccountStore()

	pub := types.PublicKey(frand.Entropy256())
	budget := NewBudget(types.Siacoins(2))

	if budget.Remaining() != types.Siacoins(2) {
		t.Fatal("expected 2 SC budget")
	}

	// spend an amount greater than the budget
	if err := budget.Spend(types.Siacoins(3)); err == nil {
		t.Fatal("expected error when spending more than the budget")
	}

	if balance, _ := eas.Balance(pub); balance != types.ZeroCurrency {
		t.Fatal("expected account to be empty")
	}

	// spend half the budget
	if err := budget.Spend(types.Siacoins(1)); err != nil {
		t.Fatal("expected to be able to spend half the budget:", err)
	}

	eas.Refund(pub, budget.Remaining())

	if balance, _ := eas.Balance(pub); balance != types.Siacoins(1) {
		t.Fatal("expected account to be refunded 1 SC")
	}
}

func TestBudgetedStream(t *testing.T) {
	budget := NewBudget(types.Siacoins(2))

	if budget.Remaining().Cmp(types.Siacoins(2)) != 0 {
		t.Fatal("expected 2 SC budget")
	}

	settings := rhp.HostSettings{
		DownloadBandwidthPrice: types.Siacoins(1).Div64(100), // 1 SC per 100 bytes
		UploadBandwidthPrice:   types.Siacoins(1).Div64(100), // 1 SC per 100 bytes
	}

	buf := bytes.NewBuffer(nil)
	rw := NewBudgetedStream(buf, budget, settings)

	// write 3/4 of the budget
	if _, err := rw.Write(frand.Bytes(150)); err != nil {
		t.Fatal(err)
	}

	if budget.Remaining() != types.Siacoins(1).Div64(2) {
		t.Fatalf("expected 1 SC remaining, got %d", budget.Remaining())
	}

	// read the remaining budget
	if _, err := rw.Read(make([]byte, 50)); err != nil {
		t.Fatal(err)
	}

	if budget.Remaining() != types.ZeroCurrency {
		t.Fatal("expected 0 SC remaining")
	}

	// overflow the budget
	if _, err := rw.Read(make([]byte, 51)); !errors.Is(err, ErrInsufficientBudget) {
		t.Fatal("expected insufficient budget error")
	}
}
