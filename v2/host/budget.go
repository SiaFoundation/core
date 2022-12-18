package host

import (
	"errors"
	"fmt"
	"io"

	"go.sia.tech/core/v2/net/rhp"
	"go.sia.tech/core/v2/types"
)

// A Budget provides helpers for managing the RPC budget.
type Budget struct {
	value types.Currency
}

var (
	// ErrInsufficientBudget is returned when the renter's budget is not
	// sufficient to cover the payment.
	ErrInsufficientBudget = errors.New("insufficient budget")
)

// Remaining returns the amount remaining in the budget
func (b *Budget) Remaining() types.Currency {
	return b.value
}

// Spend subtracts amount from the remaining budget.
func (b *Budget) Spend(amount types.Currency) error {
	if amount.Cmp(b.value) > 0 {
		return fmt.Errorf("unable to spend %d, %d remaining: %w", amount, b.value, ErrInsufficientBudget)
	}
	b.value = b.value.Sub(amount)
	return nil
}

// Increase increases the budget by the specified amount.
func (b *Budget) Increase(amount types.Currency) {
	b.value = b.value.Add(amount)
}

// NewBudget returns a new Budget.
func NewBudget(value types.Currency) *Budget {
	return &Budget{
		value: value,
	}
}

// A BudgetedStream limits reads and writes using an RPC budget. Writes
// subtract the download bandwidth price multiplied by the number of bytes
// written and reads subtract the upload bandwidth price multiplied by the
// number of bytes read.
type BudgetedStream struct {
	rw     io.ReadWriter
	budget *Budget

	uploadBandwidthPrice   types.Currency
	downloadBandwidthPrice types.Currency
}

// Read reads data from the underlying stream. Implements io.Reader.
func (l *BudgetedStream) Read(buf []byte) (n int, err error) {
	n, err = l.rw.Read(buf)
	if err != nil {
		return
	}
	cost := l.uploadBandwidthPrice.Mul64(uint64(n))
	if err = l.budget.Spend(cost); err != nil {
		return
	}
	return
}

// Write writes data to the underlying stream. Implements io.Writer.
func (l *BudgetedStream) Write(buf []byte) (n int, err error) {
	n, err = l.rw.Write(buf)
	if err != nil {
		return
	}
	cost := l.downloadBandwidthPrice.Mul64(uint64(n))
	if err = l.budget.Spend(cost); err != nil {
		return
	}
	return
}

// NewBudgetedStream initializes a new stream limited by the budget.
func NewBudgetedStream(rw io.ReadWriter, budget *Budget, settings rhp.HostSettings) *BudgetedStream {
	return &BudgetedStream{
		rw:     rw,
		budget: budget,

		uploadBandwidthPrice:   settings.UploadBandwidthPrice,
		downloadBandwidthPrice: settings.DownloadBandwidthPrice,
	}
}
