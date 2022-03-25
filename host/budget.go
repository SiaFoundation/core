package host

import (
	"errors"
	"fmt"
	"io"

	"go.sia.tech/core/net/rhp"
	"go.sia.tech/core/types"
)

// A Budget provides helpers for managing the RPC budget.
type Budget struct {
	spent types.Currency
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

// Refund returns the remaining budget and sets the budget to 0.
func (b *Budget) Refund() (v types.Currency) {
	v = b.value
	b.value = types.ZeroCurrency
	return
}

// Spent returns the amount of the budget spent by the renter.
func (b *Budget) Spent() types.Currency {
	return b.spent
}

// Spend subtracts amount from the remaining budget.
func (b *Budget) Spend(amount types.Currency) error {
	if amount.Cmp(b.value) > 0 {
		return fmt.Errorf("unable to spend %d, %d remaining: %w", amount, b.value, ErrInsufficientBudget)
	}
	b.spent = b.spent.Add(amount)
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

	readPrice  types.Currency
	writePrice types.Currency

	readSpending  types.Currency
	writeSpending types.Currency
}

// Read reads data from the underlying stream. Implements io.Reader.
func (l *BudgetedStream) Read(buf []byte) (n int, err error) {
	n, err = l.rw.Read(buf)
	if err != nil {
		return
	}
	cost := l.readPrice.Mul64(uint64(n))
	if err = l.budget.Spend(cost); err != nil {
		return
	}
	l.readSpending = l.readSpending.Add(cost)
	return
}

// Write writes data to the underlying stream. Implements io.Writer.
func (l *BudgetedStream) Write(buf []byte) (n int, err error) {
	n, err = l.rw.Write(buf)
	if err != nil {
		return
	}
	cost := l.writePrice.Mul64(uint64(n))
	if err = l.budget.Spend(cost); err != nil {
		return
	}
	l.writeSpending = l.writeSpending.Add(cost)
	return
}

// Spending returns the amount of the budget spent by reading and writing to the stream
func (l *BudgetedStream) Spending() (read, write types.Currency) {
	return l.readSpending, l.writeSpending
}

// NewBudgetedStream initializes a new stream limited by the budget.
func NewBudgetedStream(rw io.ReadWriter, budget *Budget, settings rhp.HostSettings) *BudgetedStream {
	return &BudgetedStream{
		rw:     rw,
		budget: budget,

		readPrice:  settings.UploadBandwidthPrice,
		writePrice: settings.DownloadBandwidthPrice,
	}
}
