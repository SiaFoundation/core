package host

import (
	"errors"
	"fmt"
	"time"

	"go.sia.tech/core/net/mux"
	"go.sia.tech/core/net/rhp"
	"go.sia.tech/core/net/rpc"
	"go.sia.tech/core/types"
)

type rpcBudget struct {
	value types.Currency
}

var (
	// ErrInsufficientBudget is returned when the renter's budget is not
	// sufficient to cover the payment.
	ErrInsufficientBudget = errors.New("insufficient budget")
)

// Remaining returns the amount remaining in the budget
func (budget *rpcBudget) Remaining() types.Currency {
	return budget.value
}

// Spend subtracts amount from the remaining budget.
func (budget *rpcBudget) Spend(amount types.Currency) error {
	if amount.Cmp(budget.value) > 0 {
		return fmt.Errorf("unable to spend %d, %d remaining: %w", amount, budget.value, ErrInsufficientBudget)
	}
	budget.value = budget.value.Sub(amount)
	return nil
}

// Increase increases the budget by the specified amount.
func (budget *rpcBudget) Increase(amount types.Currency) {
	budget.value = budget.value.Add(amount)
}

func newRPCBudget(value types.Currency) *rpcBudget {
	return &rpcBudget{
		value: value,
	}
}

func validateEAWithdrawal(req rhp.PayByEphemeralAccountRequest, height uint64) (types.Hash256, error) {
	// verify the signature is correct.
	h := types.NewHasher()
	req.Message.EncodeTo(h.E)
	withdrawID := h.Sum()

	if !req.Message.AccountID.VerifyHash(withdrawID, req.Signature) {
		return types.Hash256{}, errors.New("withdrawal request signature is invalid")
	}

	switch {
	case req.Message.Expiry < height:
		return types.Hash256{}, errors.New("withdrawal request expired")
	case req.Message.Expiry > height+20:
		return types.Hash256{}, errors.New("withdrawal request too far in the future")
	case req.Message.Amount.IsZero():
		return types.Hash256{}, errors.New("withdrawal request has zero amount")
	}
	return withdrawID, nil
}

// processEAPayment processes a payment using an ephemeral account.
func (sh *SessionHandler) processEAPayment(stream *mux.Stream) (*rpcBudget, types.PublicKey, error) {
	height := sh.cm.Tip().Height

	var req rhp.PayByEphemeralAccountRequest
	if err := rpc.ReadObject(stream, &req); err != nil {
		return nil, types.PublicKey{}, fmt.Errorf("failed to read EA payment request: %w", err)
	}

	withdrawID, err := validateEAWithdrawal(req, height)
	if err != nil {
		return nil, types.PublicKey{}, fmt.Errorf("invalid EA payment request: %w", err)
	}

	// withdraw the funds from the account.
	_, err = sh.accounts.Debit(req.Message.AccountID, withdrawID, req.Message.Amount)
	if err != nil {
		return nil, types.PublicKey{}, fmt.Errorf("failed to withdraw from ephemeral account: %w", err)
	}
	return newRPCBudget(req.Message.Amount), req.Message.AccountID, nil
}

// processContractPayment processes a payment using an existing contract.
func (sh *SessionHandler) processContractPayment(stream *mux.Stream) (*rpcBudget, types.PublicKey, error) {
	var req rhp.PayByContractRequest
	if err := rpc.ReadObject(stream, &req); err != nil {
		return nil, types.PublicKey{}, fmt.Errorf("failed to read contract payment request: %w", err)
	}

	contract, err := sh.lockContract(req.ContractID, time.Second*30)
	if err != nil {
		return nil, types.PublicKey{}, fmt.Errorf("failed to lock contract %v: %w", req.ContractID, err)
	}
	defer sh.unlockContract(req.ContractID)

	if contract.Revision.ValidHostOutput.Value.Cmp(req.NewOutputs.ValidHostValue) > 0 {
		return nil, types.PublicKey{}, errors.New("new valid host payout must be greater than current")
	}

	// calculate the fund amount as the difference between the new and old
	// valid host outputs.
	fundAmount := req.NewOutputs.ValidHostValue.Sub(contract.Revision.ValidHostOutput.Value)

	// create a new revision with updated output values and renter signature
	revision := contract.FileContractRevision
	revision.Revision.RevisionNumber = req.NewRevisionNumber
	req.NewOutputs.Apply(&revision.Revision)

	vc, err := sh.cm.TipContext()
	if err != nil {
		return nil, types.PublicKey{}, fmt.Errorf("failed to get validation context: %w", err)
	}

	// sign the new revision and apply the renter's signature.
	sigHash := vc.ContractSigHash(revision.Revision)
	revision.HostSignature = sh.privkey.SignHash(sigHash)
	revision.RenterSignature = req.Signature

	if err := validatePaymentRevision(vc, contract.FileContractRevision, revision, fundAmount); err != nil {
		return nil, types.PublicKey{}, fmt.Errorf("invalid payment revision: %w", err)
	}

	// update the contract.
	if err := sh.contracts.ReviseContract(revision); err != nil {
		return nil, types.PublicKey{}, fmt.Errorf("failed to update stored contract revision: %w", err)
	}

	// send the updated host signature to the renter
	err = rpc.WriteResponse(stream, &rhp.RPCRevisionSigningResponse{
		Signature: revision.HostSignature,
	})
	if err != nil {
		return nil, types.PublicKey{}, fmt.Errorf("failed to send host signature response: %w", err)
	}

	return newRPCBudget(fundAmount), req.RefundAccount, nil
}

// processPayment processes a payment request from the renter, returns the
// budget and refund account ID.
func (sh *SessionHandler) processPayment(stream *mux.Stream) (*rpcBudget, types.PublicKey, error) {
	var req rpc.Specifier
	if err := rpc.ReadRequest(stream, &req); err != nil {
		return nil, types.PublicKey{}, fmt.Errorf("failed to read payment request: %w", err)
	}

	switch req {
	case rhp.PayByEphemeralAccount:
		return sh.processEAPayment(stream)
	case rhp.PayByContract:
		return sh.processContractPayment(stream)
	default:
		return nil, types.PublicKey{}, fmt.Errorf("unknown payment type %v", req)
	}
}
