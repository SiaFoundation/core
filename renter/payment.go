package renter

import (
	"errors"
	"fmt"

	"go.sia.tech/core/net/mux"
	"go.sia.tech/core/net/rhp"
	"go.sia.tech/core/net/rpc"
	"go.sia.tech/core/types"

	"lukechampine.com/frand"
)

type (
	// A PaymentMethod pays for RPC usage during an renter-host session.
	PaymentMethod interface {
		Pay(s *mux.Stream, amount types.Currency) error
	}

	payByEphemeralAccount struct {
		accountID types.PublicKey
		privkey   types.PrivateKey
		expiry    uint64
	}

	payByContract struct {
		rev             *types.FileContractRevision
		privkey         types.PrivateKey
		hostKey         types.PublicKey
		refundAccountID types.PublicKey

		cm ChainManager
	}
)

// Pay pays the host the given amount from the renter's ephemeral account.
func (p *payByEphemeralAccount) Pay(stream *mux.Stream, amount types.Currency) error {
	var nonce [8]byte
	frand.Read(nonce[:])

	req := &rhp.PayByEphemeralAccountRequest{
		Message: rhp.WithdrawalMessage{
			AccountID: p.accountID,
			Amount:    amount,
			Expiry:    p.expiry,
			Nonce:     nonce,
		},
	}

	h := types.NewHasher()
	req.Message.EncodeTo(h.E)

	req.Signature = p.privkey.SignHash(h.Sum())
	if err := rpc.WriteRequest(stream, rhp.PayByEphemeralAccount, req); err != nil {
		return fmt.Errorf("failed to write ephemeral account payment request specifier: %w", err)
	}

	return nil
}

// Pay pays the host the given amount from the renter's contract.
func (p *payByContract) Pay(stream *mux.Stream, amount types.Currency) error {
	// verify the contract has enough funds to pay the amount.
	switch {
	case p.rev.Revision.ValidRenterOutput.Value.Cmp(amount) < 0:
		return errors.New("insufficient renter funds")
	case p.rev.Revision.MissedRenterOutput.Value.Cmp(amount) < 0:
		return errors.New("insufficient renter funds")
	}

	vc, err := p.cm.TipContext()
	if err != nil {
		return fmt.Errorf("failed to get current validation context: %w", err)
	}

	// update the revision to pay for the usage.
	updated := p.rev.Revision
	updated.RevisionNumber++
	updated.ValidRenterOutput.Value = updated.ValidRenterOutput.Value.Sub(amount)
	updated.MissedRenterOutput.Value = updated.MissedRenterOutput.Value.Sub(amount)
	updated.ValidHostOutput.Value = updated.ValidHostOutput.Value.Add(amount)
	updated.MissedHostOutput.Value = updated.MissedHostOutput.Value.Add(amount)
	revisionHash := vc.ContractSigHash(updated)

	req := &rhp.PayByContractRequest{
		RefundAccount: p.refundAccountID,

		ContractID:        p.rev.Parent.ID,
		NewRevisionNumber: updated.RevisionNumber,
		NewOutputs: rhp.ContractOutputs{
			MissedHostValue:   updated.MissedHostOutput.Value,
			MissedRenterValue: updated.MissedRenterOutput.Value,
			ValidHostValue:    updated.ValidHostOutput.Value,
			ValidRenterValue:  updated.ValidRenterOutput.Value,
		},
		Signature: p.privkey.SignHash(revisionHash),
	}

	// write the payment request.
	if err := rpc.WriteRequest(stream, rhp.PayByContract, req); err != nil {
		return fmt.Errorf("failed to write contract payment request specifier: %w", err)
	}

	// read the payment response.
	var resp rhp.RPCRevisionSigningResponse
	if err := rpc.ReadResponse(stream, &resp); err != nil {
		return fmt.Errorf("failed to read contract payment response: %w", err)
	}

	// verify the host's signature.
	if !p.hostKey.VerifyHash(revisionHash, resp.Signature) {
		return errors.New("could not verify host signature")
	}

	// update the contract to reflect the payment and new signatures
	p.rev.Revision = updated
	p.rev.RenterSignature = req.Signature
	p.rev.HostSignature = resp.Signature
	return nil
}

// PayByContract creates a new contract payment method.
func (s *Session) PayByContract(rev *types.FileContractRevision, priv types.PrivateKey, refundAccountID types.PublicKey) PaymentMethod {
	return &payByContract{
		rev:             rev,
		privkey:         priv,
		hostKey:         s.hostKey,
		refundAccountID: refundAccountID,
		cm:              s.cm,
	}
}

// PayByEphemeralAccount creates a new ephemeral account payment method.
func (s *Session) PayByEphemeralAccount(accountID types.PublicKey, priv types.PrivateKey, expiry uint64) PaymentMethod {
	return &payByEphemeralAccount{
		accountID: accountID,
		privkey:   priv,
		expiry:    expiry,
	}
}
