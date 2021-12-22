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
		contract        *Contract
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

	req.Signature = p.privkey.SignHash(types.HashObject(&req.Message))
	if err := rpc.WriteRequest(stream, rhp.PayByEphemeralAccount, req); err != nil {
		return fmt.Errorf("failed to write ephemeral account payment request specifier: %w", err)
	}

	return nil
}

// Pay pays the host the given amount from the renter's contract.
func (p *payByContract) Pay(stream *mux.Stream, amount types.Currency) error {
	// verify the contract has enough funds to pay the amount.
	switch {
	case p.contract.Revision.ValidRenterOutput.Value.Cmp(amount) < 0:
		return errors.New("insufficient renter funds")
	case p.contract.Revision.MissedRenterOutput.Value.Cmp(amount) < 0:
		return errors.New("insufficient renter funds")
	}

	vc, err := p.cm.TipContext()
	if err != nil {
		return fmt.Errorf("failed to get current validation context: %w", err)
	}

	// update the revision to pay for the usage.
	revision := p.contract.Revision
	revision.RevisionNumber++
	revision.ValidRenterOutput.Value = revision.ValidRenterOutput.Value.Sub(amount)
	revision.MissedRenterOutput.Value = revision.MissedRenterOutput.Value.Sub(amount)
	revision.ValidHostOutput.Value = revision.ValidHostOutput.Value.Add(amount)
	revision.MissedHostOutput.Value = revision.MissedHostOutput.Value.Add(amount)
	revisionHash := vc.ContractSigHash(revision)

	req := &rhp.PayByContractRequest{
		RefundAccount: p.refundAccountID,

		ContractID:        p.contract.ID,
		NewRevisionNumber: revision.RevisionNumber,
		NewOutputs: rhp.ContractOutputs{
			MissedHostValue:   revision.MissedHostOutput.Value,
			MissedRenterValue: revision.MissedRenterOutput.Value,
			ValidHostValue:    revision.ValidHostOutput.Value,
			ValidRenterValue:  revision.ValidRenterOutput.Value,
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
	p.contract.Revision = revision
	p.contract.RenterSignature = req.Signature
	p.contract.HostSignature = resp.Signature
	return nil
}

// PayByContract creates a new contract payment method.
func (s *Session) PayByContract(contract *Contract, priv types.PrivateKey, refundAccountID types.PublicKey) PaymentMethod {
	return &payByContract{
		contract:        contract,
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
