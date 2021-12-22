package renter

import (
	"errors"
	"fmt"

	"go.sia.tech/core/net/rhp"
	"go.sia.tech/core/net/rpc"
	"go.sia.tech/core/types"
)

// A Contract groups the ID, latest revision, and signatures of a contract.
type Contract struct {
	ID              types.ElementID
	Revision        types.FileContract
	HostSignature   types.Signature
	RenterSignature types.Signature
}

// FormContract negotiates a new contract with the host using the specified
// funds and duration.
func (s *Session) FormContract(renterKey types.PrivateKey, hostFunds, renterFunds types.Currency, endHeight uint64) (Contract, []types.Transaction, error) {
	vc, err := s.cm.TipContext()
	if err != nil {
		return Contract{}, nil, fmt.Errorf("failed to get validation context: %w", err)
	}
	startHeight := vc.Index.Height
	if endHeight < startHeight {
		return Contract{}, nil, errors.New("end height must be greater than start height")
	}

	outputAddr := s.wallet.Address()
	if err != nil {
		return Contract{}, nil, fmt.Errorf("failed to generate address: %w", err)
	}

	renterPub := renterKey.PublicKey()

	// retrieve the host's current settings. The host is not expecting
	// payment for forming contracts.
	settings, err := s.ScanSettings()
	if err != nil {
		return Contract{}, nil, fmt.Errorf("failed to get settings: %w", err)
	}

	// if the host's collateral is more than their max collateral, the contract
	// will be rejected.
	if settings.MaxCollateral.Cmp(hostFunds) < 0 {
		return Contract{}, nil, errors.New("host payout is greater than max collateral")
	}

	// subtract the contract formation fee from the renter's funds and add it to
	// the host's funds.
	renterPayout := renterFunds.Sub(settings.ContractFee)
	hostPayout := hostFunds.Add(settings.ContractFee)

	// build the contract.
	fc := types.FileContract{
		ValidRenterOutput: types.SiacoinOutput{
			Value:   renterPayout,
			Address: outputAddr,
		},
		MissedRenterOutput: types.SiacoinOutput{
			Value:   renterPayout,
			Address: outputAddr,
		},
		ValidHostOutput: types.SiacoinOutput{
			Value:   hostPayout,
			Address: settings.Address,
		},
		MissedHostOutput: types.SiacoinOutput{
			Value:   hostPayout,
			Address: settings.Address,
		},
		WindowStart:     endHeight,
		WindowEnd:       endHeight + settings.WindowSize,
		RenterPublicKey: renterPub,
		HostPublicKey:   s.hostKey,
	}

	txn := types.Transaction{
		FileContracts: []types.FileContract{fc},
	}
	// TODO: better fee calculation.
	txn.MinerFee = settings.TxnFeeMaxRecommended.Mul64(vc.TransactionWeight(txn))
	// fund the formation transaction with the renter funds + siafund tax +
	// miner fee.
	renterFundAmount := renterFunds.Add(vc.FileContractTax(fc)).Add(txn.MinerFee)

	toSign, cleanup, err := s.wallet.FundTransaction(&txn, renterFundAmount, nil)
	if err != nil {
		return Contract{}, nil, fmt.Errorf("failed to fund transaction: %w", err)
	}
	defer cleanup()

	req := &rhp.RPCFormContractRequest{
		Transactions: []types.Transaction{txn},
		RenterKey:    fc.RenterPublicKey,
	}

	stream, err := s.session.DialStream()
	if err != nil {
		return Contract{}, nil, fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	if err := rpc.WriteRequest(stream, rhp.RPCFormContractID, req); err != nil {
		return Contract{}, nil, fmt.Errorf("failed to write form contract request: %w", err)
	}

	var resp rhp.RPCFormContractAdditions
	if err := rpc.ReadResponse(stream, &resp); err != nil {
		return Contract{}, nil, fmt.Errorf("failed to read host additions: %w", err)
	}

	txn.SiacoinInputs = append(txn.SiacoinInputs, resp.Inputs...)
	txn.SiacoinOutputs = append(txn.SiacoinOutputs, resp.Outputs...)

	if err := s.wallet.SignTransaction(vc, &txn, toSign); err != nil {
		return Contract{}, nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	sigHash := vc.ContractSigHash(fc)
	renterSigs := rhp.RPCFormContractSignatures{
		ContractSignatures: make([][]types.InputSignature, len(txn.SiacoinInputs)),
		RevisionSignature:  renterKey.SignHash(sigHash),
	}
	for i := range txn.SiacoinInputs {
		renterSigs.ContractSignatures[i] = append(renterSigs.ContractSignatures[i], txn.SiacoinInputs[i].Signatures...)
	}

	if err := rpc.WriteResponse(stream, &renterSigs); err != nil {
		return Contract{}, nil, fmt.Errorf("failed to write renter signatures: %w", err)
	}

	var hostSigs rhp.RPCFormContractSignatures
	if err := rpc.ReadResponse(stream, &hostSigs); err != nil {
		return Contract{}, nil, fmt.Errorf("failed to read host signatures: %w", err)
	}

	// verify the host's signature
	if !fc.HostPublicKey.VerifyHash(sigHash, hostSigs.RevisionSignature) {
		return Contract{}, nil, errors.New("host revision signature is invalid")
	}

	for i := range hostSigs.ContractSignatures {
		txn.SiacoinInputs[i].Signatures = append(txn.SiacoinInputs[i].Signatures, hostSigs.ContractSignatures[i]...)
	}
	return Contract{
		ID:              txn.FileContractID(0),
		Revision:        fc,
		HostSignature:   hostSigs.RevisionSignature,
		RenterSignature: renterSigs.RevisionSignature,
	}, append(resp.Parents, txn), nil
}
