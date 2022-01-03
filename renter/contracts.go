package renter

import (
	"errors"
	"fmt"
	"math"

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

	req := &rhp.RPCContractRequest{
		Transactions: []types.Transaction{txn},
	}

	stream, err := s.session.DialStream()
	if err != nil {
		return Contract{}, nil, fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	if err := rpc.WriteRequest(stream, rhp.RPCFormContractID, req); err != nil {
		return Contract{}, nil, fmt.Errorf("failed to write form contract request: %w", err)
	}

	var resp rhp.RPCContractAdditions
	if err := rpc.ReadResponse(stream, &resp); err != nil {
		return Contract{}, nil, fmt.Errorf("failed to read host additions: %w", err)
	}

	txn.SiacoinInputs = append(txn.SiacoinInputs, resp.Inputs...)
	txn.SiacoinOutputs = append(txn.SiacoinOutputs, resp.Outputs...)

	if err := s.wallet.SignTransaction(vc, &txn, toSign); err != nil {
		return Contract{}, nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	sigHash := vc.ContractSigHash(fc)
	renterSigs := rhp.RPCContractSignatures{
		SiacoinInputSignatures: make([][]types.InputSignature, len(txn.SiacoinInputs)),
		RevisionSignature:      renterKey.SignHash(sigHash),
	}
	for i := range txn.SiacoinInputs {
		renterSigs.SiacoinInputSignatures[i] = append(renterSigs.SiacoinInputSignatures[i], txn.SiacoinInputs[i].Signatures...)
	}

	if err := rpc.WriteResponse(stream, &renterSigs); err != nil {
		return Contract{}, nil, fmt.Errorf("failed to write renter signatures: %w", err)
	}

	var hostSigs rhp.RPCContractSignatures
	if err := rpc.ReadResponse(stream, &hostSigs); err != nil {
		return Contract{}, nil, fmt.Errorf("failed to read host signatures: %w", err)
	}

	// verify the host's signature
	if !fc.HostPublicKey.VerifyHash(sigHash, hostSigs.RevisionSignature) {
		return Contract{}, nil, errors.New("host revision signature is invalid")
	}

	for i := range hostSigs.SiacoinInputSignatures {
		txn.SiacoinInputs[i].Signatures = append(txn.SiacoinInputs[i].Signatures, hostSigs.SiacoinInputSignatures[i]...)
	}
	return Contract{
		ID:              txn.FileContractID(0),
		Revision:        fc,
		HostSignature:   hostSigs.RevisionSignature,
		RenterSignature: renterSigs.RevisionSignature,
	}, append(resp.Parents, txn), nil
}

// RenewContract clears an existing contract with the host and using the
// specified funds and duration.
func (s *Session) RenewContract(renterKey types.PrivateKey, contract *types.FileContractRevision, additionalCollateral, additionalRenterFunds types.Currency, endHeight uint64) (Contract, []types.Transaction, error) {
	settingsID, settings, err := s.currentSettings()
	if err != nil {
		return Contract{}, nil, fmt.Errorf("failed to use settings: %w", err)
	}

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

	renewal := types.FileContract{
		Filesize:        contract.Revision.Filesize,
		FileMerkleRoot:  contract.Revision.FileMerkleRoot,
		WindowStart:     startHeight,
		WindowEnd:       endHeight + settings.WindowSize,
		RenterPublicKey: contract.Revision.RenterPublicKey,
		HostPublicKey:   contract.Revision.HostPublicKey,
		ValidHostOutput: types.SiacoinOutput{
			Address: settings.Address,
		},
		MissedHostOutput: types.SiacoinOutput{
			Address: settings.Address,
			Value:   settings.ContractFee.Add(additionalCollateral),
		},
		ValidRenterOutput: types.SiacoinOutput{
			Address: outputAddr,
			Value:   additionalRenterFunds,
		},
		MissedRenterOutput: types.SiacoinOutput{
			Address: outputAddr,
			Value:   additionalRenterFunds,
		},
	}

	// calculate the "base" storage cost to the renter and risked collateral for
	// the host for the data already in the contract. If the contract height did
	// not increase, base costs are zero.
	var baseStorageCost, baseCollateral types.Currency
	if renewal.WindowEnd > contract.Revision.WindowEnd {
		extension := renewal.WindowEnd - contract.Revision.WindowEnd
		baseStorageCost = settings.StoragePrice.Mul64(renewal.Filesize).Mul64(extension)
		baseCollateral = settings.Collateral.Mul64(renewal.Filesize).Mul64(extension)
	}

	// calculate the total collateral the host is expected to add to the
	// contract.
	totalCollateral := baseCollateral.Add(additionalCollateral)
	if totalCollateral.Cmp(settings.MaxCollateral) > 0 {
		return Contract{}, nil, errors.New("collateral too large")
	}

	// add the contract fee, base storage revenue, and total collateral to the
	// host's valid output. In the event of failure this amount will be burned
	renewal.ValidHostOutput.Value = settings.ContractFee.Add(baseStorageCost).Add(totalCollateral)

	// clear the existing contract.
	clearing := contract.Revision
	clearing.RevisionNumber = math.MaxUint64
	clearing.Filesize = 0
	clearing.FileMerkleRoot = types.Hash256{}
	clearing.MissedHostOutput.Value = clearing.ValidHostOutput.Value
	clearing.MissedRenterOutput.Value = clearing.ValidRenterOutput.Value

	// create the transaction with the clearing transaction and new file
	// contract formation.
	txn := types.Transaction{
		FileContractRevisions: []types.FileContractRevision{{
			Parent:   contract.Parent,
			Revision: clearing,
		}},
		FileContracts: []types.FileContract{renewal},
	}
	// TODO: better fee calculation.
	txn.MinerFee = settings.TxnFeeMaxRecommended.Mul64(vc.TransactionWeight(txn))
	// fund the formation transaction with the renter funds, contract fee, base
	// storage cost, siafund tax, and miner fee.
	renterFundAmount := additionalRenterFunds.Add(settings.ContractFee).Add(baseStorageCost).Add(vc.FileContractTax(renewal)).Add(txn.MinerFee)

	toSign, cleanup, err := s.wallet.FundTransaction(&txn, renterFundAmount, nil)
	if err != nil {
		return Contract{}, nil, fmt.Errorf("failed to fund transaction: %w", err)
	}
	defer cleanup()

	req := &rhp.RPCContractRequest{
		Transactions: []types.Transaction{txn},
	}

	stream, err := s.session.DialStream()
	if err != nil {
		return Contract{}, nil, fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	if err := rpc.WriteRequest(stream, rhp.RPCRenewContractID, &settingsID); err != nil {
		return Contract{}, nil, fmt.Errorf("failed to write RPC id: %w", err)
	} else if err := rpc.WriteObject(stream, req); err != nil {
		return Contract{}, nil, fmt.Errorf("failed to write request: %w", err)
	}

	var resp rhp.RPCContractAdditions
	if err := rpc.ReadResponse(stream, &resp); err != nil {
		return Contract{}, nil, fmt.Errorf("failed to read host additions: %w", err)
	}

	txn.SiacoinInputs = append(txn.SiacoinInputs, resp.Inputs...)
	txn.SiacoinOutputs = append(txn.SiacoinOutputs, resp.Outputs...)

	if err := s.wallet.SignTransaction(vc, &txn, toSign); err != nil {
		return Contract{}, nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	renewalHash := vc.ContractSigHash(renewal)
	clearingHash := vc.ContractSigHash(clearing)
	renterSigs := rhp.RPCRenewContractSignatures{
		ClearingRevisionSignature: renterKey.SignHash(clearingHash),
		RenewalSignature:          renterKey.SignHash(renewalHash),
	}
	for i := range txn.SiacoinInputs {
		renterSigs.SiacoinInputSignatures[i] = append(renterSigs.SiacoinInputSignatures[i], txn.SiacoinInputs[i].Signatures...)
	}

	if err := rpc.WriteResponse(stream, &renterSigs); err != nil {
		return Contract{}, nil, fmt.Errorf("failed to write renter signatures: %w", err)
	}

	var hostSigs rhp.RPCRenewContractSignatures
	if err := rpc.ReadResponse(stream, &hostSigs); err != nil {
		return Contract{}, nil, fmt.Errorf("failed to read host signatures: %w", err)
	}

	// verify the host's clearing revision and renewal revision signature
	if !clearing.HostPublicKey.VerifyHash(clearingHash, hostSigs.ClearingRevisionSignature) {
		return Contract{}, nil, errors.New("host's revision signature is invalid")
	} else if !clearing.HostPublicKey.VerifyHash(renewalHash, hostSigs.RenewalSignature) {
		return Contract{}, nil, errors.New("host's renewal signature is invalid")
	}

	for i := range hostSigs.SiacoinInputSignatures {
		txn.SiacoinInputs[i].Signatures = append(txn.SiacoinInputs[i].Signatures, hostSigs.SiacoinInputSignatures[i]...)
	}
	return Contract{
		ID:              txn.FileContractID(0),
		Revision:        renewal,
		HostSignature:   hostSigs.ClearingRevisionSignature,
		RenterSignature: renterSigs.ClearingRevisionSignature,
	}, append(resp.Parents, txn), nil
}
