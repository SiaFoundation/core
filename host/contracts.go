package host

import (
	"errors"
	"fmt"
	"math"

	"go.sia.tech/core/net/mux"
	"go.sia.tech/core/net/rhp"
	"go.sia.tech/core/net/rpc"
	"go.sia.tech/core/types"
)

func validContractFormation(fc types.FileContract, currentHeight uint64, settings rhp.HostSettings) error {
	switch {
	case fc.Filesize != 0:
		return errors.New("initial filesize should be 0")
	case fc.RevisionNumber != 0:
		return errors.New("initial revision number should be 0")
	case fc.FileMerkleRoot != types.Hash256{}:
		return errors.New("initial Merkle root should be empty")
	case fc.WindowStart < currentHeight+settings.WindowSize:
		return errors.New("contract ends too soon to safely submit the contract transaction")
	case fc.WindowStart > currentHeight+settings.MaxDuration:
		return errors.New("contract duration is too long")
	case fc.WindowEnd < fc.WindowStart+settings.WindowSize:
		return errors.New("proof window is too small")
	case fc.ValidHostOutput.Address != settings.Address:
		return errors.New("wrong address for host valid output")
	case fc.MissedHostOutput.Address != settings.Address:
		return errors.New("wrong address for host missed output")
	case fc.ValidHostOutput.Value.Cmp(fc.MissedHostOutput.Value) != 0:
		return errors.New("host valid output value does not match host missed output value")
	case fc.ValidRenterOutput.Value.Cmp(fc.MissedRenterOutput.Value) != 0:
		return errors.New("renter valid output value does not match renter missed output value")
	case fc.ValidHostOutput.Value.Cmp(settings.ContractFee) < 0:
		return errors.New("insufficient initial host payout")
	case fc.ValidHostOutput.Value.Sub(settings.ContractFee).Cmp(settings.MaxCollateral) > 0:
		return errors.New("excessive initial collateral")
	}
	return nil
}

func validateStdRevision(current, revision types.FileContract) error {
	switch {
	case revision.RevisionNumber <= current.RevisionNumber:
		return errors.New("revision number must increase")
	case revision.WindowStart != current.WindowStart:
		return errors.New("window start must not change")
	case revision.WindowEnd != current.WindowEnd:
		return errors.New("window end must not change")
	case revision.RenterPublicKey != current.RenterPublicKey:
		return errors.New("renter public key must not change")
	case revision.HostPublicKey != current.HostPublicKey:
		return errors.New("host public key must not change")
	case revision.ValidRenterOutput.Address != current.ValidRenterOutput.Address:
		return errors.New("address of valid renter output must not change")
	case revision.ValidHostOutput.Address != current.ValidHostOutput.Address:
		return errors.New("address of valid host output must not change")
	case revision.MissedRenterOutput.Address != current.MissedRenterOutput.Address:
		return errors.New("address of missed renter output must not change")
	case revision.MissedHostOutput.Address != current.MissedHostOutput.Address:
		return errors.New("address of missed host output must not change")
	}
	return nil
}

// validateProgramRevision verifies that the program revision is valid and only
// the missed host output value is modified by the expected burn amount.
func validateProgramRevision(current, revision types.FileContract, additionalStorage, additionalCollateral types.Currency) error {
	// verify the new revision is valid given the existing revision.
	if err := validateStdRevision(current, revision); err != nil {
		return err
	}

	expectedBurn := additionalStorage.Add(additionalCollateral)
	if expectedBurn.Cmp(current.MissedHostOutput.Value) > 0 {
		return errors.New("expected burn amount is greater than the missed host output value")
	}
	missedHostValue := current.MissedHostOutput.Value.Sub(expectedBurn)

	switch {
	case revision.MissedHostOutput.Value != missedHostValue:
		return errors.New("revision has incorrect collateral transfer")
	case revision.ValidHostOutput.Value != current.ValidHostOutput.Value:
		return errors.New("host valid output value should not change")
	case revision.ValidRenterOutput.Value != current.ValidRenterOutput.Value:
		return errors.New("renter valid output value should not change")
	case revision.MissedRenterOutput.Value != current.MissedRenterOutput.Value:
		return errors.New("renter missed output value should not change")
	}
	return nil
}

func validatePaymentRevision(current, revision types.FileContract, amount types.Currency) error {
	// verify the new revision is valid given the existing revision.
	if err := validateStdRevision(current, revision); err != nil {
		return err
	}

	// validate that all fields are consistent with only transferring the amount
	// from the renter payouts to the host payouts.
	switch {
	case revision.FileMerkleRoot != current.FileMerkleRoot:
		return errors.New("file merkle root must not change")
	case revision.Filesize != current.Filesize:
		return errors.New("file size must not change")
	case revision.MissedHostOutput.Value.Cmp(amount) < 0:
		return errors.New("host missed output value should increase by the amount")
	case revision.ValidHostOutput.Value.Cmp(amount) < 0:
		return errors.New("host valid output value should increase by the amount")
	case revision.MissedHostOutput.Value.Sub(amount) != current.MissedHostOutput.Value:
		return errors.New("host missed output value should increase by the amount")
	case revision.ValidHostOutput.Value.Sub(amount) != current.ValidHostOutput.Value:
		return errors.New("host valid output value should increase by the amount")
	case revision.MissedRenterOutput.Value.Add(amount) != current.MissedRenterOutput.Value:
		return errors.New("renter missed output value should decrease by the amount")
	case revision.ValidRenterOutput.Value.Add(amount) != current.ValidRenterOutput.Value:
		return errors.New("renter valid output value should decrease by the amount")
	}
	return nil
}

// validClearingRevision verifies that the revision clears the current contract
// by clearing the file fields, making the missed and valid payouts equivalent,
// and locking the contract for further revisions.
func validClearingRevision(current, revision types.FileContract) error {
	switch {
	case revision.RevisionNumber != math.MaxUint64:
		return errors.New("revision number must be max value")
	case revision.Filesize != 0:
		return errors.New("file size must be zero")
	case revision.FileMerkleRoot != types.Hash256{}:
		return errors.New("file merkle root must be cleared")
	case revision.ValidHostOutput.Value.Cmp(current.ValidHostOutput.Value) != 0:
		return errors.New("host valid output value must not change")
	case revision.ValidRenterOutput.Value.Cmp(current.ValidRenterOutput.Value) != 0:
		return errors.New("renter valid output value must not change")
	case revision.MissedHostOutput.Value.Cmp(current.ValidHostOutput.Value) != 0:
		return errors.New("host missed output value must equal host valid output value")
	case revision.MissedRenterOutput.Value.Cmp(current.ValidRenterOutput.Value) != 0:
		return errors.New("renter missed output value must equal renter valid output value")
	}
	return nil
}

// validContractRenewal verifies that the renewal revision is valid given the
// old contract. A renewal is valid if the file fields match and the revision
// number is 0.
func validContractRenewal(current, renewal types.FileContract, currentHeight uint64, settings rhp.HostSettings) error {
	switch {
	case renewal.RevisionNumber != 0:
		return errors.New("revision number must be zero")
	case renewal.Filesize != current.Filesize:
		return errors.New("file size must not change")
	case renewal.FileMerkleRoot != current.FileMerkleRoot:
		return errors.New("file merkle root must not change")
	case renewal.WindowStart < currentHeight+settings.WindowSize:
		return errors.New("contract ends too soon to safely submit the contract transaction")
	case renewal.WindowStart > currentHeight+settings.MaxDuration:
		return errors.New("contract duration is too long")
	case renewal.WindowEnd < renewal.WindowStart+settings.WindowSize:
		return errors.New("proof window is too small")
	case renewal.ValidHostOutput.Address != settings.Address:
		return errors.New("wrong address for host valid output")
	case renewal.MissedHostOutput.Address != settings.Address:
		return errors.New("wrong address for host missed output")
	case renewal.ValidHostOutput.Value.Cmp(settings.ContractFee) < 0:
		return errors.New("insufficient initial host payout")
	}
	return nil
}

func (sh *SessionHandler) handleRPCFormContract(stream *mux.Stream) {
	log := sh.log.Scope("RPCFormContract")

	vc, err := sh.cm.TipContext()
	if err != nil {
		log.Errorln("form contract:", "failed to get validation context:", err)
		return
	}

	var formContractReq rhp.RPCFormContractRequest
	if err := rpc.ReadObject(stream, &formContractReq); err != nil {
		log.Warnln("form contract:", "failed to read contract request:", err)
		return
	}

	if len(formContractReq.Transactions) == 0 || len(formContractReq.Transactions[len(formContractReq.Transactions)-1].FileContracts) == 0 {
		log.Warnln("form contract:", "no file contracts in received transaction")
		rpc.WriteResponseErr(stream, errors.New("no file contracts in received transaction"))
		return
	}

	fc := formContractReq.Transactions[len(formContractReq.Transactions)-1].FileContracts[0]
	settings := sh.settings.Settings()

	if err = validContractFormation(fc, vc.Index.Height, settings); err != nil {
		log.Warnln("form contract:", "invalid contract:", err)
		rpc.WriteResponseErr(stream, fmt.Errorf("contract refused: %w", err))
		return
	}

	parents := formContractReq.Transactions[:len(formContractReq.Transactions)-1]
	txn := formContractReq.Transactions[len(formContractReq.Transactions)-1]
	hostCollateral := fc.ValidHostOutput.Value.Sub(settings.ContractFee)
	renterInputs, renterOutputs := len(txn.SiacoinInputs), len(txn.SiacoinOutputs)

	// Fund the formation transaction with the host's collateral.
	toSign, cleanup, err := sh.wallet.FundTransaction(&txn, hostCollateral, nil)
	if err != nil {
		log.Warnln("form contract:", "unable to fund transaction:", err)
		rpc.WriteResponseErr(stream, errors.New("failed to fund contract formation transaction"))
		return
	}
	defer cleanup()

	hostAdditions := &rhp.RPCFormContractAdditions{
		Inputs:  txn.SiacoinInputs[renterInputs:],
		Outputs: txn.SiacoinOutputs[renterOutputs:],
	}

	// write the host transaction additions.
	if err := rpc.WriteResponse(stream, hostAdditions); err != nil {
		log.Warnln("form contract:", "failed to write contract additions:", err)
		return
	}

	// read the renter signatures from the stream.
	var renterSigs rhp.RPCFormContractSignatures
	if err := rpc.ReadResponse(stream, &renterSigs); err != nil {
		log.Warnln("form contract:", "failed to read renter signatures:", err)
		return
	}

	// build a no-op contract revision.
	fcr := types.FileContractRevision{
		Parent: types.FileContractElement{
			StateElement: types.StateElement{
				ID: txn.FileContractID(0),
			},
			FileContract: fc,
		},
		Revision:        fc,
		RenterSignature: renterSigs.RevisionSignature,
	}
	fcr.Revision.RevisionNumber = 1

	// verify the renter's signature
	if !fc.RenterPublicKey.VerifyHash(vc.ContractSigHash(fcr.Revision), renterSigs.RevisionSignature) {
		log.Warnln("form contract:", "renter signature is invalid")
		rpc.WriteResponseErr(stream, errors.New("revision signature is invalid"))
		return
	}

	// sign the transaction
	if err := sh.wallet.SignTransaction(vc, &txn, toSign); err != nil {
		log.Errorln("form contract:", "failed to sign transaction:", err)
		rpc.WriteResponseErr(stream, errors.New("failed to sign formation transaction"))
		return
	}

	hostSigs := &rhp.RPCFormContractSignatures{
		ContractSignatures: make([][]types.InputSignature, len(txn.SiacoinInputs)),
		RevisionSignature:  sh.privkey.SignHash(vc.ContractSigHash(fcr.Revision)),
	}
	for i := range txn.SiacoinInputs {
		hostSigs.ContractSignatures[i] = append(hostSigs.ContractSignatures[i], txn.SiacoinInputs[i].Signatures...)
	}

	// add the renter's signatures to the transaction
	for i := range renterSigs.ContractSignatures {
		txn.SiacoinInputs[i].Signatures = append(txn.SiacoinInputs[i].Signatures, renterSigs.ContractSignatures[i]...)
	}

	txnset := append(parents, txn)

	/*if err := vc.ValidateTransactionSet(txnset); err != nil {
		log.Warnln("form contract:", "failed to validate transaction set:", err)
		rpc.WriteResponse(stream, nil, fmt.Errorf("failed to validate transaction set: %w", err))
		return
	}*/

	contract := Contract{
		FileContractRevision: fcr,
		FormationSet:         txnset,
		FormationHeight:      vc.Index.Height,
		FinalizationHeight:   fcr.Parent.WindowStart,
	}

	if err := sh.contracts.AddContract(contract); err != nil {
		log.Errorln("form contract:", "failed to add contract:", err)
		rpc.WriteResponseErr(stream, errors.New("failed to add contract"))
		return
	}

	if err := sh.tpool.AcceptTransactionSet(contract.FormationSet); err != nil {
		log.Warnln("form contract:", "failed to accept transaction set:", err)
		rpc.WriteResponseErr(stream, fmt.Errorf("failed to accept transaction set: %w", err))
		return
	}

	// write the host signatures.
	if err := rpc.WriteResponse(stream, hostSigs); err != nil {
		log.Warnln("form contract:", "failed to write host signatures:", err)
		return
	}
}

func (sh *SessionHandler) handleRPCRenewContract(stream *mux.Stream) {

}
