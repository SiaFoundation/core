package host

import (
	"errors"
	"fmt"
	"math"
	"time"

	"go.sia.tech/core/consensus"
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

// validContractRenewal verifies that the renewed contract is valid given the
// old contract. A renewal is valid if the file fields match and the revision
// number is 0.
func validContractRenewal(existing, renewal types.FileContract, currentHeight uint64, settings rhp.HostSettings) error {
	switch {
	case renewal.HostPublicKey != existing.HostPublicKey:
		return errors.New("host public key must not change")
	case renewal.RenterPublicKey != existing.RenterPublicKey:
		return errors.New("renter public key must not change")
	case renewal.RevisionNumber != 0:
		return errors.New("revision number must be zero")
	case renewal.Filesize != existing.Filesize:
		return errors.New("file size must not change")
	case renewal.FileMerkleRoot != existing.FileMerkleRoot:
		return errors.New("file merkle root must not change")
	case renewal.WindowEnd < existing.WindowEnd:
		return errors.New("renewal window end must be after existing window end")
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
func validateProgramRevision(vc consensus.ValidationContext, current, revision types.FileContractRevision, additionalStorage, additionalCollateral types.Currency) error {
	// verify the host and renter signatures on the revision using the current contract's public keys.
	sigHash := vc.ContractSigHash(revision.Revision)
	if !current.Parent.HostPublicKey.VerifyHash(sigHash, revision.HostSignature) {
		return errors.New("host signature is invalid")
	} else if !current.Parent.RenterPublicKey.VerifyHash(sigHash, revision.RenterSignature) {
		return errors.New("renter signature is invalid")
	}

	// verify the new revision is valid given the existing revision.
	if err := validateStdRevision(current.Revision, revision.Revision); err != nil {
		return err
	}

	expectedBurn := additionalStorage.Add(additionalCollateral)
	if expectedBurn.Cmp(current.Revision.MissedHostOutput.Value) > 0 {
		return errors.New("expected burn amount is greater than the missed host output value")
	}
	missedHostValue := current.Revision.MissedHostOutput.Value.Sub(expectedBurn)

	switch {
	case revision.Revision.MissedHostOutput.Value != missedHostValue:
		return errors.New("revision has incorrect collateral transfer")
	case revision.Revision.ValidHostOutput.Value != current.Revision.ValidHostOutput.Value:
		return errors.New("host valid output value should not change")
	case revision.Revision.ValidRenterOutput.Value != current.Revision.ValidRenterOutput.Value:
		return errors.New("renter valid output value should not change")
	case revision.Revision.MissedRenterOutput.Value != current.Revision.MissedRenterOutput.Value:
		return errors.New("renter missed output value should not change")
	}
	return nil
}

func validatePaymentRevision(vc consensus.ValidationContext, current, revision types.FileContractRevision, amount types.Currency) error {
	// verify the host and renter signatures on the revision using the current contract's public keys.
	sigHash := vc.ContractSigHash(revision.Revision)
	if !current.Parent.HostPublicKey.VerifyHash(sigHash, revision.HostSignature) {
		return errors.New("host signature is invalid")
	} else if !current.Parent.RenterPublicKey.VerifyHash(sigHash, revision.RenterSignature) {
		return errors.New("renter signature is invalid")
	}

	// verify the new revision is valid given the existing revision.
	if err := validateStdRevision(current.Revision, revision.Revision); err != nil {
		return err
	}

	// validate that all fields are consistent with only transferring the amount
	// from the renter payouts to the host payouts.
	switch {
	case revision.Revision.FileMerkleRoot != current.Revision.FileMerkleRoot:
		return errors.New("file merkle root must not change")
	case revision.Revision.Filesize != current.Revision.Filesize:
		return errors.New("file size must not change")
	case revision.Revision.MissedHostOutput.Value.Cmp(amount) < 0:
		return errors.New("host missed output value should increase by the amount")
	case revision.Revision.ValidHostOutput.Value.Cmp(amount) < 0:
		return errors.New("host valid output value should increase by the amount")
	case revision.Revision.MissedHostOutput.Value.Sub(amount) != current.Revision.MissedHostOutput.Value:
		return errors.New("host missed output value should increase by the amount")
	case revision.Revision.ValidHostOutput.Value.Sub(amount) != current.Revision.ValidHostOutput.Value:
		return errors.New("host valid output value should increase by the amount")
	case revision.Revision.MissedRenterOutput.Value.Add(amount) != current.Revision.MissedRenterOutput.Value:
		return errors.New("renter missed output value should decrease by the amount")
	case revision.Revision.ValidRenterOutput.Value.Add(amount) != current.Revision.ValidRenterOutput.Value:
		return errors.New("renter valid output value should decrease by the amount")
	}
	return nil
}

// validClearingRevision verifies that the revision clears the current contract
// by clearing the file fields, making the missed and valid payouts equivalent,
// and locking the contract for further revisions.
func validClearingRevision(vc consensus.ValidationContext, current, clearing types.FileContractRevision) error {
	// verify the host and renter signatures using the existing contract's public keys.
	sigHash := vc.ContractSigHash(clearing.Revision)
	if !current.Parent.HostPublicKey.VerifyHash(sigHash, clearing.HostSignature) {
		return errors.New("host signature is invalid")
	} else if !current.Parent.RenterPublicKey.VerifyHash(sigHash, clearing.RenterSignature) {
		return errors.New("renter signature is invalid")
	}

	// verify the new revision is valid given the existing revision.
	if err := validateStdRevision(current.Revision, clearing.Revision); err != nil {
		return err
	}

	switch {
	case clearing.Revision.RevisionNumber != math.MaxUint64:
		return errors.New("revision number must be max value")
	case clearing.Revision.Filesize != 0:
		return errors.New("file size must be zero")
	case clearing.Revision.FileMerkleRoot != types.Hash256{}:
		return errors.New("file merkle root must be cleared")
	case clearing.Revision.ValidHostOutput.Value.Cmp(current.Revision.ValidHostOutput.Value) != 0:
		return errors.New("host valid output value must not change")
	case clearing.Revision.ValidRenterOutput.Value.Cmp(current.Revision.ValidRenterOutput.Value) != 0:
		return errors.New("renter valid output value must not change")
	case clearing.Revision.MissedHostOutput.Value.Cmp(current.Revision.ValidHostOutput.Value) != 0:
		return errors.New("host missed output value must equal host valid output value")
	case clearing.Revision.MissedRenterOutput.Value.Cmp(current.Revision.ValidRenterOutput.Value) != 0:
		return errors.New("renter missed output value must equal renter valid output value")
	}
	return nil
}

func (sh *SessionHandler) handleRPCFormContract(stream *mux.Stream) {
	log := sh.log.Scope("RPCFormContract")

	var formContractReq rhp.RPCContractRequest
	if err := rpc.ReadObject(stream, &formContractReq); err != nil {
		log.Warnln("failed to read contract request:", err)
		return
	}

	if len(formContractReq.Transactions) == 0 || len(formContractReq.Transactions[len(formContractReq.Transactions)-1].FileContracts) == 0 {
		log.Warnln("no file contracts in received transaction")
		rpc.WriteResponseErr(stream, errors.New("no file contracts in received transaction"))
		return
	}

	fc := formContractReq.Transactions[len(formContractReq.Transactions)-1].FileContracts[0]
	settings := sh.settings.Settings()

	if !settings.AcceptingContracts {
		rpc.WriteResponseErr(stream, errors.New("host is not accepting contracts"))
		return
	}

	if err := validContractFormation(fc, sh.cm.Tip().Height, settings); err != nil {
		log.Warnln("invalid contract:", err)
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
		log.Warnln("unable to fund transaction:", err)
		rpc.WriteResponseErr(stream, errors.New("failed to fund contract formation transaction"))
		return
	}
	defer cleanup()

	hostAdditions := &rhp.RPCContractAdditions{
		Inputs:  txn.SiacoinInputs[renterInputs:],
		Outputs: txn.SiacoinOutputs[renterOutputs:],
	}

	// write the host transaction additions.
	if err := rpc.WriteResponse(stream, hostAdditions); err != nil {
		log.Warnln("failed to write contract additions:", err)
		return
	}

	// read the renter signatures from the stream.
	var renterSigs rhp.RPCContractSignatures
	if err := rpc.ReadResponse(stream, &renterSigs); err != nil {
		log.Warnln("failed to read renter signatures:", err)
		return
	}

	vc, err := sh.cm.TipContext()
	if err != nil {
		log.Errorln("failed to get validation context:", err)
		return
	}

	fcr := types.FileContractRevision{
		Parent: types.FileContractElement{
			StateElement: types.StateElement{
				ID: txn.FileContractID(0),
			},
			FileContract: fc,
		},
		Revision:        fc,
		HostSignature:   sh.privkey.SignHash(vc.ContractSigHash(fc)),
		RenterSignature: renterSigs.RevisionSignature,
	}

	// verify the renter's signature
	if !fc.RenterPublicKey.VerifyHash(vc.ContractSigHash(fcr.Revision), fcr.RenterSignature) {
		log.Warnln("renter signature is invalid")
		rpc.WriteResponseErr(stream, errors.New("revision signature is invalid"))
		return
	}

	// sign the transaction
	if err := sh.wallet.SignTransaction(vc, &txn, toSign); err != nil {
		log.Errorln("failed to sign transaction:", err)
		rpc.WriteResponseErr(stream, errors.New("failed to sign formation transaction"))
		return
	}

	hostSigs := &rhp.RPCContractSignatures{
		SiacoinInputSignatures: make([][]types.InputSignature, len(txn.SiacoinInputs)),
		RevisionSignature:      fcr.HostSignature,
	}
	for i := range txn.SiacoinInputs {
		hostSigs.SiacoinInputSignatures[i] = append(hostSigs.SiacoinInputSignatures[i], txn.SiacoinInputs[i].Signatures...)
	}

	// add the renter's signatures to the transaction
	for i := range renterSigs.SiacoinInputSignatures {
		txn.SiacoinInputs[i].Signatures = append(txn.SiacoinInputs[i].Signatures, renterSigs.SiacoinInputSignatures[i]...)
	}

	contract := Contract{
		FileContractRevision: fcr,
		FormationSet:         append(parents, txn),
		FormationHeight:      vc.Index.Height,
		FinalizationHeight:   fcr.Parent.WindowStart,
	}

	if err := vc.ValidateTransactionSet(contract.FormationSet); err != nil {
		log.Warnln("failed to validate transaction set:", err)
		rpc.WriteResponseErr(stream, fmt.Errorf("failed to validate transaction set: %w", err))
		return
	}

	if err := sh.contracts.add(contract); err != nil {
		log.Errorln("failed to add contract:", err)
		rpc.WriteResponseErr(stream, errors.New("failed to add contract"))
		return
	}

	if err := sh.tpool.AcceptTransactionSet(contract.FormationSet); err != nil {
		log.Warnln("failed to accept transaction set:", err)
		rpc.WriteResponseErr(stream, fmt.Errorf("failed to accept transaction set: %w", err))
		return
	}

	// write the host signatures.
	if err := rpc.WriteResponse(stream, hostSigs); err != nil {
		log.Warnln("failed to write host signatures:", err)
		return
	}
}

func (sh *SessionHandler) handleRPCRenewContract(stream *mux.Stream) {
	log := sh.log.Scope("RPCRenewContract")

	var settingsID rhp.SettingsID
	if err := rpc.ReadObject(stream, &settingsID); err != nil {
		log.Warnln("failed to read contract request:", err)
		return
	}

	settings, err := sh.validSettings(settingsID)
	if err != nil {
		log.Warnln("failed to get settings:", err)
		rpc.WriteResponseErr(stream, fmt.Errorf("failed to get settings: %w", err))
		return
	}

	var renewContractReq rhp.RPCContractRequest
	if err := rpc.ReadRequest(stream, &renewContractReq); err != nil {
		log.Warnln("failed to read contract request:", err)
		rpc.WriteResponseErr(stream, fmt.Errorf("failed to read contract request: %w", err))
		return
	}

	if len(renewContractReq.Transactions) == 0 || len(renewContractReq.Transactions[len(renewContractReq.Transactions)-1].FileContracts) == 0 || len(renewContractReq.Transactions[len(renewContractReq.Transactions)-1].FileContractRevisions) == 0 {
		log.Warnln("no file contract or revision in received transaction")
		rpc.WriteResponseErr(stream, errors.New("no file contract or revision in received transaction"))
		return
	}

	parents := renewContractReq.Transactions[:len(renewContractReq.Transactions)-1]
	txn := renewContractReq.Transactions[len(renewContractReq.Transactions)-1]
	renewal := renewContractReq.Transactions[len(renewContractReq.Transactions)-1].FileContracts[0]
	contractID := renewContractReq.Transactions[len(renewContractReq.Transactions)-1].FileContractRevisions[0].Parent.ID

	existing, err := sh.contracts.lock(contractID, time.Second*10)
	if err != nil {
		log.Warnln("failed to lock contract:", err)
		rpc.WriteResponseErr(stream, fmt.Errorf("failed to lock contract %v: %w", contractID, err))
		return
	}
	defer sh.contracts.unlock(contractID)

	vc, err := sh.cm.TipContext()
	if err != nil {
		log.Errorln("failed to get validation context:", err)
		rpc.WriteResponseErr(stream, errors.New("failed to get validation context"))
		return
	}

	// validate the fields of the contract renewal, signatures are not validated
	// yet since we don't have them.
	if err := validContractRenewal(existing.Revision, renewal, vc.Index.Height, settings); err != nil {
		log.Warnln("failed to validate contract renewal:", err)
		rpc.WriteResponseErr(stream, fmt.Errorf("failed to validate contract renewal: %w", err))
		return
	}

	// calculate the "base" storage cost to the renter and risked collateral for
	// the host for the data already in the contract. If the contract height did
	// not increase, base costs are zero since the storage is already payed for.
	var baseStorageCost types.Currency
	if renewal.WindowEnd > existing.Revision.WindowEnd {
		extension := renewal.WindowEnd - existing.Revision.WindowEnd
		baseStorageCost = settings.StoragePrice.Mul64(renewal.Filesize).Mul64(extension)
	}

	// calculate the amount the host needs to fund as the difference between the
	// valid proof outputs and the base storage revenue plus contract fee. The
	// renter is responsible for funding the remainder.
	hostCollateral := renewal.ValidHostOutput.Value.Sub(settings.ContractFee).Sub(baseStorageCost)

	// clear the existing contract
	clearing := existing.Revision
	clearing.RevisionNumber = math.MaxUint64
	clearing.Filesize = 0
	clearing.FileMerkleRoot = types.Hash256{}
	clearing.MissedHostOutput.Value = clearing.ValidHostOutput.Value
	clearing.MissedRenterOutput.Value = clearing.ValidRenterOutput.Value

	renterInputs, renterOutputs := len(txn.SiacoinInputs), len(txn.SiacoinOutputs)
	toSign, cleanup, err := sh.wallet.FundTransaction(&txn, hostCollateral, nil)
	if err != nil {
		log.Warnln("failed to fund %v collateral in renewal transaction for %v: %w", hostCollateral, contractID, err)
		rpc.WriteResponseErr(stream, errors.New("failed to fund renewal transaction"))
		return
	}
	defer cleanup()

	hostAdditions := &rhp.RPCContractAdditions{
		Inputs:  txn.SiacoinInputs[renterInputs:],
		Outputs: txn.SiacoinOutputs[renterOutputs:],
	}

	// write the host transaction additions.
	if err := rpc.WriteResponse(stream, hostAdditions); err != nil {
		log.Warnln("failed to write contract additions:", err)
		return
	}

	// read the renter signatures from the stream.
	var renterSigs rhp.RPCRenewContractSignatures
	if err := rpc.ReadResponse(stream, &renterSigs); err != nil {
		log.Warnln("failed to read renter signatures:", err)
		return
	}

	clearingRevision := existing.FileContractRevision
	clearingRevision.Revision = clearing
	clearingRevision.RenterSignature = renterSigs.ClearingRevisionSignature
	clearingRevision.HostSignature = sh.privkey.SignHash(vc.ContractSigHash(clearing))

	// validate the clearing revision, will also validate the host and renter
	// signatures.
	if err := validClearingRevision(vc, existing.FileContractRevision, clearingRevision); err != nil {
		log.Warnln("failed to validate clearing revision:", err)
		rpc.WriteResponseErr(stream, fmt.Errorf("failed to validate clearing revision: %w", err))
		return
	}

	renewalSigHash := vc.ContractSigHash(renewal)
	renewalRevision := types.FileContractRevision{
		Parent: types.FileContractElement{
			StateElement: types.StateElement{
				ID: txn.FileContractID(0),
			},
			FileContract: renewal,
		},
		Revision:        renewal,
		HostSignature:   sh.privkey.SignHash(renewalSigHash),
		RenterSignature: renterSigs.RenewalSignature,
	}

	// verify the renter's renewal signature and sign the transaction
	if !renewal.RenterPublicKey.VerifyHash(renewalSigHash, renewalRevision.RenterSignature) {
		log.Warnln("renter signature is invalid")
		rpc.WriteResponseErr(stream, errors.New("revision signature is invalid"))
		return
	} else if err := sh.wallet.SignTransaction(vc, &txn, toSign); err != nil {
		log.Errorln("failed to sign transaction:", err)
		rpc.WriteResponseErr(stream, errors.New("failed to sign formation transaction"))
		return
	}

	// send the renter the host signatures, at this point no renter signatures
	// have been added to the renewal transaction.
	hostSigs := &rhp.RPCRenewContractSignatures{
		SiacoinInputSignatures:    make([][]types.InputSignature, len(txn.SiacoinInputs)),
		RenewalSignature:          renewalRevision.HostSignature,
		ClearingRevisionSignature: clearingRevision.HostSignature,
	}
	for i := range txn.SiacoinInputs {
		hostSigs.SiacoinInputSignatures[i] = append(hostSigs.SiacoinInputSignatures[i], txn.SiacoinInputs[i].Signatures...)
	}

	// add the renter's signatures to the transaction
	for i := range renterSigs.SiacoinInputSignatures {
		txn.SiacoinInputs[i].Signatures = append(txn.SiacoinInputs[i].Signatures, renterSigs.SiacoinInputSignatures[i]...)
	}

	contract := Contract{
		FileContractRevision: renewalRevision,
		FormationSet:         append(parents, txn),
		FormationHeight:      vc.Index.Height,
		FinalizationHeight:   renewalRevision.Parent.WindowStart,
	}

	if err := vc.ValidateTransactionSet(contract.FormationSet); err != nil {
		log.Warnln("failed to validate transaction set:", err)
		rpc.WriteResponseErr(stream, fmt.Errorf("failed to validate transaction set: %w", err))
		return
	}

	// update the renewed contract with the clearing revision and add the new
	// contract.
	sh.contracts.revise(clearingRevision)
	if err := sh.contracts.add(contract); err != nil {
		log.Errorln("failed to add contract:", err)
		rpc.WriteResponseErr(stream, errors.New("failed to add contract"))
		return
	}

	// broadcast the renewal transaction
	if err := sh.tpool.AcceptTransactionSet(contract.FormationSet); err != nil {
		log.Warnln("failed to accept transaction set:", err)
		rpc.WriteResponseErr(stream, fmt.Errorf("failed to accept transaction set: %w", err))
		return
	}

	// write the host signatures.
	if err := rpc.WriteResponse(stream, hostSigs); err != nil {
		log.Warnln("failed to write host signatures:", err)
		return
	}
}
