package host

import (
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"go.sia.tech/core/net/mux"
	"go.sia.tech/core/net/rhp"
	"go.sia.tech/core/net/rpc"
)

type (
	// A budgetedStream limits reads and writes to a ReadWriter using an RPC
	// budget. Writes subtract the download bandwidth price multiplied by the
	// number of bytes written and reads subtract the upload bandwidth price
	// multiplied by the number of bytes read.
	budgetedStream struct {
		rw       io.ReadWriter
		budget   *rpcBudget
		settings rhp.HostSettings
	}
)

func (l *budgetedStream) Read(buf []byte) (n int, err error) {
	n, err = l.rw.Read(buf)
	if err != nil {
		return
	}
	cost := l.settings.UploadBandwidthPrice.Mul64(uint64(n))
	if err = l.budget.Spend(cost); err != nil {
		return
	}
	return
}

func (l *budgetedStream) Write(buf []byte) (n int, err error) {
	n, err = l.rw.Write(buf)
	if err != nil {
		return
	}
	cost := l.settings.DownloadBandwidthPrice.Mul64(uint64(n))
	if err = l.budget.Spend(cost); err != nil {
		return
	}
	return
}

func newBudgetedStream(rw io.ReadWriter, budget *rpcBudget, settings rhp.HostSettings) *budgetedStream {
	return &budgetedStream{
		rw:       rw,
		budget:   budget,
		settings: settings,
	}
}

func (sh *SessionHandler) handleRPCExecuteProgram(stream *mux.Stream) {
	log := sh.log.Scope("RPCExecute")
	var settingsID rhp.SettingsID
	if err := rpc.ReadObject(stream, &settingsID); err != nil {
		log.Warnln("failed to read settings UID:", err)
		return
	}

	settings, err := sh.validSettings(settingsID)
	if err != nil {
		log.Warnf("settings uid %s not found:", settingsID)
		rpc.WriteResponseErr(stream, err)
		return
	}

	budget, refundAccount, err := sh.processPayment(stream)
	if err != nil {
		log.Warnln("failed to process payment:", err)
		rpc.WriteResponseErr(stream, err)
		return
	}
	defer func() {
		sh.accounts.Refund(refundAccount, budget.Remaining())
	}()

	// wrap the stream in a budget to pay for bandwidth usage, also serves as
	// a data limit since all usage is deducted from the budget.
	budgetedStream := newBudgetedStream(stream, budget, settings)

	// read the program
	var executeReq rhp.RPCExecuteProgramRequest
	err = rpc.ReadResponse(budgetedStream, &executeReq)
	if err != nil {
		log.Warnln("failed to read execute program request:", err)
		rpc.WriteResponseErr(stream, errors.New("failed to read execute request"))
		return
	}

	var requiresContract, requiresFinalization bool
	for _, instr := range executeReq.Instructions {
		requiresContract = requiresContract || instr.RequiresContract()
		requiresFinalization = requiresFinalization || instr.RequiresFinalization()
	}

	vc, err := sh.cm.TipContext()
	if err != nil {
		log.Warnln("failed to get validation context:", err)
		rpc.WriteResponseErr(stream, errors.New("failed to get validation context"))
		return
	}

	executor := newExecutor(sh.privkey, sh.sectors, sh.registry, vc, settings, budget)
	// revert any changes to the host state that were made by the program. Also
	// adds the failure refund back to the budget for the deferred refund.
	defer executor.Revert()

	// If the program requires finalization or a contract, verify that the
	// contract is valid and lockable.
	if requiresFinalization || requiresContract {
		// lock the contract
		contract, err := sh.contracts.lock(executeReq.FileContractID, time.Second*10)
		if err != nil {
			log.Warnln("failed to lock contract:", err)
			_ = rpc.WriteResponseErr(stream, fmt.Errorf("failed to lock contract: %w", err))
			return
		}
		defer sh.contracts.unlock(executeReq.FileContractID)

		// verify we can still modify the contract
		switch {
		case contract.Revision.RevisionNumber == math.MaxUint64:
			log.Warnf("cannot use contract %s for execution: already finalized", executeReq.FileContractID)
			_ = rpc.WriteResponseErr(stream, errors.New("contract not valid for revision"))
			return
		case vc.Index.Height >= contract.Revision.WindowStart:
			log.Warnf("cannot use contract %s for execution: in proof window", executeReq.FileContractID)
			_ = rpc.WriteResponseErr(stream, errors.New("contract not valid for revision"))
			return
		}

		if err := executor.setContract(contract.FileContractRevision); err != nil {
			log.Warnln("failed to set contract:", err)
			_ = rpc.WriteResponseErr(stream, errors.New("failed to set contract"))
			return
		}
	}

	// subtract the initialization cost from the budget. Initialization costs
	// are not refunded if execution fails. Also includes finalization cost if
	// the program is requires it.
	execCost := rhp.ExecutionCost(settings, executeReq.ProgramDataLength, uint64(len(executeReq.Instructions)), requiresFinalization)
	if err := budget.Spend(execCost.BaseCost); err != nil {
		log.Warnln("failed to pay execution costs:", err)
		_ = rpc.WriteResponseErr(stream, fmt.Errorf("failed to pay for program execution: %w", err))
		return
	}

	// execute each instruction in the program, sending the output to the renter.
	// Execution is stopped on any error.
	lr := io.LimitReader(budgetedStream, int64(executeReq.ProgramDataLength))
	for i, instruction := range executeReq.Instructions {
		if err := executor.ExecuteInstruction(lr, budgetedStream, instruction); err != nil {
			log.Warnf("failed to execute instruction %v: %s", i, err)
			return
		}
	}

	if !requiresFinalization {
		if err := executor.Commit(); err != nil {
			log.Errorln("failed to commit program:", err)
			return
		}
		return
	}

	// if the program requires finalization the contract must be updated with
	// additional collateral, roots, and filesize.

	var finalizeReq rhp.RPCFinalizeProgramRequest
	if err := rpc.ReadResponse(stream, &finalizeReq); err != nil {
		err = fmt.Errorf("failed to read finalize request: %w", err)
		log.Warnln(err)
		_ = rpc.WriteResponseErr(stream, err)
		return
	}

	contract, err := executor.FinalizeContract(finalizeReq)
	if err != nil {
		err = fmt.Errorf("failed to finalize contract: %w", err)
		log.Warnln(err)
		_ = rpc.WriteResponseErr(stream, err)
		return
	}

	if err := sh.contracts.revise(contract); err != nil {
		log.Errorln("failed to update contract revision:", err)
		_ = rpc.WriteResponseErr(stream, errors.New("failed to update contract revision"))
		return
	}

	if err := sh.sectors.SetContractRoots(contract.Parent.ID, executor.newRoots); err != nil {
		log.Errorln("failed to update contract revision:", err)
		_ = rpc.WriteResponseErr(stream, errors.New("failed to update contract roots"))
		return
	}

	err = rpc.WriteResponse(stream, &rhp.RPCRevisionSigningResponse{
		Signature: contract.HostSignature,
	})
	if err != nil {
		log.Errorln("failed to write host signature response:", err)
		return
	}

	// the program has successfully executed and finalized, commit any state
	// changes.
	if err := executor.Commit(); err != nil {
		log.Errorln("failed to commit program:", err)
		return
	}
}
