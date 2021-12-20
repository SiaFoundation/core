package host

import (
	"encoding/json"
	"errors"
	"io"
	"time"

	"go.sia.tech/core/net/mux"
	"go.sia.tech/core/net/rhp"
	"go.sia.tech/core/net/rpc"
	"go.sia.tech/core/types"
	"lukechampine.com/frand"
)

func (sh *SessionHandler) handleRPCAccountBalance(stream *mux.Stream) {
	log := sh.log.Scope("RPCAccountBalance")

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

	if err := budget.Spend(settings.RPCAccountBalanceCost); err != nil {
		log.Warnln("failed to pay for account balance RPC:", err)
		rpc.WriteResponseErr(stream, err)
		return
	}

	var req rhp.RPCAccountBalanceRequest
	if err = rpc.ReadResponse(stream, &req); err != nil {
		log.Warnln("failed to read account balance request:", err)
		rpc.WriteResponseErr(stream, errors.New("failed to read account balance request"))
		return
	}

	balance, err := sh.accounts.Balance(req.AccountID)
	if err != nil {
		log.Warnln("failed to get account balance:", err)
		rpc.WriteResponseErr(stream, err)
		return
	}

	resp := &rhp.RPCAccountBalanceResponse{
		Balance: balance,
	}
	if err = rpc.WriteResponse(stream, resp); err != nil {
		log.Warnln("RPC account balance:", "failed to write account balance response:", err)
		return
	}
}

func (sh *SessionHandler) handleRPCFundAccount(stream *mux.Stream) {
	log := sh.log.Scope("RPCFundAccount")

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

	if err := budget.Spend(settings.RPCFundAccountCost); err != nil {
		log.Warnln("failed to pay for fund account RPC:", err)
		rpc.WriteResponseErr(stream, err)
		return
	}

	var req rhp.RPCFundAccountRequest
	if err = rpc.ReadResponse(stream, &req); err != nil {
		log.Warnln("failed to read fund account request:", err)
		rpc.WriteResponseErr(stream, errors.New("failed to read fund account request"))
		return
	}

	fundAmount := budget.Remaining()
	balance, err := sh.accounts.Credit(req.AccountID, fundAmount)
	if err != nil {
		log.Warnln("failed to fund account:", err)
		rpc.WriteResponseErr(stream, errors.New("failed to fund account"))
		return
	}
	if err := budget.Spend(fundAmount); err != nil {
		log.Warnln("failed to spend account funding:", err)
		rpc.WriteResponseErr(stream, err)
		return
	}

	resp := &rhp.RPCFundAccountResponse{
		Balance: balance,
		Receipt: rhp.Receipt{
			Host:      sh.privkey.PublicKey(),
			Account:   req.AccountID,
			Amount:    fundAmount,
			Timestamp: time.Now(),
		},
	}

	h := types.NewHasher()
	resp.Receipt.EncodeTo(h.E)
	resp.Signature = sh.privkey.SignHash(h.Sum())

	// write the receipt and current balance.
	err = rpc.WriteResponse(stream, resp)
	if err != nil {
		log.Warnln("failed to write fund account response:", err)
		return
	}
}

func (sh *SessionHandler) handleRPCLatestRevision(stream *mux.Stream) {
	log := sh.log.Scope("RPCLatestRevision")

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

	if err := budget.Spend(settings.RPCLatestRevisionCost); err != nil {
		log.Warnln("failed to pay for latest revision RPC:", err)
		rpc.WriteResponseErr(stream, err)
		return
	}

	var req rhp.RPCLatestRevisionRequest
	if err = rpc.ReadResponse(stream, &req); err != nil {
		log.Warnln("failed to read latest revision request:", err)
		rpc.WriteResponseErr(stream, errors.New("failed to read latest revision request"))
		return
	}

	contract, err := sh.contracts.Contract(req.ContractID)
	if err != nil {
		log.Warnf("failed to get contract %s: %s", req.ContractID, err)
		rpc.WriteResponseErr(stream, errors.New("failed to get contract"))
		return
	}

	resp := &rhp.RPCLatestRevisionResponse{
		Revision: contract.FileContractRevision,
	}
	if err := rpc.WriteResponse(stream, resp); err != nil {
		log.Warnln("failed to write latest revision response:", err)
		return
	}
}

func (sh *SessionHandler) handleRPCSettings(stream *mux.Stream) {
	log := sh.log.Scope("RPCSettings")

	settings := sh.settings.Settings()
	buf, err := json.Marshal(settings)
	if err != nil {
		log.Errorln("failed to marshal settings:", err)
		return
	}

	// write the price table to the stream. The price table is sent
	// before payment so the renter can determine if they want to
	// continue interacting with the host.
	err = rpc.WriteResponse(stream, &rhp.RPCSettingsResponse{
		Settings: buf,
	})
	if err != nil {
		log.Warnln("failed to write settings response:", err)
		return
	}

	// process the payment, catch connection closed and EOF errors since the renter
	// likely did not intend to pay.
	budget, refundAccount, err := sh.processPayment(stream)
	if errors.Is(err, mux.ErrClosedConn) || errors.Is(err, mux.ErrClosedStream) || errors.Is(err, io.EOF) {
		return
	} else if err != nil {
		log.Warnln("failed to process payment:", err)
		rpc.WriteResponseErr(stream, err)
		return
	}
	defer func() {
		sh.accounts.Refund(refundAccount, budget.Remaining())
	}()

	if err := budget.Spend(settings.RPCHostSettingsCost); err != nil {
		log.Warnln("failed to pay for settings RPC:", err)
		rpc.WriteResponseErr(stream, err)
		return
	}

	// track the settings so the renter can reference it in later RPC.
	resp := rhp.RPCSettingsRegisteredResponse{
		ID: frand.Entropy128(),
	}
	sh.registerSettings(resp.ID, settings)

	// write the registered settings ID to the stream.
	if err := rpc.WriteResponse(stream, &resp); err != nil {
		log.Warnln("failed to write tracking response:", err)
		return
	}
}
