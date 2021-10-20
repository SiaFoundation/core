//go:build gofuzz
// +build gofuzz

package consensus

import (
	"crypto/ed25519"

	"go.sia.tech/core/types"
)

func Fuzz(data []byte) int {
	var txn types.Transaction
	d := types.NewBufDecoder(data)
	txn.DecodeFrom(d)
	if d.Err() != nil {
		return -1
	}
	improveFuzzability(&txn)
	vc := vcForFuzzing(&txn)
	if vc.ValidateTransaction(txn) == nil {
		return 1
	}
	return 0
}

var (
	anyoneCanSpend        = types.AnyoneCanSpend()
	anyoneCanSpendAddress = types.PolicyAddress(anyoneCanSpend)
	zeroPrivkey           = ed25519.NewKeyFromSeed(make([]byte, 32))
	zeroPubkey            = zeroPrivkey.Public().(ed25519.PublicKey)
)

func improveFuzzability(txn *types.Transaction) {
	// TODO: fuzz contract resolutions
	txn.FileContractResolutions = nil

	// TODO: fuzz foundation address changes
	txn.NewFoundationAddress = types.VoidAddress

	// set all addresses to AnyoneCanSpend
	for i := range txn.SiacoinInputs {
		sci := &txn.SiacoinInputs[i]
		sci.SpendPolicy = anyoneCanSpend
		sci.Parent.Address = anyoneCanSpendAddress
	}
	for i := range txn.SiafundInputs {
		sfi := &txn.SiafundInputs[i]
		sfi.SpendPolicy = anyoneCanSpend
		sfi.Parent.Address = anyoneCanSpendAddress
	}

	// override file contract pubkeys so that we can sign them
	for i := range txn.FileContractRevisions {
		fcr := &txn.FileContractRevisions[i]
		copy(fcr.Parent.RenterPublicKey[:], zeroPubkey)
		copy(fcr.Parent.HostPublicKey[:], zeroPubkey)
		sigHash := (&ValidationContext{}).ContractSigHash(fcr.Revision)
		fcr.RenterSignature = types.SignHash(zeroPrivkey, sigHash)
		fcr.HostSignature = types.SignHash(zeroPrivkey, sigHash)
	}
}

func vcForFuzzing(txn *types.Transaction) ValidationContext {
	var setupTxn types.Transaction
	for _, sci := range txn.SiacoinInputs {
		setupTxn.SiacoinOutputs = append(setupTxn.SiacoinOutputs, sci.Parent.SiacoinOutput)
	}
	for _, sfi := range txn.SiafundInputs {
		setupTxn.SiafundOutputs = append(setupTxn.SiafundOutputs, sfi.Parent.SiafundOutput)
	}
	for _, fcr := range txn.FileContractRevisions {
		// ensure that FileContractTax will not overflow when we call ApplyBlock
		fc := fcr.Parent.FileContract
		if _, overflow := fc.ValidRenterOutput.Value.AddWithOverflow(fc.ValidHostOutput.Value); overflow {
			fc.ValidRenterOutput.Value = types.ZeroCurrency
		}
		setupTxn.FileContracts = append(setupTxn.FileContracts, fc)
	}
	block := types.Block{Transactions: []types.Transaction{setupTxn}}

	au := ApplyBlock(ValidationContext{}, block)
	au.NewSiacoinElements = au.NewSiacoinElements[1:] // skip block reward
	for i, sce := range au.NewSiacoinElements {
		if sce.Address != txn.SiacoinInputs[i].Parent.Address {
			panic("elements do not match") // sanity check
		}
		txn.SiacoinInputs[i].Parent = sce
	}
	for i, sfe := range au.NewSiafundElements {
		if sfe.Address != txn.SiafundInputs[i].Parent.Address {
			panic("elements do not match") // sanity check
		}
		txn.SiafundInputs[i].Parent = sfe
	}
	for i, fce := range au.NewFileContracts {
		if fce.FileMerkleRoot != txn.FileContractRevisions[i].Parent.FileMerkleRoot {
			panic("elements do not match") // sanity check
		}
		txn.FileContractRevisions[i].Parent = fce
	}

	return au.Context
}
