package rhp

import (
	"bytes"

	"go.sia.tech/core/types"
)

// EncodeTo implements types.EncoderTo.
func (ad AccountDeposit) EncodeTo(e *types.Encoder) {
	ad.Account.EncodeTo(e)
	types.V2Currency(ad.Amount).EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (ad *AccountDeposit) DecodeFrom(d *types.Decoder) {
	ad.Account.DecodeFrom(d)
	(*types.V2Currency)(&ad.Amount).DecodeFrom(d)
}

// EncodeTo implements types.EncoderTo.
func (hp HostPrices) EncodeTo(e *types.Encoder) {
	types.V2Currency(hp.ContractPrice).EncodeTo(e)
	types.V2Currency(hp.Collateral).EncodeTo(e)
	types.V2Currency(hp.StoragePrice).EncodeTo(e)
	types.V2Currency(hp.IngressPrice).EncodeTo(e)
	types.V2Currency(hp.EgressPrice).EncodeTo(e)
	types.V2Currency(hp.FreeSectorPrice).EncodeTo(e)
	e.WriteUint64(hp.TipHeight)
	e.WriteTime(hp.ValidUntil)
	hp.Signature.EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (hp *HostPrices) DecodeFrom(d *types.Decoder) {
	(*types.V2Currency)(&hp.ContractPrice).DecodeFrom(d)
	(*types.V2Currency)(&hp.Collateral).DecodeFrom(d)
	(*types.V2Currency)(&hp.StoragePrice).DecodeFrom(d)
	(*types.V2Currency)(&hp.IngressPrice).DecodeFrom(d)
	(*types.V2Currency)(&hp.EgressPrice).DecodeFrom(d)
	(*types.V2Currency)(&hp.FreeSectorPrice).DecodeFrom(d)
	hp.TipHeight = d.ReadUint64()
	hp.ValidUntil = d.ReadTime()
	hp.Signature.DecodeFrom(d)
}

// EncodeTo implements types.EncoderTo.
func (hs HostSettings) EncodeTo(e *types.Encoder) {
	e.Write(hs.ProtocolVersion[:])
	e.WriteString(hs.Release)
	hs.WalletAddress.EncodeTo(e)
	e.WriteBool(hs.AcceptingContracts)
	types.V2Currency(hs.MaxCollateral).EncodeTo(e)
	e.WriteUint64(hs.MaxContractDuration)
	e.WriteUint64(hs.RemainingStorage)
	e.WriteUint64(hs.TotalStorage)
	hs.Prices.EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (hs *HostSettings) DecodeFrom(d *types.Decoder) {
	d.Read(hs.ProtocolVersion[:])
	hs.Release = d.ReadString()
	hs.WalletAddress.DecodeFrom(d)
	hs.AcceptingContracts = d.ReadBool()
	(*types.V2Currency)(&hs.MaxCollateral).DecodeFrom(d)
	hs.MaxContractDuration = d.ReadUint64()
	hs.RemainingStorage = d.ReadUint64()
	hs.TotalStorage = d.ReadUint64()
	hs.Prices.DecodeFrom(d)
}

// EncodeTo implements types.EncoderTo.
func (a Account) EncodeTo(e *types.Encoder) { e.Write(a[:]) }

// DecodeFrom implements types.DecoderFrom.
func (a *Account) DecodeFrom(d *types.Decoder) { d.Read(a[:]) }

func (at AccountToken) encodeTo(e *types.Encoder) {
	at.HostKey.EncodeTo(e)
	at.Account.EncodeTo(e)
	e.WriteTime(at.ValidUntil)
	at.Signature.EncodeTo(e)
}

func (at *AccountToken) decodeFrom(d *types.Decoder) {
	at.HostKey.DecodeFrom(d)
	at.Account.DecodeFrom(d)
	at.ValidUntil = d.ReadTime()
	at.Signature.DecodeFrom(d)
}

func (r *RPCError) encodeTo(e *types.Encoder) {
	e.WriteUint8(r.Code)
	e.WriteString(r.Description)
}
func (r *RPCError) decodeFrom(d *types.Decoder) {
	r.Code = d.ReadUint8()
	r.Description = d.ReadString()
}
func (r *RPCError) maxLen() int {
	return 1024
}

const (
	reasonableObjectSize         = 10 * 1024
	reasonableTransactionSetSize = 100 * 1024
)

func sizeof(v types.EncoderTo) int {
	var buf bytes.Buffer
	e := types.NewEncoder(&buf)
	v.EncodeTo(e)
	e.Flush()
	return buf.Len()
}

var (
	sizeofCurrency       = sizeof(types.V2Currency{})
	sizeofHash           = sizeof(types.Hash256{})
	sizeofSignature      = sizeof(types.Signature{})
	sizeofContract       = sizeof(types.V2FileContract{})
	sizeofPrices         = sizeof(HostPrices{})
	sizeofAccount        = sizeof(Account{})
	sizeofAccountToken   = sizeof(types.EncoderFunc(AccountToken{}.encodeTo))
	sizeofAccountDeposit = sizeof(AccountDeposit{})
)

// An Object can be sent or received via a Transport.
type Object interface {
	encodeTo(*types.Encoder)
	decodeFrom(*types.Decoder)
	maxLen() int
}

func (*RPCSettingsRequest) encodeTo(*types.Encoder)   {}
func (*RPCSettingsRequest) decodeFrom(*types.Decoder) {}
func (*RPCSettingsRequest) maxLen() int               { return 0 }

func (r *RPCSettingsResponse) encodeTo(e *types.Encoder) {
	r.Settings.EncodeTo(e)
}
func (r *RPCSettingsResponse) decodeFrom(d *types.Decoder) {
	r.Settings.DecodeFrom(d)
}
func (r *RPCSettingsResponse) maxLen() int {
	return reasonableObjectSize
}

func (r *RPCFormContractParams) encodeTo(e *types.Encoder) {
	r.RenterPublicKey.EncodeTo(e)
	r.RenterAddress.EncodeTo(e)
	types.V2Currency(r.Allowance).EncodeTo(e)
	types.V2Currency(r.Collateral).EncodeTo(e)
	e.WriteUint64(r.ProofHeight)
}

func (r *RPCFormContractParams) decodeFrom(d *types.Decoder) {
	r.RenterPublicKey.DecodeFrom(d)
	r.RenterAddress.DecodeFrom(d)
	(*types.V2Currency)(&r.Allowance).DecodeFrom(d)
	(*types.V2Currency)(&r.Collateral).DecodeFrom(d)
	r.ProofHeight = d.ReadUint64()
}

func (r *RPCFormContractRequest) encodeTo(e *types.Encoder) {
	r.Prices.EncodeTo(e)
	r.Contract.encodeTo(e)
	r.Basis.EncodeTo(e)
	types.V2Currency(r.MinerFee).EncodeTo(e)
	types.EncodeSlice(e, r.RenterInputs)
	types.EncodeSlice(e, r.RenterParents)
}
func (r *RPCFormContractRequest) decodeFrom(d *types.Decoder) {
	r.Prices.DecodeFrom(d)
	r.Contract.decodeFrom(d)
	r.Basis.DecodeFrom(d)
	(*types.V2Currency)(&r.MinerFee).DecodeFrom(d)
	types.DecodeSlice(d, &r.RenterInputs)
	types.DecodeSlice(d, &r.RenterParents)
}
func (r *RPCFormContractRequest) maxLen() int {
	return reasonableObjectSize
}

func (r *RPCFormContractResponse) encodeTo(e *types.Encoder) {
	types.EncodeSlice(e, r.HostInputs)
}

func (r *RPCFormContractResponse) decodeFrom(d *types.Decoder) {
	types.DecodeSlice(d, &r.HostInputs)
}
func (r *RPCFormContractResponse) maxLen() int {
	return reasonableObjectSize
}

func (r *RPCFormContractSecondResponse) encodeTo(e *types.Encoder) {
	r.RenterContractSignature.EncodeTo(e)
	types.EncodeSlice(e, r.RenterSatisfiedPolicies)
}
func (r *RPCFormContractSecondResponse) decodeFrom(d *types.Decoder) {
	r.RenterContractSignature.DecodeFrom(d)
	types.DecodeSlice(d, &r.RenterSatisfiedPolicies)
}
func (r *RPCFormContractSecondResponse) maxLen() int {
	return reasonableObjectSize
}

func (r *RPCFormContractThirdResponse) encodeTo(e *types.Encoder) {
	r.Basis.EncodeTo(e)
	types.EncodeSlice(e, r.TransactionSet)
}
func (r *RPCFormContractThirdResponse) decodeFrom(d *types.Decoder) {
	r.Basis.DecodeFrom(d)
	types.DecodeSlice(d, &r.TransactionSet)
}
func (r *RPCFormContractThirdResponse) maxLen() int {
	return reasonableTransactionSetSize
}

func (r *RPCRenewContractParams) encodeTo(e *types.Encoder) {
	r.ContractID.EncodeTo(e)
	types.V2Currency(r.Allowance).EncodeTo(e)
	types.V2Currency(r.Collateral).EncodeTo(e)
	e.WriteUint64(r.ProofHeight)
}

func (r *RPCRenewContractParams) decodeFrom(d *types.Decoder) {
	r.ContractID.DecodeFrom(d)
	(*types.V2Currency)(&r.Allowance).DecodeFrom(d)
	(*types.V2Currency)(&r.Collateral).DecodeFrom(d)
	r.ProofHeight = d.ReadUint64()
}

func (r *RPCRenewContractRequest) encodeTo(e *types.Encoder) {
	r.Prices.EncodeTo(e)
	r.Renewal.encodeTo(e)
	types.V2Currency(r.MinerFee).EncodeTo(e)
	r.Basis.EncodeTo(e)
	types.EncodeSlice(e, r.RenterInputs)
	types.EncodeSlice(e, r.RenterParents)
	r.ChallengeSignature.EncodeTo(e)
}
func (r *RPCRenewContractRequest) decodeFrom(d *types.Decoder) {
	r.Prices.DecodeFrom(d)
	r.Renewal.decodeFrom(d)
	(*types.V2Currency)(&r.MinerFee).DecodeFrom(d)
	r.Basis.DecodeFrom(d)
	types.DecodeSlice(d, &r.RenterInputs)
	types.DecodeSlice(d, &r.RenterParents)
	r.ChallengeSignature.DecodeFrom(d)
}
func (r *RPCRenewContractRequest) maxLen() int {
	return reasonableObjectSize
}

func (r *RPCRenewContractResponse) encodeTo(e *types.Encoder) {
	types.EncodeSlice(e, r.HostInputs)
}
func (r *RPCRenewContractResponse) decodeFrom(d *types.Decoder) {
	types.DecodeSlice(d, &r.HostInputs)
}
func (r *RPCRenewContractResponse) maxLen() int {
	return reasonableObjectSize
}

func (r *RPCRenewContractSecondResponse) encodeTo(e *types.Encoder) {
	r.RenterRenewalSignature.EncodeTo(e)
	r.RenterContractSignature.EncodeTo(e)
	types.EncodeSlice(e, r.RenterSatisfiedPolicies)
}
func (r *RPCRenewContractSecondResponse) decodeFrom(d *types.Decoder) {
	r.RenterRenewalSignature.DecodeFrom(d)
	r.RenterContractSignature.DecodeFrom(d)
	types.DecodeSlice(d, &r.RenterSatisfiedPolicies)
}
func (r *RPCRenewContractSecondResponse) maxLen() int {
	return reasonableObjectSize
}

func (r *RPCRenewContractThirdResponse) encodeTo(e *types.Encoder) {
	r.Basis.EncodeTo(e)
	types.EncodeSlice(e, r.TransactionSet)
}
func (r *RPCRenewContractThirdResponse) decodeFrom(d *types.Decoder) {
	r.Basis.DecodeFrom(d)
	types.DecodeSlice(d, &r.TransactionSet)
}
func (r *RPCRenewContractThirdResponse) maxLen() int {
	return reasonableTransactionSetSize
}

func (r *RPCRefreshContractParams) encodeTo(e *types.Encoder) {
	r.ContractID.EncodeTo(e)
	types.V2Currency(r.Allowance).EncodeTo(e)
	types.V2Currency(r.Collateral).EncodeTo(e)
}

func (r *RPCRefreshContractParams) decodeFrom(d *types.Decoder) {
	r.ContractID.DecodeFrom(d)
	(*types.V2Currency)(&r.Allowance).DecodeFrom(d)
	(*types.V2Currency)(&r.Collateral).DecodeFrom(d)
}

func (r *RPCRefreshContractRequest) encodeTo(e *types.Encoder) {
	r.Prices.EncodeTo(e)
	r.Refresh.encodeTo(e)
	types.V2Currency(r.MinerFee).EncodeTo(e)
	r.Basis.EncodeTo(e)
	types.EncodeSlice(e, r.RenterInputs)
	types.EncodeSlice(e, r.RenterParents)
	r.ChallengeSignature.EncodeTo(e)
}
func (r *RPCRefreshContractRequest) decodeFrom(d *types.Decoder) {
	r.Prices.DecodeFrom(d)
	r.Refresh.decodeFrom(d)
	(*types.V2Currency)(&r.MinerFee).DecodeFrom(d)
	r.Basis.DecodeFrom(d)
	types.DecodeSlice(d, &r.RenterInputs)
	types.DecodeSlice(d, &r.RenterParents)
	r.ChallengeSignature.DecodeFrom(d)
}
func (r *RPCRefreshContractRequest) maxLen() int {
	return reasonableObjectSize
}

func (r *RPCRefreshContractResponse) encodeTo(e *types.Encoder) {
	types.EncodeSlice(e, r.HostInputs)
}
func (r *RPCRefreshContractResponse) decodeFrom(d *types.Decoder) {
	types.DecodeSlice(d, &r.HostInputs)
}
func (r *RPCRefreshContractResponse) maxLen() int {
	return reasonableObjectSize
}

func (r *RPCRefreshContractSecondResponse) encodeTo(e *types.Encoder) {
	r.RenterRenewalSignature.EncodeTo(e)
	r.RenterContractSignature.EncodeTo(e)
	types.EncodeSlice(e, r.RenterSatisfiedPolicies)
}
func (r *RPCRefreshContractSecondResponse) decodeFrom(d *types.Decoder) {
	r.RenterRenewalSignature.DecodeFrom(d)
	r.RenterContractSignature.DecodeFrom(d)
	types.DecodeSlice(d, &r.RenterSatisfiedPolicies)
}
func (r *RPCRefreshContractSecondResponse) maxLen() int {
	return reasonableObjectSize
}

func (r *RPCRefreshContractThirdResponse) encodeTo(e *types.Encoder) {
	r.Basis.EncodeTo(e)
	types.EncodeSlice(e, r.TransactionSet)
}
func (r *RPCRefreshContractThirdResponse) decodeFrom(d *types.Decoder) {
	r.Basis.DecodeFrom(d)
	types.DecodeSlice(d, &r.TransactionSet)
}
func (r *RPCRefreshContractThirdResponse) maxLen() int {
	return reasonableTransactionSetSize
}

func (r *RPCFreeSectorsRequest) encodeTo(e *types.Encoder) {
	r.ContractID.EncodeTo(e)
	r.Prices.EncodeTo(e)
	types.EncodeSliceFn(e, r.Indices, func(e *types.Encoder, v uint64) {
		e.WriteUint64(v)
	})
	r.ChallengeSignature.EncodeTo(e)
}
func (r *RPCFreeSectorsRequest) decodeFrom(d *types.Decoder) {
	r.ContractID.DecodeFrom(d)
	r.Prices.DecodeFrom(d)
	types.DecodeSliceFn(d, &r.Indices, func(d *types.Decoder) uint64 {
		return d.ReadUint64()
	})
	r.ChallengeSignature.DecodeFrom(d)
}
func (r *RPCFreeSectorsRequest) maxLen() int {
	return reasonableObjectSize
}

func (r *RPCFreeSectorsResponse) encodeTo(e *types.Encoder) {
	types.EncodeSlice(e, r.OldSubtreeHashes)
	types.EncodeSlice(e, r.OldLeafHashes)
	r.NewMerkleRoot.EncodeTo(e)
}
func (r *RPCFreeSectorsResponse) decodeFrom(d *types.Decoder) {
	types.DecodeSlice(d, &r.OldSubtreeHashes)
	types.DecodeSlice(d, &r.OldLeafHashes)
	r.NewMerkleRoot.DecodeFrom(d)
}
func (r *RPCFreeSectorsResponse) maxLen() int {
	return reasonableObjectSize
}

func (r *RPCFreeSectorsSecondResponse) encodeTo(e *types.Encoder) {
	r.RenterSignature.EncodeTo(e)
}
func (r *RPCFreeSectorsSecondResponse) decodeFrom(d *types.Decoder) {
	r.RenterSignature.DecodeFrom(d)
}
func (r *RPCFreeSectorsSecondResponse) maxLen() int {
	return sizeofSignature
}

func (r *RPCFreeSectorsThirdResponse) encodeTo(e *types.Encoder) {
	r.HostSignature.EncodeTo(e)
}
func (r *RPCFreeSectorsThirdResponse) decodeFrom(d *types.Decoder) {
	r.HostSignature.DecodeFrom(d)
}
func (r *RPCFreeSectorsThirdResponse) maxLen() int {
	return sizeofSignature
}

func (r *RPCAppendSectorsRequest) encodeTo(e *types.Encoder) {
	r.Prices.EncodeTo(e)
	types.EncodeSlice(e, r.Sectors)
	r.ContractID.EncodeTo(e)
	r.ChallengeSignature.EncodeTo(e)
}
func (r *RPCAppendSectorsRequest) decodeFrom(d *types.Decoder) {
	r.Prices.DecodeFrom(d)
	types.DecodeSlice(d, &r.Sectors)
	r.ContractID.DecodeFrom(d)
	r.ChallengeSignature.DecodeFrom(d)
}
func (r *RPCAppendSectorsRequest) maxLen() int {
	return reasonableObjectSize
}

func (r *RPCAppendSectorsResponse) encodeTo(e *types.Encoder) {
	types.EncodeSliceFn(e, r.Accepted, (*types.Encoder).WriteBool)
	types.EncodeSlice(e, r.SubtreeRoots)
	r.NewMerkleRoot.EncodeTo(e)
}
func (r *RPCAppendSectorsResponse) decodeFrom(d *types.Decoder) {
	types.DecodeSliceFn(d, &r.Accepted, (*types.Decoder).ReadBool)
	types.DecodeSlice(d, &r.SubtreeRoots)
	r.NewMerkleRoot.DecodeFrom(d)
}
func (r *RPCAppendSectorsResponse) maxLen() int {
	return reasonableObjectSize
}

func (r *RPCAppendSectorsSecondResponse) encodeTo(e *types.Encoder) {
	r.RenterSignature.EncodeTo(e)
}
func (r *RPCAppendSectorsSecondResponse) decodeFrom(d *types.Decoder) {
	r.RenterSignature.DecodeFrom(d)
}
func (r *RPCAppendSectorsSecondResponse) maxLen() int {
	return sizeofSignature
}

func (r *RPCAppendSectorsThirdResponse) encodeTo(e *types.Encoder) {
	r.HostSignature.EncodeTo(e)
}
func (r *RPCAppendSectorsThirdResponse) decodeFrom(d *types.Decoder) {
	r.HostSignature.DecodeFrom(d)
}
func (r *RPCAppendSectorsThirdResponse) maxLen() int {
	return sizeofSignature
}

func (r *RPCLatestRevisionRequest) encodeTo(e *types.Encoder) {
	r.ContractID.EncodeTo(e)
}
func (r *RPCLatestRevisionRequest) decodeFrom(d *types.Decoder) {
	r.ContractID.DecodeFrom(d)
}
func (r *RPCLatestRevisionRequest) maxLen() int {
	return sizeofHash
}

func (r *RPCLatestRevisionResponse) encodeTo(e *types.Encoder) {
	r.Contract.EncodeTo(e)
	e.WriteBool(r.Revisable)
	e.WriteBool(r.Renewed)
}
func (r *RPCLatestRevisionResponse) decodeFrom(d *types.Decoder) {
	r.Contract.DecodeFrom(d)
	r.Revisable = d.ReadBool()
	r.Renewed = d.ReadBool()
}
func (r *RPCLatestRevisionResponse) maxLen() int {
	return sizeofContract
}

func (r *RPCReadSectorRequest) encodeTo(e *types.Encoder) {
	r.Prices.EncodeTo(e)
	r.Token.encodeTo(e)
	r.Root.EncodeTo(e)
	e.WriteUint64(r.Offset)
	e.WriteUint64(r.Length)
}
func (r *RPCReadSectorRequest) decodeFrom(d *types.Decoder) {
	r.Prices.DecodeFrom(d)
	r.Token.decodeFrom(d)
	r.Root.DecodeFrom(d)
	r.Offset = d.ReadUint64()
	r.Length = d.ReadUint64()
}
func (r *RPCReadSectorRequest) maxLen() int {
	return sizeofPrices + sizeofAccountToken + sizeofHash + 8 + 8
}

func (r *RPCReadSectorResponse) encodeTo(e *types.Encoder) {
	types.EncodeSlice(e, r.Proof)
	e.WriteUint64(r.DataLength)
}
func (r *RPCReadSectorResponse) decodeFrom(d *types.Decoder) {
	types.DecodeSlice(d, &r.Proof)
	r.DataLength = d.ReadUint64()
}
func (r *RPCReadSectorResponse) maxLen() int {
	return reasonableObjectSize + 8 + SectorSize
}

func (r RPCWriteSectorRequest) encodeTo(e *types.Encoder) {
	r.Prices.EncodeTo(e)
	r.Token.encodeTo(e)
	e.WriteUint64(r.DataLength)
}
func (r *RPCWriteSectorRequest) decodeFrom(d *types.Decoder) {
	r.Prices.DecodeFrom(d)
	r.Token.decodeFrom(d)
	r.DataLength = d.ReadUint64()
}
func (r *RPCWriteSectorRequest) maxLen() int {
	return sizeofPrices + sizeofAccountToken + 8 + 8
}

func (r *RPCWriteSectorResponse) encodeTo(e *types.Encoder) {
	r.Root.EncodeTo(e)
}
func (r *RPCWriteSectorResponse) decodeFrom(d *types.Decoder) {
	r.Root.DecodeFrom(d)
}
func (r *RPCWriteSectorResponse) maxLen() int {
	return sizeofHash
}

func (r *RPCSectorRootsRequest) encodeTo(e *types.Encoder) {
	r.Prices.EncodeTo(e)
	r.ContractID.EncodeTo(e)
	r.RenterSignature.EncodeTo(e)
	e.WriteUint64(r.Offset)
	e.WriteUint64(r.Length)
}
func (r *RPCSectorRootsRequest) decodeFrom(d *types.Decoder) {
	r.Prices.DecodeFrom(d)
	r.ContractID.DecodeFrom(d)
	r.RenterSignature.DecodeFrom(d)
	r.Offset = d.ReadUint64()
	r.Length = d.ReadUint64()
}
func (r *RPCSectorRootsRequest) maxLen() int {
	return sizeofPrices + 32 + sizeofSignature + 8 + 8
}

func (r *RPCSectorRootsResponse) encodeTo(e *types.Encoder) {
	types.EncodeSlice(e, r.Proof)
	types.EncodeSlice(e, r.Roots)
	r.HostSignature.EncodeTo(e)
}
func (r *RPCSectorRootsResponse) decodeFrom(d *types.Decoder) {
	types.DecodeSlice(d, &r.Proof)
	types.DecodeSlice(d, &r.Roots)
	r.HostSignature.DecodeFrom(d)
}
func (r *RPCSectorRootsResponse) maxLen() int {
	return 1 << 20 // 1 MiB
}

func (r *RPCAccountBalanceRequest) encodeTo(e *types.Encoder) {
	r.Account.EncodeTo(e)
}
func (r *RPCAccountBalanceRequest) decodeFrom(d *types.Decoder) {
	r.Account.DecodeFrom(d)
}
func (r *RPCAccountBalanceRequest) maxLen() int {
	return sizeofAccount
}

func (r *RPCAccountBalanceResponse) encodeTo(e *types.Encoder) {
	types.V2Currency(r.Balance).EncodeTo(e)
}
func (r *RPCAccountBalanceResponse) decodeFrom(d *types.Decoder) {
	(*types.V2Currency)(&r.Balance).DecodeFrom(d)
}
func (r *RPCAccountBalanceResponse) maxLen() int {
	return sizeofCurrency
}

func (r *RPCReplenishAccountsRequest) encodeTo(e *types.Encoder) {
	types.EncodeSlice(e, r.Accounts)
	types.V2Currency(r.Target).EncodeTo(e)
	r.ContractID.EncodeTo(e)
	r.ChallengeSignature.EncodeTo(e)
}
func (r *RPCReplenishAccountsRequest) decodeFrom(d *types.Decoder) {
	types.DecodeSlice(d, &r.Accounts)
	(*types.V2Currency)(&r.Target).DecodeFrom(d)
	r.ContractID.DecodeFrom(d)
	r.ChallengeSignature.DecodeFrom(d)
}
func (r *RPCReplenishAccountsRequest) maxLen() int {
	return 8 + (sizeofHash * MaxAccountBatchSize) + sizeofCurrency + sizeofHash + sizeofSignature
}

func (r *RPCReplenishAccountsResponse) encodeTo(e *types.Encoder) {
	types.EncodeSlice(e, r.Deposits)
}
func (r *RPCReplenishAccountsResponse) decodeFrom(d *types.Decoder) {
	types.DecodeSlice(d, &r.Deposits)
}
func (r *RPCReplenishAccountsResponse) maxLen() int {
	return 8 + (sizeofAccountDeposit * MaxAccountBatchSize)
}

func (r *RPCReplenishAccountsSecondResponse) encodeTo(e *types.Encoder) {
	r.RenterSignature.EncodeTo(e)
}
func (r *RPCReplenishAccountsSecondResponse) decodeFrom(d *types.Decoder) {
	r.RenterSignature.DecodeFrom(d)
}
func (r *RPCReplenishAccountsSecondResponse) maxLen() int {
	return sizeofSignature
}

func (r *RPCReplenishAccountsThirdResponse) encodeTo(e *types.Encoder) {
	r.HostSignature.EncodeTo(e)
}
func (r *RPCReplenishAccountsThirdResponse) decodeFrom(d *types.Decoder) {
	r.HostSignature.DecodeFrom(d)
}
func (r *RPCReplenishAccountsThirdResponse) maxLen() int {
	return sizeofSignature
}

func (r *RPCFundAccountsRequest) encodeTo(e *types.Encoder) {
	r.ContractID.EncodeTo(e)
	types.EncodeSlice(e, r.Deposits)
	r.RenterSignature.EncodeTo(e)
}
func (r *RPCFundAccountsRequest) decodeFrom(d *types.Decoder) {
	r.ContractID.DecodeFrom(d)
	types.DecodeSlice(d, &r.Deposits)
	r.RenterSignature.DecodeFrom(d)
}
func (r *RPCFundAccountsRequest) maxLen() int {
	return sizeofHash + 8 + (sizeofAccountDeposit * MaxAccountBatchSize) + sizeofSignature
}

func (r *RPCFundAccountsResponse) encodeTo(e *types.Encoder) {
	types.EncodeSliceCast[types.V2Currency](e, r.Balances)
	r.HostSignature.EncodeTo(e)
}
func (r *RPCFundAccountsResponse) decodeFrom(d *types.Decoder) {
	types.DecodeSliceCast[types.V2Currency, types.Currency](d, &r.Balances)
	r.HostSignature.DecodeFrom(d)
}
func (r *RPCFundAccountsResponse) maxLen() int {
	return 8 + (sizeofCurrency * MaxAccountBatchSize) + sizeofSignature
}

func (r *RPCVerifySectorRequest) encodeTo(e *types.Encoder) {
	r.Prices.EncodeTo(e)
	r.Token.encodeTo(e)
	r.Root.EncodeTo(e)
	e.WriteUint64(r.LeafIndex)
}
func (r *RPCVerifySectorRequest) decodeFrom(d *types.Decoder) {
	r.Prices.DecodeFrom(d)
	r.Token.decodeFrom(d)
	r.Root.DecodeFrom(d)
	r.LeafIndex = d.ReadUint64()
}
func (r *RPCVerifySectorRequest) maxLen() int {
	return 1024
}

func (r *RPCVerifySectorResponse) encodeTo(e *types.Encoder) {
	types.EncodeSlice(e, r.Proof)
	e.Write(r.Leaf[:])
}
func (r *RPCVerifySectorResponse) decodeFrom(d *types.Decoder) {
	types.DecodeSlice(d, &r.Proof)
	d.Read(r.Leaf[:])
}
func (r *RPCVerifySectorResponse) maxLen() int {
	return reasonableObjectSize
}
