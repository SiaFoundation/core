package rhp

import (
	"bytes"
	"fmt"

	"go.sia.tech/core/types"
)

// EncodeTo implements types.EncoderTo.
func (hp HostPrices) EncodeTo(e *types.Encoder) {
	types.V2Currency(hp.ContractPrice).EncodeTo(e)
	types.V2Currency(hp.Collateral).EncodeTo(e)
	types.V2Currency(hp.StoragePrice).EncodeTo(e)
	types.V2Currency(hp.IngressPrice).EncodeTo(e)
	types.V2Currency(hp.EgressPrice).EncodeTo(e)
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
	hp.TipHeight = d.ReadUint64()
	hp.ValidUntil = d.ReadTime()
	hp.Signature.DecodeFrom(d)
}

// EncodeTo implements types.EncoderTo.
func (hs HostSettings) EncodeTo(e *types.Encoder) {
	e.Write(hs.Version[:])
	e.WritePrefix(len(hs.NetAddresses))
	for i := range hs.NetAddresses {
		e.WriteString(hs.NetAddresses[i].Protocol)
		e.WriteString(hs.NetAddresses[i].Address)
	}
	hs.WalletAddress.EncodeTo(e)
	e.WriteBool(hs.AcceptingContracts)
	types.V2Currency(hs.MaxCollateral).EncodeTo(e)
	e.WriteUint64(hs.MaxDuration)
	e.WriteUint64(hs.RemainingStorage)
	e.WriteUint64(hs.TotalStorage)
	hs.Prices.EncodeTo(e)
}

// DecodeFrom implements types.DecoderFrom.
func (hs *HostSettings) DecodeFrom(d *types.Decoder) {
	d.Read(hs.Version[:])
	hs.NetAddresses = make([]NetAddress, d.ReadPrefix())
	for i := range hs.NetAddresses {
		hs.NetAddresses[i].Protocol = d.ReadString()
		hs.NetAddresses[i].Address = d.ReadString()
	}
	hs.WalletAddress.DecodeFrom(d)
	hs.AcceptingContracts = d.ReadBool()
	(*types.V2Currency)(&hs.MaxCollateral).DecodeFrom(d)
	hs.MaxDuration = d.ReadUint64()
	hs.RemainingStorage = d.ReadUint64()
	hs.TotalStorage = d.ReadUint64()
	hs.Prices.DecodeFrom(d)
}

// EncodeTo implements types.EncoderTo.
func (a WriteAction) EncodeTo(e *types.Encoder) {
	e.WriteUint8(a.Type)
	switch a.Type {
	case ActionAppend:
		a.Root.EncodeTo(e)
	case ActionSwap:
		e.WriteUint64(a.A)
		e.WriteUint64(a.B)
	case ActionTrim:
		e.WriteUint64(a.N)
	default:
		panic("invalid action type")
	}
}

// DecodeFrom implements types.DecoderFrom.
func (a *WriteAction) DecodeFrom(d *types.Decoder) {
	a.Type = d.ReadUint8()
	switch a.Type {
	case ActionAppend:
		a.Root.DecodeFrom(d)
	case ActionSwap:
		a.A = d.ReadUint64()
		a.B = d.ReadUint64()
	case ActionTrim:
		a.N = d.ReadUint64()
	default:
		d.SetErr(fmt.Errorf("invalid action type (%v)", a.Type))
	}
}

func (r *RPCError) encodeTo(e *types.Encoder) {
	e.WriteUint8(r.Code)
	e.WriteString(r.Description)
}
func (r *RPCError) decodeFrom(d *types.Decoder) {
	r.Code = d.ReadUint8()
	r.Description = d.ReadString()
}
func (r *RPCError) maxLen() int { return 1 + 1024 }

const reasonableObjectSize = 10 * 1024

func sizeof(v types.EncoderTo) int {
	var buf bytes.Buffer
	e := types.NewEncoder(&buf)
	v.EncodeTo(e)
	e.Flush()
	return buf.Len()
}

var sizeofCurrency = sizeof(types.V2Currency{})
var sizeofSignature = sizeof(types.Signature{})
var sizeofPrices = sizeof(HostPrices{})
var sizeofContract = sizeof(types.V2FileContract{})

// An Object can be sent or received via a Transport.
type Object interface {
	encodeTo(*types.Encoder)
	decodeFrom(*types.Decoder)
	maxLen() int
}

func (RPCSettingsRequest) encodeTo(*types.Encoder)   {}
func (RPCSettingsRequest) decodeFrom(*types.Decoder) {}
func (RPCSettingsRequest) maxLen() int               { return 0 }

func (r *RPCSettingsResponse) encodeTo(e *types.Encoder) {
	r.Settings.EncodeTo(e)
}
func (r *RPCSettingsResponse) decodeFrom(d *types.Decoder) {
	r.Settings.DecodeFrom(d)
}
func (r *RPCSettingsResponse) maxLen() int { return reasonableObjectSize }

func (r *RPCFormContractRequest) encodeTo(e *types.Encoder) {
	r.Prices.EncodeTo(e)
	r.Contract.EncodeTo(e)
	e.WritePrefix(len(r.RenterInputs))
	for i := range r.RenterInputs {
		r.RenterInputs[i].EncodeTo(e)
	}
}
func (r *RPCFormContractRequest) decodeFrom(d *types.Decoder) {
	r.Prices.DecodeFrom(d)
	r.Contract.DecodeFrom(d)
	r.RenterInputs = make([]types.V2SiacoinInput, d.ReadPrefix())
	for i := range r.RenterInputs {
		r.RenterInputs[i].DecodeFrom(d)
	}
}
func (r *RPCFormContractRequest) maxLen() int { return reasonableObjectSize }

func (r *RPCFormContractResponse) encodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.HostInputs))
	for i := range r.HostInputs {
		r.HostInputs[i].EncodeTo(e)
	}
}
func (r *RPCFormContractResponse) decodeFrom(d *types.Decoder) {
	r.HostInputs = make([]types.V2SiacoinInput, d.ReadPrefix())
	for i := range r.HostInputs {
		r.HostInputs[i].DecodeFrom(d)
	}
}
func (r *RPCFormContractResponse) maxLen() int { return reasonableObjectSize }

func (r *SignatureResponse) encodeTo(e *types.Encoder) {
	(*types.Signature)(r).EncodeTo(e)
}
func (r *SignatureResponse) decodeFrom(d *types.Decoder) {
	(*types.Signature)(r).DecodeFrom(d)
}
func (r *SignatureResponse) maxLen() int { return sizeofSignature }

func (r *RPCRenewContractRequest) encodeTo(e *types.Encoder) {
	r.Prices.EncodeTo(e)
	r.Renewal.EncodeTo(e)
	e.WritePrefix(len(r.RenterInputs))
	for i := range r.RenterInputs {
		r.RenterInputs[i].EncodeTo(e)
	}
}
func (r *RPCRenewContractRequest) decodeFrom(d *types.Decoder) {
	r.Prices.DecodeFrom(d)
	r.Renewal.DecodeFrom(d)
	r.RenterInputs = make([]types.V2SiacoinInput, d.ReadPrefix())
	for i := range r.RenterInputs {
		r.RenterInputs[i].DecodeFrom(d)
	}
}
func (r *RPCRenewContractRequest) maxLen() int { return reasonableObjectSize }

func (r *RPCRenewContractResponse) encodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.HostInputs))
	for i := range r.HostInputs {
		r.HostInputs[i].EncodeTo(e)
	}
}
func (r *RPCRenewContractResponse) decodeFrom(d *types.Decoder) {
	r.HostInputs = make([]types.V2SiacoinInput, d.ReadPrefix())
	for i := range r.HostInputs {
		r.HostInputs[i].DecodeFrom(d)
	}
}
func (r *RPCRenewContractResponse) maxLen() int { return reasonableObjectSize }

func (r *RPCModifySectorsRequest) encodeTo(e *types.Encoder) {
	r.Prices.EncodeTo(e)
	e.WritePrefix(len(r.Actions))
	for i := range r.Actions {
		r.Actions[i].EncodeTo(e)
	}
}
func (r *RPCModifySectorsRequest) decodeFrom(d *types.Decoder) {
	r.Prices.DecodeFrom(d)
	r.Actions = make([]WriteAction, d.ReadPrefix())
	for i := range r.Actions {
		r.Actions[i].DecodeFrom(d)
	}
}
func (r *RPCModifySectorsRequest) maxLen() int { return reasonableObjectSize }

func (r *RPCModifySectorsResponse) encodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.Proof))
	for i := range r.Proof {
		r.Proof[i].EncodeTo(e)
	}
}
func (r *RPCModifySectorsResponse) decodeFrom(d *types.Decoder) {
	r.Proof = make([]types.Hash256, d.ReadPrefix())
	for i := range r.Proof {
		r.Proof[i].DecodeFrom(d)
	}
}
func (r *RPCModifySectorsResponse) maxLen() int { return reasonableObjectSize }

func (r *RPCLatestRevisionRequest) encodeTo(e *types.Encoder) {
	r.ContractID.EncodeTo(e)
}
func (r *RPCLatestRevisionRequest) decodeFrom(d *types.Decoder) {
	r.ContractID.DecodeFrom(d)
}
func (r *RPCLatestRevisionRequest) maxLen() int { return 32 }

func (r *RPCLatestRevisionResponse) encodeTo(e *types.Encoder) {
	r.Contract.EncodeTo(e)
}
func (r *RPCLatestRevisionResponse) decodeFrom(d *types.Decoder) {
	r.Contract.DecodeFrom(d)
}
func (r *RPCLatestRevisionResponse) maxLen() int { return sizeofContract }

func (r *RPCReadSectorRequest) encodeTo(e *types.Encoder) {
	r.Prices.EncodeTo(e)
	r.Root.EncodeTo(e)
	e.WriteUint64(r.Offset)
	e.WriteUint64(r.Length)
}
func (r *RPCReadSectorRequest) decodeFrom(d *types.Decoder) {
	r.Prices.DecodeFrom(d)
	r.Root.DecodeFrom(d)
	r.Offset = d.ReadUint64()
	r.Length = d.ReadUint64()
}
func (r *RPCReadSectorRequest) maxLen() int { return sizeofPrices + 32 + 8 + 8 }

func (r *RPCReadSectorResponse) encodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.Proof))
	for i := range r.Proof {
		r.Proof[i].EncodeTo(e)
	}
	e.WriteBytes(r.Sector)
}
func (r *RPCReadSectorResponse) decodeFrom(d *types.Decoder) {
	r.Proof = make([]types.Hash256, d.ReadPrefix())
	for i := range r.Proof {
		r.Proof[i].DecodeFrom(d)
	}
	r.Sector = d.ReadBytes()
}
func (r *RPCReadSectorResponse) maxLen() int { return reasonableObjectSize + 8 + SectorSize }

func (r *RPCWriteSectorRequest) encodeTo(e *types.Encoder) {
	r.Prices.EncodeTo(e)
	e.WriteBytes(r.Sector)
}
func (r *RPCWriteSectorRequest) decodeFrom(d *types.Decoder) {
	r.Prices.DecodeFrom(d)
	r.Sector = d.ReadBytes()
}
func (r *RPCWriteSectorRequest) maxLen() int { return sizeofPrices + 8 + SectorSize }

func (r *RPCWriteSectorResponse) encodeTo(e *types.Encoder) {
	r.Root.EncodeTo(e)
}
func (r *RPCWriteSectorResponse) decodeFrom(d *types.Decoder) {
	r.Root.DecodeFrom(d)
}
func (r *RPCWriteSectorResponse) maxLen() int { return 32 }

func (r *RPCSectorRootsRequest) encodeTo(e *types.Encoder) {
	r.Prices.EncodeTo(e)
	e.WriteUint64(r.Offset)
	e.WriteUint64(r.Length)
}
func (r *RPCSectorRootsRequest) decodeFrom(d *types.Decoder) {
	r.Prices.DecodeFrom(d)
	r.Offset = d.ReadUint64()
	r.Length = d.ReadUint64()
}
func (r *RPCSectorRootsRequest) maxLen() int { return sizeofPrices + 8 + 8 }

func (r *RPCSectorRootsResponse) encodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.Roots))
	for i := range r.Roots {
		r.Roots[i].EncodeTo(e)
	}
}
func (r *RPCSectorRootsResponse) decodeFrom(d *types.Decoder) {
	r.Roots = make([]types.Hash256, d.ReadPrefix())
	for i := range r.Roots {
		r.Roots[i].DecodeFrom(d)
	}
}
func (r *RPCSectorRootsResponse) maxLen() int { return reasonableObjectSize } // TODO: possibly larger?

func (r *RPCAccountBalanceRequest) encodeTo(e *types.Encoder) {
	r.Account.EncodeTo(e)
}
func (r *RPCAccountBalanceRequest) decodeFrom(d *types.Decoder) {
	r.Account.DecodeFrom(d)
}
func (r *RPCAccountBalanceRequest) maxLen() int { return 32 }

func (r *RPCAccountBalanceResponse) encodeTo(e *types.Encoder) {
	types.V2Currency(r.Balance).EncodeTo(e)
}
func (r *RPCAccountBalanceResponse) decodeFrom(d *types.Decoder) {
	(*types.V2Currency)(&r.Balance).DecodeFrom(d)
}
func (r *RPCAccountBalanceResponse) maxLen() int { return sizeofCurrency }

func (r *RPCFundAccountRequest) encodeTo(e *types.Encoder) {
	r.Account.EncodeTo(e)
	r.ContractID.EncodeTo(e)
	types.V2Currency(r.Amount).EncodeTo(e)
	r.RenterSignature.EncodeTo(e)
}
func (r *RPCFundAccountRequest) decodeFrom(d *types.Decoder) {
	r.Account.DecodeFrom(d)
	r.ContractID.DecodeFrom(d)
	(*types.V2Currency)(&r.Amount).DecodeFrom(d)
	r.RenterSignature.DecodeFrom(d)
}
func (r *RPCFundAccountRequest) maxLen() int { return 32 + 32 + sizeofCurrency + sizeofSignature }

func (r *RPCFundAccountResponse) encodeTo(e *types.Encoder) {
	types.V2Currency(r.NewBalance).EncodeTo(e)
	r.HostSignature.EncodeTo(e)
}
func (r *RPCFundAccountResponse) decodeFrom(d *types.Decoder) {
	(*types.V2Currency)(&r.NewBalance).DecodeFrom(d)
	r.HostSignature.DecodeFrom(d)
}
func (r *RPCFundAccountResponse) maxLen() int { return sizeofCurrency + sizeofSignature }
