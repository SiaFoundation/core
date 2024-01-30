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
	e.WriteString(hs.Version)
	e.WritePrefix(len(hs.Protocols))
	for i := range hs.Protocols {
		e.WriteString(hs.Protocols[i].Name)
		e.WriteString(hs.Protocols[i].Address)
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
	hs.Version = d.ReadString()
	hs.Protocols = make([]Protocol, d.ReadPrefix())
	for i := range hs.Protocols {
		hs.Protocols[i].Name = d.ReadString()
		hs.Protocols[i].Address = d.ReadString()
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

const reasonableObjectSize = 10 * 1024

func sizeof(v types.EncoderTo) int {
	var buf bytes.Buffer
	e := types.NewEncoder(&buf)
	v.EncodeTo(e)
	e.Flush()
	return buf.Len()
}

var sizeofPrices = sizeof(HostPrices{})
var sizeofContract = sizeof(types.V2FileContract{})
var sizeofRenewal = sizeof(types.V2FileContractRenewal{})

// An RPC can be sent or received via a Transport.
type RPC interface {
	encodeRequest(e *types.Encoder)
	decodeRequest(d *types.Decoder)
	maxRequestLen() int
	encodeResponse(e *types.Encoder)
	decodeResponse(d *types.Decoder)
	maxResponseLen() int
}

func (RPCSettings) encodeRequest(*types.Encoder) {}
func (RPCSettings) decodeRequest(*types.Decoder) {}
func (RPCSettings) maxRequestLen() int           { return 0 }
func (r *RPCSettings) encodeResponse(e *types.Encoder) {
	r.Settings.EncodeTo(e)
}
func (r *RPCSettings) decodeResponse(d *types.Decoder) {
	r.Settings.DecodeFrom(d)
}
func (r *RPCSettings) maxResponseLen() int { return reasonableObjectSize }

func (r *RPCFormContract) encodeRequest(e *types.Encoder) {
	r.Prices.EncodeTo(e)
	r.Contract.EncodeTo(e)
	e.WritePrefix(len(r.RenterInputs))
	for i := range r.RenterInputs {
		r.RenterInputs[i].EncodeTo(e)
	}
}
func (r *RPCFormContract) decodeRequest(d *types.Decoder) {
	r.Prices.DecodeFrom(d)
	r.Contract.DecodeFrom(d)
	r.RenterInputs = make([]types.V2SiacoinInput, d.ReadPrefix())
	for i := range r.RenterInputs {
		r.RenterInputs[i].DecodeFrom(d)
	}
}
func (r *RPCFormContract) maxRequestLen() int { return reasonableObjectSize }

func (r *RPCFormContract) encodeResponse(e *types.Encoder) {
	e.WritePrefix(len(r.HostInputs))
	for i := range r.HostInputs {
		r.HostInputs[i].EncodeTo(e)
	}
}
func (r *RPCFormContract) decodeResponse(d *types.Decoder) {
	r.HostInputs = make([]types.V2SiacoinInput, d.ReadPrefix())
	for i := range r.HostInputs {
		r.HostInputs[i].DecodeFrom(d)
	}
}
func (r *RPCFormContract) maxResponseLen() int { return reasonableObjectSize }

func (r *RPCSignatures) encodeRequest(e *types.Encoder) {
	r.RenterSignature.EncodeTo(e)
}
func (r *RPCSignatures) decodeRequest(d *types.Decoder) {
	r.RenterSignature.DecodeFrom(d)
}
func (r *RPCSignatures) maxRequestLen() int { return 64 }

func (r *RPCSignatures) encodeResponse(e *types.Encoder) {
	r.HostSignature.EncodeTo(e)
}
func (r *RPCSignatures) decodeResponse(d *types.Decoder) {
	r.HostSignature.DecodeFrom(d)
}
func (r *RPCSignatures) maxResponseLen() int { return 64 }

func (r *RPCReviseContract) encodeRequest(e *types.Encoder) {
	r.Prices.EncodeTo(e)
	r.Revision.EncodeTo(e)
}
func (r *RPCReviseContract) decodeRequest(d *types.Decoder) {
	r.Prices.DecodeFrom(d)
	r.Revision.DecodeFrom(d)
}
func (r *RPCReviseContract) maxRequestLen() int { return sizeofPrices + sizeofContract } // ??

func (r *RPCReviseContract) encodeResponse(e *types.Encoder) {
	r.Revision.HostSignature.EncodeTo(e)
}
func (r *RPCReviseContract) decodeResponse(d *types.Decoder) {
	r.Revision.HostSignature.DecodeFrom(d)
}
func (r *RPCReviseContract) maxResponseLen() int { return 64 }

func (r *RPCRenewContract) encodeRequest(e *types.Encoder) {
	r.Prices.EncodeTo(e)
	r.Renewal.EncodeTo(e)
}
func (r *RPCRenewContract) decodeRequest(d *types.Decoder) {
	r.Prices.DecodeFrom(d)
	r.Renewal.DecodeFrom(d)
}
func (r *RPCRenewContract) maxRequestLen() int { return sizeofPrices + sizeofRenewal }

func (r *RPCRenewContract) encodeResponse(e *types.Encoder) {
	r.Renewal.HostSignature.EncodeTo(e)
}
func (r *RPCRenewContract) decodeResponse(d *types.Decoder) {
	r.Renewal.HostSignature.DecodeFrom(d)
}
func (r *RPCRenewContract) maxResponseLen() int { return 64 }

func (r *RPCLatestRevision) encodeRequest(e *types.Encoder) {
	r.ContractID.EncodeTo(e)
}
func (r *RPCLatestRevision) decodeRequest(d *types.Decoder) {
	r.ContractID.DecodeFrom(d)
}
func (r *RPCLatestRevision) maxRequestLen() int { return 32 }

func (r *RPCLatestRevision) encodeResponse(e *types.Encoder) {
	r.Contract.EncodeTo(e)
}
func (r *RPCLatestRevision) decodeResponse(d *types.Decoder) {
	r.Contract.DecodeFrom(d)
}
func (r *RPCLatestRevision) maxResponseLen() int { return sizeofContract }

func (r *RPCReadSector) encodeRequest(e *types.Encoder) {
	r.Prices.EncodeTo(e)
	r.Root.EncodeTo(e)
	e.WriteUint64(r.Offset)
	e.WriteUint64(r.Length)
}
func (r *RPCReadSector) decodeRequest(d *types.Decoder) {
	r.Prices.DecodeFrom(d)
	r.Root.DecodeFrom(d)
	r.Offset = d.ReadUint64()
	r.Length = d.ReadUint64()
}
func (r *RPCReadSector) maxRequestLen() int { return sizeofPrices + 32 + 8 + 8 }

func (r *RPCReadSector) encodeResponse(e *types.Encoder) {
	e.WriteBytes(r.Sector)
}
func (r *RPCReadSector) decodeResponse(d *types.Decoder) {
	r.Sector = d.ReadBytes()
}
func (r *RPCReadSector) maxResponseLen() int { return 8 + SectorSize }

func (r *RPCWriteSector) encodeRequest(e *types.Encoder) {
	r.Prices.EncodeTo(e)
	e.WriteBytes(r.Sector)
}
func (r *RPCWriteSector) decodeRequest(d *types.Decoder) {
	r.Prices.DecodeFrom(d)
	r.Sector = d.ReadBytes()
}
func (r *RPCWriteSector) maxRequestLen() int { return sizeofPrices + 8 + SectorSize }

func (r *RPCWriteSector) encodeResponse(e *types.Encoder) {
	r.Root.EncodeTo(e)
}
func (r *RPCWriteSector) decodeResponse(d *types.Decoder) {
	r.Root.DecodeFrom(d)
}
func (r *RPCWriteSector) maxResponseLen() int { return 32 }

func (r *RPCModifySectors) encodeRequest(e *types.Encoder) {
	e.WritePrefix(len(r.Actions))
	for i := range r.Actions {
		r.Actions[i].EncodeTo(e)
	}
}
func (r *RPCModifySectors) decodeRequest(d *types.Decoder) {
	r.Actions = make([]WriteAction, d.ReadPrefix())
	for i := range r.Actions {
		r.Actions[i].DecodeFrom(d)
	}
}
func (r *RPCModifySectors) maxRequestLen() int { return reasonableObjectSize }

func (r *RPCModifySectors) encodeResponse(e *types.Encoder) {
	e.WritePrefix(len(r.Proof))
	for i := range r.Proof {
		r.Proof[i].EncodeTo(e)
	}
}
func (r *RPCModifySectors) decodeResponse(d *types.Decoder) {
	r.Proof = make([]types.Hash256, d.ReadPrefix())
	for i := range r.Proof {
		r.Proof[i].DecodeFrom(d)
	}
}
func (r *RPCModifySectors) maxResponseLen() int { return reasonableObjectSize }

func (r *RPCSectorRoots) encodeRequest(e *types.Encoder) {
	r.Prices.EncodeTo(e)
	e.WriteUint64(r.Offset)
	e.WriteUint64(r.Length)
}
func (r *RPCSectorRoots) decodeRequest(d *types.Decoder) {
	r.Prices.DecodeFrom(d)
	r.Offset = d.ReadUint64()
	r.Length = d.ReadUint64()
}
func (r *RPCSectorRoots) maxRequestLen() int { return sizeofPrices + 8 + 8 }

func (r *RPCSectorRoots) encodeResponse(e *types.Encoder) {
	e.WritePrefix(len(r.Roots))
	for i := range r.Roots {
		r.Roots[i].EncodeTo(e)
	}
}
func (r *RPCSectorRoots) decodeResponse(d *types.Decoder) {
	r.Roots = make([]types.Hash256, d.ReadPrefix())
	for i := range r.Roots {
		r.Roots[i].DecodeFrom(d)
	}
}
func (r *RPCSectorRoots) maxResponseLen() int { return reasonableObjectSize } // ??

func (r *RPCAccountBalance) encodeRequest(e *types.Encoder) {
	r.Account.EncodeTo(e)
}
func (r *RPCAccountBalance) decodeRequest(d *types.Decoder) {
	r.Account.DecodeFrom(d)
}
func (r *RPCAccountBalance) maxRequestLen() int { return 32 }

func (r *RPCAccountBalance) encodeResponse(e *types.Encoder) {
	types.V2Currency(r.Balance).EncodeTo(e)
}
func (r *RPCAccountBalance) decodeResponse(d *types.Decoder) {
	(*types.V2Currency)(&r.Balance).DecodeFrom(d)
}
func (r *RPCAccountBalance) maxResponseLen() int { return 16 }

func (r *RPCFundAccount) encodeRequest(e *types.Encoder) {
	r.Account.EncodeTo(e)
	r.Revision.EncodeTo(e)
	r.RenterSignature.EncodeTo(e)
}
func (r *RPCFundAccount) decodeRequest(d *types.Decoder) {
	r.Account.DecodeFrom(d)
	r.Revision.DecodeFrom(d)
	r.RenterSignature.DecodeFrom(d)
}
func (r *RPCFundAccount) maxRequestLen() int { return 32 + sizeofContract + 64 }

func (r *RPCFundAccount) encodeResponse(e *types.Encoder) {
	r.HostSignature.EncodeTo(e)
	types.V2Currency(r.NewBalance).EncodeTo(e)
}
func (r *RPCFundAccount) decodeResponse(d *types.Decoder) {
	r.HostSignature.DecodeFrom(d)
	(*types.V2Currency)(&r.NewBalance).DecodeFrom(d)
}
func (r *RPCFundAccount) maxResponseLen() int { return 64 + 16 }

// RPC IDs
var (
	idSettings       = types.NewSpecifier("Settings")
	idFormContract   = types.NewSpecifier("FormContract")
	idSignatures     = types.NewSpecifier("Signatures")
	idReviseContract = types.NewSpecifier("ReviseContract")
	idRenewContract  = types.NewSpecifier("RenewContract")
	idLatestRevision = types.NewSpecifier("LatestRevision")
	idReadSector     = types.NewSpecifier("ReadSector")
	idWriteSector    = types.NewSpecifier("WriteSector")
	idModifySectors  = types.NewSpecifier("ModifySectors")
	idSectorRoots    = types.NewSpecifier("SectorRoots")
	idAccountBalance = types.NewSpecifier("AccountBalance")
	idFundAccount    = types.NewSpecifier("FundAccount")
)

func idForRPC(r RPC) types.Specifier {
	switch r.(type) {
	case *RPCSettings:
		return idSettings
	case *RPCFormContract:
		return idFormContract
	case *RPCSignatures:
		return idSignatures
	case *RPCReviseContract:
		return idReviseContract
	case *RPCRenewContract:
		return idRenewContract
	case *RPCLatestRevision:
		return idLatestRevision
	case *RPCReadSector:
		return idReadSector
	case *RPCWriteSector:
		return idWriteSector
	case *RPCModifySectors:
		return idModifySectors
	case *RPCSectorRoots:
		return idSectorRoots
	case *RPCAccountBalance:
		return idAccountBalance
	case *RPCFundAccount:
		return idFundAccount
	default:
		panic(fmt.Sprintf("unhandled RPC type %T", r))
	}
}

// RPCforID returns the RPC type corresponding to the given ID.
func RPCforID(id types.Specifier) RPC {
	switch id {
	case idSettings:
		return new(RPCSettings)
	case idFormContract:
		return new(RPCFormContract)
	case idSignatures:
		return new(RPCSignatures)
	case idReviseContract:
		return new(RPCReviseContract)
	case idRenewContract:
		return new(RPCRenewContract)
	case idLatestRevision:
		return new(RPCLatestRevision)
	case idReadSector:
		return new(RPCReadSector)
	case idWriteSector:
		return new(RPCWriteSector)
	case idModifySectors:
		return new(RPCModifySectors)
	case idSectorRoots:
		return new(RPCSectorRoots)
	case idAccountBalance:
		return new(RPCAccountBalance)
	case idFundAccount:
		return new(RPCFundAccount)
	default:
		return nil
	}
}
