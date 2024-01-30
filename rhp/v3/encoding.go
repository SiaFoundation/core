package rhp

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"go.sia.tech/core/types"
)

// EncodeTo implements ProtocolObject.
func (r *RPCError) EncodeTo(e *types.Encoder) {
	r.Type.EncodeTo(e)
	e.WriteBytes(r.Data)
	e.WriteString(r.Description)
}

// DecodeFrom implements ProtocolObject.
func (r *RPCError) DecodeFrom(d *types.Decoder) {
	r.Type.DecodeFrom(d)
	r.Data = d.ReadBytes()
	r.Description = d.ReadString()
}

// EncodeTo implements ProtocolObject.
func (s *SettingsID) EncodeTo(e *types.Encoder) { e.Write(s[:]) }

// DecodeFrom implements ProtocolObject.
func (s *SettingsID) DecodeFrom(d *types.Decoder) { d.Read(s[:]) }

// String implements fmt.Stringer.
func (s SettingsID) String() string {
	return hex.EncodeToString(s[:])
}

// LoadString loads the unique id from the given string.
func (s *SettingsID) LoadString(input string) error {
	if len(input) != len(s)*2 {
		return errors.New("incorrect length")
	}
	uidBytes, err := hex.DecodeString(input)
	if err != nil {
		return errors.New("could not unmarshal hash: " + err.Error())
	}
	copy(s[:], uidBytes)
	return nil
}

// MarshalJSON marshals an id as a hex string.
func (s SettingsID) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON decodes the json hex string of the id.
func (s *SettingsID) UnmarshalJSON(b []byte) error {
	if len(b) != len(SettingsID{})*2+2 {
		return errors.New("incorrect length")
	}
	return s.LoadString(string(bytes.Trim(b, `"`)))
}

// EncodeTo implements ProtocolObject.
func (resp *rpcResponse) EncodeTo(e *types.Encoder) {
	e.WriteBool(resp.err != nil)
	if resp.err != nil {
		resp.err.EncodeTo(e)
		return
	}
	resp.data.EncodeTo(e)
}

// DecodeFrom implements ProtocolObject.
func (resp *rpcResponse) DecodeFrom(d *types.Decoder) {
	if d.ReadBool() {
		resp.err = new(RPCError)
		resp.err.DecodeFrom(d)
		return
	}
	resp.data.DecodeFrom(d)
}

// EncodeTo implements ProtocolObject.
func (a *Account) EncodeTo(e *types.Encoder) {
	var uk types.UnlockKey
	if *a != ZeroAccount {
		uk.Algorithm = types.SpecifierEd25519
		uk.Key = a[:]
	}
	uk.EncodeTo(e)
}

// DecodeFrom implements ProtocolObject.
func (a *Account) DecodeFrom(d *types.Decoder) {
	var spk types.UnlockKey
	spk.DecodeFrom(d)
	if spk.Algorithm == (types.Specifier{}) && len(spk.Key) == 0 {
		*a = ZeroAccount
		return
	} else if spk.Algorithm != types.SpecifierEd25519 {
		d.SetErr(fmt.Errorf("unsupported signature algorithm: %v", spk.Algorithm))
		return
	}
	copy(a[:], spk.Key)
}

// MarshalText implements encoding.TextUnmarshaler.
func (a Account) MarshalText() ([]byte, error) { return types.PublicKey(a).MarshalText() }

// UnmarshalText implements encoding.TextUnmarshaler.
func (a *Account) UnmarshalText(b []byte) error { return (*types.PublicKey)(a).UnmarshalText(b) }

// String implements fmt.Stringer.
func (a Account) String() string { return types.PublicKey(a).String() }

// EncodeTo implements ProtocolObject.
func (r *PayByEphemeralAccountRequest) EncodeTo(e *types.Encoder) {
	r.Account.EncodeTo(e)
	e.WriteUint64(r.Expiry)
	types.V1Currency(r.Amount).EncodeTo(e)
	e.Write(r.Nonce[:])
	r.Signature.EncodeTo(e)
	e.WriteUint64(uint64(r.Priority))
}

// DecodeFrom implements ProtocolObject.
func (r *PayByEphemeralAccountRequest) DecodeFrom(d *types.Decoder) {
	r.Account.DecodeFrom(d)
	r.Expiry = d.ReadUint64()
	(*types.V1Currency)(&r.Amount).DecodeFrom(d)
	d.Read(r.Nonce[:])
	r.Signature.DecodeFrom(d)
	r.Priority = int64(d.ReadUint64())
}

// EncodeTo implements ProtocolObject.
func (r *PayByContractRequest) EncodeTo(e *types.Encoder) {
	r.ContractID.EncodeTo(e)
	e.WriteUint64(r.RevisionNumber)
	e.WritePrefix(len(r.ValidProofValues))
	for i := range r.ValidProofValues {
		types.V1Currency(r.ValidProofValues[i]).EncodeTo(e)
	}
	e.WritePrefix(len(r.MissedProofValues))
	for i := range r.MissedProofValues {
		types.V1Currency(r.MissedProofValues[i]).EncodeTo(e)
	}
	r.RefundAccount.EncodeTo(e)
	e.WriteBytes(r.Signature[:])
}

// DecodeFrom implements ProtocolObject.
func (r *PayByContractRequest) DecodeFrom(d *types.Decoder) {
	r.ContractID.DecodeFrom(d)
	r.RevisionNumber = d.ReadUint64()
	r.ValidProofValues = make([]types.Currency, d.ReadPrefix())
	for i := range r.ValidProofValues {
		(*types.V1Currency)(&r.ValidProofValues[i]).DecodeFrom(d)
	}
	r.MissedProofValues = make([]types.Currency, d.ReadPrefix())
	for i := range r.MissedProofValues {
		(*types.V1Currency)(&r.MissedProofValues[i]).DecodeFrom(d)
	}
	r.RefundAccount.DecodeFrom(d)
	copy(r.Signature[:], d.ReadBytes())
}

// EncodeTo implements ProtocolObject.
func (r *PaymentResponse) EncodeTo(e *types.Encoder) {
	r.Signature.EncodeTo(e)
}

// DecodeFrom implements ProtocolObject.
func (r *PaymentResponse) DecodeFrom(d *types.Decoder) {
	r.Signature.DecodeFrom(d)
}

// EncodeTo implements ProtocolObject.
func (RPCPriceTableResponse) EncodeTo(e *types.Encoder) {}

// DecodeFrom implements ProtocolObject.
func (RPCPriceTableResponse) DecodeFrom(d *types.Decoder) {}

// EncodeTo implements ProtocolObject.
func (r *RPCUpdatePriceTableResponse) EncodeTo(e *types.Encoder) {
	e.WriteBytes(r.PriceTableJSON)
}

// DecodeFrom implements ProtocolObject.
func (r *RPCUpdatePriceTableResponse) DecodeFrom(d *types.Decoder) {
	r.PriceTableJSON = d.ReadBytes()
}

// EncodeTo implements ProtocolObject.
func (r *RPCFundAccountRequest) EncodeTo(e *types.Encoder) {
	r.Account.EncodeTo(e)
}

// DecodeFrom implements ProtocolObject.
func (r *RPCFundAccountRequest) DecodeFrom(d *types.Decoder) {
	r.Account.DecodeFrom(d)
}

// EncodeTo implements ProtocolObject.
func (r *FundAccountReceipt) EncodeTo(e *types.Encoder) {
	r.Host.EncodeTo(e)
	r.Account.EncodeTo(e)
	types.V1Currency(r.Amount).EncodeTo(e)
	e.WriteTime(r.Timestamp)
}

// DecodeFrom implements ProtocolObject.
func (r *FundAccountReceipt) DecodeFrom(d *types.Decoder) {
	r.Host.DecodeFrom(d)
	r.Account.DecodeFrom(d)
	(*types.V1Currency)(&r.Amount).DecodeFrom(d)
	r.Timestamp = d.ReadTime()
}

// EncodeTo implements ProtocolObject.
func (r *RPCFundAccountResponse) EncodeTo(e *types.Encoder) {
	types.V1Currency(r.Balance).EncodeTo(e)
	r.Receipt.EncodeTo(e)
	r.Signature.EncodeTo(e)
}

// DecodeFrom implements ProtocolObject.
func (r *RPCFundAccountResponse) DecodeFrom(d *types.Decoder) {
	(*types.V1Currency)(&r.Balance).DecodeFrom(d)
	r.Receipt.DecodeFrom(d)
	r.Signature.DecodeFrom(d)
}

// EncodeTo implements ProtocolObject.
func (r *RPCAccountBalanceRequest) EncodeTo(e *types.Encoder) {
	r.Account.EncodeTo(e)
}

// DecodeFrom implements ProtocolObject.
func (r *RPCAccountBalanceRequest) DecodeFrom(d *types.Decoder) {
	r.Account.DecodeFrom(d)
}

// EncodeTo implements ProtocolObject.
func (r *RPCAccountBalanceResponse) EncodeTo(e *types.Encoder) {
	types.V1Currency(r.Balance).EncodeTo(e)
}

// DecodeFrom implements ProtocolObject.
func (r *RPCAccountBalanceResponse) DecodeFrom(d *types.Decoder) {
	(*types.V1Currency)(&r.Balance).DecodeFrom(d)
}

// EncodeTo implements ProtocolObject.
func (r *RPCExecuteProgramRequest) EncodeTo(e *types.Encoder) {
	r.FileContractID.EncodeTo(e)
	e.WritePrefix(len(r.Program))

	var buf bytes.Buffer
	ie := types.NewEncoder(&buf)
	for _, instr := range r.Program {
		instructionID(instr).EncodeTo(e)
		buf.Reset()
		instr.EncodeTo(ie)
		ie.Flush()
		e.WriteBytes(buf.Bytes())
	}
	e.WriteBytes(r.ProgramData)
}

// DecodeFrom implements ProtocolObject.
func (r *RPCExecuteProgramRequest) DecodeFrom(d *types.Decoder) {
	r.FileContractID.DecodeFrom(d)
	r.Program = make([]Instruction, d.ReadPrefix())
	for i := range r.Program {
		var id types.Specifier
		id.DecodeFrom(d)
		r.Program[i] = instructionForID(id, d.ReadUint64())
		if r.Program[i] == nil {
			d.SetErr(fmt.Errorf("unrecognized instruction id: %q", id))
			return
		}
		if r.Program[i].DecodeFrom(d); d.Err() != nil {
			return
		}
	}
	r.ProgramData = d.ReadBytes()
}

// EncodeTo implements ProtocolObject.
func (r *RPCExecuteProgramResponse) EncodeTo(e *types.Encoder) {
	types.V1Currency(r.AdditionalCollateral).EncodeTo(e)
	e.WriteUint64(r.OutputLength)
	r.NewMerkleRoot.EncodeTo(e)
	e.WriteUint64(r.NewSize)
	e.WritePrefix(len(r.Proof))
	for i := range r.Proof {
		r.Proof[i].EncodeTo(e)
	}
	var errString string
	if r.Error != nil {
		errString = r.Error.Error()
	}
	e.WriteString(errString)
	types.V1Currency(r.TotalCost).EncodeTo(e)
	types.V1Currency(r.FailureRefund).EncodeTo(e)
	e.Write(r.Output)
}

// DecodeFrom implements ProtocolObject.
func (r *RPCExecuteProgramResponse) DecodeFrom(d *types.Decoder) {
	(*types.V1Currency)(&r.AdditionalCollateral).DecodeFrom(d)
	r.OutputLength = d.ReadUint64()
	r.NewMerkleRoot.DecodeFrom(d)
	r.NewSize = d.ReadUint64()
	r.Proof = make([]types.Hash256, d.ReadPrefix())
	for i := range r.Proof {
		r.Proof[i].DecodeFrom(d)
	}
	if s := d.ReadString(); s != "" {
		r.Error = errors.New(s)
	}
	(*types.V1Currency)(&r.TotalCost).DecodeFrom(d)
	(*types.V1Currency)(&r.FailureRefund).DecodeFrom(d)
	r.Output = make([]byte, r.OutputLength)
	d.Read(r.Output)
}

// EncodeTo implements ProtocolObject.
func (r *RPCFinalizeProgramRequest) EncodeTo(e *types.Encoder) {
	e.WriteBytes(r.Signature[:])
	e.WriteUint64(r.RevisionNumber)
	e.WritePrefix(len(r.ValidProofValues))
	for _, v := range r.ValidProofValues {
		types.V1Currency(v).EncodeTo(e)
	}
	e.WritePrefix(len(r.MissedProofValues))
	for _, v := range r.MissedProofValues {
		types.V1Currency(v).EncodeTo(e)
	}
}

// DecodeFrom implements ProtocolObject.
func (r *RPCFinalizeProgramRequest) DecodeFrom(d *types.Decoder) {
	copy(r.Signature[:], d.ReadBytes())
	r.RevisionNumber = d.ReadUint64()
	r.ValidProofValues = make([]types.Currency, d.ReadPrefix())
	for i := range r.ValidProofValues {
		(*types.V1Currency)(&r.ValidProofValues[i]).DecodeFrom(d)
	}
	r.MissedProofValues = make([]types.Currency, d.ReadPrefix())
	for i := range r.MissedProofValues {
		(*types.V1Currency)(&r.MissedProofValues[i]).DecodeFrom(d)
	}
}

// EncodeTo implements ProtocolObject.
func (r *RPCFinalizeProgramResponse) EncodeTo(e *types.Encoder) {
	e.WriteBytes(r.Signature[:])
}

// DecodeFrom implements ProtocolObject.
func (r *RPCFinalizeProgramResponse) DecodeFrom(d *types.Decoder) {
	copy(r.Signature[:], d.ReadBytes())
}

// EncodeTo implements ProtocolObject.
func (r *RPCLatestRevisionRequest) EncodeTo(e *types.Encoder) {
	r.ContractID.EncodeTo(e)
}

// DecodeFrom implements ProtocolObject.
func (r *RPCLatestRevisionRequest) DecodeFrom(d *types.Decoder) {
	r.ContractID.DecodeFrom(d)
}

// EncodeTo implements ProtocolObject.
func (r *RPCLatestRevisionResponse) EncodeTo(e *types.Encoder) {
	r.Revision.EncodeTo(e)
}

// DecodeFrom implements ProtocolObject.
func (r *RPCLatestRevisionResponse) DecodeFrom(d *types.Decoder) {
	r.Revision.DecodeFrom(d)
}

// EncodeTo implements ProtocolObject.
func (r *RPCRenewContractRequest) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.TransactionSet))
	for i := range r.TransactionSet {
		r.TransactionSet[i].EncodeTo(e)
	}
	r.RenterKey.EncodeTo(e)
	r.FinalRevisionSignature.EncodeTo(e)
}

// DecodeFrom implements ProtocolObject
func (r *RPCRenewContractRequest) DecodeFrom(d *types.Decoder) {
	r.TransactionSet = make([]types.Transaction, d.ReadPrefix())
	for i := range r.TransactionSet {
		r.TransactionSet[i].DecodeFrom(d)
	}
	r.RenterKey.DecodeFrom(d)
	r.FinalRevisionSignature.DecodeFrom(d)
}

// EncodeTo implements ProtocolObject
func (r *RPCRenewContractHostAdditions) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.Parents))
	for i := range r.Parents {
		r.Parents[i].EncodeTo(e)
	}
	e.WritePrefix(len(r.SiacoinInputs))
	for i := range r.SiacoinInputs {
		r.SiacoinInputs[i].EncodeTo(e)
	}
	e.WritePrefix(len(r.SiacoinOutputs))
	for i := range r.SiacoinOutputs {
		types.V1SiacoinOutput(r.SiacoinOutputs[i]).EncodeTo(e)
	}
	r.FinalRevisionSignature.EncodeTo(e)
}

// DecodeFrom implements ProtocolObject
func (r *RPCRenewContractHostAdditions) DecodeFrom(d *types.Decoder) {
	r.Parents = make([]types.Transaction, d.ReadPrefix())
	for i := range r.Parents {
		r.Parents[i].DecodeFrom(d)
	}
	r.SiacoinInputs = make([]types.SiacoinInput, d.ReadPrefix())
	for i := range r.SiacoinInputs {
		r.SiacoinInputs[i].DecodeFrom(d)
	}
	r.SiacoinOutputs = make([]types.SiacoinOutput, d.ReadPrefix())
	for i := range r.SiacoinOutputs {
		(*types.V1SiacoinOutput)(&r.SiacoinOutputs[i]).DecodeFrom(d)
	}
	r.FinalRevisionSignature.DecodeFrom(d)
}

// EncodeTo implements ProtocolObject
func (r *RPCRenewSignatures) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.TransactionSignatures))
	for i := range r.TransactionSignatures {
		r.TransactionSignatures[i].EncodeTo(e)
	}
	r.RevisionSignature.EncodeTo(e)
}

// DecodeFrom implements ProtocolObject
func (r *RPCRenewSignatures) DecodeFrom(d *types.Decoder) {
	r.TransactionSignatures = make([]types.TransactionSignature, d.ReadPrefix())
	for i := range r.TransactionSignatures {
		r.TransactionSignatures[i].DecodeFrom(d)
	}
	r.RevisionSignature.DecodeFrom(d)
}

func instructionID(instr Instruction) types.Specifier {
	switch instr.(type) {
	case *InstrAppendSector:
		return idInstrAppendSector
	case *InstrAppendSectorRoot:
		return idInstrAppendSectorRoot
	case *InstrDropSectors:
		return idInstrDropSectors
	case *InstrHasSector:
		return idInstrHasSector
	case *InstrStoreSector:
		return idInstrStoreSector
	case *InstrUpdateSector:
		return idInstrUpdateSector
	case *InstrReadOffset:
		return idInstrReadOffset
	case *InstrReadSector:
		return idInstrReadSector
	case *InstrRevision:
		return idInstrContractRevision
	case *InstrSwapSector:
		return idInstrSwapSector
	case *InstrUpdateRegistry, *InstrUpdateRegistryNoType:
		return idInstrUpdateRegistry
	case *InstrReadRegistry, *InstrReadRegistryNoVersion:
		return idInstrReadRegistry
	default:
		panic(fmt.Sprintf("unhandled instruction type: %T", instr))
	}
}

func instructionForID(id types.Specifier, argsLen uint64) Instruction {
	switch id {
	case idInstrAppendSector:
		return new(InstrAppendSector)
	case idInstrAppendSectorRoot:
		return new(InstrAppendSectorRoot)
	case idInstrDropSectors:
		return new(InstrDropSectors)
	case idInstrHasSector:
		return new(InstrHasSector)
	case idInstrStoreSector:
		return new(InstrStoreSector)
	case idInstrUpdateSector:
		return new(InstrUpdateSector)
	case idInstrReadOffset:
		return new(InstrReadOffset)
	case idInstrReadSector:
		return new(InstrReadSector)
	case idInstrContractRevision:
		return new(InstrRevision)
	case idInstrSwapSector:
		return new(InstrSwapSector)
	case idInstrUpdateRegistry:
		if argsLen == 56 { // special handling for pre-1.5.7 update registry instructions
			return new(InstrUpdateRegistryNoType)
		}
		return new(InstrUpdateRegistry)
	case idInstrReadRegistry:
		if argsLen == 24 { // special handling for pre-1.5.7 read registry instructions
			return new(InstrReadRegistryNoVersion)
		}
		return new(InstrReadRegistry)
	default:
		return nil
	}
}
