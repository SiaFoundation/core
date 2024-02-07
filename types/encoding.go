package types

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
)

// An Encoder writes Sia objects to an underlying stream.
type Encoder struct {
	w   io.Writer
	buf [1024]byte
	n   int
	err error
}

// Flush writes any pending data to the underlying stream. It returns the first
// error encountered by the Encoder.
func (e *Encoder) Flush() error {
	if e.err == nil && e.n > 0 {
		_, e.err = e.w.Write(e.buf[:e.n])
		e.n = 0
	}
	return e.err
}

// Write implements io.Writer.
func (e *Encoder) Write(p []byte) (int, error) {
	lenp := len(p)
	for e.err == nil && len(p) > 0 {
		if e.n == len(e.buf) {
			e.Flush()
		}
		c := copy(e.buf[e.n:], p)
		e.n += c
		p = p[c:]
	}
	return lenp, e.err
}

// WriteBool writes a bool value to the underlying stream.
func (e *Encoder) WriteBool(b bool) {
	var buf [1]byte
	if b {
		buf[0] = 1
	}
	e.Write(buf[:])
}

// WriteUint8 writes a uint8 value to the underlying stream.
func (e *Encoder) WriteUint8(u uint8) {
	e.Write([]byte{u})
}

// WriteUint64 writes a uint64 value to the underlying stream.
func (e *Encoder) WriteUint64(u uint64) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], u)
	e.Write(buf[:])
}

// WritePrefix writes a length prefix to the underlying stream.
func (e *Encoder) WritePrefix(i int) { e.WriteUint64(uint64(i)) }

// WriteTime writes a time.Time value to the underlying stream.
func (e *Encoder) WriteTime(t time.Time) { e.WriteUint64(uint64(t.Unix())) }

// WriteBytes writes a length-prefixed []byte to the underlying stream.
func (e *Encoder) WriteBytes(b []byte) {
	e.WritePrefix(len(b))
	e.Write(b)
}

// WriteString writes a length-prefixed string to the underlying stream.
func (e *Encoder) WriteString(s string) {
	e.WriteBytes([]byte(s))
}

// Reset resets the Encoder to write to w. Any unflushed data, along with any
// error previously encountered, is discarded.
func (e *Encoder) Reset(w io.Writer) {
	e.w = w
	e.n = 0
	e.err = nil
}

// NewEncoder returns an Encoder that wraps the provided stream.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{
		w: w,
	}
}

// An EncoderTo can encode itself to a stream via an Encoder.
type EncoderTo interface {
	EncodeTo(e *Encoder)
}

// EncoderFunc implements types.EncoderTo with a function.
type EncoderFunc func(*Encoder)

// EncodeTo implements types.EncoderTo.
func (fn EncoderFunc) EncodeTo(e *Encoder) { fn(e) }

// A Decoder reads values from an underlying stream. Callers MUST check
// (*Decoder).Err before using any decoded values.
type Decoder struct {
	lr  io.LimitedReader
	buf [64]byte
	err error
}

// SetErr sets the Decoder's error if it has not already been set. SetErr should
// only be called from DecodeFrom methods.
func (d *Decoder) SetErr(err error) {
	if err != nil && d.err == nil {
		d.err = err
		// clear d.buf so that future reads always return zero
		d.buf = [len(d.buf)]byte{}
	}
}

// Err returns the first error encountered during decoding.
func (d *Decoder) Err() error { return d.err }

// Read implements the io.Reader interface. It always returns an error if fewer
// than len(p) bytes were read.
func (d *Decoder) Read(p []byte) (int, error) {
	n := 0
	for len(p[n:]) > 0 && d.err == nil {
		want := len(p[n:])
		if want > len(d.buf) {
			want = len(d.buf)
		}
		var read int
		read, d.err = io.ReadFull(&d.lr, d.buf[:want])
		n += copy(p[n:], d.buf[:read])
	}
	return n, d.err
}

// ReadBool reads a bool value from the underlying stream.
func (d *Decoder) ReadBool() bool {
	d.Read(d.buf[:1])
	switch d.buf[0] {
	case 0:
		return false
	case 1:
		return true
	default:
		d.SetErr(fmt.Errorf("invalid bool value (%v)", d.buf[0]))
		return false
	}
}

// ReadUint8 reads a uint8 value from the underlying stream.
func (d *Decoder) ReadUint8() uint8 {
	d.Read(d.buf[:1])
	return d.buf[0]
}

// ReadUint64 reads a uint64 value from the underlying stream.
func (d *Decoder) ReadUint64() uint64 {
	d.Read(d.buf[:8])
	return binary.LittleEndian.Uint64(d.buf[:8])
}

// ReadPrefix reads a length prefix from the underlying stream. If the length
// exceeds the number of bytes remaining in the stream, ReadPrefix sets d.Err
// and returns 0.
func (d *Decoder) ReadPrefix() int {
	n := d.ReadUint64()
	if n > uint64(d.lr.N) {
		d.SetErr(fmt.Errorf("encoded object contains invalid length prefix (%v elems > %v bytes left in stream)", n, d.lr.N))
		return 0
	}
	return int(n)
}

// ReadTime reads a time.Time from the underlying stream.
func (d *Decoder) ReadTime() time.Time { return time.Unix(int64(d.ReadUint64()), 0) }

// ReadBytes reads a length-prefixed []byte from the underlying stream.
func (d *Decoder) ReadBytes() []byte {
	b := make([]byte, d.ReadPrefix())
	d.Read(b)
	return b
}

// ReadString reads a length-prefixed string from the underlying stream.
func (d *Decoder) ReadString() string {
	return string(d.ReadBytes())
}

// NewDecoder returns a Decoder that wraps the provided stream.
func NewDecoder(lr io.LimitedReader) *Decoder {
	return &Decoder{
		lr: lr,
	}
}

// A DecoderFrom can decode itself from a stream via a Decoder.
type DecoderFrom interface {
	DecodeFrom(d *Decoder)
}

// DecoderFunc implements types.DecoderTo with a function.
type DecoderFunc func(*Decoder)

// DecodeFrom implements types.DecoderTo.
func (fn DecoderFunc) DecodeFrom(d *Decoder) { fn(d) }

// NewBufDecoder returns a Decoder for the provided byte slice.
func NewBufDecoder(buf []byte) *Decoder {
	return NewDecoder(io.LimitedReader{
		R: bytes.NewReader(buf),
		N: int64(len(buf)),
	})
}

// implementations of EncoderTo and DecoderFrom for core types

// EncodeTo implements types.EncoderTo.
func (h Hash256) EncodeTo(e *Encoder) { e.Write(h[:]) }

// EncodeTo implements types.EncoderTo.
func (id BlockID) EncodeTo(e *Encoder) { e.Write(id[:]) }

// EncodeTo implements types.EncoderTo.
func (id TransactionID) EncodeTo(e *Encoder) { e.Write(id[:]) }

// EncodeTo implements types.EncoderTo.
func (a Address) EncodeTo(e *Encoder) { e.Write(a[:]) }

// EncodeTo implements types.EncoderTo.
func (pk PublicKey) EncodeTo(e *Encoder) { e.Write(pk[:]) }

// EncodeTo implements types.EncoderTo.
func (s Signature) EncodeTo(e *Encoder) { e.Write(s[:]) }

// EncodeTo implements types.EncoderTo.
func (s Specifier) EncodeTo(e *Encoder) { e.Write(s[:]) }

// EncodeTo implements types.EncoderTo.
func (uk UnlockKey) EncodeTo(e *Encoder) {
	uk.Algorithm.EncodeTo(e)
	e.WriteBytes(uk.Key)
}

// EncodeTo implements types.EncoderTo.
func (uc UnlockConditions) EncodeTo(e *Encoder) {
	e.WriteUint64(uc.Timelock)
	e.WritePrefix(len(uc.PublicKeys))
	for _, pk := range uc.PublicKeys {
		pk.EncodeTo(e)
	}
	e.WriteUint64(uc.SignaturesRequired)
}

// V1Currency provides v1 encoding for Currency.
type V1Currency Currency

// V2Currency provides v2 encoding for Currency.
type V2Currency Currency

// EncodeTo implements types.EncoderTo.
func (c V1Currency) EncodeTo(e *Encoder) {
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[:8], c.Hi)
	binary.BigEndian.PutUint64(buf[8:], c.Lo)
	e.WriteBytes(bytes.TrimLeft(buf[:], "\x00"))
}

// EncodeTo implements types.EncoderTo.
func (c V2Currency) EncodeTo(e *Encoder) {
	e.WriteUint64(c.Lo)
	e.WriteUint64(c.Hi)
}

// EncodeTo implements types.EncoderTo.
func (index ChainIndex) EncodeTo(e *Encoder) {
	e.WriteUint64(index.Height)
	index.ID.EncodeTo(e)
}

// V1SiacoinOutput provides v1 encoding for SiacoinOutput.
type V1SiacoinOutput SiacoinOutput

// V2SiacoinOutput provides v2 encoding for SiacoinOutput.
type V2SiacoinOutput SiacoinOutput

// EncodeTo implements types.EncoderTo.
func (sco V1SiacoinOutput) EncodeTo(e *Encoder) {
	V1Currency(sco.Value).EncodeTo(e)
	sco.Address.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (sco V2SiacoinOutput) EncodeTo(e *Encoder) {
	V2Currency(sco.Value).EncodeTo(e)
	sco.Address.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (id SiacoinOutputID) EncodeTo(e *Encoder) { e.Write(id[:]) }

// V1SiafundOutput provides v1 encoding for SiafundOutput.
type V1SiafundOutput SiafundOutput

// V2SiafundOutput provides v2 encoding for SiafundOutput.
type V2SiafundOutput SiafundOutput

// EncodeTo implements types.EncoderTo.
func (sfo V1SiafundOutput) EncodeTo(e *Encoder) {
	V1Currency(NewCurrency64(sfo.Value)).EncodeTo(e)
	sfo.Address.EncodeTo(e)
	(V1Currency{}).EncodeTo(e) // siad expects a "ClaimStart" value
}

// EncodeTo implements types.EncoderTo.
func (sfo V2SiafundOutput) EncodeTo(e *Encoder) {
	e.WriteUint64(sfo.Value)
	sfo.Address.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (id SiafundOutputID) EncodeTo(e *Encoder) { e.Write(id[:]) }

// EncodeTo implements types.EncoderTo.
func (in SiacoinInput) EncodeTo(e *Encoder) {
	in.ParentID.EncodeTo(e)
	in.UnlockConditions.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (in SiafundInput) EncodeTo(e *Encoder) {
	in.ParentID.EncodeTo(e)
	in.UnlockConditions.EncodeTo(e)
	in.ClaimAddress.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (fc FileContract) EncodeTo(e *Encoder) {
	e.WriteUint64(fc.Filesize)
	fc.FileMerkleRoot.EncodeTo(e)
	e.WriteUint64(fc.WindowStart)
	e.WriteUint64(fc.WindowEnd)
	V1Currency(fc.Payout).EncodeTo(e)
	e.WritePrefix(len(fc.ValidProofOutputs))
	for _, sco := range fc.ValidProofOutputs {
		V1SiacoinOutput(sco).EncodeTo(e)
	}
	e.WritePrefix(len(fc.MissedProofOutputs))
	for _, sco := range fc.MissedProofOutputs {
		V1SiacoinOutput(sco).EncodeTo(e)
	}
	fc.UnlockHash.EncodeTo(e)
	e.WriteUint64(fc.RevisionNumber)
}

// EncodeTo implements types.EncoderTo.
func (id FileContractID) EncodeTo(e *Encoder) { e.Write(id[:]) }

// EncodeTo implements types.EncoderTo.
func (rev FileContractRevision) EncodeTo(e *Encoder) {
	rev.ParentID.EncodeTo(e)
	rev.UnlockConditions.EncodeTo(e)
	e.WriteUint64(rev.FileContract.RevisionNumber)
	e.WriteUint64(rev.FileContract.Filesize)
	rev.FileContract.FileMerkleRoot.EncodeTo(e)
	e.WriteUint64(rev.FileContract.WindowStart)
	e.WriteUint64(rev.FileContract.WindowEnd)
	e.WritePrefix(len(rev.FileContract.ValidProofOutputs))
	for _, sco := range rev.FileContract.ValidProofOutputs {
		(*V1SiacoinOutput)(&sco).EncodeTo(e)
	}
	e.WritePrefix(len(rev.FileContract.MissedProofOutputs))
	for _, sco := range rev.FileContract.MissedProofOutputs {
		(*V1SiacoinOutput)(&sco).EncodeTo(e)
	}
	rev.FileContract.UnlockHash.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (sp StorageProof) EncodeTo(e *Encoder) {
	sp.ParentID.EncodeTo(e)
	e.Write(sp.Leaf[:])
	e.WritePrefix(len(sp.Proof))
	for _, h := range sp.Proof {
		h.EncodeTo(e)
	}
}

// EncodeTo implements types.EncoderTo.
func (fau FoundationAddressUpdate) EncodeTo(e *Encoder) {
	fau.NewPrimary.EncodeTo(e)
	fau.NewFailsafe.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (cf CoveredFields) EncodeTo(e *Encoder) {
	e.WriteBool(cf.WholeTransaction)
	for _, f := range [][]uint64{
		cf.SiacoinInputs,
		cf.SiacoinOutputs,
		cf.FileContracts,
		cf.FileContractRevisions,
		cf.StorageProofs,
		cf.SiafundInputs,
		cf.SiafundOutputs,
		cf.MinerFees,
		cf.ArbitraryData,
		cf.Signatures,
	} {
		e.WritePrefix(len(f))
		for _, i := range f {
			e.WriteUint64(i)
		}
	}
}

// EncodeTo implements types.EncoderTo.
func (ts TransactionSignature) EncodeTo(e *Encoder) {
	ts.ParentID.EncodeTo(e)
	e.WriteUint64(ts.PublicKeyIndex)
	e.WriteUint64(ts.Timelock)
	ts.CoveredFields.EncodeTo(e)
	e.WriteBytes(ts.Signature)
}

type txnSansSigs Transaction

func (txn txnSansSigs) EncodeTo(e *Encoder) {
	e.WritePrefix(len((txn.SiacoinInputs)))
	for i := range txn.SiacoinInputs {
		txn.SiacoinInputs[i].EncodeTo(e)
	}
	e.WritePrefix(len((txn.SiacoinOutputs)))
	for i := range txn.SiacoinOutputs {
		V1SiacoinOutput(txn.SiacoinOutputs[i]).EncodeTo(e)
	}
	e.WritePrefix(len((txn.FileContracts)))
	for i := range txn.FileContracts {
		txn.FileContracts[i].EncodeTo(e)
	}
	e.WritePrefix(len((txn.FileContractRevisions)))
	for i := range txn.FileContractRevisions {
		txn.FileContractRevisions[i].EncodeTo(e)
	}
	e.WritePrefix(len((txn.StorageProofs)))
	for i := range txn.StorageProofs {
		txn.StorageProofs[i].EncodeTo(e)
	}
	e.WritePrefix(len((txn.SiafundInputs)))
	for i := range txn.SiafundInputs {
		txn.SiafundInputs[i].EncodeTo(e)
	}
	e.WritePrefix(len((txn.SiafundOutputs)))
	for i := range txn.SiafundOutputs {
		V1SiafundOutput(txn.SiafundOutputs[i]).EncodeTo(e)
	}
	e.WritePrefix(len((txn.MinerFees)))
	for i := range txn.MinerFees {
		V1Currency(txn.MinerFees[i]).EncodeTo(e)
	}
	e.WritePrefix(len((txn.ArbitraryData)))
	for i := range txn.ArbitraryData {
		e.WriteBytes(txn.ArbitraryData[i])
	}
}

// EncodeTo implements types.EncoderTo.
func (txn Transaction) EncodeTo(e *Encoder) {
	txnSansSigs(txn).EncodeTo(e)
	e.WritePrefix(len((txn.Signatures)))
	for i := range txn.Signatures {
		txn.Signatures[i].EncodeTo(e)
	}
}

func (p SpendPolicy) encodePolicy(e *Encoder) {
	const (
		opInvalid = iota
		opAbove
		opAfter
		opPublicKey
		opHash
		opThreshold
		opOpaque
		opUnlockConditions
	)
	switch p := p.Type.(type) {
	case PolicyTypeAbove:
		e.WriteUint8(opAbove)
		e.WriteUint64(uint64(p))
	case PolicyTypeAfter:
		e.WriteUint8(opAfter)
		e.WriteTime(time.Time(p))
	case PolicyTypePublicKey:
		e.WriteUint8(opPublicKey)
		PublicKey(p).EncodeTo(e)
	case PolicyTypeHash:
		e.WriteUint8(opHash)
		Hash256(p).EncodeTo(e)
	case PolicyTypeThreshold:
		e.WriteUint8(opThreshold)
		e.WriteUint8(p.N)
		e.WriteUint8(uint8(len(p.Of)))
		for i := range p.Of {
			p.Of[i].encodePolicy(e)
		}
	case PolicyTypeOpaque:
		e.WriteUint8(opOpaque)
		Hash256(p).EncodeTo(e)
	case PolicyTypeUnlockConditions:
		e.WriteUint8(opUnlockConditions)
		UnlockConditions(p).EncodeTo(e)
	default:
		panic(fmt.Sprintf("unhandled policy type %T", p))
	}
}

// EncodeTo implements types.EncoderTo.
func (p SpendPolicy) EncodeTo(e *Encoder) {
	const version = 1
	e.WriteUint8(version)
	p.encodePolicy(e)
}

// EncodeTo implements types.EncoderTo.
func (sp SatisfiedPolicy) EncodeTo(e *Encoder) {
	sp.Policy.EncodeTo(e)
	var sigi, prei int
	var rec func(SpendPolicy)
	rec = func(p SpendPolicy) {
		switch p := p.Type.(type) {
		case PolicyTypePublicKey:
			sp.Signatures[sigi].EncodeTo(e)
			sigi++
		case PolicyTypeHash:
			e.WriteBytes(sp.Preimages[prei])
			prei++
		case PolicyTypeThreshold:
			for i := range p.Of {
				rec(p.Of[i])
			}
		case PolicyTypeUnlockConditions:
			for i := range p.PublicKeys {
				rec(PolicyPublicKey(*(*PublicKey)(p.PublicKeys[i].Key)))
			}
		default:
			// nothing to do
		}
	}
	rec(sp.Policy)
}

// EncodeTo implements types.EncoderTo.
func (se StateElement) EncodeTo(e *Encoder) {
	se.ID.EncodeTo(e)
	e.WriteUint64(se.LeafIndex)
	e.WritePrefix(len(se.MerkleProof))
	for _, p := range se.MerkleProof {
		p.EncodeTo(e)
	}
}

// EncodeTo implements types.EncoderTo.
func (in V2SiacoinInput) EncodeTo(e *Encoder) {
	in.Parent.EncodeTo(e)
	in.SatisfiedPolicy.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (cie ChainIndexElement) EncodeTo(e *Encoder) {
	cie.StateElement.EncodeTo(e)
	cie.ChainIndex.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (sce SiacoinElement) EncodeTo(e *Encoder) {
	sce.StateElement.EncodeTo(e)
	V2SiacoinOutput(sce.SiacoinOutput).EncodeTo(e)
	e.WriteUint64(sce.MaturityHeight)
}

// EncodeTo implements types.EncoderTo.
func (in V2SiafundInput) EncodeTo(e *Encoder) {
	in.Parent.EncodeTo(e)
	in.ClaimAddress.EncodeTo(e)
	in.SatisfiedPolicy.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (sfe SiafundElement) EncodeTo(e *Encoder) {
	sfe.StateElement.EncodeTo(e)
	V2SiafundOutput(sfe.SiafundOutput).EncodeTo(e)
	V2Currency(sfe.ClaimStart).EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (fc V2FileContract) EncodeTo(e *Encoder) {
	e.WriteUint64(fc.Filesize)
	fc.FileMerkleRoot.EncodeTo(e)
	e.WriteUint64(fc.ProofHeight)
	e.WriteUint64(fc.ExpirationHeight)
	V2SiacoinOutput(fc.RenterOutput).EncodeTo(e)
	V2SiacoinOutput(fc.HostOutput).EncodeTo(e)
	V2Currency(fc.MissedHostValue).EncodeTo(e)
	V2Currency(fc.TotalCollateral).EncodeTo(e)
	fc.RenterPublicKey.EncodeTo(e)
	fc.HostPublicKey.EncodeTo(e)
	e.WriteUint64(fc.RevisionNumber)
	fc.RenterSignature.EncodeTo(e)
	fc.HostSignature.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (fce FileContractElement) EncodeTo(e *Encoder) {
	fce.StateElement.EncodeTo(e)
	fce.FileContract.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (fce V2FileContractElement) EncodeTo(e *Encoder) {
	fce.StateElement.EncodeTo(e)
	fce.V2FileContract.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (rev V2FileContractRevision) EncodeTo(e *Encoder) {
	rev.Parent.EncodeTo(e)
	rev.Revision.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (ren V2FileContractRenewal) EncodeTo(e *Encoder) {
	ren.FinalRevision.EncodeTo(e)
	ren.NewContract.EncodeTo(e)
	V2Currency(ren.RenterRollover).EncodeTo(e)
	V2Currency(ren.HostRollover).EncodeTo(e)
	ren.RenterSignature.EncodeTo(e)
	ren.HostSignature.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (fcf V2FileContractFinalization) EncodeTo(e *Encoder) {
	V2FileContract(fcf).EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (sp V2StorageProof) EncodeTo(e *Encoder) {
	sp.ProofIndex.EncodeTo(e)
	e.Write(sp.Leaf[:])
	e.WritePrefix(len(sp.Proof))
	for _, p := range sp.Proof {
		p.EncodeTo(e)
	}
}

// EncodeTo implements types.EncoderTo.
func (V2FileContractExpiration) EncodeTo(e *Encoder) {}

// EncodeTo implements types.EncoderTo.
func (res V2FileContractResolution) EncodeTo(e *Encoder) {
	res.Parent.EncodeTo(e)
	switch r := res.Resolution.(type) {
	case *V2FileContractRenewal:
		e.WriteUint8(0)
	case *V2StorageProof:
		e.WriteUint8(1)
	case *V2FileContractFinalization:
		e.WriteUint8(2)
	case *V2FileContractExpiration:
		e.WriteUint8(3)
	default:
		panic(fmt.Sprintf("unhandled resolution type %T", r))
	}
	res.Resolution.(EncoderTo).EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (a Attestation) EncodeTo(e *Encoder) {
	a.PublicKey.EncodeTo(e)
	e.WriteString(a.Key)
	e.WriteBytes(a.Value)
	a.Signature.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (txn V2Transaction) EncodeTo(e *Encoder) {
	const version = 2
	e.WriteUint8(version)

	var fields uint64
	for i, b := range [...]bool{
		len(txn.SiacoinInputs) != 0,
		len(txn.SiacoinOutputs) != 0,
		len(txn.SiafundInputs) != 0,
		len(txn.SiafundOutputs) != 0,
		len(txn.FileContracts) != 0,
		len(txn.FileContractRevisions) != 0,
		len(txn.FileContractResolutions) != 0,
		len(txn.Attestations) != 0,
		len(txn.ArbitraryData) != 0,
		txn.NewFoundationAddress != nil,
		!txn.MinerFee.IsZero(),
	} {
		if b {
			fields |= 1 << i
		}
	}
	e.WriteUint64(fields)

	if fields&(1<<0) != 0 {
		e.WritePrefix(len(txn.SiacoinInputs))
		for _, in := range txn.SiacoinInputs {
			in.EncodeTo(e)
		}
	}
	if fields&(1<<1) != 0 {
		e.WritePrefix(len(txn.SiacoinOutputs))
		for _, out := range txn.SiacoinOutputs {
			V2SiacoinOutput(out).EncodeTo(e)
		}
	}
	if fields&(1<<2) != 0 {
		e.WritePrefix(len(txn.SiafundInputs))
		for _, in := range txn.SiafundInputs {
			in.EncodeTo(e)
		}
	}
	if fields&(1<<3) != 0 {
		e.WritePrefix(len(txn.SiafundOutputs))
		for _, out := range txn.SiafundOutputs {
			V2SiafundOutput(out).EncodeTo(e)
		}
	}
	if fields&(1<<4) != 0 {
		e.WritePrefix(len(txn.FileContracts))
		for _, fc := range txn.FileContracts {
			fc.EncodeTo(e)
		}
	}
	if fields&(1<<5) != 0 {
		e.WritePrefix(len(txn.FileContractRevisions))
		for _, rev := range txn.FileContractRevisions {
			rev.EncodeTo(e)
		}
	}
	if fields&(1<<6) != 0 {
		e.WritePrefix(len(txn.FileContractResolutions))
		for _, fcr := range txn.FileContractResolutions {
			fcr.EncodeTo(e)
		}
	}
	if fields&(1<<7) != 0 {
		e.WritePrefix(len(txn.Attestations))
		for _, a := range txn.Attestations {
			a.EncodeTo(e)
		}
	}
	if fields&(1<<8) != 0 {
		e.WriteBytes(txn.ArbitraryData)
	}
	if fields&(1<<9) != 0 {
		txn.NewFoundationAddress.EncodeTo(e)
	}
	if fields&(1<<10) != 0 {
		V2Currency(txn.MinerFee).EncodeTo(e)
	}
}

// V2TransactionSemantics is a helper type that provides a "semantic encoding"
// of a v2 transaction, for use in computing IDs and signature hashes.
type V2TransactionSemantics V2Transaction

// EncodeTo implements types.EncoderTo.
func (txn V2TransactionSemantics) EncodeTo(e *Encoder) {
	nilSigs := func(sigs ...*Signature) {
		for i := range sigs {
			*sigs[i] = Signature{}
		}
	}

	e.WritePrefix(len(txn.SiacoinInputs))
	for _, in := range txn.SiacoinInputs {
		in.Parent.ID.EncodeTo(e)
	}
	e.WritePrefix(len(txn.SiacoinOutputs))
	for _, out := range txn.SiacoinOutputs {
		V2SiacoinOutput(out).EncodeTo(e)
	}
	e.WritePrefix(len(txn.SiafundInputs))
	for _, in := range txn.SiafundInputs {
		in.Parent.ID.EncodeTo(e)
	}
	e.WritePrefix(len(txn.SiafundOutputs))
	for _, out := range txn.SiafundOutputs {
		V2SiafundOutput(out).EncodeTo(e)
	}
	e.WritePrefix(len(txn.FileContracts))
	for _, fc := range txn.FileContracts {
		nilSigs(&fc.RenterSignature, &fc.HostSignature)
		fc.EncodeTo(e)
	}
	e.WritePrefix(len(txn.FileContractRevisions))
	for _, fcr := range txn.FileContractRevisions {
		fcr.Parent.ID.EncodeTo(e)
		nilSigs(&fcr.Revision.RenterSignature, &fcr.Revision.HostSignature)
		fcr.Revision.EncodeTo(e)
	}
	e.WritePrefix(len(txn.FileContractResolutions))
	for _, fcr := range txn.FileContractResolutions {
		fcr.Parent.ID.EncodeTo(e)
		// normalize (being careful not to modify the original)
		switch res := fcr.Resolution.(type) {
		case *V2FileContractFinalization:
			fc := *res
			nilSigs(&fc.RenterSignature, &fc.HostSignature)
			fcr.Resolution = &fc
		case *V2FileContractRenewal:
			renewal := *res
			nilSigs(
				&renewal.NewContract.RenterSignature, &renewal.NewContract.HostSignature,
				&renewal.FinalRevision.RenterSignature, &renewal.FinalRevision.HostSignature,
				&renewal.RenterSignature, &renewal.HostSignature,
			)
			fcr.Resolution = &renewal
		case *V2StorageProof:
			sp := *res
			sp.ProofIndex.MerkleProof = nil
			fcr.Resolution = &sp
		}
		fcr.Resolution.(EncoderTo).EncodeTo(e)
	}
	e.WritePrefix(len(txn.Attestations))
	for _, a := range txn.Attestations {
		a.EncodeTo(e)
	}
	e.WriteBytes(txn.ArbitraryData)
	e.WriteBool(txn.NewFoundationAddress != nil)
	if txn.NewFoundationAddress != nil {
		txn.NewFoundationAddress.EncodeTo(e)
	}
	V2Currency(txn.MinerFee).EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (b V2BlockData) EncodeTo(e *Encoder) {
	e.WriteUint64(b.Height)
	b.Commitment.EncodeTo(e)
	V2TransactionsMultiproof(b.Transactions).EncodeTo(e)
}

// V1Block provides v1 encoding for Block.
type V1Block Block

// EncodeTo implements types.EncoderTo.
func (b V1Block) EncodeTo(e *Encoder) {
	b.ParentID.EncodeTo(e)
	e.WriteUint64(b.Nonce)
	e.WriteTime(b.Timestamp)
	e.WritePrefix(len(b.MinerPayouts))
	for i := range b.MinerPayouts {
		V1SiacoinOutput(b.MinerPayouts[i]).EncodeTo(e)
	}
	e.WritePrefix(len(b.Transactions))
	for i := range b.Transactions {
		b.Transactions[i].EncodeTo(e)
	}
}

// V2Block provides v2 encoding for Block.
type V2Block Block

// EncodeTo implements types.EncoderTo.
func (b V2Block) EncodeTo(e *Encoder) {
	V1Block(b).EncodeTo(e)
	e.WriteBool(b.V2 != nil)
	if b.V2 != nil {
		b.V2.EncodeTo(e)
	}
}

// DecodeFrom implements types.DecoderFrom.
func (h *Hash256) DecodeFrom(d *Decoder) { d.Read(h[:]) }

// DecodeFrom implements types.DecoderFrom.
func (id *BlockID) DecodeFrom(d *Decoder) { d.Read(id[:]) }

// DecodeFrom implements types.DecoderFrom.
func (id *TransactionID) DecodeFrom(d *Decoder) { d.Read(id[:]) }

// DecodeFrom implements types.DecoderFrom.
func (a *Address) DecodeFrom(d *Decoder) { d.Read(a[:]) }

// DecodeFrom implements types.DecoderFrom.
func (pk *PublicKey) DecodeFrom(d *Decoder) { d.Read(pk[:]) }

// DecodeFrom implements types.DecoderFrom.
func (s *Signature) DecodeFrom(d *Decoder) { d.Read(s[:]) }

// DecodeFrom implements types.DecoderFrom.
func (s *Specifier) DecodeFrom(d *Decoder) { d.Read(s[:]) }

// DecodeFrom implements types.DecoderFrom.
func (uk *UnlockKey) DecodeFrom(d *Decoder) {
	uk.Algorithm.DecodeFrom(d)
	uk.Key = d.ReadBytes()
}

// DecodeFrom implements types.DecoderFrom.
func (uc *UnlockConditions) DecodeFrom(d *Decoder) {
	uc.Timelock = d.ReadUint64()
	uc.PublicKeys = make([]UnlockKey, d.ReadPrefix())
	for i := range uc.PublicKeys {
		uc.PublicKeys[i].DecodeFrom(d)
	}
	uc.SignaturesRequired = d.ReadUint64()
}

// DecodeFrom implements types.DecoderFrom.
func (c *V1Currency) DecodeFrom(d *Decoder) {
	var buf [16]byte
	n := d.ReadPrefix()
	if n > 16 {
		d.SetErr(fmt.Errorf("Currency too large: %v bytes", n))
		return
	}
	d.Read(buf[16-n:])
	c.Hi = binary.BigEndian.Uint64(buf[:8])
	c.Lo = binary.BigEndian.Uint64(buf[8:])
}

// DecodeFrom implements types.DecoderFrom.
func (c *V2Currency) DecodeFrom(d *Decoder) {
	c.Lo = d.ReadUint64()
	c.Hi = d.ReadUint64()
}

// DecodeFrom implements types.DecoderFrom.
func (index *ChainIndex) DecodeFrom(d *Decoder) {
	index.Height = d.ReadUint64()
	index.ID.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (sco *V1SiacoinOutput) DecodeFrom(d *Decoder) {
	(*V1Currency)(&sco.Value).DecodeFrom(d)
	sco.Address.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (sco *V2SiacoinOutput) DecodeFrom(d *Decoder) {
	(*V2Currency)(&sco.Value).DecodeFrom(d)
	sco.Address.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (id *SiacoinOutputID) DecodeFrom(d *Decoder) { d.Read(id[:]) }

// DecodeFrom implements types.DecoderFrom.
func (sfo *V1SiafundOutput) DecodeFrom(d *Decoder) {
	var val V1Currency
	val.DecodeFrom(d)
	if val.Hi != 0 {
		d.SetErr(errors.New("value overflows siafund representation"))
		return
	}
	sfo.Value = val.Lo
	sfo.Address.DecodeFrom(d)
	(&V1Currency{}).DecodeFrom(d) // siad expects a "ClaimStart" value
}

// DecodeFrom implements types.DecoderFrom.
func (sfo *V2SiafundOutput) DecodeFrom(d *Decoder) {
	sfo.Value = d.ReadUint64()
	sfo.Address.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (id *SiafundOutputID) DecodeFrom(d *Decoder) { d.Read(id[:]) }

// DecodeFrom implements types.DecoderFrom.
func (in *SiacoinInput) DecodeFrom(d *Decoder) {
	in.ParentID.DecodeFrom(d)
	in.UnlockConditions.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (in *SiafundInput) DecodeFrom(d *Decoder) {
	in.ParentID.DecodeFrom(d)
	in.UnlockConditions.DecodeFrom(d)
	in.ClaimAddress.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (fc *FileContract) DecodeFrom(d *Decoder) {
	fc.Filesize = d.ReadUint64()
	fc.FileMerkleRoot.DecodeFrom(d)
	fc.WindowStart = d.ReadUint64()
	fc.WindowEnd = d.ReadUint64()
	(*V1Currency)(&fc.Payout).DecodeFrom(d)
	fc.ValidProofOutputs = make([]SiacoinOutput, d.ReadPrefix())
	for i := range fc.ValidProofOutputs {
		(*V1SiacoinOutput)(&fc.ValidProofOutputs[i]).DecodeFrom(d)
	}
	fc.MissedProofOutputs = make([]SiacoinOutput, d.ReadPrefix())
	for i := range fc.MissedProofOutputs {
		(*V1SiacoinOutput)(&fc.MissedProofOutputs[i]).DecodeFrom(d)
	}
	fc.UnlockHash.DecodeFrom(d)
	fc.RevisionNumber = d.ReadUint64()
}

// DecodeFrom implements types.DecoderFrom.
func (id *FileContractID) DecodeFrom(d *Decoder) { d.Read(id[:]) }

// DecodeFrom implements types.DecoderFrom.
func (rev *FileContractRevision) DecodeFrom(d *Decoder) {
	rev.ParentID.DecodeFrom(d)
	rev.UnlockConditions.DecodeFrom(d)
	rev.FileContract.RevisionNumber = d.ReadUint64()
	rev.FileContract.Filesize = d.ReadUint64()
	rev.FileContract.FileMerkleRoot.DecodeFrom(d)
	rev.FileContract.WindowStart = d.ReadUint64()
	rev.FileContract.WindowEnd = d.ReadUint64()
	rev.FileContract.ValidProofOutputs = make([]SiacoinOutput, d.ReadPrefix())
	for i := range rev.FileContract.ValidProofOutputs {
		(*V1SiacoinOutput)(&rev.FileContract.ValidProofOutputs[i]).DecodeFrom(d)
	}
	rev.FileContract.MissedProofOutputs = make([]SiacoinOutput, d.ReadPrefix())
	for i := range rev.FileContract.MissedProofOutputs {
		(*V1SiacoinOutput)(&rev.FileContract.MissedProofOutputs[i]).DecodeFrom(d)
	}
	rev.FileContract.UnlockHash.DecodeFrom(d)

	// see FileContractRevision docstring
	rev.FileContract.Payout = NewCurrency(math.MaxUint64, math.MaxUint64)
}

// DecodeFrom implements types.DecoderFrom.
func (sp *StorageProof) DecodeFrom(d *Decoder) {
	sp.ParentID.DecodeFrom(d)
	d.Read(sp.Leaf[:])
	sp.Proof = make([]Hash256, d.ReadPrefix())
	for i := range sp.Proof {
		sp.Proof[i].DecodeFrom(d)
	}
}

// DecodeFrom implements types.DecoderFrom.
func (fau *FoundationAddressUpdate) DecodeFrom(d *Decoder) {
	fau.NewPrimary.DecodeFrom(d)
	fau.NewFailsafe.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (cf *CoveredFields) DecodeFrom(d *Decoder) {
	cf.WholeTransaction = d.ReadBool()
	for _, f := range []*[]uint64{
		&cf.SiacoinInputs,
		&cf.SiacoinOutputs,
		&cf.FileContracts,
		&cf.FileContractRevisions,
		&cf.StorageProofs,
		&cf.SiafundInputs,
		&cf.SiafundOutputs,
		&cf.MinerFees,
		&cf.ArbitraryData,
		&cf.Signatures,
	} {
		*f = make([]uint64, d.ReadPrefix())
		for i := range *f {
			(*f)[i] = d.ReadUint64()
		}
	}
}

// DecodeFrom implements types.DecoderFrom.
func (ts *TransactionSignature) DecodeFrom(d *Decoder) {
	ts.ParentID.DecodeFrom(d)
	ts.PublicKeyIndex = d.ReadUint64()
	ts.Timelock = d.ReadUint64()
	ts.CoveredFields.DecodeFrom(d)
	ts.Signature = d.ReadBytes()
}

// DecodeFrom implements types.DecoderFrom.
func (txn *Transaction) DecodeFrom(d *Decoder) {
	txn.SiacoinInputs = make([]SiacoinInput, d.ReadPrefix())
	for i := range txn.SiacoinInputs {
		txn.SiacoinInputs[i].DecodeFrom(d)
	}
	txn.SiacoinOutputs = make([]SiacoinOutput, d.ReadPrefix())
	for i := range txn.SiacoinOutputs {
		(*V1SiacoinOutput)(&txn.SiacoinOutputs[i]).DecodeFrom(d)
	}
	txn.FileContracts = make([]FileContract, d.ReadPrefix())
	for i := range txn.FileContracts {
		txn.FileContracts[i].DecodeFrom(d)
	}
	txn.FileContractRevisions = make([]FileContractRevision, d.ReadPrefix())
	for i := range txn.FileContractRevisions {
		txn.FileContractRevisions[i].DecodeFrom(d)
	}
	txn.StorageProofs = make([]StorageProof, d.ReadPrefix())
	for i := range txn.StorageProofs {
		txn.StorageProofs[i].DecodeFrom(d)
	}
	txn.SiafundInputs = make([]SiafundInput, d.ReadPrefix())
	for i := range txn.SiafundInputs {
		txn.SiafundInputs[i].DecodeFrom(d)
	}
	txn.SiafundOutputs = make([]SiafundOutput, d.ReadPrefix())
	for i := range txn.SiafundOutputs {
		(*V1SiafundOutput)(&txn.SiafundOutputs[i]).DecodeFrom(d)
	}
	txn.MinerFees = make([]Currency, d.ReadPrefix())
	for i := range txn.MinerFees {
		(*V1Currency)(&txn.MinerFees[i]).DecodeFrom(d)
	}
	txn.ArbitraryData = make([][]byte, d.ReadPrefix())
	for i := range txn.ArbitraryData {
		txn.ArbitraryData[i] = d.ReadBytes()
	}
	txn.Signatures = make([]TransactionSignature, d.ReadPrefix())
	for i := range txn.Signatures {
		txn.Signatures[i].DecodeFrom(d)
	}
}

// DecodeFrom implements types.DecoderFrom.
func (p *SpendPolicy) DecodeFrom(d *Decoder) {
	const (
		version     = 1
		maxPolicies = 1024
	)
	const (
		opInvalid = iota
		opAbove
		opAfter
		opPublicKey
		opHash
		opThreshold
		opOpaque
		opUnlockConditions
	)

	var totalPolicies int
	var readPolicy func() (SpendPolicy, error)
	readPolicy = func() (SpendPolicy, error) {
		switch op := d.ReadUint8(); op {
		case opAbove:
			return PolicyAbove(d.ReadUint64()), nil
		case opAfter:
			return PolicyAfter(d.ReadTime()), nil
		case opPublicKey:
			var pk PublicKey
			pk.DecodeFrom(d)
			return PolicyPublicKey(pk), nil
		case opHash:
			var h Hash256
			h.DecodeFrom(d)
			return PolicyHash(h), nil
		case opThreshold:
			n := d.ReadUint8()
			of := make([]SpendPolicy, d.ReadUint8())
			if totalPolicies += len(of); totalPolicies > maxPolicies {
				return SpendPolicy{}, errors.New("policy is too complex")
			}
			var err error
			for i := range of {
				if of[i], err = readPolicy(); err != nil {
					return SpendPolicy{}, err
				}
			}
			return PolicyThreshold(n, of), nil
		case opOpaque:
			var p PolicyTypeOpaque
			(*Address)(&p).DecodeFrom(d)
			return SpendPolicy{p}, nil
		case opUnlockConditions:
			var uc UnlockConditions
			uc.DecodeFrom(d)
			return SpendPolicy{PolicyTypeUnlockConditions(uc)}, nil
		default:
			return SpendPolicy{}, fmt.Errorf("unknown policy (opcode %d)", op)
		}
	}

	if v := d.ReadUint8(); v != version {
		d.SetErr(fmt.Errorf("unsupported policy version (%v)", version))
		return
	}
	var err error
	*p, err = readPolicy()
	d.SetErr(err)
}

// DecodeFrom implements types.DecoderFrom.
func (sp *SatisfiedPolicy) DecodeFrom(d *Decoder) {
	sp.Policy.DecodeFrom(d)
	// if policy decoding fails, the code below (namely the array cast) may
	// panic, so abort early
	if d.Err() != nil {
		return
	}

	var rec func(SpendPolicy)
	rec = func(p SpendPolicy) {
		switch p := p.Type.(type) {
		case PolicyTypePublicKey:
			var s Signature
			s.DecodeFrom(d)
			sp.Signatures = append(sp.Signatures, s)
		case PolicyTypeHash:
			sp.Preimages = append(sp.Preimages, d.ReadBytes())
		case PolicyTypeThreshold:
			for i := range p.Of {
				rec(p.Of[i])
			}
		case PolicyTypeUnlockConditions:
			for i := range p.PublicKeys {
				rec(PolicyPublicKey(*(*PublicKey)(p.PublicKeys[i].Key)))
			}
		default:
			// nothing to do
		}
	}
	rec(sp.Policy)
}

// DecodeFrom implements types.DecoderFrom.
func (se *StateElement) DecodeFrom(d *Decoder) {
	se.ID.DecodeFrom(d)
	se.LeafIndex = d.ReadUint64()
	se.MerkleProof = make([]Hash256, d.ReadPrefix())
	for i := range se.MerkleProof {
		se.MerkleProof[i].DecodeFrom(d)
	}
}

// DecodeFrom implements types.DecoderFrom.
func (in *V2SiacoinInput) DecodeFrom(d *Decoder) {
	in.Parent.DecodeFrom(d)
	in.SatisfiedPolicy.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (cie *ChainIndexElement) DecodeFrom(d *Decoder) {
	cie.StateElement.DecodeFrom(d)
	cie.ChainIndex.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (sce *SiacoinElement) DecodeFrom(d *Decoder) {
	sce.StateElement.DecodeFrom(d)
	(*V2SiacoinOutput)(&sce.SiacoinOutput).DecodeFrom(d)
	sce.MaturityHeight = d.ReadUint64()
}

// DecodeFrom implements types.DecoderFrom.
func (in *V2SiafundInput) DecodeFrom(d *Decoder) {
	in.Parent.DecodeFrom(d)
	in.ClaimAddress.DecodeFrom(d)
	in.SatisfiedPolicy.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (sfe *SiafundElement) DecodeFrom(d *Decoder) {
	sfe.StateElement.DecodeFrom(d)
	(*V2SiafundOutput)(&sfe.SiafundOutput).DecodeFrom(d)
	(*V2Currency)(&sfe.ClaimStart).DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (fc *V2FileContract) DecodeFrom(d *Decoder) {
	fc.Filesize = d.ReadUint64()
	fc.FileMerkleRoot.DecodeFrom(d)
	fc.ProofHeight = d.ReadUint64()
	fc.ExpirationHeight = d.ReadUint64()
	(*V2SiacoinOutput)(&fc.RenterOutput).DecodeFrom(d)
	(*V2SiacoinOutput)(&fc.HostOutput).DecodeFrom(d)
	(*V2Currency)(&fc.MissedHostValue).DecodeFrom(d)
	(*V2Currency)(&fc.TotalCollateral).DecodeFrom(d)
	fc.RenterPublicKey.DecodeFrom(d)
	fc.HostPublicKey.DecodeFrom(d)
	fc.RevisionNumber = d.ReadUint64()
	fc.RenterSignature.DecodeFrom(d)
	fc.HostSignature.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (fce *FileContractElement) DecodeFrom(d *Decoder) {
	fce.StateElement.DecodeFrom(d)
	fce.FileContract.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (fce *V2FileContractElement) DecodeFrom(d *Decoder) {
	fce.StateElement.DecodeFrom(d)
	fce.V2FileContract.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (rev *V2FileContractRevision) DecodeFrom(d *Decoder) {
	rev.Parent.DecodeFrom(d)
	rev.Revision.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (ren *V2FileContractRenewal) DecodeFrom(d *Decoder) {
	ren.FinalRevision.DecodeFrom(d)
	ren.NewContract.DecodeFrom(d)
	(*V2Currency)(&ren.RenterRollover).DecodeFrom(d)
	(*V2Currency)(&ren.HostRollover).DecodeFrom(d)
	ren.RenterSignature.DecodeFrom(d)
	ren.HostSignature.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (fcf V2FileContractFinalization) DecodeFrom(d *Decoder) {
	(*V2FileContract)(&fcf).DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (sp *V2StorageProof) DecodeFrom(d *Decoder) {
	sp.ProofIndex.DecodeFrom(d)
	d.Read(sp.Leaf[:])
	sp.Proof = make([]Hash256, d.ReadPrefix())
	for i := range sp.Proof {
		sp.Proof[i].DecodeFrom(d)
	}
}

// DecodeFrom implements types.DecoderFrom.
func (*V2FileContractExpiration) DecodeFrom(d *Decoder) {}

// DecodeFrom implements types.DecoderFrom.
func (res *V2FileContractResolution) DecodeFrom(d *Decoder) {
	res.Parent.DecodeFrom(d)
	switch t := d.ReadUint8(); t {
	case 0:
		res.Resolution = new(V2FileContractRenewal)
	case 1:
		res.Resolution = new(V2StorageProof)
	case 2:
		res.Resolution = new(V2FileContractFinalization)
	case 3:
		res.Resolution = new(V2FileContractExpiration)
	default:
		d.SetErr(fmt.Errorf("unknown resolution type %d", t))
	}
	res.Resolution.(DecoderFrom).DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (a *Attestation) DecodeFrom(d *Decoder) {
	a.PublicKey.DecodeFrom(d)
	a.Key = d.ReadString()
	a.Value = d.ReadBytes()
	a.Signature.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (txn *V2Transaction) DecodeFrom(d *Decoder) {
	if version := d.ReadUint8(); version != 2 {
		d.SetErr(fmt.Errorf("unsupported transaction version (%v)", version))
		return
	}

	fields := d.ReadUint64()

	if fields&(1<<0) != 0 {
		txn.SiacoinInputs = make([]V2SiacoinInput, d.ReadPrefix())
		for i := range txn.SiacoinInputs {
			txn.SiacoinInputs[i].DecodeFrom(d)
		}
	}
	if fields&(1<<1) != 0 {
		txn.SiacoinOutputs = make([]SiacoinOutput, d.ReadPrefix())
		for i := range txn.SiacoinOutputs {
			(*V2SiacoinOutput)(&txn.SiacoinOutputs[i]).DecodeFrom(d)
		}
	}
	if fields&(1<<2) != 0 {
		txn.SiafundInputs = make([]V2SiafundInput, d.ReadPrefix())
		for i := range txn.SiafundInputs {
			txn.SiafundInputs[i].DecodeFrom(d)
		}
	}
	if fields&(1<<3) != 0 {
		txn.SiafundOutputs = make([]SiafundOutput, d.ReadPrefix())
		for i := range txn.SiafundOutputs {
			(*V2SiafundOutput)(&txn.SiafundOutputs[i]).DecodeFrom(d)
		}
	}
	if fields&(1<<4) != 0 {
		txn.FileContracts = make([]V2FileContract, d.ReadPrefix())
		for i := range txn.FileContracts {
			txn.FileContracts[i].DecodeFrom(d)
		}
	}
	if fields&(1<<5) != 0 {
		txn.FileContractRevisions = make([]V2FileContractRevision, d.ReadPrefix())
		for i := range txn.FileContractRevisions {
			txn.FileContractRevisions[i].DecodeFrom(d)
		}
	}
	if fields&(1<<6) != 0 {
		txn.FileContractResolutions = make([]V2FileContractResolution, d.ReadPrefix())
		for i := range txn.FileContractResolutions {
			txn.FileContractResolutions[i].DecodeFrom(d)
		}
	}
	if fields&(1<<7) != 0 {
		txn.Attestations = make([]Attestation, d.ReadPrefix())
		for i := range txn.Attestations {
			txn.Attestations[i].DecodeFrom(d)
		}
	}
	if fields&(1<<8) != 0 {
		txn.ArbitraryData = d.ReadBytes()
	}
	if fields&(1<<9) != 0 {
		txn.NewFoundationAddress = new(Address)
		txn.NewFoundationAddress.DecodeFrom(d)
	}
	if fields&(1<<10) != 0 {
		(*V2Currency)(&txn.MinerFee).DecodeFrom(d)
	}
}

// DecodeFrom implements types.DecoderFrom.
func (b *V2BlockData) DecodeFrom(d *Decoder) {
	b.Height = d.ReadUint64()
	b.Commitment.DecodeFrom(d)
	(*V2TransactionsMultiproof)(&b.Transactions).DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (b *V1Block) DecodeFrom(d *Decoder) {
	b.ParentID.DecodeFrom(d)
	b.Nonce = d.ReadUint64()
	b.Timestamp = d.ReadTime()
	b.MinerPayouts = make([]SiacoinOutput, d.ReadPrefix())
	for i := range b.MinerPayouts {
		(*V1SiacoinOutput)(&b.MinerPayouts[i]).DecodeFrom(d)
	}
	b.Transactions = make([]Transaction, d.ReadPrefix())
	for i := range b.Transactions {
		b.Transactions[i].DecodeFrom(d)
	}
}

// DecodeFrom implements types.DecoderFrom.
func (b *V2Block) DecodeFrom(d *Decoder) {
	(*V1Block)(b).DecodeFrom(d)
	if d.ReadBool() {
		b.V2 = new(V2BlockData)
		b.V2.DecodeFrom(d)
	}
}
