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

// EncodedLen returns the length of v when encoded.
func EncodedLen(v interface{}) int {
	var buf bytes.Buffer
	e := NewEncoder(&buf)
	if et, ok := v.(EncoderTo); ok {
		et.EncodeTo(e)
	} else {
		switch v := v.(type) {
		case bool:
			e.WriteBool(v)
		case uint64:
			e.WriteUint64(v)
		case time.Time:
			e.WriteTime(v)
		case []byte:
			e.WritePrefix(len(v))
			e.Write(v)
		default:
			panic(fmt.Sprintf("cannot encode type %T", v))
		}
	}
	_ = e.Flush() // no error possible
	return buf.Len()
}

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

// EncodeTo implements types.EncoderTo.
func (w Work) EncodeTo(e *Encoder) { e.Write(w.NumHashes[:]) }

// EncodeTo implements types.EncoderTo.
func (c Currency) EncodeTo(e *Encoder) {
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[:8], c.Hi)
	binary.BigEndian.PutUint64(buf[8:], c.Lo)
	i := 0
	for i < len(buf) && buf[i] == 0 {
		i++
	}
	e.WritePrefix(len(buf[i:]))
	e.Write(buf[i:])
}

// EncodeTo implements types.EncoderTo.
func (index ChainIndex) EncodeTo(e *Encoder) {
	e.WriteUint64(index.Height)
	index.ID.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (h BlockHeader) EncodeTo(e *Encoder) {
	h.ParentID.EncodeTo(e)
	e.WriteUint64(h.Nonce)
	e.WriteTime(h.Timestamp)
	h.MerkleRoot.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (sco SiacoinOutput) EncodeTo(e *Encoder) {
	sco.Value.EncodeTo(e)
	sco.Address.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (id SiacoinOutputID) EncodeTo(e *Encoder) { e.Write(id[:]) }

// EncodeTo implements types.EncoderTo.
func (sfo SiafundOutput) EncodeTo(e *Encoder) {
	NewCurrency64(sfo.Value).EncodeTo(e)
	sfo.Address.EncodeTo(e)
	// siad expects a "ClaimStart" value
	(Currency{}).EncodeTo(e)
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
	fc.Payout.EncodeTo(e)
	e.WritePrefix(len(fc.ValidProofOutputs))
	for _, sco := range fc.ValidProofOutputs {
		sco.EncodeTo(e)
	}
	e.WritePrefix(len(fc.MissedProofOutputs))
	for _, sco := range fc.MissedProofOutputs {
		sco.EncodeTo(e)
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
	e.WriteUint64(rev.Revision.RevisionNumber)
	e.WriteUint64(rev.Revision.Filesize)
	rev.Revision.FileMerkleRoot.EncodeTo(e)
	e.WriteUint64(rev.Revision.WindowStart)
	e.WriteUint64(rev.Revision.WindowEnd)
	e.WritePrefix(len(rev.Revision.ValidProofOutputs))
	for _, sco := range rev.Revision.ValidProofOutputs {
		sco.EncodeTo(e)
	}
	e.WritePrefix(len(rev.Revision.MissedProofOutputs))
	for _, sco := range rev.Revision.MissedProofOutputs {
		sco.EncodeTo(e)
	}
	rev.Revision.UnlockHash.EncodeTo(e)
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

// EncodeTo implements types.EncoderTo.
func (txn Transaction) EncodeTo(e *Encoder) {
	txn.encodeNoSignatures(e)
	e.WritePrefix(len((txn.Signatures)))
	for i := range txn.Signatures {
		txn.Signatures[i].EncodeTo(e)
	}
}

func (txn *Transaction) encodeNoSignatures(e *Encoder) {
	e.WritePrefix(len((txn.SiacoinInputs)))
	for i := range txn.SiacoinInputs {
		txn.SiacoinInputs[i].EncodeTo(e)
	}
	e.WritePrefix(len((txn.SiacoinOutputs)))
	for i := range txn.SiacoinOutputs {
		txn.SiacoinOutputs[i].EncodeTo(e)
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
		txn.SiafundOutputs[i].EncodeTo(e)
	}
	e.WritePrefix(len((txn.MinerFees)))
	for i := range txn.MinerFees {
		txn.MinerFees[i].EncodeTo(e)
	}
	e.WritePrefix(len((txn.ArbitraryData)))
	for i := range txn.ArbitraryData {
		e.WriteBytes(txn.ArbitraryData[i])
	}
}

// EncodeTo implements types.EncoderTo.
func (b Block) EncodeTo(e *Encoder) {
	b.ParentID.EncodeTo(e)
	e.WriteUint64(b.Nonce)
	e.WriteTime(b.Timestamp)
	e.WritePrefix(len(b.MinerPayouts))
	for i := range b.MinerPayouts {
		b.MinerPayouts[i].EncodeTo(e)
	}
	e.WritePrefix(len(b.Transactions))
	for i := range b.Transactions {
		b.Transactions[i].EncodeTo(e)
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
func (w *Work) DecodeFrom(d *Decoder) { d.Read(w.NumHashes[:]) }

// DecodeFrom implements types.DecoderFrom.
func (c *Currency) DecodeFrom(d *Decoder) {
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
func (index *ChainIndex) DecodeFrom(d *Decoder) {
	index.Height = d.ReadUint64()
	index.ID.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (h *BlockHeader) DecodeFrom(d *Decoder) {
	h.ParentID.DecodeFrom(d)
	h.Nonce = d.ReadUint64()
	h.Timestamp = d.ReadTime()
	h.MerkleRoot.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (sco *SiacoinOutput) DecodeFrom(d *Decoder) {
	sco.Value.DecodeFrom(d)
	sco.Address.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (id *SiacoinOutputID) DecodeFrom(d *Decoder) { d.Read(id[:]) }

// DecodeFrom implements types.DecoderFrom.
func (sfo *SiafundOutput) DecodeFrom(d *Decoder) {
	var val Currency
	val.DecodeFrom(d)
	if val.Hi != 0 {
		d.SetErr(errors.New("value overflows siafund representation"))
		return
	}
	sfo.Value = val.Lo
	sfo.Address.DecodeFrom(d)
	// siad expects a "ClaimStart" value
	(&Currency{}).DecodeFrom(d)
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
	fc.Payout.DecodeFrom(d)
	fc.ValidProofOutputs = make([]SiacoinOutput, d.ReadPrefix())
	for i := range fc.ValidProofOutputs {
		fc.ValidProofOutputs[i].DecodeFrom(d)
	}
	fc.MissedProofOutputs = make([]SiacoinOutput, d.ReadPrefix())
	for i := range fc.MissedProofOutputs {
		fc.MissedProofOutputs[i].DecodeFrom(d)
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
	rev.Revision.RevisionNumber = d.ReadUint64()
	rev.Revision.Filesize = d.ReadUint64()
	rev.Revision.FileMerkleRoot.DecodeFrom(d)
	rev.Revision.WindowStart = d.ReadUint64()
	rev.Revision.WindowEnd = d.ReadUint64()
	rev.Revision.ValidProofOutputs = make([]SiacoinOutput, d.ReadPrefix())
	for i := range rev.Revision.ValidProofOutputs {
		rev.Revision.ValidProofOutputs[i].DecodeFrom(d)
	}
	rev.Revision.MissedProofOutputs = make([]SiacoinOutput, d.ReadPrefix())
	for i := range rev.Revision.MissedProofOutputs {
		rev.Revision.MissedProofOutputs[i].DecodeFrom(d)
	}
	rev.Revision.UnlockHash.DecodeFrom(d)

	// see FileContractRevision docstring
	rev.Revision.Payout = NewCurrency(math.MaxUint64, math.MaxUint64)
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
		txn.SiacoinOutputs[i].DecodeFrom(d)
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
		txn.SiafundOutputs[i].DecodeFrom(d)
	}
	txn.MinerFees = make([]Currency, d.ReadPrefix())
	for i := range txn.MinerFees {
		txn.MinerFees[i].DecodeFrom(d)
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
func (b *Block) DecodeFrom(d *Decoder) {
	b.ParentID.DecodeFrom(d)
	b.Nonce = d.ReadUint64()
	b.Timestamp = d.ReadTime()
	b.MinerPayouts = make([]SiacoinOutput, d.ReadPrefix())
	for i := range b.MinerPayouts {
		b.MinerPayouts[i].DecodeFrom(d)
	}
	b.Transactions = make([]Transaction, d.ReadPrefix())
	for i := range b.Transactions {
		b.Transactions[i].DecodeFrom(d)
	}
}
