package types

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"time"

	"golang.org/x/crypto/blake2b"
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
	for len(p) > 0 {
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
		case SpendPolicy:
			e.WritePolicy(v)
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
		n += copy(p, d.buf[:read])
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

// A Hasher streams objects into an instance of Sia's hash function.
type Hasher struct {
	h hash.Hash
	E *Encoder
}

// Reset resets the underlying hash digest state.
func (h *Hasher) Reset() { h.h.Reset() }

// Sum returns the digest of the objects written to the Hasher.
func (h *Hasher) Sum() (sum Hash256) {
	_ = h.E.Flush() // no error possible
	h.h.Sum(sum[:0])
	return
}

// NewHasher returns a new Hasher instance.
func NewHasher() *Hasher {
	h, _ := blake2b.New256(nil)
	e := NewEncoder(h)
	return &Hasher{h, e}
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
func (is InputSignature) EncodeTo(e *Encoder) { e.Write(is[:]) }

// EncodeTo implements types.EncoderTo.
func (w Work) EncodeTo(e *Encoder) { e.Write(w.NumHashes[:]) }

// EncodeTo implements types.EncoderTo.
func (c Currency) EncodeTo(e *Encoder) {
	e.WriteUint64(c.Lo)
	e.WriteUint64(c.Hi)
}

// EncodeTo implements types.EncoderTo.
func (index ChainIndex) EncodeTo(e *Encoder) {
	e.WriteUint64(index.Height)
	index.ID.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (h BlockHeader) EncodeTo(e *Encoder) {
	e.WriteUint64(h.Height)
	h.ParentID.EncodeTo(e)
	e.Write(h.Nonce[:])
	e.WriteTime(h.Timestamp)
	h.MinerAddress.EncodeTo(e)
	h.Commitment.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (id OutputID) EncodeTo(e *Encoder) {
	id.TransactionID.EncodeTo(e)
	e.WriteUint64(id.Index)
}

// EncodeTo implements types.EncoderTo.
func (b Beneficiary) EncodeTo(e *Encoder) {
	b.Value.EncodeTo(e)
	b.Address.EncodeTo(e)
}

func (e *Encoder) writeMerkleProof(proof []Hash256) {
	e.WritePrefix(len(proof))
	for _, p := range proof {
		p.EncodeTo(e)
	}
}

// EncodeTo implements types.EncoderTo
func (in SiacoinInput) EncodeTo(e *Encoder) {
	in.Parent.EncodeTo(e)
	e.WritePolicy(in.SpendPolicy)
	e.WritePrefix(len(in.Signatures))
	for _, sig := range in.Signatures {
		sig.EncodeTo(e)
	}
}

// EncodeTo implements types.EncoderTo
func (out SiacoinOutput) EncodeTo(e *Encoder) {
	out.ID.EncodeTo(e)
	out.Value.EncodeTo(e)
	out.Address.EncodeTo(e)
	e.WriteUint64(out.Timelock)
	e.writeMerkleProof(out.MerkleProof)
	e.WriteUint64(out.LeafIndex)
}

// EncodeTo implements types.EncoderTo
func (in SiafundInput) EncodeTo(e *Encoder) {
	in.Parent.EncodeTo(e)
	in.ClaimAddress.EncodeTo(e)
	e.WritePolicy(in.SpendPolicy)
	e.WritePrefix(len(in.Signatures))
	for _, sig := range in.Signatures {
		sig.EncodeTo(e)
	}
}

// EncodeTo implements types.EncoderTo
func (out SiafundOutput) EncodeTo(e *Encoder) {
	out.ID.EncodeTo(e)
	out.Value.EncodeTo(e)
	out.Address.EncodeTo(e)
	out.ClaimStart.EncodeTo(e)
	e.writeMerkleProof(out.MerkleProof)
	e.WriteUint64(out.LeafIndex)
}

// EncodeTo implements types.EncoderTo
func (fc FileContractState) EncodeTo(e *Encoder) {
	e.WriteUint64(fc.Filesize)
	fc.FileMerkleRoot.EncodeTo(e)
	e.WriteUint64(fc.WindowStart)
	e.WriteUint64(fc.WindowEnd)
	fc.ValidRenterOutput.EncodeTo(e)
	fc.ValidHostOutput.EncodeTo(e)
	fc.MissedRenterOutput.EncodeTo(e)
	fc.MissedHostOutput.EncodeTo(e)
	fc.RenterPublicKey.EncodeTo(e)
	fc.HostPublicKey.EncodeTo(e)
	e.WriteUint64(fc.RevisionNumber)
}

// EncodeTo implements types.EncoderTo
func (fc FileContract) EncodeTo(e *Encoder) {
	fc.ID.EncodeTo(e)
	fc.State.EncodeTo(e)
	e.writeMerkleProof(fc.MerkleProof)
	e.WriteUint64(fc.LeafIndex)
}

// EncodeTo implements types.EncoderTo
func (rev FileContractRevision) EncodeTo(e *Encoder) {
	rev.Parent.EncodeTo(e)
	rev.NewState.EncodeTo(e)
	rev.RenterSignature.EncodeTo(e)
	rev.HostSignature.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo
func (sp StorageProof) EncodeTo(e *Encoder) {
	sp.WindowStart.EncodeTo(e)
	e.writeMerkleProof(sp.WindowProof)
	e.Write(sp.DataSegment[:])
	e.writeMerkleProof(sp.SegmentProof)
}

// EncodeTo implements types.EncoderTo
func (res FileContractResolution) EncodeTo(e *Encoder) {
	res.Parent.EncodeTo(e)
	res.StorageProof.EncodeTo(e)
}

const (
	opInvalid = iota
	opAbove
	opPublicKey
	opThreshold
	opUnlockConditions
)

// WritePolicy writes a SpendPolicy to the underlying stream.
func (e *Encoder) WritePolicy(p SpendPolicy) {
	writeUint8 := func(u uint8) { e.Write([]byte{u}) }

	var writePolicy func(SpendPolicy)
	writePolicy = func(p SpendPolicy) {
		switch p := p.(type) {
		case PolicyAbove:
			writeUint8(opAbove)
			e.WriteUint64(uint64(p))
		case PolicyPublicKey:
			writeUint8(opPublicKey)
			PublicKey(p).EncodeTo(e)
		case PolicyThreshold:
			writeUint8(opThreshold)
			writeUint8(p.N)
			writeUint8(uint8(len(p.Of)))
			for i := range p.Of {
				writePolicy(p.Of[i])
			}
		case PolicyUnlockConditions:
			writeUint8(opUnlockConditions)
			e.WriteUint64(p.Timelock)
			writeUint8(uint8(len(p.PublicKeys)))
			for i := range p.PublicKeys {
				p.PublicKeys[i].EncodeTo(e)
			}
			writeUint8(p.SignaturesRequired)
		default:
			panic("unhandled policy type")
		}
	}

	const version = 1
	writeUint8(version)
	writePolicy(p)
}

// EncodeTo implements types.EncoderTo.
func (txn Transaction) EncodeTo(e *Encoder) {
	e.WritePrefix(len(txn.SiacoinInputs))
	for _, in := range txn.SiacoinInputs {
		in.EncodeTo(e)
	}
	e.WritePrefix(len(txn.SiacoinOutputs))
	for _, out := range txn.SiacoinOutputs {
		out.EncodeTo(e)
	}
	e.WritePrefix(len(txn.SiafundInputs))
	for _, in := range txn.SiafundInputs {
		in.EncodeTo(e)
	}
	e.WritePrefix(len(txn.SiafundOutputs))
	for _, out := range txn.SiafundOutputs {
		out.EncodeTo(e)
	}
	e.WritePrefix(len(txn.FileContracts))
	for _, fc := range txn.FileContracts {
		fc.EncodeTo(e)
	}
	e.WritePrefix(len(txn.FileContractRevisions))
	for _, rev := range txn.FileContractRevisions {
		rev.EncodeTo(e)
	}
	e.WritePrefix(len(txn.FileContractResolutions))
	for _, res := range txn.FileContractResolutions {
		res.EncodeTo(e)
	}
	e.WritePrefix(len(txn.ArbitraryData))
	e.Write(txn.ArbitraryData)
	txn.NewFoundationAddress.EncodeTo(e)
	txn.MinerFee.EncodeTo(e)
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
func (is *InputSignature) DecodeFrom(d *Decoder) { d.Read(is[:]) }

// DecodeFrom implements types.DecoderFrom.
func (w *Work) DecodeFrom(d *Decoder) { d.Read(w.NumHashes[:]) }

// DecodeFrom implements types.DecoderFrom.
func (c *Currency) DecodeFrom(d *Decoder) {
	c.Lo = d.ReadUint64()
	c.Hi = d.ReadUint64()
}

// DecodeFrom implements types.DecoderFrom.
func (index *ChainIndex) DecodeFrom(d *Decoder) {
	index.Height = d.ReadUint64()
	index.ID.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (h *BlockHeader) DecodeFrom(d *Decoder) {
	h.Height = d.ReadUint64()
	h.ParentID.DecodeFrom(d)
	d.Read(h.Nonce[:])
	h.Timestamp = d.ReadTime()
	h.MinerAddress.DecodeFrom(d)
	h.Commitment.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (id *OutputID) DecodeFrom(d *Decoder) {
	id.TransactionID.DecodeFrom(d)
	id.Index = d.ReadUint64()
}

// DecodeFrom implements types.DecoderFrom.
func (b *Beneficiary) DecodeFrom(d *Decoder) {
	b.Value.DecodeFrom(d)
	b.Address.DecodeFrom(d)
}

// ReadPolicy reads a SpendPolicy from the underlying stream.
func (d *Decoder) ReadPolicy() (p SpendPolicy) {
	var buf [1]byte
	readUint8 := func() uint8 {
		d.Read(buf[:1])
		return buf[0]
	}

	const maxPolicies = 1024
	totalPolicies := 1
	var readPolicy func() (SpendPolicy, error)
	readPolicy = func() (SpendPolicy, error) {
		switch op := readUint8(); op {
		case opAbove:
			return PolicyAbove(d.ReadUint64()), nil
		case opPublicKey:
			var pk PublicKey
			pk.DecodeFrom(d)
			return PolicyPublicKey(pk), nil
		case opThreshold:
			thresh := PolicyThreshold{
				N:  readUint8(),
				Of: make([]SpendPolicy, readUint8()),
			}
			totalPolicies += len(thresh.Of)
			if totalPolicies > maxPolicies {
				return nil, errors.New("policy is too complex")
			}
			var err error
			for i := range thresh.Of {
				thresh.Of[i], err = readPolicy()
				if err != nil {
					return nil, err
				}
			}
			return thresh, nil
		case opUnlockConditions:
			uc := PolicyUnlockConditions{
				Timelock:   d.ReadUint64(),
				PublicKeys: make([]PublicKey, readUint8()),
			}
			for i := range uc.PublicKeys {
				uc.PublicKeys[i].DecodeFrom(d)
			}
			uc.SignaturesRequired = readUint8()
			return uc, nil
		default:
			return nil, fmt.Errorf("unknown policy (opcode %v)", op)
		}
	}

	if version := readUint8(); version != 1 {
		d.SetErr(fmt.Errorf("unsupported policy version (%v)", version))
		return
	}
	p, err := readPolicy()
	d.SetErr(err)
	return p
}

func (d *Decoder) readMerkleProof() []Hash256 {
	proof := make([]Hash256, d.ReadPrefix())
	for i := range proof {
		proof[i].DecodeFrom(d)
	}
	return proof
}

// DecodeFrom implements types.DecoderFrom.
func (in *SiacoinInput) DecodeFrom(d *Decoder) {
	in.Parent.DecodeFrom(d)
	in.SpendPolicy = d.ReadPolicy()
	in.Signatures = make([]InputSignature, d.ReadPrefix())
	for i := range in.Signatures {
		in.Signatures[i].DecodeFrom(d)
	}
}

// DecodeFrom implements types.DecoderFrom.
func (out *SiacoinOutput) DecodeFrom(d *Decoder) {
	out.ID.DecodeFrom(d)
	out.Value.DecodeFrom(d)
	out.Address.DecodeFrom(d)
	out.Timelock = d.ReadUint64()
	out.MerkleProof = d.readMerkleProof()
	out.LeafIndex = d.ReadUint64()
}

// DecodeFrom implements types.DecoderFrom.
func (in *SiafundInput) DecodeFrom(d *Decoder) {
	in.Parent.DecodeFrom(d)
	in.ClaimAddress.DecodeFrom(d)
	in.SpendPolicy = d.ReadPolicy()
	in.Signatures = make([]InputSignature, d.ReadPrefix())
	for i := range in.Signatures {
		in.Signatures[i].DecodeFrom(d)
	}
}

// DecodeFrom implements types.DecoderFrom.
func (out *SiafundOutput) DecodeFrom(d *Decoder) {
	out.ID.DecodeFrom(d)
	out.Value.DecodeFrom(d)
	out.Address.DecodeFrom(d)
	out.ClaimStart.DecodeFrom(d)
	out.MerkleProof = d.readMerkleProof()
	out.LeafIndex = d.ReadUint64()
}

// DecodeFrom implements types.DecoderFrom.
func (fc *FileContractState) DecodeFrom(d *Decoder) {
	fc.Filesize = d.ReadUint64()
	fc.FileMerkleRoot.DecodeFrom(d)
	fc.WindowStart = d.ReadUint64()
	fc.WindowEnd = d.ReadUint64()
	fc.ValidRenterOutput.DecodeFrom(d)
	fc.ValidHostOutput.DecodeFrom(d)
	fc.MissedRenterOutput.DecodeFrom(d)
	fc.MissedHostOutput.DecodeFrom(d)
	fc.RenterPublicKey.DecodeFrom(d)
	fc.HostPublicKey.DecodeFrom(d)
	fc.RevisionNumber = d.ReadUint64()
}

// DecodeFrom implements types.DecoderFrom.
func (fc *FileContract) DecodeFrom(d *Decoder) {
	fc.ID.DecodeFrom(d)
	fc.State.DecodeFrom(d)
	fc.MerkleProof = d.readMerkleProof()
	fc.LeafIndex = d.ReadUint64()
}

// DecodeFrom implements types.DecoderFrom.
func (rev *FileContractRevision) DecodeFrom(d *Decoder) {
	rev.Parent.DecodeFrom(d)
	rev.NewState.DecodeFrom(d)
	rev.RenterSignature.DecodeFrom(d)
	rev.HostSignature.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (sp *StorageProof) DecodeFrom(d *Decoder) {
	sp.WindowStart.DecodeFrom(d)
	sp.WindowProof = d.readMerkleProof()
	d.Read(sp.DataSegment[:])
	sp.SegmentProof = d.readMerkleProof()
}

// DecodeFrom implements types.DecoderFrom.
func (res *FileContractResolution) DecodeFrom(d *Decoder) {
	res.Parent.DecodeFrom(d)
	res.StorageProof.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (txn *Transaction) DecodeFrom(d *Decoder) {
	txn.SiacoinInputs = make([]SiacoinInput, d.ReadPrefix())
	for i := range txn.SiacoinInputs {
		txn.SiacoinInputs[i].DecodeFrom(d)
	}
	txn.SiacoinOutputs = make([]Beneficiary, d.ReadPrefix())
	for i := range txn.SiacoinOutputs {
		txn.SiacoinOutputs[i].DecodeFrom(d)
	}
	txn.SiafundInputs = make([]SiafundInput, d.ReadPrefix())
	for i := range txn.SiafundInputs {
		txn.SiafundInputs[i].DecodeFrom(d)
	}
	txn.SiafundOutputs = make([]Beneficiary, d.ReadPrefix())
	for i := range txn.SiafundOutputs {
		txn.SiafundOutputs[i].DecodeFrom(d)
	}
	txn.FileContracts = make([]FileContractState, d.ReadPrefix())
	for i := range txn.FileContracts {
		txn.FileContracts[i].DecodeFrom(d)
	}
	txn.FileContractRevisions = make([]FileContractRevision, d.ReadPrefix())
	for i := range txn.FileContractRevisions {
		txn.FileContractRevisions[i].DecodeFrom(d)
	}
	txn.FileContractResolutions = make([]FileContractResolution, d.ReadPrefix())
	for i := range txn.FileContractResolutions {
		txn.FileContractResolutions[i].DecodeFrom(d)
	}
	txn.ArbitraryData = make([]byte, d.ReadPrefix())
	d.Read(txn.ArbitraryData)
	txn.NewFoundationAddress.DecodeFrom(d)
	txn.MinerFee.DecodeFrom(d)
}
