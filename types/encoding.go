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
func (d *Decoder) ReadTime() time.Time { return time.Unix(int64(d.ReadUint64()), 0).UTC() }

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
	e.WriteUint64(h.Nonce)
	e.WriteTime(h.Timestamp)
	h.MinerAddress.EncodeTo(e)
	h.Commitment.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (id ElementID) EncodeTo(e *Encoder) {
	id.Source.EncodeTo(e)
	e.WriteUint64(id.Index)
}

// EncodeTo implements types.EncoderTo.
func (sco SiacoinOutput) EncodeTo(e *Encoder) {
	sco.Value.EncodeTo(e)
	sco.Address.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (sfo SiafundOutput) EncodeTo(e *Encoder) {
	e.WriteUint64(sfo.Value)
	sfo.Address.EncodeTo(e)
}

func (e *Encoder) writeMerkleProof(proof []Hash256) {
	e.WritePrefix(len(proof))
	for _, p := range proof {
		p.EncodeTo(e)
	}
}

// EncodeTo implements types.EncoderTo.
func (se StateElement) EncodeTo(e *Encoder) {
	se.ID.EncodeTo(e)
	e.WriteUint64(se.LeafIndex)
	e.writeMerkleProof(se.MerkleProof)
}

// EncodeTo implements types.EncoderTo.
func (in SiacoinInput) EncodeTo(e *Encoder) {
	in.Parent.EncodeTo(e)
	e.WritePolicy(in.SpendPolicy)
	e.WritePrefix(len(in.Signatures))
	for _, sig := range in.Signatures {
		sig.EncodeTo(e)
	}
}

// EncodeTo implements types.EncoderTo.
func (sce SiacoinElement) EncodeTo(e *Encoder) {
	sce.StateElement.EncodeTo(e)
	sce.SiacoinOutput.EncodeTo(e)
	e.WriteUint64(sce.MaturityHeight)
}

// EncodeTo implements types.EncoderTo.
func (in SiafundInput) EncodeTo(e *Encoder) {
	in.Parent.EncodeTo(e)
	in.ClaimAddress.EncodeTo(e)
	e.WritePolicy(in.SpendPolicy)
	e.WritePrefix(len(in.Signatures))
	for _, sig := range in.Signatures {
		sig.EncodeTo(e)
	}
}

// EncodeTo implements types.EncoderTo.
func (sfe SiafundElement) EncodeTo(e *Encoder) {
	sfe.StateElement.EncodeTo(e)
	sfe.SiafundOutput.EncodeTo(e)
	sfe.ClaimStart.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (fc FileContract) EncodeTo(e *Encoder) {
	e.WriteUint64(fc.Filesize)
	fc.FileMerkleRoot.EncodeTo(e)
	e.WriteUint64(fc.WindowStart)
	e.WriteUint64(fc.WindowEnd)
	fc.RenterOutput.EncodeTo(e)
	fc.HostOutput.EncodeTo(e)
	fc.MissedHostValue.EncodeTo(e)
	fc.TotalCollateral.EncodeTo(e)
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
func (rev FileContractRevision) EncodeTo(e *Encoder) {
	rev.Parent.EncodeTo(e)
	rev.Revision.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (ren FileContractRenewal) EncodeTo(e *Encoder) {
	ren.FinalRevision.EncodeTo(e)
	ren.InitialRevision.EncodeTo(e)
	ren.RenterRollover.EncodeTo(e)
	ren.HostRollover.EncodeTo(e)
	ren.RenterSignature.EncodeTo(e)
	ren.HostSignature.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (sp StorageProof) EncodeTo(e *Encoder) {
	sp.WindowStart.EncodeTo(e)
	e.writeMerkleProof(sp.WindowProof)
	e.Write(sp.Leaf[:])
	e.writeMerkleProof(sp.Proof)
}

// EncodeTo implements types.EncoderTo.
func (res FileContractResolution) EncodeTo(e *Encoder) {
	res.Parent.EncodeTo(e)
	res.Renewal.EncodeTo(e)
	res.StorageProof.EncodeTo(e)
	res.Finalization.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (a Attestation) EncodeTo(e *Encoder) {
	a.PublicKey.EncodeTo(e)
	e.WriteString(a.Key)
	e.WriteBytes(a.Value)
	a.Signature.EncodeTo(e)
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
			panic(fmt.Sprintf("unhandled policy type, %T", p))
		}
	}

	const version = 1
	writeUint8(version)
	writePolicy(p)
}

// EncodeTo implements types.EncoderTo.
func (txn Transaction) EncodeTo(e *Encoder) {
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
		txn.NewFoundationAddress != VoidAddress,
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
			out.EncodeTo(e)
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
			out.EncodeTo(e)
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
		for _, res := range txn.FileContractResolutions {
			res.EncodeTo(e)
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
		txn.MinerFee.EncodeTo(e)
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
	h.Nonce = d.ReadUint64()
	h.Timestamp = d.ReadTime()
	h.MinerAddress.DecodeFrom(d)
	h.Commitment.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (id *ElementID) DecodeFrom(d *Decoder) {
	id.Source.DecodeFrom(d)
	id.Index = d.ReadUint64()
}

// DecodeFrom implements types.DecoderFrom.
func (sco *SiacoinOutput) DecodeFrom(d *Decoder) {
	sco.Value.DecodeFrom(d)
	sco.Address.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (sfo *SiafundOutput) DecodeFrom(d *Decoder) {
	sfo.Value = d.ReadUint64()
	sfo.Address.DecodeFrom(d)
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
func (se *StateElement) DecodeFrom(d *Decoder) {
	se.ID.DecodeFrom(d)
	se.LeafIndex = d.ReadUint64()
	se.MerkleProof = d.readMerkleProof()
}

// DecodeFrom implements types.DecoderFrom.
func (in *SiacoinInput) DecodeFrom(d *Decoder) {
	in.Parent.DecodeFrom(d)
	in.SpendPolicy = d.ReadPolicy()
	in.Signatures = make([]Signature, d.ReadPrefix())
	for i := range in.Signatures {
		in.Signatures[i].DecodeFrom(d)
	}
}

// DecodeFrom implements types.DecoderFrom.
func (sce *SiacoinElement) DecodeFrom(d *Decoder) {
	sce.StateElement.DecodeFrom(d)
	sce.SiacoinOutput.DecodeFrom(d)
	sce.MaturityHeight = d.ReadUint64()
}

// DecodeFrom implements types.DecoderFrom.
func (in *SiafundInput) DecodeFrom(d *Decoder) {
	in.Parent.DecodeFrom(d)
	in.ClaimAddress.DecodeFrom(d)
	in.SpendPolicy = d.ReadPolicy()
	in.Signatures = make([]Signature, d.ReadPrefix())
	for i := range in.Signatures {
		in.Signatures[i].DecodeFrom(d)
	}
}

// DecodeFrom implements types.DecoderFrom.
func (sfe *SiafundElement) DecodeFrom(d *Decoder) {
	sfe.StateElement.DecodeFrom(d)
	sfe.SiafundOutput.DecodeFrom(d)
	sfe.ClaimStart.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (fc *FileContract) DecodeFrom(d *Decoder) {
	fc.Filesize = d.ReadUint64()
	fc.FileMerkleRoot.DecodeFrom(d)
	fc.WindowStart = d.ReadUint64()
	fc.WindowEnd = d.ReadUint64()
	fc.RenterOutput.DecodeFrom(d)
	fc.HostOutput.DecodeFrom(d)
	fc.MissedHostValue.DecodeFrom(d)
	fc.TotalCollateral.DecodeFrom(d)
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
func (rev *FileContractRevision) DecodeFrom(d *Decoder) {
	rev.Parent.DecodeFrom(d)
	rev.Revision.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (ren *FileContractRenewal) DecodeFrom(d *Decoder) {
	ren.FinalRevision.DecodeFrom(d)
	ren.InitialRevision.DecodeFrom(d)
	ren.RenterRollover.DecodeFrom(d)
	ren.HostRollover.DecodeFrom(d)
	ren.RenterSignature.DecodeFrom(d)
	ren.HostSignature.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (sp *StorageProof) DecodeFrom(d *Decoder) {
	sp.WindowStart.DecodeFrom(d)
	sp.WindowProof = d.readMerkleProof()
	d.Read(sp.Leaf[:])
	sp.Proof = d.readMerkleProof()
}

// DecodeFrom implements types.DecoderFrom.
func (res *FileContractResolution) DecodeFrom(d *Decoder) {
	res.Parent.DecodeFrom(d)
	res.Renewal.DecodeFrom(d)
	res.StorageProof.DecodeFrom(d)
	res.Finalization.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (a *Attestation) DecodeFrom(d *Decoder) {
	a.PublicKey.DecodeFrom(d)
	a.Key = d.ReadString()
	a.Value = d.ReadBytes()
	a.Signature.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (txn *Transaction) DecodeFrom(d *Decoder) {
	fields := d.ReadUint64()

	if fields&(1<<0) != 0 {
		txn.SiacoinInputs = make([]SiacoinInput, d.ReadPrefix())
		for i := range txn.SiacoinInputs {
			txn.SiacoinInputs[i].DecodeFrom(d)
		}
	}
	if fields&(1<<1) != 0 {
		txn.SiacoinOutputs = make([]SiacoinOutput, d.ReadPrefix())
		for i := range txn.SiacoinOutputs {
			txn.SiacoinOutputs[i].DecodeFrom(d)
		}
	}
	if fields&(1<<2) != 0 {
		txn.SiafundInputs = make([]SiafundInput, d.ReadPrefix())
		for i := range txn.SiafundInputs {
			txn.SiafundInputs[i].DecodeFrom(d)
		}
	}
	if fields&(1<<3) != 0 {
		txn.SiafundOutputs = make([]SiafundOutput, d.ReadPrefix())
		for i := range txn.SiafundOutputs {
			txn.SiafundOutputs[i].DecodeFrom(d)
		}
	}
	if fields&(1<<4) != 0 {
		txn.FileContracts = make([]FileContract, d.ReadPrefix())
		for i := range txn.FileContracts {
			txn.FileContracts[i].DecodeFrom(d)
		}
	}
	if fields&(1<<5) != 0 {
		txn.FileContractRevisions = make([]FileContractRevision, d.ReadPrefix())
		for i := range txn.FileContractRevisions {
			txn.FileContractRevisions[i].DecodeFrom(d)
		}
	}
	if fields&(1<<6) != 0 {
		txn.FileContractResolutions = make([]FileContractResolution, d.ReadPrefix())
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
		txn.NewFoundationAddress.DecodeFrom(d)
	}
	if fields&(1<<10) != 0 {
		txn.MinerFee.DecodeFrom(d)
	}
}
