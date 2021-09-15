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

// WriteHash writes a hash to the underlying stream.
func (e *Encoder) WriteHash(h Hash256) { e.Write(h[:]) }

// WriteAddress writes an Address to the underlying stream.
func (e *Encoder) WriteAddress(a Address) { e.Write(a[:]) }

// WritePublicKey writes a public key to the underlying stream.
func (e *Encoder) WritePublicKey(pk PublicKey) { e.Write(pk[:]) }

// WriteSignature writes a signature to the underlying stream.
func (e *Encoder) WriteSignature(is InputSignature) { e.Write(is[:]) }

// WriteUint8 writes a uint8 value to the underlying stream.
func (e *Encoder) WriteUint8(p uint8) { e.Write([]byte{p}) }

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

// WriteWork writes a Work value to the underlying stream.
func (e *Encoder) WriteWork(w Work) { e.WriteHash(w.NumHashes) }

// WriteCurrency writes a Currency value to the underlying stream.
func (e *Encoder) WriteCurrency(c Currency) {
	e.WriteUint64(c.Lo)
	e.WriteUint64(c.Hi)
}

// WriteChainIndex writes a ChainIndex to the underlying stream.
func (e *Encoder) WriteChainIndex(index ChainIndex) {
	e.WriteUint64(index.Height)
	e.WriteHash(Hash256(index.ID))
}

// WriteHeader writes a BlockHeader to the underlying stream.
func (e *Encoder) WriteHeader(h BlockHeader) {
	e.WriteUint64(h.Height)
	e.WriteHash(Hash256(h.ParentID))
	e.Write(h.Nonce[:])
	e.WriteTime(h.Timestamp)
	e.WriteAddress(h.MinerAddress)
	e.WriteHash(h.Commitment)
}

// WriteOutputID writes an OutputID to the underlying stream.
func (e *Encoder) WriteOutputID(id OutputID) {
	e.WriteHash(Hash256(id.TransactionID))
	e.WriteUint64(id.Index)
}

// WriteBeneficiary writes a Beneficiary to the underlying stream.
func (e *Encoder) WriteBeneficiary(b Beneficiary) {
	e.WriteCurrency(b.Value)
	e.WriteAddress(b.Address)
}

func (e *Encoder) writeMerkleProof(proof []Hash256) {
	e.WritePrefix(len(proof))
	for _, p := range proof {
		e.WriteHash(p)
	}
}

// WriteSiacoinInput writes a SiacoinInput to the underlying stream.
func (e *Encoder) WriteSiacoinInput(in SiacoinInput) {
	e.WriteSiacoinOutput(in.Parent)
	e.WritePolicy(in.SpendPolicy)
	e.WritePrefix(len(in.Signatures))
	for _, sig := range in.Signatures {
		e.WriteSignature(sig)
	}
}

// WriteSiacoinOutput writes a SiacoinOutput to the underlying stream.
func (e *Encoder) WriteSiacoinOutput(out SiacoinOutput) {
	e.WriteOutputID(out.ID)
	e.WriteCurrency(out.Value)
	e.WriteAddress(out.Address)
	e.WriteUint64(out.Timelock)
	e.writeMerkleProof(out.MerkleProof)
	e.WriteUint64(out.LeafIndex)
}

// WriteSiafundInput writes a SiafundInput to the underlying stream.
func (e *Encoder) WriteSiafundInput(in SiafundInput) {
	e.WriteSiafundOutput(in.Parent)
	e.WriteAddress(in.ClaimAddress)
	e.WritePolicy(in.SpendPolicy)
	e.WritePrefix(len(in.Signatures))
	for _, sig := range in.Signatures {
		e.WriteSignature(sig)
	}
}

// WriteSiafundOutput writes a SiafundOutput to the underlying stream.
func (e *Encoder) WriteSiafundOutput(out SiafundOutput) {
	e.WriteOutputID(out.ID)
	e.WriteCurrency(out.Value)
	e.WriteAddress(out.Address)
	e.WriteCurrency(out.ClaimStart)
	e.writeMerkleProof(out.MerkleProof)
	e.WriteUint64(out.LeafIndex)
}

// WriteFileContractState writes a FileContractState to the underlying stream.
func (e *Encoder) WriteFileContractState(fc FileContractState) {
	e.WriteUint64(fc.Filesize)
	e.WriteHash(fc.FileMerkleRoot)
	e.WriteUint64(fc.WindowStart)
	e.WriteUint64(fc.WindowEnd)
	e.WriteBeneficiary(fc.ValidRenterOutput)
	e.WriteBeneficiary(fc.ValidHostOutput)
	e.WriteBeneficiary(fc.MissedRenterOutput)
	e.WriteBeneficiary(fc.MissedHostOutput)
	e.WritePublicKey(fc.RenterPublicKey)
	e.WritePublicKey(fc.HostPublicKey)
	e.WriteUint64(fc.RevisionNumber)
}

// WriteFileContract writes a FileContract to the underlying stream.
func (e *Encoder) WriteFileContract(fc FileContract) {
	e.WriteOutputID(fc.ID)
	e.WriteFileContractState(fc.State)
	e.writeMerkleProof(fc.MerkleProof)
	e.WriteUint64(fc.LeafIndex)
}

// WriteFileContractRevision writes a FileContractRevision to the underlying
// stream.
func (e *Encoder) WriteFileContractRevision(rev FileContractRevision) {
	e.WriteFileContract(rev.Parent)
	e.WriteFileContractState(rev.NewState)
	e.WriteSignature(rev.RenterSignature)
	e.WriteSignature(rev.HostSignature)
}

// WriteStorageProof writes a StorageProof to the underlying stream.
func (e *Encoder) WriteStorageProof(sp StorageProof) {
	e.WriteChainIndex(sp.WindowStart)
	e.writeMerkleProof(sp.WindowProof)
	e.Write(sp.DataSegment[:])
	e.writeMerkleProof(sp.SegmentProof)
}

// WriteFileContractResolution writes a FileContractResolution value to the
// underlying stream.
func (e *Encoder) WriteFileContractResolution(res FileContractResolution) {
	e.WriteFileContract(res.Parent)
	e.WriteStorageProof(res.StorageProof)
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
	var writePolicy func(SpendPolicy)
	writePolicy = func(p SpendPolicy) {
		switch p := p.(type) {
		case PolicyAbove:
			e.WriteUint8(opAbove)
			e.WriteUint64(uint64(p))
		case PolicyPublicKey:
			e.WriteUint8(opPublicKey)
			e.WritePublicKey(PublicKey(p))
		case PolicyThreshold:
			e.WriteUint8(opThreshold)
			e.WriteUint8(p.N)
			e.WriteUint8(uint8(len(p.Of)))
			for i := range p.Of {
				writePolicy(p.Of[i])
			}
		case PolicyUnlockConditions:
			e.WriteUint8(opUnlockConditions)
			e.WriteUint64(p.Timelock)
			e.WriteUint8(uint8(len(p.PublicKeys)))
			for i := range p.PublicKeys {
				e.WritePublicKey(p.PublicKeys[i])
			}
			e.WriteUint8(p.SignaturesRequired)
		default:
			panic("unhandled policy type")
		}
	}

	const version = 1
	e.WriteUint8(version)
	writePolicy(p)
}

// WriteTransaction writes a Transaction value to the underlying stream.
func (e *Encoder) WriteTransaction(txn Transaction) {
	e.WritePrefix(len(txn.SiacoinInputs))
	for _, in := range txn.SiacoinInputs {
		e.WriteSiacoinInput(in)
	}
	e.WritePrefix(len(txn.SiacoinOutputs))
	for _, out := range txn.SiacoinOutputs {
		e.WriteBeneficiary(out)
	}
	e.WritePrefix(len(txn.SiafundInputs))
	for _, in := range txn.SiafundInputs {
		e.WriteSiafundInput(in)
	}
	e.WritePrefix(len(txn.SiafundOutputs))
	for _, out := range txn.SiafundOutputs {
		e.WriteBeneficiary(out)
	}
	e.WritePrefix(len(txn.FileContracts))
	for _, fc := range txn.FileContracts {
		e.WriteFileContractState(fc)
	}
	e.WritePrefix(len(txn.FileContractRevisions))
	for _, rev := range txn.FileContractRevisions {
		e.WriteFileContractRevision(rev)
	}
	e.WritePrefix(len(txn.FileContractResolutions))
	for _, res := range txn.FileContractResolutions {
		e.WriteFileContractResolution(res)
	}
	e.WritePrefix(len(txn.ArbitraryData))
	e.Write(txn.ArbitraryData)
	e.WriteAddress(txn.NewFoundationAddress)
	e.WriteCurrency(txn.MinerFee)
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
func (d *Decoder) ReadPrefix() uint64 {
	n := d.ReadUint64()
	if n > uint64(d.lr.N) {
		d.SetErr(fmt.Errorf("encoded object contains invalid length prefix (%v elems > %v bytes left in stream)", n, d.lr.N))
		return 0
	}
	return n
}

// ReadTime reads a time.Time from the underlying stream.
func (d *Decoder) ReadTime() time.Time { return time.Unix(int64(d.ReadUint64()), 0) }

// ReadHash reads a hash from the underlying stream.
func (d *Decoder) ReadHash() (h Hash256) {
	d.Read(h[:])
	return
}

// ReadAddress reads an address from the underlying stream.
func (d *Decoder) ReadAddress() Address { return Address(d.ReadHash()) }

// ReadPublicKey reads a public key from the underlying stream.
func (d *Decoder) ReadPublicKey() PublicKey { return PublicKey(d.ReadHash()) }

// ReadSignature reads an InputSignature from the underlying stream.
func (d *Decoder) ReadSignature() (is InputSignature) {
	d.Read(is[:])
	return
}

// ReadWork reads a Work value from the underlying stream.
func (d *Decoder) ReadWork() Work { return Work{d.ReadHash()} }

// ReadCurrency reads a Currency value from the underlying stream.
func (d *Decoder) ReadCurrency() (c Currency) {
	return NewCurrency(d.ReadUint64(), d.ReadUint64())
}

// ReadChainIndex reads a ChainIndex from the underlying stream.
func (d *Decoder) ReadChainIndex() ChainIndex {
	return ChainIndex{
		d.ReadUint64(),
		BlockID(d.ReadHash()),
	}
}

// ReadHeader reads a BlockHeader from the underlying stream.
func (d *Decoder) ReadHeader() (h BlockHeader) {
	h.Height = d.ReadUint64()
	h.ParentID = BlockID(d.ReadHash())
	d.Read(h.Nonce[:])
	h.Timestamp = d.ReadTime()
	h.MinerAddress = d.ReadAddress()
	h.Commitment = d.ReadHash()
	return
}

// ReadOutputID reads an OutputID from the underlying stream.
func (d *Decoder) ReadOutputID() OutputID {
	return OutputID{
		TransactionID(d.ReadHash()),
		d.ReadUint64(),
	}
}

// ReadBeneficiary reads a Beneficiary from the underlying stream.
func (d *Decoder) ReadBeneficiary() Beneficiary {
	return Beneficiary{
		d.ReadCurrency(),
		d.ReadAddress(),
	}
}

// ReadPolicy reads a SpendPolicy from the underlying stream.
func (d *Decoder) ReadPolicy() (p SpendPolicy) {
	const maxPolicies = 1024
	totalPolicies := 1
	var readPolicy func() (SpendPolicy, error)
	readPolicy = func() (SpendPolicy, error) {
		switch op := d.ReadUint8(); op {
		case opAbove:
			return PolicyAbove(d.ReadUint64()), nil
		case opPublicKey:
			return PolicyPublicKey(d.ReadHash()), nil
		case opThreshold:
			thresh := PolicyThreshold{
				N:  d.ReadUint8(),
				Of: make([]SpendPolicy, d.ReadUint8()),
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
				PublicKeys: make([]PublicKey, d.ReadUint8()),
			}
			for i := range uc.PublicKeys {
				uc.PublicKeys[i] = PublicKey(d.ReadHash())
			}
			uc.SignaturesRequired = d.ReadUint8()
			return uc, nil
		default:
			return nil, fmt.Errorf("unknown policy (opcode %v)", op)
		}
	}

	if version := d.ReadUint8(); version != 1 {
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
		proof[i] = d.ReadHash()
	}
	return proof
}

// ReadSiacoinInput reads a SiacoinInput from the underlying stream.
func (d *Decoder) ReadSiacoinInput() (in SiacoinInput) {
	in.Parent = d.ReadSiacoinOutput()
	in.SpendPolicy = d.ReadPolicy()
	in.Signatures = make([]InputSignature, d.ReadPrefix())
	for i := range in.Signatures {
		in.Signatures[i] = d.ReadSignature()
	}
	return
}

// ReadSiacoinOutput reads a SiacoinOutput from the underlying stream.
func (d *Decoder) ReadSiacoinOutput() SiacoinOutput {
	return SiacoinOutput{
		d.ReadOutputID(),
		d.ReadCurrency(),
		d.ReadAddress(),
		d.ReadUint64(),
		d.readMerkleProof(),
		d.ReadUint64(),
	}
}

// ReadSiafundInput reads a SiafundInput from the underlying stream.
func (d *Decoder) ReadSiafundInput() (in SiafundInput) {
	in.Parent = d.ReadSiafundOutput()
	in.ClaimAddress = d.ReadAddress()
	in.SpendPolicy = d.ReadPolicy()
	in.Signatures = make([]InputSignature, d.ReadPrefix())
	for i := range in.Signatures {
		in.Signatures[i] = d.ReadSignature()
	}
	return
}

// ReadSiafundOutput reads a SiafundOutput from the underlying stream.
func (d *Decoder) ReadSiafundOutput() SiafundOutput {
	return SiafundOutput{
		d.ReadOutputID(),
		d.ReadCurrency(),
		d.ReadAddress(),
		d.ReadCurrency(),
		d.readMerkleProof(),
		d.ReadUint64(),
	}
}

// ReadFileContractState reads a FileContractState from the underlying stream.
func (d *Decoder) ReadFileContractState() FileContractState {
	return FileContractState{
		d.ReadUint64(),
		d.ReadHash(),
		d.ReadUint64(),
		d.ReadUint64(),
		d.ReadBeneficiary(),
		d.ReadBeneficiary(),
		d.ReadBeneficiary(),
		d.ReadBeneficiary(),
		PublicKey(d.ReadHash()),
		PublicKey(d.ReadHash()),
		d.ReadUint64(),
	}
}

// ReadFileContract reads a FileContract from the underlying stream.
func (d *Decoder) ReadFileContract() (fc FileContract) {
	return FileContract{
		d.ReadOutputID(),
		d.ReadFileContractState(),
		d.readMerkleProof(),
		d.ReadUint64(),
	}
}

// ReadFileContractRevision reads a FileContractRevision from the underlying
// stream.
func (d *Decoder) ReadFileContractRevision() FileContractRevision {
	return FileContractRevision{
		d.ReadFileContract(),
		d.ReadFileContractState(),
		d.ReadSignature(),
		d.ReadSignature(),
	}
}

// ReadStorageProof reads a StorageProof from the underlying stream.
func (d *Decoder) ReadStorageProof() (sp StorageProof) {
	sp.WindowStart = d.ReadChainIndex()
	sp.WindowProof = d.readMerkleProof()
	d.Read(sp.DataSegment[:])
	sp.SegmentProof = d.readMerkleProof()
	return
}

// ReadFileContractResolution reads a FileContractResolution from the underlying
// stream.
func (d *Decoder) ReadFileContractResolution() (res FileContractResolution) {
	return FileContractResolution{d.ReadFileContract(), d.ReadStorageProof()}
}

// ReadTransaction reads a transaction from the underlying stream.
func (d *Decoder) ReadTransaction() (txn Transaction) {
	txn.SiacoinInputs = make([]SiacoinInput, d.ReadPrefix())
	for i := range txn.SiacoinInputs {
		txn.SiacoinInputs[i] = d.ReadSiacoinInput()
	}
	txn.SiacoinOutputs = make([]Beneficiary, d.ReadPrefix())
	for i := range txn.SiacoinOutputs {
		txn.SiacoinOutputs[i] = d.ReadBeneficiary()
	}
	txn.SiafundInputs = make([]SiafundInput, d.ReadPrefix())
	for i := range txn.SiafundInputs {
		txn.SiafundInputs[i] = d.ReadSiafundInput()
	}
	txn.SiafundOutputs = make([]Beneficiary, d.ReadPrefix())
	for i := range txn.SiafundOutputs {
		txn.SiafundOutputs[i] = d.ReadBeneficiary()
	}
	txn.FileContracts = make([]FileContractState, d.ReadPrefix())
	for i := range txn.FileContracts {
		txn.FileContracts[i] = d.ReadFileContractState()
	}
	txn.FileContractRevisions = make([]FileContractRevision, d.ReadPrefix())
	for i := range txn.FileContractRevisions {
		txn.FileContractRevisions[i] = d.ReadFileContractRevision()
	}
	txn.FileContractResolutions = make([]FileContractResolution, d.ReadPrefix())
	for i := range txn.FileContractResolutions {
		txn.FileContractResolutions[i] = d.ReadFileContractResolution()
	}
	txn.ArbitraryData = make([]byte, d.ReadPrefix())
	d.Read(txn.ArbitraryData)
	txn.NewFoundationAddress = d.ReadAddress()
	txn.MinerFee = d.ReadCurrency()

	return
}

// NewDecoder returns a Decoder that wraps the provided stream.
func NewDecoder(lr io.LimitedReader) *Decoder {
	return &Decoder{
		lr: lr,
	}
}

// NewBufDecoder returns a Decoder for the provided byte slice.
func NewBufDecoder(buf []byte) *Decoder {
	return NewDecoder(io.LimitedReader{
		R: bytes.NewReader(buf),
		N: int64(len(buf)),
	})
}

// A DecoderFrom can decode itself from a stream via a Decoder.
type DecoderFrom interface {
	DecodeFrom(d *Decoder)
}

// A Hasher streams objects into an instance of Sia's hash function.
type Hasher struct {
	h hash.Hash
	*Encoder
}

// Reset resets the underlying hash digest state.
func (h *Hasher) Reset() { h.h.Reset() }

// Sum returns the digest of the objects written to the Hasher.
func (h *Hasher) Sum() (sum Hash256) {
	_ = h.Encoder.Flush() // no error possible
	h.h.Sum(sum[:0])
	return
}

// NewHasher returns a new Hasher instance.
func NewHasher() *Hasher {
	h, _ := blake2b.New256(nil)
	e := NewEncoder(h)
	return &Hasher{h, e}
}
