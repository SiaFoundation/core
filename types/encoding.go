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

// WriteAddress writes an address to the underlying stream.
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

// WriteInt writes an int value to the underlying stream.
func (e *Encoder) WriteInt(i int) { e.WriteUint64(uint64(i)) }

// WriteTime writes a time value to the underlying stream.
func (e *Encoder) WriteTime(t time.Time) { e.WriteUint64(uint64(t.Unix())) }

// WriteWork writes a Work value to the underlying stream.
func (e *Encoder) WriteWork(w Work) { e.WriteHash(w.NumHashes) }

// WriteCurrency writes a Currency value to the underlying stream.
func (e *Encoder) WriteCurrency(c Currency) {
	e.WriteUint64(c.Lo)
	e.WriteUint64(c.Hi)
}

// WriteChainIndex writes a ChainIndex value to the underlying stream.
func (e *Encoder) WriteChainIndex(index ChainIndex) {
	e.WriteUint64(index.Height)
	e.WriteHash(Hash256(index.ID))
}

// WriteOutputID writes an OutputID value to the underlying stream.
func (e *Encoder) WriteOutputID(id OutputID) {
	e.WriteHash(Hash256(id.TransactionID))
	e.WriteUint64(id.Index)
}

// WriteBeneficiary writes a Beneficiary value to the underlying stream.
func (e *Encoder) WriteBeneficiary(b Beneficiary) {
	e.WriteCurrency(b.Value)
	e.WriteAddress(b.Address)
}

// WriteFileContractState writes a FileContractState value to the
// underlying stream.
func (e *Encoder) WriteFileContractState(rev FileContractState) {
	e.WriteUint64(rev.Filesize)
	e.WriteHash(rev.FileMerkleRoot)
	e.WriteUint64(rev.WindowStart)
	e.WriteUint64(rev.WindowEnd)
	e.WriteBeneficiary(rev.ValidRenterOutput)
	e.WriteBeneficiary(rev.ValidHostOutput)
	e.WriteBeneficiary(rev.MissedRenterOutput)
	e.WriteBeneficiary(rev.MissedHostOutput)
	e.WritePublicKey(rev.RenterPublicKey)
	e.WritePublicKey(rev.HostPublicKey)
	e.WriteUint64(rev.RevisionNumber)
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
	writeMerkleProof := func(proof []Hash256) {
		e.WriteInt(len(proof))
		for _, p := range proof {
			e.WriteHash(p)
		}
	}

	e.WriteInt(len(txn.SiacoinInputs))
	for _, in := range txn.SiacoinInputs {
		e.WriteOutputID(in.Parent.ID)
		e.WriteCurrency(in.Parent.Value)
		e.WriteAddress(in.Parent.Address)
		e.WriteUint64(in.Parent.Timelock)
		writeMerkleProof(in.Parent.MerkleProof)
		e.WriteUint64(in.Parent.LeafIndex)
		e.WritePolicy(in.SpendPolicy)
		e.WriteInt(len(in.Signatures))
		for _, sig := range in.Signatures {
			e.WriteSignature(sig)
		}
	}
	e.WriteInt(len(txn.SiacoinOutputs))
	for _, out := range txn.SiacoinOutputs {
		e.WriteBeneficiary(out)
	}
	e.WriteInt(len(txn.SiafundInputs))
	for _, in := range txn.SiafundInputs {
		e.WriteOutputID(in.Parent.ID)
		e.WriteCurrency(in.Parent.Value)
		e.WriteAddress(in.Parent.Address)
		e.WriteCurrency(in.Parent.ClaimStart)
		writeMerkleProof(in.Parent.MerkleProof)
		e.WriteUint64(in.Parent.LeafIndex)
		e.WriteAddress(in.ClaimAddress)
		e.WritePolicy(in.SpendPolicy)
		e.WriteInt(len(in.Signatures))
		for _, sig := range in.Signatures {
			e.WriteSignature(sig)
		}
	}
	e.WriteInt(len(txn.SiafundOutputs))
	for _, out := range txn.SiafundOutputs {
		e.WriteBeneficiary(out)
	}
	e.WriteInt(len(txn.FileContracts))
	for _, fc := range txn.FileContracts {
		e.WriteFileContractState(fc)
	}
	e.WriteInt(len(txn.FileContractRevisions))
	for _, fcr := range txn.FileContractRevisions {
		e.WriteOutputID(fcr.Parent.ID)
		e.WriteFileContractState(fcr.Parent.State)
		writeMerkleProof(fcr.Parent.MerkleProof)
		e.WriteUint64(fcr.Parent.LeafIndex)
		e.WriteFileContractState(fcr.NewState)
		e.WriteSignature(fcr.RenterSignature)
		e.WriteSignature(fcr.HostSignature)
	}
	e.WriteInt(len(txn.FileContractResolutions))
	for _, fcr := range txn.FileContractResolutions {
		e.WriteOutputID(fcr.Parent.ID)
		e.WriteFileContractState(fcr.Parent.State)
		writeMerkleProof(fcr.Parent.MerkleProof)
		e.WriteUint64(fcr.Parent.LeafIndex)
		e.WriteChainIndex(fcr.StorageProof.WindowStart)
		writeMerkleProof(fcr.StorageProof.WindowProof)
		e.Write(fcr.StorageProof.DataSegment[:])
		writeMerkleProof(fcr.StorageProof.SegmentProof)
	}
	e.WriteInt(len(txn.ArbitraryData))
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

// A Decoder reads values from an underlying stream. Callers MUST check
// (*Decoder).Err before using any decoded values.
type Decoder struct {
	lr  io.LimitedReader
	buf [64]byte
	err error
}

func (d *Decoder) setErr(err error) {
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
		d.setErr(fmt.Errorf("encoded object contains invalid length prefix (%v elems > %v bytes left in stream)", n, d.lr.N))
		return 0
	}
	return n
}

// ReadTime reads a time.Time from the underlying stream.
func (d *Decoder) ReadTime() time.Time {
	return time.Unix(int64(d.ReadUint64()), 0)
}

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
	return ChainIndex{d.ReadUint64(), BlockID(d.ReadHash())}
}

// ReadOutputID reads an OutputID from the underlying stream.
func (d *Decoder) ReadOutputID() OutputID {
	return OutputID{TransactionID(d.ReadHash()), d.ReadUint64()}
}

// ReadBeneficiary reads a Beneficiary from the underlying stream.
func (d *Decoder) ReadBeneficiary() Beneficiary {
	return Beneficiary{d.ReadCurrency(), d.ReadAddress()}
}

// ReadFileContractState reads a FileContractState from the underlying stream.
func (d *Decoder) ReadFileContractState() (fc FileContractState) {
	fc.Filesize = d.ReadUint64()
	fc.FileMerkleRoot = d.ReadHash()
	fc.WindowStart = d.ReadUint64()
	fc.WindowEnd = d.ReadUint64()
	fc.ValidRenterOutput = d.ReadBeneficiary()
	fc.ValidHostOutput = d.ReadBeneficiary()
	fc.MissedRenterOutput = d.ReadBeneficiary()
	fc.MissedHostOutput = d.ReadBeneficiary()
	fc.RenterPublicKey = PublicKey(d.ReadHash())
	fc.HostPublicKey = PublicKey(d.ReadHash())
	fc.RevisionNumber = d.ReadUint64()
	return
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
		d.setErr(fmt.Errorf("unsupported policy version (%v)", version))
		return
	}
	p, err := readPolicy()
	d.setErr(err)
	return p
}

// ReadTransaction reads a transaction from the underlying stream.
func (d *Decoder) ReadTransaction() (txn Transaction) {
	readMerkleProof := func() []Hash256 {
		proof := make([]Hash256, d.ReadPrefix())
		for i := range proof {
			proof[i] = d.ReadHash()
		}
		return proof
	}

	txn.SiacoinInputs = make([]SiacoinInput, d.ReadPrefix())
	for i := range txn.SiacoinInputs {
		in := &txn.SiacoinInputs[i]
		in.Parent.ID = d.ReadOutputID()
		in.Parent.Value = d.ReadCurrency()
		in.Parent.Address = d.ReadAddress()
		in.Parent.Timelock = d.ReadUint64()
		in.Parent.MerkleProof = readMerkleProof()
		in.Parent.LeafIndex = d.ReadUint64()
		in.SpendPolicy = d.ReadPolicy()
		in.Signatures = make([]InputSignature, d.ReadPrefix())
		for i := range in.Signatures {
			in.Signatures[i] = d.ReadSignature()
		}
	}
	txn.SiacoinOutputs = make([]Beneficiary, d.ReadPrefix())
	for i := range txn.SiacoinOutputs {
		txn.SiacoinOutputs[i] = d.ReadBeneficiary()
	}
	txn.SiafundInputs = make([]SiafundInput, d.ReadPrefix())
	for i := range txn.SiafundInputs {
		in := &txn.SiafundInputs[i]
		in.Parent.ID = d.ReadOutputID()
		in.Parent.Value = d.ReadCurrency()
		in.Parent.Address = d.ReadAddress()
		in.Parent.ClaimStart = d.ReadCurrency()
		in.Parent.MerkleProof = readMerkleProof()
		in.Parent.LeafIndex = d.ReadUint64()
		in.ClaimAddress = d.ReadAddress()
		in.SpendPolicy = d.ReadPolicy()
		in.Signatures = make([]InputSignature, d.ReadPrefix())
		for i := range in.Signatures {
			in.Signatures[i] = d.ReadSignature()
		}
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
		fcr := &txn.FileContractRevisions[i]
		fcr.Parent.ID = d.ReadOutputID()
		fcr.Parent.State = d.ReadFileContractState()
		fcr.Parent.MerkleProof = readMerkleProof()
		fcr.Parent.LeafIndex = d.ReadUint64()
		fcr.NewState = d.ReadFileContractState()
		fcr.RenterSignature = d.ReadSignature()
		fcr.HostSignature = d.ReadSignature()
	}
	txn.FileContractResolutions = make([]FileContractResolution, d.ReadPrefix())
	for i := range txn.FileContractResolutions {
		fcr := &txn.FileContractResolutions[i]
		fcr.Parent.ID = d.ReadOutputID()
		fcr.Parent.State = d.ReadFileContractState()
		fcr.Parent.MerkleProof = readMerkleProof()
		fcr.Parent.LeafIndex = d.ReadUint64()
		fcr.StorageProof.WindowStart.Height = d.ReadUint64()
		fcr.StorageProof.WindowStart.ID = BlockID(d.ReadHash())
		fcr.StorageProof.WindowProof = readMerkleProof()
		d.Read(fcr.StorageProof.DataSegment[:])
		fcr.StorageProof.SegmentProof = readMerkleProof()
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

// A Hasher streams objects into an instance of Sia's hash function.
type Hasher struct {
	h hash.Hash
	e *Encoder
}

// Write implements io.Writer.
func (h *Hasher) Write(p []byte) (int, error) { return h.e.Write(p) }

// WriteHash writes a hash value to the hash digest.
func (h *Hasher) WriteHash(p Hash256) { h.e.WriteHash(p) }

// WriteAddress writes an address to the hash digest.
func (h *Hasher) WriteAddress(a Address) { h.e.WriteAddress(a) }

// WritePublicKey writes a public key to the hash digest.
func (h *Hasher) WritePublicKey(pk PublicKey) { h.e.WritePublicKey(pk) }

// WriteSignature writes a signature to the hash digest.
func (h *Hasher) WriteSignature(p InputSignature) { h.e.WriteSignature(p) }

// WriteUint8 writes a uint8 value to the hash digest.
func (h *Hasher) WriteUint8(u uint8) { h.e.WriteUint8(u) }

// WriteUint64 writes a uint64 value to the hash digest.
func (h *Hasher) WriteUint64(u uint64) { h.e.WriteUint64(u) }

// WriteInt writes an int value to the hash digest.
func (h *Hasher) WriteInt(i int) { h.e.WriteInt(i) }

// WriteTime writes a time.Time to the hash digest.
func (h *Hasher) WriteTime(t time.Time) { h.e.WriteTime(t) }

// WriteWork writes a Work value to the hash digest.
func (h *Hasher) WriteWork(w Work) { h.e.WriteWork(w) }

// WriteCurrency writes a Currency value to the hash digest.
func (h *Hasher) WriteCurrency(c Currency) { h.e.WriteCurrency(c) }

// WriteChainIndex writes a ChainIndex to the hash digest.
func (h *Hasher) WriteChainIndex(index ChainIndex) { h.e.WriteChainIndex(index) }

// WriteOutputID writes an OutputID to the hash digest.
func (h *Hasher) WriteOutputID(o OutputID) { h.e.WriteOutputID(o) }

// WriteBeneficiary writes a beneficiary to the hash digest.
func (h *Hasher) WriteBeneficiary(b Beneficiary) { h.e.WriteBeneficiary(b) }

// WriteFileContractState writes a FileContractState to the hash digest.
func (h *Hasher) WriteFileContractState(fc FileContractState) { h.e.WriteFileContractState(fc) }

// WritePolicy writes a SpendPolicy to the hash digest.
func (h *Hasher) WritePolicy(p SpendPolicy) { h.e.WritePolicy(p) }

// WriteTransaction writes a transaction to the hash digest.
func (h *Hasher) WriteTransaction(txn Transaction) { h.e.WriteTransaction(txn) }

// Reset resets the underlying hash digest state.
func (h *Hasher) Reset() { h.h.Reset() }

// Sum returns the digest of the objects written to the Hasher.
func (h *Hasher) Sum() (sum Hash256) {
	_ = h.e.Flush() // no error possible
	h.h.Sum(sum[:0])
	return
}

// NewHasher returns a new Hasher instance.
func NewHasher() *Hasher {
	h, _ := blake2b.New256(nil)
	e := NewEncoder(h)
	return &Hasher{h, e}
}
