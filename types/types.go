// Package types defines the essential types of the Sia blockchain.
package types

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"time"

	"lukechampine.com/frand"
)

// MaxRevisionNumber is used to finalize a FileContract. When a contract's
// RevisionNumber is set to this value, no further revisions are possible.
const MaxRevisionNumber = math.MaxUint64

// Various specifiers.
var (
	SpecifierEd25519       = NewSpecifier("ed25519")
	SpecifierSiacoinOutput = NewSpecifier("siacoin output")
	SpecifierSiafundOutput = NewSpecifier("siafund output")
	SpecifierFileContract  = NewSpecifier("file contract")
	SpecifierStorageProof  = NewSpecifier("storage proof")
	SpecifierFoundation    = NewSpecifier("foundation")
	SpecifierEntropy       = NewSpecifier("entropy")
)

// A Hash256 is a generic 256-bit cryptographic hash.
type Hash256 [32]byte

// A PublicKey is an Ed25519 public key.
type PublicKey [32]byte

// VerifyHash verifies that s is a valid signature of h by pk.
func (pk PublicKey) VerifyHash(h Hash256, s Signature) bool {
	return ed25519.Verify(pk[:], h[:], s[:])
}

// UnlockKey returns pk as an UnlockKey.
func (pk PublicKey) UnlockKey() UnlockKey {
	return UnlockKey{
		Algorithm: SpecifierEd25519,
		Key:       pk[:],
	}
}

// A PrivateKey is an Ed25519 private key.
type PrivateKey []byte

// PublicKey returns the PublicKey corresponding to priv.
func (priv PrivateKey) PublicKey() (pk PublicKey) {
	copy(pk[:], priv[32:])
	return
}

// SignHash signs h with priv, producing a Signature.
func (priv PrivateKey) SignHash(h Hash256) (s Signature) {
	copy(s[:], ed25519.Sign(ed25519.PrivateKey(priv), h[:]))
	return
}

// NewPrivateKeyFromSeed calculates a private key from a seed.
func NewPrivateKeyFromSeed(seed []byte) PrivateKey {
	return PrivateKey(ed25519.NewKeyFromSeed(seed))
}

// GeneratePrivateKey creates a new private key from a secure entropy source.
func GeneratePrivateKey() PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	frand.Read(seed)
	pk := NewPrivateKeyFromSeed(seed)
	for i := range seed {
		seed[i] = 0
	}
	return pk
}

// A Signature is an Ed25519 signature.
type Signature [64]byte

// A Specifier is a fixed-size, 0-padded identifier.
type Specifier [16]byte

// NewSpecifier returns a specifier containing the provided name.
func NewSpecifier(name string) (s Specifier) {
	copy(s[:], name)
	return
}

// An UnlockKey can provide one of the signatures required by a set of
// UnlockConditions.
type UnlockKey struct {
	Algorithm Specifier
	Key       []byte
}

// UnlockConditions specify the conditions for spending an output or revising a
// file contract.
type UnlockConditions struct {
	Timelock           uint64
	PublicKeys         []UnlockKey
	SignaturesRequired uint64
}

// UnlockHash computes the hash of a set of UnlockConditions. Such hashes are
// most commonly used as addresses, but are also used in file contracts.
func (uc UnlockConditions) UnlockHash() Address {
	h := hasherPool.Get().(*Hasher)
	defer hasherPool.Put(h)
	h.Reset()

	var acc merkleAccumulator
	h.E.WriteUint8(leafHashPrefix)
	h.E.WriteUint64(uc.Timelock)
	acc.addLeaf(h.Sum())
	for _, key := range uc.PublicKeys {
		h.Reset()
		h.E.WriteUint8(leafHashPrefix)
		key.EncodeTo(h.E)
		acc.addLeaf(h.Sum())
	}
	h.Reset()
	h.E.WriteUint8(leafHashPrefix)
	h.E.WriteUint64(uc.SignaturesRequired)
	acc.addLeaf(h.Sum())
	return Address(acc.root())
}

// An Address is the hash of a set of UnlockConditions.
type Address Hash256

// VoidAddress is an address whose signing key does not exist. Sending coins to
// this address ensures that they will never be recoverable by anyone.
var VoidAddress Address

// A BlockID uniquely identifies a block.
type BlockID Hash256

// Cmp compares two BlockIDs.
func (bid BlockID) Cmp(t BlockID) int {
	return bytes.Compare(bid[:], t[:])
}

// MinerOutputID returns the ID of the block's i'th miner payout.
func (bid BlockID) MinerOutputID(i int) SiacoinOutputID {
	buf := make([]byte, 32+8)
	copy(buf, bid[:])
	binary.LittleEndian.PutUint64(buf[32:], uint64(i))
	return SiacoinOutputID(HashBytes(buf))
}

// FoundationOutputID returns the ID of the block's Foundation subsidy.
func (bid BlockID) FoundationOutputID() SiacoinOutputID {
	buf := make([]byte, 32+16)
	copy(buf, bid[:])
	copy(buf[32:], SpecifierFoundation[:])
	return SiacoinOutputID(HashBytes(buf))
}

// A TransactionID uniquely identifies a transaction.
type TransactionID Hash256

// A ChainIndex pairs a block's height with its ID.
type ChainIndex struct {
	Height uint64
	ID     BlockID
}

// A SiacoinOutput is the recipient of some of the siacoins spent in a
// transaction.
type SiacoinOutput struct {
	Value   Currency
	Address Address
}

// A SiacoinOutputID uniquely identifies a siacoin output.
type SiacoinOutputID Hash256

// A SiacoinInput spends an unspent SiacoinOutput in the UTXO set by
// revealing and satisfying its unlock conditions.
type SiacoinInput struct {
	ParentID         SiacoinOutputID
	UnlockConditions UnlockConditions
}

// A SiafundOutput is the recipient of some of the siafunds spent in a
// transaction.
type SiafundOutput struct {
	Value   uint64
	Address Address
}

// A SiafundOutputID uniquely identifies a siafund output.
type SiafundOutputID Hash256

// ClaimOutputID returns the ID of the SiacoinOutput that is created when
// the siafund output is spent.
func (sfoid SiafundOutputID) ClaimOutputID() SiacoinOutputID {
	return SiacoinOutputID(HashBytes(sfoid[:]))
}

// A SiafundInput spends an unspent SiafundOutput in the UTXO set by revealing
// and satisfying its unlock conditions. SiafundInputs also include a
// ClaimAddress, specifying the recipient of the siacoins that were earned by
// the output.
type SiafundInput struct {
	ParentID         SiafundOutputID
	UnlockConditions UnlockConditions
	ClaimAddress     Address
}

// A FileContract is a storage agreement between a renter and a host. It
// contains a bidirectional payment channel that resolves as either "valid" or
// "missed" depending on whether a valid StorageProof is submitted for the
// contract.
type FileContract struct {
	Filesize           uint64
	FileMerkleRoot     Hash256
	WindowStart        uint64
	WindowEnd          uint64
	Payout             Currency
	ValidProofOutputs  []SiacoinOutput
	MissedProofOutputs []SiacoinOutput
	UnlockHash         Hash256
	RevisionNumber     uint64
}

// EndHeight returns the height at which the contract's host is no longer
// obligated to store the contract data.
func (fc *FileContract) EndHeight() uint64 { return fc.WindowStart }

// ValidRenterOutput returns the output that will be created for the renter if
// the contract resolves valid.
func (fc *FileContract) ValidRenterOutput() SiacoinOutput { return fc.ValidProofOutputs[0] }

// ValidRenterPayout returns the amount of siacoins that the renter will receive
// if the contract resolves valid.
func (fc *FileContract) ValidRenterPayout() Currency { return fc.ValidRenterOutput().Value }

// MissedRenterOutput returns the output that will be created for the renter if
// the contract resolves missed.
func (fc *FileContract) MissedRenterOutput() SiacoinOutput { return fc.MissedProofOutputs[0] }

// MissedRenterPayout returns the amount of siacoins that the renter will receive
// if the contract resolves missed.
func (fc *FileContract) MissedRenterPayout() Currency { return fc.MissedRenterOutput().Value }

// ValidHostOutput returns the output that will be created for the host if
// the contract resolves valid.
func (fc *FileContract) ValidHostOutput() SiacoinOutput { return fc.ValidProofOutputs[1] }

// ValidHostPayout returns the amount of siacoins that the host will receive
// if the contract resolves valid.
func (fc *FileContract) ValidHostPayout() Currency { return fc.ValidHostOutput().Value }

// MissedHostOutput returns the output that will be created for the host if
// the contract resolves missed.
func (fc *FileContract) MissedHostOutput() SiacoinOutput { return fc.MissedProofOutputs[1] }

// MissedHostPayout returns the amount of siacoins that the host will receive
// if the contract resolves missed.
func (fc *FileContract) MissedHostPayout() Currency { return fc.MissedHostOutput().Value }

// A FileContractID uniquely identifies a file contract.
type FileContractID Hash256

// ValidOutputID returns the ID of the valid proof output at index i.
func (fcid FileContractID) ValidOutputID(i int) SiacoinOutputID {
	h := hasherPool.Get().(*Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	SpecifierStorageProof.EncodeTo(h.E)
	fcid.EncodeTo(h.E)
	h.E.WriteBool(true)
	h.E.WriteUint64(uint64(i))
	return SiacoinOutputID(h.Sum())
}

// MissedOutputID returns the ID of the missed proof output at index i.
func (fcid FileContractID) MissedOutputID(i int) SiacoinOutputID {
	h := hasherPool.Get().(*Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	SpecifierStorageProof.EncodeTo(h.E)
	fcid.EncodeTo(h.E)
	h.E.WriteBool(false)
	h.E.WriteUint64(uint64(i))
	return SiacoinOutputID(h.Sum())
}

// A FileContractRevision updates the state of an existing file contract.
type FileContractRevision struct {
	ParentID         FileContractID
	UnlockConditions UnlockConditions
	// NOTE: the Payout field of the contract is not "really" part of a
	// revision. A revision cannot change the total payout, so the original siad
	// code defines FileContractRevision as an entirely separate struct without
	// a Payout field. Here, we instead reuse the FileContract type, which means
	// we must treat its Payout field as invalid. To guard against developer
	// error, we set it to a sentinel value when decoding it.
	FileContract
}

// A StorageProof asserts the presence of a randomly-selected leaf within the
// Merkle tree of a FileContract's data.
type StorageProof struct {
	ParentID FileContractID
	Leaf     [64]byte
	Proof    []Hash256
}

// A FoundationAddressUpdate updates the primary and failsafe Foundation subsidy
// addresses.
type FoundationAddressUpdate struct {
	NewPrimary  Address
	NewFailsafe Address
}

// CoveredFields indicates which fields of a transaction are covered by a
// signature.
type CoveredFields struct {
	WholeTransaction      bool
	SiacoinInputs         []uint64
	SiacoinOutputs        []uint64
	FileContracts         []uint64
	FileContractRevisions []uint64
	StorageProofs         []uint64
	SiafundInputs         []uint64
	SiafundOutputs        []uint64
	MinerFees             []uint64
	ArbitraryData         []uint64
	Signatures            []uint64
}

// A TransactionSignature signs transaction data.
type TransactionSignature struct {
	ParentID       Hash256
	PublicKeyIndex uint64
	Timelock       uint64
	CoveredFields  CoveredFields
	Signature      []byte
}

// A Transaction transfers value by consuming existing Outputs and creating new
// Outputs.
type Transaction struct {
	SiacoinInputs         []SiacoinInput
	SiacoinOutputs        []SiacoinOutput
	FileContracts         []FileContract
	FileContractRevisions []FileContractRevision
	StorageProofs         []StorageProof
	SiafundInputs         []SiafundInput
	SiafundOutputs        []SiafundOutput
	MinerFees             []Currency
	ArbitraryData         [][]byte
	Signatures            []TransactionSignature
}

// ID returns the "semantic hash" of the transaction, covering all of the
// transaction's effects, but not incidental data such as signatures. This
// ensures that the ID will remain stable (i.e. non-malleable).
//
// To hash all of the data in a transaction, use the EncodeTo method.
func (txn *Transaction) ID() TransactionID {
	h := hasherPool.Get().(*Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	txn.encodeNoSignatures(h.E)
	return TransactionID(h.Sum())
}

// SiacoinOutputID returns the ID of the siacoin output at index i.
func (txn *Transaction) SiacoinOutputID(i int) SiacoinOutputID {
	h := hasherPool.Get().(*Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	SpecifierSiacoinOutput.EncodeTo(h.E)
	txn.encodeNoSignatures(h.E)
	h.E.WriteUint64(uint64(i))
	return SiacoinOutputID(h.Sum())
}

// SiafundOutputID returns the ID of the siafund output at index i.
func (txn *Transaction) SiafundOutputID(i int) SiafundOutputID {
	h := hasherPool.Get().(*Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	SpecifierSiafundOutput.EncodeTo(h.E)
	txn.encodeNoSignatures(h.E)
	h.E.WriteUint64(uint64(i))
	return SiafundOutputID(h.Sum())
}

// SiafundClaimOutputID returns the ID of the siacoin claim output for the
// siafund input at index i.
func (txn *Transaction) SiafundClaimOutputID(i int) SiacoinOutputID {
	sfid := txn.SiafundOutputID(i)
	return SiacoinOutputID(HashBytes(sfid[:]))
}

// FileContractID returns the ID of the file contract at index i.
func (txn *Transaction) FileContractID(i int) FileContractID {
	h := hasherPool.Get().(*Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	SpecifierFileContract.EncodeTo(h.E)
	txn.encodeNoSignatures(h.E)
	h.E.WriteUint64(uint64(i))
	return FileContractID(h.Sum())
}

// A BlockHeader contains a Block's non-transaction data.
type BlockHeader struct {
	ParentID   BlockID
	Nonce      uint64
	Timestamp  time.Time
	MerkleRoot Hash256
}

// ID returns a hash that uniquely identifies a block.
func (bh BlockHeader) ID() BlockID {
	buf := make([]byte, 32+8+8+32)
	copy(buf[0:32], bh.ParentID[:])
	binary.LittleEndian.PutUint64(buf[32:40], bh.Nonce)
	binary.LittleEndian.PutUint64(buf[40:48], uint64(bh.Timestamp.Unix()))
	copy(buf[48:80], bh.MerkleRoot[:])
	return BlockID(HashBytes(buf))
}

// CurrentTimestamp returns the current time, rounded to the nearest second. The
// time zone is set to UTC.
func CurrentTimestamp() time.Time { return time.Now().Round(time.Second).UTC() }

// A Block is a set of transactions grouped under a header.
type Block struct {
	ParentID     BlockID
	Nonce        uint64
	Timestamp    time.Time
	MinerPayouts []SiacoinOutput
	Transactions []Transaction
}

// Header returns the header for the block.
//
// Note that this is a relatively expensive operation, as it computes the Merkle
// root of the block's transactions.
func (b *Block) Header() BlockHeader {
	h := hasherPool.Get().(*Hasher)
	defer hasherPool.Put(h)
	var acc merkleAccumulator
	for _, mp := range b.MinerPayouts {
		h.Reset()
		h.E.WriteUint8(leafHashPrefix)
		mp.EncodeTo(h.E)
		acc.addLeaf(h.Sum())
	}
	for _, txn := range b.Transactions {
		h.Reset()
		h.E.WriteUint8(leafHashPrefix)
		txn.EncodeTo(h.E)
		acc.addLeaf(h.Sum())
	}
	return BlockHeader{
		ParentID:   b.ParentID,
		Nonce:      b.Nonce,
		Timestamp:  b.Timestamp,
		MerkleRoot: acc.root(),
	}
}

// ID returns a hash that uniquely identifies a block. It is equivalent to
// b.Header().ID().
//
// Note that this is a relatively expensive operation, as it computes the Merkle
// root of the block's transactions.
func (b *Block) ID() BlockID { return b.Header().ID() }

// Implementations of fmt.Stringer, encoding.Text(Un)marshaler, and json.(Un)marshaler

func stringerHex(prefix string, data []byte) string {
	return prefix + ":" + hex.EncodeToString(data[:])
}

func marshalHex(prefix string, data []byte) ([]byte, error) {
	return []byte(stringerHex(prefix, data)), nil
}

func unmarshalHex(dst []byte, prefix string, data []byte) error {
	n, err := hex.Decode(dst, bytes.TrimPrefix(data, []byte(prefix+":")))
	if n < len(dst) {
		err = io.EOF
	}
	if err != nil {
		return fmt.Errorf("decoding %v:<hex> failed: %w", prefix, err)
	}
	return nil
}

func marshalJSONHex(prefix string, data []byte) ([]byte, error) {
	return []byte(`"` + stringerHex(prefix, data) + `"`), nil
}

func unmarshalJSONHex(dst []byte, prefix string, data []byte) error {
	return unmarshalHex(dst, prefix, bytes.Trim(data, `"`))
}

// String implements fmt.Stringer.
func (h Hash256) String() string { return stringerHex("h", h[:]) }

// MarshalText implements encoding.TextMarshaler.
func (h Hash256) MarshalText() ([]byte, error) { return marshalHex("h", h[:]) }

// UnmarshalText implements encoding.TextUnmarshaler.
func (h *Hash256) UnmarshalText(b []byte) error { return unmarshalHex(h[:], "h", b) }

// MarshalJSON implements json.Marshaler.
func (h Hash256) MarshalJSON() ([]byte, error) { return marshalJSONHex("h", h[:]) }

// UnmarshalJSON implements json.Unmarshaler.
func (h *Hash256) UnmarshalJSON(b []byte) error { return unmarshalJSONHex(h[:], "h", b) }

// String implements fmt.Stringer.
func (ci ChainIndex) String() string {
	// use the 4 least-significant bytes of ID -- in a mature chain, the
	// most-significant bytes will be zeros
	return fmt.Sprintf("%d::%x", ci.Height, ci.ID[len(ci.ID)-4:])
}

// MarshalText implements encoding.TextMarshaler.
func (ci ChainIndex) MarshalText() ([]byte, error) {
	return []byte(fmt.Sprintf("%d::%x", ci.Height, ci.ID[:])), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (ci *ChainIndex) UnmarshalText(b []byte) (err error) {
	parts := bytes.Split(b, []byte("::"))
	if len(parts) != 2 {
		return fmt.Errorf("decoding <height>::<id> failed: wrong number of separators")
	} else if ci.Height, err = strconv.ParseUint(string(parts[0]), 10, 64); err != nil {
		return fmt.Errorf("decoding <height>::<id> failed: %w", err)
	} else if n, err := hex.Decode(ci.ID[:], parts[1]); err != nil {
		return fmt.Errorf("decoding <height>::<id> failed: %w", err)
	} else if n < len(ci.ID) {
		return fmt.Errorf("decoding <height>::<id> failed: %w", io.EOF)
	}
	return nil
}

// ParseChainIndex parses a chain index from a string.
func ParseChainIndex(s string) (ci ChainIndex, err error) {
	err = ci.UnmarshalText([]byte(s))
	return
}

// String implements fmt.Stringer.
func (s Specifier) String() string { return strconv.Quote(string(bytes.Trim(s[:], "\x00"))) }

// MarshalText implements encoding.TextMarshaler.
func (s Specifier) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *Specifier) UnmarshalText(b []byte) error {
	str, err := strconv.Unquote(string(b))
	if err != nil {
		return err
	} else if len(str) > len(s) {
		return fmt.Errorf("specifier %s too long", str)
	}
	copy(s[:], str)
	return nil
}

// MarshalJSON implements json.Marshaler.
func (s Specifier) MarshalJSON() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalJSON implements json.Unmarshaler.
func (s *Specifier) UnmarshalJSON(b []byte) error { return s.UnmarshalText(b) }

// String implements fmt.Stringer.
func (a Address) String() string {
	checksum := HashBytes(a[:])
	return stringerHex("addr", append(a[:], checksum[:6]...))
}

// MarshalText implements encoding.TextMarshaler.
func (a Address) MarshalText() ([]byte, error) { return []byte(a.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (a *Address) UnmarshalText(b []byte) (err error) {
	withChecksum := make([]byte, 32+6)
	n, err := hex.Decode(withChecksum, bytes.TrimPrefix(b, []byte("addr:")))
	if err != nil {
		err = fmt.Errorf("decoding addr:<hex> failed: %w", err)
	} else if n != len(withChecksum) {
		err = fmt.Errorf("decoding addr:<hex> failed: %w", io.EOF)
	} else if checksum := HashBytes(withChecksum[:32]); !bytes.Equal(checksum[:6], withChecksum[32:]) {
		err = errors.New("bad checksum")
	}
	copy(a[:], withChecksum[:32])
	return
}

// MarshalJSON implements json.Marshaler.
func (a Address) MarshalJSON() ([]byte, error) {
	checksum := HashBytes(a[:])
	return marshalJSONHex("addr", append(a[:], checksum[:6]...))
}

// UnmarshalJSON implements json.Unmarshaler.
func (a *Address) UnmarshalJSON(b []byte) (err error) {
	return a.UnmarshalText(bytes.Trim(b, `"`))
}

// ParseAddress parses an address from a prefixed hex encoded string.
func ParseAddress(s string) (a Address, err error) {
	err = a.UnmarshalText([]byte(s))
	return
}

// String implements fmt.Stringer.
func (bid BlockID) String() string { return stringerHex("bid", bid[:]) }

// MarshalText implements encoding.TextMarshaler.
func (bid BlockID) MarshalText() ([]byte, error) { return marshalHex("bid", bid[:]) }

// UnmarshalText implements encoding.TextUnmarshaler.
func (bid *BlockID) UnmarshalText(b []byte) error { return unmarshalHex(bid[:], "bid", b) }

// MarshalJSON implements json.Marshaler.
func (bid BlockID) MarshalJSON() ([]byte, error) { return marshalJSONHex("bid", bid[:]) }

// UnmarshalJSON implements json.Unmarshaler.
func (bid *BlockID) UnmarshalJSON(b []byte) error { return unmarshalJSONHex(bid[:], "bid", b) }

// String implements fmt.Stringer.
func (pk PublicKey) String() string { return stringerHex("ed25519", pk[:]) }

// MarshalText implements encoding.TextMarshaler.
func (pk PublicKey) MarshalText() ([]byte, error) { return marshalHex("ed25519", pk[:]) }

// UnmarshalText implements encoding.TextUnmarshaler.
func (pk *PublicKey) UnmarshalText(b []byte) error { return unmarshalHex(pk[:], "ed25519", b) }

// MarshalJSON implements json.Marshaler.
func (pk PublicKey) MarshalJSON() ([]byte, error) { return marshalJSONHex("ed25519", pk[:]) }

// UnmarshalJSON implements json.Unmarshaler.
func (pk *PublicKey) UnmarshalJSON(b []byte) error { return unmarshalJSONHex(pk[:], "ed25519", b) }

// String implements fmt.Stringer.
func (tid TransactionID) String() string { return stringerHex("txid", tid[:]) }

// MarshalText implements encoding.TextMarshaler.
func (tid TransactionID) MarshalText() ([]byte, error) { return marshalHex("txid", tid[:]) }

// UnmarshalText implements encoding.TextUnmarshaler.
func (tid *TransactionID) UnmarshalText(b []byte) error { return unmarshalHex(tid[:], "txid", b) }

// MarshalJSON implements json.Marshaler.
func (tid TransactionID) MarshalJSON() ([]byte, error) { return marshalJSONHex("txid", tid[:]) }

// UnmarshalJSON implements json.Unmarshaler.
func (tid *TransactionID) UnmarshalJSON(b []byte) error { return unmarshalJSONHex(tid[:], "txid", b) }

// String implements fmt.Stringer.
func (scoid SiacoinOutputID) String() string { return stringerHex("scoid", scoid[:]) }

// MarshalText implements encoding.TextMarshaler.
func (scoid SiacoinOutputID) MarshalText() ([]byte, error) { return marshalHex("scoid", scoid[:]) }

// UnmarshalText implements encoding.TextUnmarshaler.
func (scoid *SiacoinOutputID) UnmarshalText(b []byte) error {
	return unmarshalHex(scoid[:], "scoid", b)
}

// MarshalJSON implements json.Marshaler.
func (scoid SiacoinOutputID) MarshalJSON() ([]byte, error) { return marshalJSONHex("scoid", scoid[:]) }

// UnmarshalJSON implements json.Unmarshaler.
func (scoid *SiacoinOutputID) UnmarshalJSON(b []byte) error {
	return unmarshalJSONHex(scoid[:], "scoid", b)
}

// String implements fmt.Stringer.
func (sfoid SiafundOutputID) String() string { return stringerHex("sfoid", sfoid[:]) }

// MarshalText implements encoding.TextMarshaler.
func (sfoid SiafundOutputID) MarshalText() ([]byte, error) { return marshalHex("sfoid", sfoid[:]) }

// UnmarshalText implements encoding.TextUnmarshaler.
func (sfoid *SiafundOutputID) UnmarshalText(b []byte) error {
	return unmarshalHex(sfoid[:], "sfoid", b)
}

// MarshalJSON implements json.Marshaler.
func (sfoid SiafundOutputID) MarshalJSON() ([]byte, error) { return marshalJSONHex("sfoid", sfoid[:]) }

// UnmarshalJSON implements json.Unmarshaler.
func (sfoid *SiafundOutputID) UnmarshalJSON(b []byte) error {
	return unmarshalJSONHex(sfoid[:], "sfoid", b)
}

// String implements fmt.Stringer.
func (fcid FileContractID) String() string { return stringerHex("fcid", fcid[:]) }

// MarshalText implements encoding.TextMarshaler.
func (fcid FileContractID) MarshalText() ([]byte, error) { return marshalHex("fcid", fcid[:]) }

// UnmarshalText implements encoding.TextUnmarshaler.
func (fcid *FileContractID) UnmarshalText(b []byte) error { return unmarshalHex(fcid[:], "fcid", b) }

// MarshalJSON implements json.Marshaler.
func (fcid FileContractID) MarshalJSON() ([]byte, error) { return marshalJSONHex("fcid", fcid[:]) }

// UnmarshalJSON implements json.Unmarshaler.
func (fcid *FileContractID) UnmarshalJSON(b []byte) error {
	return unmarshalJSONHex(fcid[:], "fcid", b)
}

// String implements fmt.Stringer.
func (sig Signature) String() string { return stringerHex("sig", sig[:]) }

// MarshalText implements encoding.TextMarshaler.
func (sig Signature) MarshalText() ([]byte, error) { return marshalHex("sig", sig[:]) }

// UnmarshalText implements encoding.TextUnmarshaler.
func (sig *Signature) UnmarshalText(b []byte) error { return unmarshalHex(sig[:], "sig", b) }

// MarshalJSON implements json.Marshaler.
func (sig Signature) MarshalJSON() ([]byte, error) { return marshalJSONHex("sig", sig[:]) }

// UnmarshalJSON implements json.Unmarshaler.
func (sig *Signature) UnmarshalJSON(b []byte) error { return unmarshalJSONHex(sig[:], "sig", b) }
