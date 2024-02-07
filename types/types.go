// Package types defines the essential types of the Sia blockchain.
package types

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"time"

	"lukechampine.com/frand"
)

const (
	// MaxRevisionNumber is used to finalize a FileContract. When a contract's
	// RevisionNumber is set to this value, no further revisions are possible.
	MaxRevisionNumber = math.MaxUint64

	// RenterContractIndex defines the index of the renter's output and public
	// key in a FileContract.
	RenterContractIndex = 0

	// HostContractIndex defines the index of the host's output and public key in
	// a FileContract.
	HostContractIndex = 1

	// EphemeralLeafIndex is used as the LeafIndex of StateElements that are created
	// and spent within the same block. Such elements do not require a proof of
	// existence. They are, however, assigned a proper index and are incorporated
	// into the state accumulator when the block is processed.
	EphemeralLeafIndex = math.MaxUint64
)

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

// StandardUnlockConditions returns the standard unlock conditions for pk.
func StandardUnlockConditions(pk PublicKey) UnlockConditions {
	return UnlockConditions{
		PublicKeys:         []UnlockKey{pk.UnlockKey()},
		SignaturesRequired: 1,
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
	Timelock           uint64      `json:"timelock"`
	PublicKeys         []UnlockKey `json:"publicKeys"`
	SignaturesRequired uint64      `json:"signaturesRequired"`
}

// UnlockHash computes the hash of a set of UnlockConditions. Such hashes are
// most commonly used as addresses, but are also used in file contracts.
func (uc UnlockConditions) UnlockHash() Address {
	// almost all UnlockConditions are standard, so optimize for that case
	if uc.Timelock == 0 &&
		len(uc.PublicKeys) == 1 &&
		uc.PublicKeys[0].Algorithm == SpecifierEd25519 &&
		len(uc.PublicKeys[0].Key) == len(PublicKey{}) &&
		uc.SignaturesRequired == 1 {
		return StandardUnlockHash(*(*PublicKey)(uc.PublicKeys[0].Key))
	}
	return unlockConditionsRoot(uc)
}

// An Address is the hash of a set of UnlockConditions.
type Address Hash256

// VoidAddress is an address whose signing key does not exist. Sending coins to
// this address ensures that they will never be recoverable by anyone.
var VoidAddress Address

// A BlockID uniquely identifies a block.
type BlockID Hash256

// CmpWork compares the work implied by two BlockIDs.
func (bid BlockID) CmpWork(t BlockID) int {
	// work is the inverse of the ID, so reverse the comparison
	return bytes.Compare(t[:], bid[:])
}

// MinerOutputID returns the ID of the block's i'th miner payout.
func (bid BlockID) MinerOutputID(i int) SiacoinOutputID {
	return hashAll(bid, i)
}

// FoundationOutputID returns the ID of the block's Foundation subsidy.
func (bid BlockID) FoundationOutputID() SiacoinOutputID {
	return hashAll(bid, SpecifierFoundation)
}

// A TransactionID uniquely identifies a transaction.
type TransactionID Hash256

// A ChainIndex pairs a block's height with its ID.
type ChainIndex struct {
	Height uint64  `json:"height"`
	ID     BlockID `json:"id"`
}

// A SiacoinOutput is the recipient of some of the siacoins spent in a
// transaction.
type SiacoinOutput struct {
	Value   Currency `json:"value"`
	Address Address  `json:"address"`
}

// A SiacoinOutputID uniquely identifies a siacoin output.
type SiacoinOutputID Hash256

// A SiacoinInput spends an unspent SiacoinOutput in the UTXO set by
// revealing and satisfying its unlock conditions.
type SiacoinInput struct {
	ParentID         SiacoinOutputID  `json:"parentID"`
	UnlockConditions UnlockConditions `json:"unlockConditions"`
}

// A SiafundOutput is the recipient of some of the siafunds spent in a
// transaction.
type SiafundOutput struct {
	Value   uint64  `json:"value"`
	Address Address `json:"address"`
}

// A SiafundOutputID uniquely identifies a siafund output.
type SiafundOutputID Hash256

// ClaimOutputID returns the ID of the SiacoinOutput that is created when
// the siafund output is spent.
func (sfoid SiafundOutputID) ClaimOutputID() SiacoinOutputID {
	return hashAll(sfoid)
}

// V2ClaimOutputID returns the ID of the SiacoinOutput that is created when the
// siafund output is spent.
func (sfoid SiafundOutputID) V2ClaimOutputID() SiacoinOutputID {
	return hashAll("id/v2siacoinclaimoutput", sfoid)
}

// A SiafundInput spends an unspent SiafundOutput in the UTXO set by revealing
// and satisfying its unlock conditions. SiafundInputs also include a
// ClaimAddress, specifying the recipient of the siacoins that were earned by
// the output.
type SiafundInput struct {
	ParentID         SiafundOutputID  `json:"parentID"`
	UnlockConditions UnlockConditions `json:"unlockConditions"`
	ClaimAddress     Address          `json:"claimAddress"`
}

// A FileContract is a storage agreement between a renter and a host. It
// contains a bidirectional payment channel that resolves as either "valid" or
// "missed" depending on whether a valid StorageProof is submitted for the
// contract.
type FileContract struct {
	Filesize           uint64          `json:"filesize"`
	FileMerkleRoot     Hash256         `json:"fileMerkleRoot"`
	WindowStart        uint64          `json:"windowStart"`
	WindowEnd          uint64          `json:"windowEnd"`
	Payout             Currency        `json:"payout"`
	ValidProofOutputs  []SiacoinOutput `json:"validProofOutputs"`
	MissedProofOutputs []SiacoinOutput `json:"missedProofOutputs"`
	UnlockHash         Hash256         `json:"unlockHash"`
	RevisionNumber     uint64          `json:"revisionNumber"`
}

// EndHeight returns the height at which the contract's host is no longer
// obligated to store the contract data.
func (fc *FileContract) EndHeight() uint64 { return fc.WindowStart }

// ValidRenterOutput returns the output that will be created for the renter if
// the contract resolves valid.
func (fc *FileContract) ValidRenterOutput() SiacoinOutput {
	return fc.ValidProofOutputs[RenterContractIndex]
}

// ValidRenterPayout returns the amount of siacoins that the renter will receive
// if the contract resolves valid.
func (fc *FileContract) ValidRenterPayout() Currency { return fc.ValidRenterOutput().Value }

// MissedRenterOutput returns the output that will be created for the renter if
// the contract resolves missed.
func (fc *FileContract) MissedRenterOutput() SiacoinOutput {
	return fc.MissedProofOutputs[RenterContractIndex]
}

// MissedRenterPayout returns the amount of siacoins that the renter will receive
// if the contract resolves missed.
func (fc *FileContract) MissedRenterPayout() Currency { return fc.MissedRenterOutput().Value }

// ValidHostOutput returns the output that will be created for the host if
// the contract resolves valid.
func (fc *FileContract) ValidHostOutput() SiacoinOutput {
	return fc.ValidProofOutputs[HostContractIndex]
}

// ValidHostPayout returns the amount of siacoins that the host will receive
// if the contract resolves valid.
func (fc *FileContract) ValidHostPayout() Currency { return fc.ValidHostOutput().Value }

// MissedHostOutput returns the output that will be created for the host if
// the contract resolves missed.
func (fc *FileContract) MissedHostOutput() SiacoinOutput {
	return fc.MissedProofOutputs[HostContractIndex]
}

// MissedHostPayout returns the amount of siacoins that the host will receive
// if the contract resolves missed.
func (fc *FileContract) MissedHostPayout() Currency { return fc.MissedHostOutput().Value }

// A FileContractID uniquely identifies a file contract.
type FileContractID Hash256

// ValidOutputID returns the ID of the valid proof output at index i.
func (fcid FileContractID) ValidOutputID(i int) SiacoinOutputID {
	return hashAll(SpecifierStorageProof, fcid, true, i)
}

// MissedOutputID returns the ID of the missed proof output at index i.
func (fcid FileContractID) MissedOutputID(i int) SiacoinOutputID {
	return hashAll(SpecifierStorageProof, fcid, false, i)
}

// V2RenterOutputID returns the ID of the renter output for a v2 contract.
func (fcid FileContractID) V2RenterOutputID() SiacoinOutputID {
	return hashAll("id/v2filecontractoutput", fcid, 0)
}

// V2HostOutputID returns the ID of the host output for a v2 contract.
func (fcid FileContractID) V2HostOutputID() SiacoinOutputID {
	return hashAll("id/v2filecontractoutput", fcid, 1)
}

// V2RenewalID returns the ID of the renewal of a v2 contract.
func (fcid FileContractID) V2RenewalID() FileContractID {
	return hashAll("id/v2filecontractrenewal", fcid)
}

// A FileContractRevision updates the state of an existing file contract.
type FileContractRevision struct {
	ParentID         FileContractID   `json:"parentID"`
	UnlockConditions UnlockConditions `json:"unlockConditions"`
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
	NewPrimary  Address `json:"newPrimary"`
	NewFailsafe Address `json:"newFailsafe"`
}

// CoveredFields indicates which fields of a transaction are covered by a
// signature.
type CoveredFields struct {
	WholeTransaction      bool     `json:"wholeTransaction,omitempty"`
	SiacoinInputs         []uint64 `json:"siacoinInputs,omitempty"`
	SiacoinOutputs        []uint64 `json:"siacoinOutputs,omitempty"`
	FileContracts         []uint64 `json:"fileContracts,omitempty"`
	FileContractRevisions []uint64 `json:"fileContractRevisions,omitempty"`
	StorageProofs         []uint64 `json:"storageProofs,omitempty"`
	SiafundInputs         []uint64 `json:"siafundInputs,omitempty"`
	SiafundOutputs        []uint64 `json:"siafundOutputs,omitempty"`
	MinerFees             []uint64 `json:"minerFees,omitempty"`
	ArbitraryData         []uint64 `json:"arbitraryData,omitempty"`
	Signatures            []uint64 `json:"signatures,omitempty"`
}

// A TransactionSignature signs transaction data.
type TransactionSignature struct {
	ParentID       Hash256       `json:"parentID"`
	PublicKeyIndex uint64        `json:"publicKeyIndex"`
	Timelock       uint64        `json:"timelock,omitempty"`
	CoveredFields  CoveredFields `json:"coveredFields"`
	Signature      []byte        `json:"signature"`
}

// A Transaction effects a change of blockchain state.
type Transaction struct {
	SiacoinInputs         []SiacoinInput         `json:"siacoinInputs,omitempty"`
	SiacoinOutputs        []SiacoinOutput        `json:"siacoinOutputs,omitempty"`
	FileContracts         []FileContract         `json:"fileContracts,omitempty"`
	FileContractRevisions []FileContractRevision `json:"fileContractRevisions,omitempty"`
	StorageProofs         []StorageProof         `json:"storageProofs,omitempty"`
	SiafundInputs         []SiafundInput         `json:"siafundInputs,omitempty"`
	SiafundOutputs        []SiafundOutput        `json:"siafundOutputs,omitempty"`
	MinerFees             []Currency             `json:"minerFees,omitempty"`
	ArbitraryData         [][]byte               `json:"arbitraryData,omitempty"`
	Signatures            []TransactionSignature `json:"signatures,omitempty"`
}

// ID returns the "semantic hash" of the transaction, covering all of the
// transaction's effects, but not incidental data such as signatures. This
// ensures that the ID will remain stable (i.e. non-malleable).
//
// To hash all of the data in a transaction, use the FullHash method.
func (txn *Transaction) ID() TransactionID {
	return hashAll((*txnSansSigs)(txn))
}

// FullHash returns the hash of the transaction's binary encoding. This hash is
// only used in specific circumstances; generally, ID should be used instead.
func (txn *Transaction) FullHash() Hash256 {
	return hashAll(txn)
}

// SiacoinOutputID returns the ID of the siacoin output at index i.
func (txn *Transaction) SiacoinOutputID(i int) SiacoinOutputID {
	return hashAll(SpecifierSiacoinOutput, (*txnSansSigs)(txn), i)
}

// SiafundOutputID returns the ID of the siafund output at index i.
func (txn *Transaction) SiafundOutputID(i int) SiafundOutputID {
	return hashAll(SpecifierSiafundOutput, (*txnSansSigs)(txn), i)
}

// SiafundClaimOutputID returns the ID of the siacoin claim output for the
// siafund input at index i.
func (txn *Transaction) SiafundClaimOutputID(i int) SiacoinOutputID {
	return hashAll(txn.SiafundOutputID(i))
}

// FileContractID returns the ID of the file contract at index i.
func (txn *Transaction) FileContractID(i int) FileContractID {
	return hashAll(SpecifierFileContract, (*txnSansSigs)(txn), i)
}

// TotalFees returns the sum of the transaction's miner fees.
func (txn *Transaction) TotalFees() Currency {
	var sum Currency
	for _, fee := range txn.MinerFees {
		sum = sum.Add(fee)
	}
	return sum
}

// A V2FileContract is a storage agreement between a renter and a host. It
// consists of a bidirectional payment channel that resolves as either "valid"
// or "missed" depending on whether a valid StorageProof is submitted for the
// contract.
type V2FileContract struct {
	Filesize         uint64        `json:"filesize"`
	FileMerkleRoot   Hash256       `json:"fileMerkleRoot"`
	ProofHeight      uint64        `json:"proofHeight"`
	ExpirationHeight uint64        `json:"expirationHeight"`
	RenterOutput     SiacoinOutput `json:"renterOutput"`
	HostOutput       SiacoinOutput `json:"hostOutput"`
	MissedHostValue  Currency      `json:"missedHostValue"`
	TotalCollateral  Currency      `json:"totalCollateral"`
	RenterPublicKey  PublicKey     `json:"renterPublicKey"`
	HostPublicKey    PublicKey     `json:"hostPublicKey"`
	RevisionNumber   uint64        `json:"revisionNumber"`

	// signatures cover above fields
	RenterSignature Signature `json:"renterSignature"`
	HostSignature   Signature `json:"hostSignature"`
}

// MissedHostOutput returns the host output that will be created if the contract
// resolves missed.
func (fc V2FileContract) MissedHostOutput() SiacoinOutput {
	return SiacoinOutput{
		Value:   fc.MissedHostValue,
		Address: fc.HostOutput.Address,
	}
}

// A V2SiacoinInput spends an unspent SiacoinElement in the state accumulator by
// revealing its public key and signing the transaction.
type V2SiacoinInput struct {
	Parent          SiacoinElement  `json:"parent"`
	SatisfiedPolicy SatisfiedPolicy `json:"satisfiedPolicy"`
}

// A V2SiafundInput spends an unspent SiafundElement in the state accumulator by
// revealing its public key and signing the transaction. Inputs also include a
// ClaimAddress, specifying the recipient of the siacoins that were earned by
// the SiafundElement.
type V2SiafundInput struct {
	Parent          SiafundElement  `json:"parent"`
	ClaimAddress    Address         `json:"claimAddress"`
	SatisfiedPolicy SatisfiedPolicy `json:"satisfiedPolicy"`
}

// A V2FileContractRevision updates the state of an existing file contract.
type V2FileContractRevision struct {
	Parent   V2FileContractElement `json:"parent"`
	Revision V2FileContract        `json:"revision"`
}

// A V2FileContractResolution closes a v2 file contract's payment channel. There
// are four ways a contract can be resolved:
//
// 1) The renter and host can sign a final contract revision (a "finalization"),
// after which the contract cannot be revised further.
//
// 2) The renter and host can jointly renew the contract. The old contract is
// finalized, and a portion of its funds are "rolled over" into a new contract.
//
// 3) The host can submit a storage proof, asserting that it has faithfully
// stored the contract data for the agreed-upon duration. Typically, a storage
// proof is only required if the renter is unable or unwilling to sign a
// finalization or renewal. A storage proof can only be submitted after the
// contract's ProofHeight; this allows the renter (or host) to broadcast the
// latest contract revision prior to the proof.
//
// 4) Lastly, anyone can submit a contract expiration. Typically, an expiration
// is only required if the host is unable or unwilling to sign a finalization or
// renewal. An expiration can only be submitted after the contract's
// ExpirationHeight; this gives the host a reasonable window of time after the
// ProofHeight in which to submit a storage proof.
//
// Once a contract has been resolved, it cannot be altered or resolved again.
// When a contract is resolved, its RenterOutput and HostOutput are created
// immediately (though they will not be spendable until their timelock expires).
// However, if the contract is resolved via an expiration, the HostOutput will
// have value equal to MissedHostValue; in other words, the host forfeits its
// collateral. This is considered a "missed" resolution; all other resolution
// types are "valid." As a special case, the expiration of an empty contract is
// considered valid, reflecting the fact that the host has not failed to perform
// any duty.
type V2FileContractResolution struct {
	Parent     V2FileContractElement        `json:"parent"`
	Resolution V2FileContractResolutionType `json:"resolution"`
}

// V2FileContractResolutionType enumerates the types of file contract resolution.
type V2FileContractResolutionType interface {
	isV2FileContractResolution()
}

func (*V2FileContractFinalization) isV2FileContractResolution() {}
func (*V2FileContractRenewal) isV2FileContractResolution()      {}
func (*V2StorageProof) isV2FileContractResolution()             {}
func (*V2FileContractExpiration) isV2FileContractResolution()   {}

// A V2FileContractFinalization finalizes a contract, preventing further
// revisions and immediately creating its valid outputs.
type V2FileContractFinalization V2FileContract

// A V2FileContractRenewal renews a file contract.
type V2FileContractRenewal struct {
	FinalRevision  V2FileContract `json:"finalRevision"`
	NewContract    V2FileContract `json:"newContract"`
	RenterRollover Currency       `json:"renterRollover"`
	HostRollover   Currency       `json:"hostRollover"`

	// signatures cover above fields
	RenterSignature Signature `json:"renterSignature"`
	HostSignature   Signature `json:"hostSignature"`
}

// A V2StorageProof asserts the presence of a randomly-selected leaf within the
// Merkle tree of a V2FileContract's data.
type V2StorageProof struct {
	// Selecting the leaf requires a source of unpredictable entropy; we use the
	// ID of the block at the contract's ProofHeight. The storage proof thus
	// includes a proof that this ID is the correct ancestor.
	//
	// During validation, it is imperative to check that ProofIndex.Height
	// matches the ProofHeight field of the contract's final revision;
	// otherwise, the prover could use any ProofIndex, giving them control over
	// the leaf index.
	ProofIndex ChainIndexElement

	// The leaf is always 64 bytes, extended with zeros if necessary.
	Leaf  [64]byte
	Proof []Hash256
}

// A V2FileContractExpiration resolves an expired contract. A contract is
// considered expired when its proof window has elapsed. If the contract is not
// storing any data, it will resolve as valid; otherwise, it resolves as missed.
type V2FileContractExpiration struct{}

// An Attestation associates a key-value pair with an identity. For example,
// hosts attest to their network address by setting Key to "HostAnnouncement"
// and Value to their address, thereby allowing renters to discover them.
// Generally, an attestation for a particular key is considered to overwrite any
// previous attestations with the same key. (This allows hosts to announce a new
// network address, for example.)
type Attestation struct {
	PublicKey PublicKey `json:"publicKey"`
	Key       string    `json:"key"`
	Value     []byte    `json:"value"`
	Signature Signature `json:"signature"`
}

// A StateElement is a generic element within the state accumulator.
type StateElement struct {
	ID          Hash256   `json:"id"` // SiacoinOutputID, FileContractID, etc.
	LeafIndex   uint64    `json:"leafIndex"`
	MerkleProof []Hash256 `json:"merkleProof"`
}

// A ChainIndexElement is a record of a ChainIndex within the state accumulator.
type ChainIndexElement struct {
	StateElement
	ChainIndex ChainIndex `json:"chainIndex"`
}

// A SiacoinElement is a record of a SiacoinOutput within the state accumulator.
type SiacoinElement struct {
	StateElement
	SiacoinOutput  SiacoinOutput `json:"siacoinOutput"`
	MaturityHeight uint64        `json:"maturityHeight"`
}

// A SiafundElement is a record of a SiafundOutput within the state accumulator.
type SiafundElement struct {
	StateElement
	SiafundOutput SiafundOutput `json:"siafundOutput"`
	ClaimStart    Currency      `json:"claimStart"` // value of SiafundPool when element was created
}

// A FileContractElement is a record of a FileContract within the state
// accumulator.
type FileContractElement struct {
	StateElement
	FileContract FileContract `json:"fileContract"`
}

// A V2FileContractElement is a record of a V2FileContract within the state
// accumulator.
type V2FileContractElement struct {
	StateElement
	V2FileContract V2FileContract `json:"v2FileContract"`
}

// An AttestationElement is a record of an Attestation within the state
// accumulator.
type AttestationElement struct {
	StateElement
	Attestation Attestation `json:"attestation"`
}

// A V2Transaction effects a change of blockchain state.
type V2Transaction struct {
	SiacoinInputs           []V2SiacoinInput           `json:"siacoinInputs,omitempty"`
	SiacoinOutputs          []SiacoinOutput            `json:"siacoinOutputs,omitempty"`
	SiafundInputs           []V2SiafundInput           `json:"siafundInputs,omitempty"`
	SiafundOutputs          []SiafundOutput            `json:"siafundOutputs,omitempty"`
	FileContracts           []V2FileContract           `json:"fileContracts,omitempty"`
	FileContractRevisions   []V2FileContractRevision   `json:"fileContractRevisions,omitempty"`
	FileContractResolutions []V2FileContractResolution `json:"fileContractResolutions,omitempty"`
	Attestations            []Attestation              `json:"attestations,omitempty"`
	ArbitraryData           []byte                     `json:"arbitraryData,omitempty"`
	NewFoundationAddress    *Address                   `json:"newFoundationAddress,omitempty"`
	MinerFee                Currency                   `json:"minerFee"`
}

// ID returns the "semantic hash" of the transaction, covering all of the
// transaction's effects, but not incidental data such as signatures or Merkle
// proofs. This ensures that the ID will remain stable (i.e. non-malleable).
//
// To hash all of the data in a transaction, use the FullHash method.
func (txn *V2Transaction) ID() TransactionID {
	return hashAll("id/transaction", (*V2TransactionSemantics)(txn))
}

// FullHash returns the hash of the transaction's binary encoding. This hash is
// only used in specific circumstances; generally, ID should be used instead.
func (txn *V2Transaction) FullHash() Hash256 {
	return hashAll(txn)
}

// SiacoinOutputID returns the ID for the siacoin output at index i.
func (*V2Transaction) SiacoinOutputID(txid TransactionID, i int) SiacoinOutputID {
	return hashAll("id/siacoinoutput", txid, i)
}

// SiafundOutputID returns the ID for the siafund output at index i.
func (*V2Transaction) SiafundOutputID(txid TransactionID, i int) SiafundOutputID {
	return hashAll("id/siafundoutput", txid, i)
}

// V2FileContractID returns the ID for the v2 file contract at index i.
func (*V2Transaction) V2FileContractID(txid TransactionID, i int) FileContractID {
	return hashAll("id/filecontract", txid, i)
}

// AttestationID returns the ID for the attestation at index i.
func (*V2Transaction) AttestationID(txid TransactionID, i int) Hash256 {
	return hashAll("id/attestation", txid, i)
}

// EphemeralSiacoinOutput returns a SiacoinElement for the siacoin output at
// index i.
func (txn *V2Transaction) EphemeralSiacoinOutput(i int) SiacoinElement {
	return SiacoinElement{
		StateElement: StateElement{
			ID:        Hash256(txn.SiacoinOutputID(txn.ID(), i)),
			LeafIndex: EphemeralLeafIndex,
		},
		SiacoinOutput: txn.SiacoinOutputs[i],
	}
}

// EphemeralSiafundOutput returns a SiafundElement for the siafund output at
// index i.
func (txn *V2Transaction) EphemeralSiafundOutput(i int) SiafundElement {
	return SiafundElement{
		StateElement: StateElement{
			ID:        Hash256(txn.SiafundOutputID(txn.ID(), i)),
			LeafIndex: EphemeralLeafIndex,
		},
		SiafundOutput: txn.SiafundOutputs[i],
	}
}

// DeepCopy returns a copy of txn that does not alias any of its memory.
func (txn *V2Transaction) DeepCopy() V2Transaction {
	c := *txn
	c.SiacoinInputs = append([]V2SiacoinInput(nil), c.SiacoinInputs...)
	for i := range c.SiacoinInputs {
		c.SiacoinInputs[i].Parent.MerkleProof = append([]Hash256(nil), c.SiacoinInputs[i].Parent.MerkleProof...)
		c.SiacoinInputs[i].SatisfiedPolicy.Signatures = append([]Signature(nil), c.SiacoinInputs[i].SatisfiedPolicy.Signatures...)
		c.SiacoinInputs[i].SatisfiedPolicy.Preimages = append([][]byte(nil), c.SiacoinInputs[i].SatisfiedPolicy.Preimages...)
		for j := range c.SiacoinInputs[i].SatisfiedPolicy.Preimages {
			c.SiacoinInputs[i].SatisfiedPolicy.Preimages[j] = append([]byte(nil), c.SiacoinInputs[i].SatisfiedPolicy.Preimages[j]...)
		}
	}
	c.SiacoinOutputs = append([]SiacoinOutput(nil), c.SiacoinOutputs...)
	c.SiafundInputs = append([]V2SiafundInput(nil), c.SiafundInputs...)
	for i := range c.SiafundInputs {
		c.SiafundInputs[i].Parent.MerkleProof = append([]Hash256(nil), c.SiafundInputs[i].Parent.MerkleProof...)
		c.SiafundInputs[i].SatisfiedPolicy.Signatures = append([]Signature(nil), c.SiafundInputs[i].SatisfiedPolicy.Signatures...)
		c.SiafundInputs[i].SatisfiedPolicy.Preimages = append([][]byte(nil), c.SiafundInputs[i].SatisfiedPolicy.Preimages...)
		for j := range c.SiafundInputs[i].SatisfiedPolicy.Preimages {
			c.SiafundInputs[i].SatisfiedPolicy.Preimages[j] = append([]byte(nil), c.SiafundInputs[i].SatisfiedPolicy.Preimages[j]...)
		}
	}
	c.SiafundOutputs = append([]SiafundOutput(nil), c.SiafundOutputs...)
	c.FileContracts = append([]V2FileContract(nil), c.FileContracts...)
	c.FileContractRevisions = append([]V2FileContractRevision(nil), c.FileContractRevisions...)
	for i := range c.FileContractRevisions {
		c.FileContractRevisions[i].Parent.MerkleProof = append([]Hash256(nil), c.FileContractRevisions[i].Parent.MerkleProof...)
	}
	c.FileContractResolutions = append([]V2FileContractResolution(nil), c.FileContractResolutions...)
	for i := range c.FileContractResolutions {
		c.FileContractResolutions[i].Parent.MerkleProof = append([]Hash256(nil), c.FileContractResolutions[i].Parent.MerkleProof...)
		if sp, ok := c.FileContractResolutions[i].Resolution.(*V2StorageProof); ok {
			sp.ProofIndex.MerkleProof = append([]Hash256(nil), sp.ProofIndex.MerkleProof...)
			sp.Proof = append([]Hash256(nil), sp.Proof...)
		}
	}
	c.Attestations = append([]Attestation(nil), c.Attestations...)
	for i := range c.Attestations {
		c.Attestations[i].Value = append([]byte(nil), c.Attestations[i].Value...)
	}
	c.ArbitraryData = append([]byte(nil), c.ArbitraryData...)
	return c
}

// CurrentTimestamp returns the current time, rounded to the nearest second. The
// time zone is set to UTC.
func CurrentTimestamp() time.Time { return time.Now().Round(time.Second).UTC() }

// V2BlockData contains additional fields not present in v1 blocks.
type V2BlockData struct {
	Height       uint64          `json:"height"`
	Commitment   Hash256         `json:"commitment"`
	Transactions []V2Transaction `json:"transactions"`
}

// A Block is a set of transactions grouped under a header.
type Block struct {
	ParentID     BlockID         `json:"parentID"`
	Nonce        uint64          `json:"nonce"`
	Timestamp    time.Time       `json:"timestamp"`
	MinerPayouts []SiacoinOutput `json:"minerPayouts"`
	Transactions []Transaction   `json:"transactions"`

	V2 *V2BlockData `json:"v2,omitempty"`
}

// MerkleRoot returns the Merkle root of the block's miner payouts and
// transactions.
func (b *Block) MerkleRoot() Hash256 {
	return blockMerkleRoot(b.MinerPayouts, b.Transactions)
}

// V2Transactions returns the block's v2 transactions, if present.
func (b *Block) V2Transactions() []V2Transaction {
	if b.V2 != nil {
		return b.V2.Transactions
	}
	return nil
}

// ID returns a hash that uniquely identifies a block.
func (b *Block) ID() BlockID {
	buf := make([]byte, 32+8+8+32)
	binary.LittleEndian.PutUint64(buf[32:], b.Nonce)
	binary.LittleEndian.PutUint64(buf[40:], uint64(b.Timestamp.Unix()))
	if b.V2 != nil {
		copy(buf[:32], "sia/id/block|")
		copy(buf[48:], b.V2.Commitment[:])
	} else {
		root := b.MerkleRoot() // NOTE: expensive!
		copy(buf[:32], b.ParentID[:])
		copy(buf[48:], root[:])
	}
	return BlockID(HashBytes(buf))
}

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
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return fmt.Errorf("decoding %v:<hex> failed: %w", prefix, err)
	}
	return nil
}

// String implements fmt.Stringer.
func (h Hash256) String() string { return stringerHex("h", h[:]) }

// MarshalText implements encoding.TextMarshaler.
func (h Hash256) MarshalText() ([]byte, error) { return marshalHex("h", h[:]) }

// UnmarshalText implements encoding.TextUnmarshaler.
func (h *Hash256) UnmarshalText(b []byte) error { return unmarshalHex(h[:], "h", b) }

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
		return errors.New("decoding <height>::<id> failed: wrong number of separators")
	} else if ci.Height, err = strconv.ParseUint(string(parts[0]), 10, 64); err != nil {
		return fmt.Errorf("decoding <height>::<id> failed: %w", err)
	} else if n, err := hex.Decode(ci.ID[:], parts[1]); err != nil {
		return fmt.Errorf("decoding <height>::<id> failed: %w", err)
	} else if n < len(ci.ID) {
		return fmt.Errorf("decoding <height>::<id> failed: %w", io.ErrUnexpectedEOF)
	}
	return nil
}

// MarshalJSON implements json.Marshaler.
func (ci ChainIndex) MarshalJSON() ([]byte, error) {
	type jsonCI ChainIndex // hide MarshalText method
	return json.Marshal(jsonCI(ci))
}

// UnmarshalJSON implements json.Unmarshaler.
func (ci *ChainIndex) UnmarshalJSON(b []byte) error {
	type jsonCI ChainIndex // hide UnmarshalText method
	return json.Unmarshal(b, (*jsonCI)(ci))
}

// ParseChainIndex parses a chain index from a string.
func ParseChainIndex(s string) (ci ChainIndex, err error) {
	err = ci.UnmarshalText([]byte(s))
	return
}

// String implements fmt.Stringer.
func (s Specifier) String() string { return string(bytes.Trim(s[:], "\x00")) }

// MarshalText implements encoding.TextMarshaler.
func (s Specifier) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *Specifier) UnmarshalText(b []byte) error {
	str, err := strconv.Unquote(string(b))
	if err != nil {
		str = string(b)
	}
	if len(str) > len(s) {
		return fmt.Errorf("specifier %s too long", str)
	}
	copy(s[:], str)
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (uk UnlockKey) MarshalText() ([]byte, error) {
	return marshalHex(uk.Algorithm.String(), uk.Key[:])
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (uk *UnlockKey) UnmarshalText(b []byte) error {
	parts := bytes.Split(b, []byte(":"))
	if len(parts) != 2 {
		return errors.New("decoding <algorithm>:<key> failed: wrong number of separators")
	} else if err := uk.Algorithm.UnmarshalText(parts[0]); err != nil {
		return fmt.Errorf("decoding <algorithm>:<key> failed: %w", err)
	} else if uk.Key, err = hex.DecodeString(string(parts[1])); err != nil {
		return fmt.Errorf("decoding <algorithm>:<key> failed: %w", err)
	}
	return nil
}

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
		err = fmt.Errorf("decoding addr:<hex> failed: %w", io.ErrUnexpectedEOF)
	} else if checksum := HashBytes(withChecksum[:32]); !bytes.Equal(checksum[:6], withChecksum[32:]) {
		err = errors.New("bad checksum")
	}
	copy(a[:], withChecksum[:32])
	return
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

// String implements fmt.Stringer.
func (pk PublicKey) String() string { return stringerHex("ed25519", pk[:]) }

// MarshalText implements encoding.TextMarshaler.
func (pk PublicKey) MarshalText() ([]byte, error) { return marshalHex("ed25519", pk[:]) }

// UnmarshalText implements encoding.TextUnmarshaler.
func (pk *PublicKey) UnmarshalText(b []byte) error { return unmarshalHex(pk[:], "ed25519", b) }

// String implements fmt.Stringer.
func (tid TransactionID) String() string { return stringerHex("txid", tid[:]) }

// MarshalText implements encoding.TextMarshaler.
func (tid TransactionID) MarshalText() ([]byte, error) { return marshalHex("txid", tid[:]) }

// UnmarshalText implements encoding.TextUnmarshaler.
func (tid *TransactionID) UnmarshalText(b []byte) error { return unmarshalHex(tid[:], "txid", b) }

// String implements fmt.Stringer.
func (scoid SiacoinOutputID) String() string { return stringerHex("scoid", scoid[:]) }

// MarshalText implements encoding.TextMarshaler.
func (scoid SiacoinOutputID) MarshalText() ([]byte, error) { return marshalHex("scoid", scoid[:]) }

// UnmarshalText implements encoding.TextUnmarshaler.
func (scoid *SiacoinOutputID) UnmarshalText(b []byte) error {
	return unmarshalHex(scoid[:], "scoid", b)
}

// String implements fmt.Stringer.
func (sfoid SiafundOutputID) String() string { return stringerHex("sfoid", sfoid[:]) }

// MarshalText implements encoding.TextMarshaler.
func (sfoid SiafundOutputID) MarshalText() ([]byte, error) { return marshalHex("sfoid", sfoid[:]) }

// UnmarshalText implements encoding.TextUnmarshaler.
func (sfoid *SiafundOutputID) UnmarshalText(b []byte) error {
	return unmarshalHex(sfoid[:], "sfoid", b)
}

// String implements fmt.Stringer.
func (fcid FileContractID) String() string { return stringerHex("fcid", fcid[:]) }

// MarshalText implements encoding.TextMarshaler.
func (fcid FileContractID) MarshalText() ([]byte, error) { return marshalHex("fcid", fcid[:]) }

// UnmarshalText implements encoding.TextUnmarshaler.
func (fcid *FileContractID) UnmarshalText(b []byte) error { return unmarshalHex(fcid[:], "fcid", b) }

// String implements fmt.Stringer.
func (sig Signature) String() string { return stringerHex("sig", sig[:]) }

// MarshalText implements encoding.TextMarshaler.
func (sig Signature) MarshalText() ([]byte, error) { return marshalHex("sig", sig[:]) }

// UnmarshalText implements encoding.TextUnmarshaler.
func (sig *Signature) UnmarshalText(b []byte) error { return unmarshalHex(sig[:], "sig", b) }

// MarshalJSON implements json.Marshaler.
func (sp StorageProof) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ParentID FileContractID `json:"parentID"`
		Leaf     string         `json:"leaf"`
		Proof    []Hash256      `json:"proof"`
	}{sp.ParentID, hex.EncodeToString(sp.Leaf[:]), sp.Proof})
}

// UnmarshalJSON implements json.Unmarshaler.
func (sp *StorageProof) UnmarshalJSON(b []byte) error {
	var leaf string
	err := json.Unmarshal(b, &struct {
		ParentID *FileContractID
		Leaf     *string
		Proof    *[]Hash256
	}{&sp.ParentID, &leaf, &sp.Proof})
	if err != nil {
		return err
	} else if len(leaf) != len(sp.Leaf)*2 {
		return errors.New("invalid storage proof leaf length")
	} else if _, err = hex.Decode(sp.Leaf[:], []byte(leaf)); err != nil {
		return err
	}
	return nil
}

// MarshalJSON implements json.Marshaler.
func (sp V2StorageProof) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ProofIndex ChainIndexElement `json:"proofIndex"`
		Leaf       string            `json:"leaf"`
		Proof      []Hash256         `json:"proof"`
	}{sp.ProofIndex, hex.EncodeToString(sp.Leaf[:]), sp.Proof})
}

// UnmarshalJSON implements json.Unmarshaler.
func (sp *V2StorageProof) UnmarshalJSON(b []byte) error {
	var leaf string
	err := json.Unmarshal(b, &struct {
		ProofIndex *ChainIndexElement
		Leaf       *string
		Proof      *[]Hash256
	}{&sp.ProofIndex, &leaf, &sp.Proof})
	if err != nil {
		return err
	} else if len(leaf) != len(sp.Leaf)*2 {
		return errors.New("invalid storage proof leaf length")
	} else if _, err = hex.Decode(sp.Leaf[:], []byte(leaf)); err != nil {
		return err
	}
	return nil
}

// MarshalJSON implements json.Marshaler.
func (res V2FileContractResolution) MarshalJSON() ([]byte, error) {
	var typ string
	switch res.Resolution.(type) {
	case *V2FileContractRenewal:
		typ = "renewal"
	case *V2StorageProof:
		typ = "storage proof"
	case *V2FileContractFinalization:
		typ = "finalization"
	case *V2FileContractExpiration:
		typ = "expiration"
	default:
		panic(fmt.Sprintf("unhandled file contract resolution type %T", res.Resolution))
	}
	return json.Marshal(struct {
		Parent     V2FileContractElement        `json:"parent"`
		Type       string                       `json:"type"`
		Resolution V2FileContractResolutionType `json:"resolution"`
	}{res.Parent, typ, res.Resolution})
}

// UnmarshalJSON implements json.Marshaler.
func (res *V2FileContractResolution) UnmarshalJSON(b []byte) error {
	var p struct {
		Parent     V2FileContractElement
		Type       string
		Resolution json.RawMessage
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	switch p.Type {
	case "renewal":
		res.Resolution = new(V2FileContractRenewal)
	case "storage proof":
		res.Resolution = new(V2StorageProof)
	case "finalization":
		res.Resolution = new(V2FileContractFinalization)
	case "expiration":
		res.Resolution = new(V2FileContractExpiration)
	default:
		return fmt.Errorf("unknown file contract resolution type %q", p.Type)
	}
	if err := json.Unmarshal(p.Resolution, res.Resolution); err != nil {
		return err
	}
	res.Parent = p.Parent
	return nil
}
