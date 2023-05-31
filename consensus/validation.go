package consensus

import (
	"bytes"
	"errors"
	"fmt"
	"math/bits"
	"time"

	"go.sia.tech/core/internal/blake2b"
	"go.sia.tech/core/types"
)

// ValidateHeader validates a header in the context of s.
func ValidateHeader(s State, parentID types.BlockID, timestamp time.Time, nonce uint64, id types.BlockID) error {
	if parentID != s.Index.ID {
		return errors.New("wrong parent ID")
	} else if timestamp.Before(s.medianTimestamp()) {
		return errors.New("timestamp is too far in the past")
	} else if nonce%s.NonceFactor() != 0 {
		return errors.New("nonce is not divisible by required factor")
	} else if id.CmpWork(s.ChildTarget) < 0 {
		return errors.New("insufficient work")
	}
	return nil
}

func validateMinerPayouts(s State, b types.Block) error {
	expectedSum := s.BlockReward()
	for _, txn := range b.Transactions {
		for _, fee := range txn.MinerFees {
			if fee.IsZero() {
				return errors.New("transaction fee has zero value")
			}
			var overflow bool
			expectedSum, overflow = expectedSum.AddWithOverflow(fee)
			if overflow {
				return errors.New("transaction fees overflow")
			}
		}
	}

	var sum types.Currency
	for _, mp := range b.MinerPayouts {
		if mp.Value.IsZero() {
			return errors.New("miner payout has zero value")
		}
		var overflow bool
		sum, overflow = sum.AddWithOverflow(mp.Value)
		if overflow {
			return errors.New("miner payouts overflow")
		}
	}
	if sum != expectedSum {
		return fmt.Errorf("miner payout sum (%d) does not match block reward + fees (%d)", sum, expectedSum)
	}
	return nil
}

// ValidateOrphan validates b in the context of s.
func ValidateOrphan(s State, b types.Block) error {
	// TODO: calculate size more efficiently
	if uint64(types.EncodedLen(b)) > s.MaxBlockWeight() {
		return errors.New("block exceeds maximum weight")
	} else if err := ValidateHeader(s, b.ParentID, b.Timestamp, b.Nonce, b.ID()); err != nil {
		return err
	} else if err := validateMinerPayouts(s, b); err != nil {
		return err
	}
	return nil
}

// A MidState represents the state of the blockchain within a block.
type MidState struct {
	base        State
	scos        map[types.SiacoinOutputID]types.SiacoinOutput
	sfos        map[types.SiafundOutputID]types.SiafundOutput
	claims      map[types.SiafundOutputID]types.Currency
	fcs         map[types.FileContractID]types.FileContract
	spends      map[types.Hash256]types.TransactionID
	siafundPool types.Currency
}

// Index returns the index of the MidState's base state.
func (ms *MidState) Index() types.ChainIndex {
	return ms.base.Index
}

func (ms *MidState) siacoinOutput(store Store, id types.SiacoinOutputID) (types.SiacoinOutput, bool) {
	sco, ok := ms.scos[id]
	if !ok {
		sco, ok = store.SiacoinOutput(id)
	}
	return sco, ok
}

func (ms *MidState) siafundOutput(store Store, id types.SiafundOutputID) (types.SiafundOutput, types.Currency, types.Currency, bool) {
	sfo, ok := ms.sfos[id]
	claimStart := ms.claims[id]
	if !ok {
		sfo, claimStart, ok = store.SiafundOutput(id)
	}
	claimPortion := ms.siafundPool.Sub(claimStart).Div64(ms.base.SiafundCount()).Mul64(sfo.Value)
	return sfo, claimStart, claimPortion, ok
}

func (ms *MidState) fileContract(store Store, id types.FileContractID) (types.FileContract, bool) {
	fc, ok := ms.fcs[id]
	if !ok {
		fc, ok = store.FileContract(id)
	}
	return fc, ok
}

func (ms *MidState) mustSiacoinOutput(store Store, id types.SiacoinOutputID) types.SiacoinOutput {
	sco, ok := ms.siacoinOutput(store, id)
	if !ok {
		panic("missing SiacoinOutput")
	}
	return sco
}

func (ms *MidState) mustSiafundOutput(store Store, id types.SiafundOutputID) (types.SiafundOutput, types.Currency, types.Currency) {
	sfo, claimStart, claimPortion, ok := ms.siafundOutput(store, id)
	if !ok {
		panic("missing SiafundOutput")
	}
	return sfo, claimStart, claimPortion
}

func (ms *MidState) mustFileContract(store Store, id types.FileContractID) types.FileContract {
	fc, ok := ms.fileContract(store, id)
	if !ok {
		panic("missing FileContract")
	}
	return fc
}

func (ms *MidState) spent(id types.Hash256) (types.TransactionID, bool) {
	txid, ok := ms.spends[id]
	return txid, ok
}

// NewMidState constructs a MidState initialized to the provided base state.
func NewMidState(s State) *MidState {
	return &MidState{
		base:        s,
		scos:        make(map[types.SiacoinOutputID]types.SiacoinOutput),
		sfos:        make(map[types.SiafundOutputID]types.SiafundOutput),
		claims:      make(map[types.SiafundOutputID]types.Currency),
		fcs:         make(map[types.FileContractID]types.FileContract),
		spends:      make(map[types.Hash256]types.TransactionID),
		siafundPool: s.SiafundPool,
	}
}

func validateCurrencyOverflow(ms *MidState, txn types.Transaction) error {
	// Check that the sum of all currency values in the transaction will not
	// overflow our 128-bit representation. This allows us to safely add
	// currency values in other validation checks without fear of overflow.
	//
	// NOTE: Assuming emission is unchanged, the total supply won't hit 2^128
	// Hastings for another 10,000 years.
	//
	// NOTE: We are only checking for overflow within a single transaction, but
	// that's okay. Later, we check that the transaction's inputs equal its
	// outputs, which is an even stricter check: it means a transaction's
	// currency values can't exceed the current total supply. Thus, even if you
	// sum up values multiple transactions, there's still no risk of overflow as
	// long as the transactions are individually valid.

	var sum types.Currency
	var overflow bool
	add := func(c types.Currency) {
		if !overflow {
			sum, overflow = sum.AddWithOverflow(c)
		}
	}
	for _, sco := range txn.SiacoinOutputs {
		add(sco.Value)
	}
	for _, sfo := range txn.SiafundOutputs {
		overflow = overflow || sfo.Value > ms.base.SiafundCount()
	}
	for _, fc := range txn.FileContracts {
		add(fc.Payout)
		for _, in := range fc.ValidProofOutputs {
			add(in.Value)
		}
		for _, in := range fc.MissedProofOutputs {
			add(in.Value)
		}
	}
	for _, fcr := range txn.FileContractRevisions {
		// NOTE: Payout is skipped; see types.FileContractRevision docstring
		for _, in := range fcr.FileContract.ValidProofOutputs {
			add(in.Value)
		}
		for _, in := range fcr.FileContract.MissedProofOutputs {
			add(in.Value)
		}
	}

	if overflow {
		return errors.New("transaction outputs exceed inputs") // technically true
	}
	return nil
}

func validateMinimumValues(ms *MidState, txn types.Transaction) error {
	zero := false
	for _, sco := range txn.SiacoinOutputs {
		zero = zero || sco.Value.IsZero()
	}
	for _, fc := range txn.FileContracts {
		zero = zero || fc.Payout.IsZero()
	}
	for _, sfo := range txn.SiafundOutputs {
		zero = zero || sfo.Value == 0
	}
	for _, fee := range txn.MinerFees {
		zero = zero || fee.IsZero()
	}
	if zero {
		return errors.New("transaction creates a zero-valued output")
	}
	return nil
}

func validateSiacoins(ms *MidState, store Store, txn types.Transaction) error {
	// NOTE: storage proofs and siafund claim outputs can also create new
	// siacoin outputs, but we don't need to account for them here because they
	// have a maturity delay and are thus unspendable within the same block

	var inputSum types.Currency
	for i, sci := range txn.SiacoinInputs {
		if sci.UnlockConditions.Timelock > ms.base.childHeight() {
			return fmt.Errorf("siacoin input %v has timelocked parent", i)
		} else if txid, ok := ms.spent(types.Hash256(sci.ParentID)); ok {
			return fmt.Errorf("siacoin input %v double-spends parent output (previously spent in %v)", i, txid)
		}
		parent, ok := ms.siacoinOutput(store, sci.ParentID)
		if !ok {
			return fmt.Errorf("siacoin input %v spends nonexistent siacoin output %v", i, sci.ParentID)
		} else if sci.UnlockConditions.UnlockHash() != parent.Address {
			return fmt.Errorf("siacoin input %v claims incorrect unlock conditions for siacoin output %v", i, sci.ParentID)
		}
		inputSum = inputSum.Add(parent.Value)
	}
	var outputSum types.Currency
	for _, out := range txn.SiacoinOutputs {
		outputSum = outputSum.Add(out.Value)
	}
	for _, fc := range txn.FileContracts {
		outputSum = outputSum.Add(fc.Payout)
	}
	for _, fee := range txn.MinerFees {
		outputSum = outputSum.Add(fee)
	}
	if inputSum.Cmp(outputSum) != 0 {
		return fmt.Errorf("siacoin inputs (%d H) do not equal outputs (%d H)", inputSum, outputSum)
	}
	return nil
}

func validateSiafunds(ms *MidState, store Store, txn types.Transaction) error {
	var inputSum uint64
	for i, sfi := range txn.SiafundInputs {
		if sfi.UnlockConditions.Timelock > ms.base.childHeight() {
			return fmt.Errorf("siafund input %v has timelocked parent", i)
		} else if txid, ok := ms.spent(types.Hash256(sfi.ParentID)); ok {
			return fmt.Errorf("siafund input %v double-spends parent output (previously spent in %v)", i, txid)
		}
		parent, _, _, ok := ms.siafundOutput(store, sfi.ParentID)
		if !ok {
			return fmt.Errorf("siafund input %v spends nonexistent siafund output %v", i, sfi.ParentID)
		} else if sfi.UnlockConditions.UnlockHash() != parent.Address &&
			// override old developer siafund address
			!(ms.base.childHeight() >= ms.base.Network.HardforkDevAddr.Height &&
				parent.Address == ms.base.Network.HardforkDevAddr.OldAddress &&
				sfi.UnlockConditions.UnlockHash() == ms.base.Network.HardforkDevAddr.NewAddress) {
			return fmt.Errorf("siafund input %v claims incorrect unlock conditions for siafund output %v", i, sfi.ParentID)
		}
		inputSum += parent.Value
	}
	var outputSum uint64
	for _, out := range txn.SiafundOutputs {
		outputSum += out.Value
	}
	if inputSum != outputSum {
		return fmt.Errorf("siafund inputs (%v) do not equal outputs (%v)", inputSum, outputSum)
	}
	return nil
}

func validateFileContracts(ms *MidState, store Store, txn types.Transaction) error {
	for i, fc := range txn.FileContracts {
		if fc.WindowStart < ms.base.childHeight() {
			return fmt.Errorf("file contract %v has window that starts in the past", i)
		} else if fc.WindowEnd <= fc.WindowStart {
			return fmt.Errorf("file contract %v has window that ends before it begins", i)
		}
		var validSum, missedSum types.Currency
		for _, output := range fc.ValidProofOutputs {
			validSum = validSum.Add(output.Value)
		}
		for _, output := range fc.MissedProofOutputs {
			missedSum = missedSum.Add(output.Value)
		}
		if !validSum.Equals(missedSum) {
			return fmt.Errorf("file contract %v has valid payout that does not equal missed payout", i)
		} else if !fc.Payout.Equals(validSum.Add(ms.base.FileContractTax(fc))) {
			return fmt.Errorf("file contract %v has payout with incorrect tax", i)
		}
	}

	for i, fcr := range txn.FileContractRevisions {
		if fcr.UnlockConditions.Timelock > ms.base.childHeight() {
			return fmt.Errorf("file contract revision %v has timelocked parent", i)
		} else if fcr.FileContract.WindowStart < ms.base.childHeight() {
			return fmt.Errorf("file contract revision %v has window that starts in the past", i)
		} else if fcr.FileContract.WindowEnd <= fcr.FileContract.WindowStart {
			return fmt.Errorf("file contract revision %v has window that ends before it begins", i)
		} else if txid, ok := ms.spent(types.Hash256(fcr.ParentID)); ok {
			return fmt.Errorf("file contract revision %v conflicts with previous proof or revision (in %v)", i, txid)
		}
		parent, ok := ms.fileContract(store, fcr.ParentID)
		if !ok {
			return fmt.Errorf("file contract revision %v revises nonexistent file contract %v", i, fcr.ParentID)
		}
		if fcr.FileContract.RevisionNumber <= parent.RevisionNumber {
			return fmt.Errorf("file contract revision %v does not have a higher revision number than its parent", i)
		} else if types.Hash256(fcr.UnlockConditions.UnlockHash()) != parent.UnlockHash {
			return fmt.Errorf("file contract revision %v claims incorrect unlock conditions", i)
		}
		outputSum := func(outputs []types.SiacoinOutput) (sum types.Currency) {
			for _, output := range outputs {
				sum = sum.Add(output.Value)
			}
			return sum
		}
		if outputSum(fcr.FileContract.ValidProofOutputs) != outputSum(parent.ValidProofOutputs) {
			return fmt.Errorf("file contract revision %v changes valid payout sum", i)
		} else if outputSum(fcr.FileContract.MissedProofOutputs) != outputSum(parent.MissedProofOutputs) {
			return fmt.Errorf("file contract revision %v changes missed payout sum", i)
		}
	}

	// Storage proofs are height-sensitive, and thus can be invalidated by
	// shallow reorgs; to minimize disruption, we require that transactions
	// containing a storage proof do not contain siacoin outputs, siafund
	// outputs, new file contracts, or file contract revisions.
	if len(txn.StorageProofs) > 0 &&
		(len(txn.SiacoinOutputs) > 0 || len(txn.SiafundOutputs) > 0 ||
			len(txn.FileContracts) > 0 || len(txn.FileContractRevisions) > 0) {
		return errors.New("transaction contains both a storage proof and other outputs")
	}
	// A contract can only have a single storage proof.
	for i := range txn.StorageProofs {
		for j := i + 1; j < len(txn.StorageProofs); j++ {
			if txn.StorageProofs[i].ParentID == txn.StorageProofs[j].ParentID {
				return fmt.Errorf("storage proof %v resolves contract (%v) already resolved by storage proof %v", j, txn.StorageProofs[i].ParentID, i)
			}
		}
	}

	const leafSize = uint64(len(types.StorageProof{}.Leaf))
	lastLeafIndex := func(filesize uint64) uint64 {
		if filesize%leafSize != 0 {
			return filesize / leafSize
		}
		return (filesize / leafSize) - 1
	}
	storageProofLeaf := func(leafIndex, filesize uint64, leaf [64]byte) []byte {
		switch {
		case ms.base.childHeight() < ms.base.Network.HardforkTax.Height:
			return leaf[:]
		case ms.base.childHeight() < ms.base.Network.HardforkStorageProof.Height:
			if leafIndex == lastLeafIndex(filesize) {
				return leaf[:filesize%leafSize]
			}
			return leaf[:]
		default:
			if filesize == 0 {
				return nil
			} else if leafIndex == lastLeafIndex(filesize) && filesize%leafSize != 0 {
				return leaf[:filesize%leafSize]
			}
			return leaf[:]
		}
	}
	storageProofRoot := func(leafIndex uint64, filesize uint64, leaf []byte, proof []types.Hash256) types.Hash256 {
		buf := make([]byte, 1+leafSize)
		buf[0] = 0 // leaf hash prefix
		copy(buf[1:], leaf)
		root := types.HashBytes(buf)
		subtreeHeight := bits.Len64(leafIndex ^ (lastLeafIndex(filesize)))
		for i, h := range proof {
			if leafIndex&(1<<i) != 0 || i >= subtreeHeight {
				root = blake2b.SumPair(h, root)
			} else {
				root = blake2b.SumPair(root, h)
			}
		}
		return root
	}

	for i, sp := range txn.StorageProofs {
		if txid, ok := ms.spent(types.Hash256(sp.ParentID)); ok {
			return fmt.Errorf("storage proof %v conflicts with previous proof or revision (in %v)", i, txid)
		}
		fc, ok := ms.fileContract(store, sp.ParentID)
		if !ok {
			return fmt.Errorf("storage proof %v references nonexistent file contract", i)
		}
		windowStart, ok := store.BestIndex(fc.WindowStart - 1)
		if !ok {
			return fmt.Errorf("missing index for contract window start %v", fc.WindowStart)
		}
		leafIndex := ms.base.StorageProofLeafIndex(fc.Filesize, windowStart, sp.ParentID)
		leaf := storageProofLeaf(leafIndex, fc.Filesize, sp.Leaf)
		if leaf == nil {
			continue
		} else if storageProofRoot(leafIndex, fc.Filesize, leaf, sp.Proof) != fc.FileMerkleRoot {
			return fmt.Errorf("storage proof %v has root that does not match contract Merkle root", i)
		}
	}

	return nil
}

func validateArbitraryData(ms *MidState, store Store, txn types.Transaction) error {
	if ms.base.childHeight() < ms.base.Network.HardforkFoundation.Height {
		return nil
	}
	for _, arb := range txn.ArbitraryData {
		if bytes.HasPrefix(arb, types.SpecifierFoundation[:]) {
			var update types.FoundationAddressUpdate
			d := types.NewBufDecoder(arb[len(types.SpecifierFoundation):])
			if update.DecodeFrom(d); d.Err() != nil {
				return errors.New("transaction contains an improperly-encoded FoundationAddressUpdate")
			} else if update.NewPrimary == types.VoidAddress || update.NewFailsafe == types.VoidAddress {
				return errors.New("transaction contains an uninitialized FoundationAddressUpdate")
			}
			// check that the transaction is signed by a current key
			var signed bool
			for _, sci := range txn.SiacoinInputs {
				if uh := sci.UnlockConditions.UnlockHash(); uh != ms.base.FoundationPrimaryAddress && uh != ms.base.FoundationFailsafeAddress {
					continue
				}
				for _, sig := range txn.Signatures {
					signed = signed || (sig.ParentID == types.Hash256(sci.ParentID) && sig.CoveredFields.WholeTransaction)
				}
				if signed {
					break
				}
			}
			if !signed {
				return errors.New("transaction contains an unsigned FoundationAddressUpdate")
			}
		}
	}
	return nil
}

func validateSignatures(ms *MidState, txn types.Transaction) error {
	// build a map of all outstanding signatures
	//
	// NOTE: siad checks for double-spends here, but this is redundant
	type sigMapEntry struct {
		need uint64
		keys []types.UnlockKey
		used []bool
	}
	sigMap := make(map[types.Hash256]*sigMapEntry)
	addEntry := func(id types.Hash256, uc types.UnlockConditions) {
		sigMap[id] = &sigMapEntry{
			need: uc.SignaturesRequired,
			keys: uc.PublicKeys,
			used: make([]bool, len(uc.PublicKeys)),
		}
	}
	for _, sci := range txn.SiacoinInputs {
		addEntry(types.Hash256(sci.ParentID), sci.UnlockConditions)
	}
	for _, sfi := range txn.SiafundInputs {
		addEntry(types.Hash256(sfi.ParentID), sfi.UnlockConditions)
	}
	for _, fcr := range txn.FileContractRevisions {
		addEntry(types.Hash256(fcr.ParentID), fcr.UnlockConditions)
	}

	for i, sig := range txn.Signatures {
		e, ok := sigMap[types.Hash256(sig.ParentID)]
		if !ok {
			return fmt.Errorf("signature %v references parent not present in transaction", i)
		} else if sig.PublicKeyIndex >= uint64(len(e.keys)) {
			return fmt.Errorf("signature %v points to a nonexistent public key", i)
		} else if e.need == 0 || e.used[sig.PublicKeyIndex] {
			return fmt.Errorf("signature %v is redundant", i)
		} else if sig.Timelock > ms.base.childHeight() {
			return fmt.Errorf("timelock of signature %v has not expired", i)
		}
		e.used[sig.PublicKeyIndex] = true
		e.need--

		switch pk := e.keys[sig.PublicKeyIndex]; pk.Algorithm {
		case types.SpecifierEd25519:
			var epk types.PublicKey
			var esig types.Signature
			copy(epk[:], pk.Key)
			copy(esig[:], sig.Signature)
			var sigHash types.Hash256
			if sig.CoveredFields.WholeTransaction {
				sigHash = ms.base.WholeSigHash(txn, sig.ParentID, sig.PublicKeyIndex, sig.Timelock, sig.CoveredFields.Signatures)
			} else {
				sigHash = ms.base.PartialSigHash(txn, sig.CoveredFields)
			}
			if !epk.VerifyHash(sigHash, esig) {
				return fmt.Errorf("signature %v is invalid", i)
			}
		case types.SpecifierEntropy:
			return fmt.Errorf("signature %v uses an entropy public key", i)
		default:
			// signatures for unrecognized algorithms are considered valid by
			// default; this allows new algorithms to be soft-forked in
		}
	}

	for id, sig := range sigMap {
		if sig.need > 0 {
			return fmt.Errorf("parent %v has missing signatures", id)
		}
	}
	return nil
}

// ValidateTransaction validates txn within the context of ms and store.
func ValidateTransaction(ms *MidState, store Store, txn types.Transaction) error {
	if err := validateCurrencyOverflow(ms, txn); err != nil {
		return err
	} else if err := validateMinimumValues(ms, txn); err != nil {
		return err
	} else if err := validateSiacoins(ms, store, txn); err != nil {
		return err
	} else if err := validateSiafunds(ms, store, txn); err != nil {
		return err
	} else if err := validateFileContracts(ms, store, txn); err != nil {
		return err
	} else if err := validateArbitraryData(ms, store, txn); err != nil {
		return err
	} else if err := validateSignatures(ms, txn); err != nil {
		return err
	}
	return nil
}

// ValidateBlock validates b in the context of s and store.
//
// This function does not check whether the header's timestamp is too far in the
// future. That check should be performed at the time the block is received,
// e.g. in p2p networking code; see MaxFutureTimestamp.
func ValidateBlock(s State, store Store, b types.Block) error {
	if err := ValidateOrphan(s, b); err != nil {
		return err
	}
	ms := NewMidState(s)
	for _, txn := range b.Transactions {
		if err := ValidateTransaction(ms, store, txn); err != nil {
			return err
		}
		ms.ApplyTransaction(store, txn)
	}
	return nil
}
