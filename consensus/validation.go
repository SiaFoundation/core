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

// A ValidationContext contains all of the information necessary to validate a
// block.
type ValidationContext struct {
	State State
	Store Store
}

func (vc ValidationContext) validateHeader(h types.BlockHeader) error {
	if h.ParentID != vc.State.Index.ID {
		return errors.New("wrong parent ID")
	} else if h.Timestamp.Before(vc.State.medianTimestamp()) {
		return errors.New("timestamp is too far in the past")
	} else if h.Nonce%vc.State.NonceFactor() != 0 {
		return errors.New("nonce is not divisible by required factor")
	} else if types.WorkRequiredForHash(h.ID()).Cmp(vc.State.Difficulty) < 0 {
		return errors.New("insufficient work")
	}
	return nil
}

func (vc ValidationContext) validateMinerPayouts(b types.Block) error {
	expectedSum := vc.State.BlockReward()
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

func (vc ValidationContext) validateCurrencyOverflow(txns []types.Transaction) error {
	// Check that the sum of all currency values in the transaction set will not
	// overflow our 128-bit representation. This allows us to safely add
	// currency values in other validation checks without fear of overflow.
	//
	// NOTE: Assuming emission is unchanged, the total supply won't hit 2^128
	// Hastings for another 10,000 years.

	var sum types.Currency
	var overflow bool
	add := func(c types.Currency) {
		if !overflow {
			sum, overflow = sum.AddWithOverflow(c)
		}
	}
	for _, txn := range txns {
		for _, sco := range txn.SiacoinOutputs {
			add(sco.Value)
		}
		for _, sfo := range txn.SiafundOutputs {
			overflow = overflow || sfo.Value > vc.State.SiafundCount()
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
			for _, in := range fcr.Revision.ValidProofOutputs {
				add(in.Value)
			}
			for _, in := range fcr.Revision.MissedProofOutputs {
				add(in.Value)
			}
		}
	}
	if overflow {
		return errors.New("transaction outputs exceed inputs") // technically true, if unhelpful
	}
	return nil
}

func (vc ValidationContext) validateDoubleSpends(txns []types.Transaction) error {
	seen := make(map[types.Hash256]bool)
	doubleSpent := func(id types.Hash256) bool {
		if seen[id] {
			return true
		}
		seen[id] = true
		return false
	}
	for i, txn := range txns {
		for _, sci := range txn.SiacoinInputs {
			if doubleSpent(types.Hash256(sci.ParentID)) {
				return fmt.Errorf("transaction %v double-spends siacoin input %v", i, sci.ParentID)
			}
		}
		for _, sfi := range txn.SiafundInputs {
			if doubleSpent(types.Hash256(sfi.ParentID)) {
				return fmt.Errorf("transaction %v double-spends siacoin input %v", i, sfi.ParentID)
			}
		}
		for _, sp := range txn.StorageProofs {
			if doubleSpent(types.Hash256(sp.ParentID)) {
				return fmt.Errorf("transaction %v double-resolves file contract %v", i, sp.ParentID)
			}
		}
	}
	return nil
}

func (vc ValidationContext) validateMinimumValues(txn types.Transaction) error {
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

func (vc ValidationContext) validateSiacoins(txns []types.Transaction) error {
	// NOTE: storage proofs and siafund claim outputs can also create new
	// siacoin outputs, but we don't need to account for them here because they
	// have a maturity delay and are thus unspendable within the same block

	ephemeralSC := make(map[types.SiacoinOutputID]types.SiacoinOutput)
	spent := make(map[types.SiacoinOutputID]int)
	for i, txn := range txns {
		var inputSum types.Currency
		for _, sci := range txn.SiacoinInputs {
			if prev, ok := spent[sci.ParentID]; ok {
				return fmt.Errorf("transaction %v double-spends siacoin output %v (previously spent in transaction %v)", i, sci.ParentID, prev)
			}
			spent[sci.ParentID] = i
			parent, ok := ephemeralSC[sci.ParentID]
			if !ok {
				parent, ok = vc.Store.SiacoinOutput(sci.ParentID)
				if !ok {
					return fmt.Errorf("transaction %v spends nonexistent siacoin output %v", i, sci.ParentID)
				}
			}
			if sci.UnlockConditions.UnlockHash() != parent.Address {
				return fmt.Errorf("transaction %v claims incorrect unlock conditions for siacoin output %v", i, sci.ParentID)
			}
			inputSum = inputSum.Add(parent.Value)
		}
		var outputSum types.Currency
		for i, out := range txn.SiacoinOutputs {
			ephemeralSC[txn.SiacoinOutputID(i)] = out
			outputSum = outputSum.Add(out.Value)
		}
		for _, fc := range txn.FileContracts {
			outputSum = outputSum.Add(fc.Payout)
		}
		for _, fee := range txn.MinerFees {
			outputSum = outputSum.Add(fee)
		}
		if inputSum.Cmp(outputSum) != 0 {
			return fmt.Errorf("transaction %v is invalid: siacoin inputs (%v) do not equal outputs (%v)", i, inputSum, outputSum)
		}
	}
	return nil
}

func (vc ValidationContext) validateSiafunds(txns []types.Transaction) error {
	ephemeralSF := make(map[types.SiafundOutputID]types.SiafundOutput)
	spent := make(map[types.SiafundOutputID]int)
	for i, txn := range txns {
		var inputSum uint64
		for _, sfi := range txn.SiafundInputs {
			if prev, ok := spent[sfi.ParentID]; ok {
				return fmt.Errorf("transaction %v double-spends siafund output %v (previously spent in transaction %v)", i, sfi.ParentID, prev)
			}
			spent[sfi.ParentID] = i
			parent, ok := ephemeralSF[sfi.ParentID]
			if !ok {
				parent, _, ok = vc.Store.SiafundOutput(sfi.ParentID)
				if !ok {
					return fmt.Errorf("transaction %v spends nonexistent siafund output %v", i, sfi.ParentID)
				}
			}
			if sfi.UnlockConditions.UnlockHash() != parent.Address {
				return fmt.Errorf("transaction %v claims incorrect unlock conditions for siafund output %v", i, sfi.ParentID)
			}

			inputSum += parent.Value
		}
		var outputSum uint64
		for i, out := range txn.SiafundOutputs {
			ephemeralSF[txn.SiafundOutputID(i)] = out
			outputSum += out.Value
		}
		if inputSum != outputSum {
			return fmt.Errorf("transaction %v is invalid: siafund inputs (%v) do not equal outputs (%v)", i, inputSum, outputSum)
		}
	}
	return nil
}

func (vc ValidationContext) validateContracts(txns []types.Transaction) error {
	ephemeralFC := make(map[types.FileContractID]types.FileContract)
	for _, txn := range txns {
		for i, fc := range txn.FileContracts {
			ephemeralFC[txn.FileContractID(i)] = fc
		}
	}
	for txnIndex, txn := range txns {
		for i, fcr := range txn.FileContractRevisions {
			parent, ok := ephemeralFC[fcr.ParentID]
			if !ok {
				parent, ok = vc.Store.FileContract(fcr.ParentID)
				if !ok {
					return fmt.Errorf("transaction %v is invalid: file contract revision %v revises nonexistent file contract %v", txnIndex, i, fcr.ParentID)
				}
			}
			fcr.Revision.Payout = parent.Payout // see FileContractRevision docstring
			if fcr.Revision.RevisionNumber <= parent.RevisionNumber {
				return fmt.Errorf("transaction %v is invalid: file contract revision %v does not have a higher revision number than its parent", txnIndex, i)
			} else if types.Hash256(fcr.UnlockConditions.UnlockHash()) != parent.UnlockHash {
				return fmt.Errorf("transaction %v is invalid: file contract revision %v claims incorrect unlock conditions", txnIndex, i)
			}
			outputSum := func(outputs []types.SiacoinOutput) (sum types.Currency) {
				for _, output := range outputs {
					sum = sum.Add(output.Value)
				}
				return sum
			}
			if outputSum(fcr.Revision.ValidProofOutputs) != outputSum(parent.ValidProofOutputs) {
				return fmt.Errorf("transaction %v is invalid: file contract revision %v changes valid payout sum", txnIndex, i)
			} else if outputSum(fcr.Revision.MissedProofOutputs) != outputSum(parent.MissedProofOutputs) {
				return fmt.Errorf("transaction %v is invalid: file contract revision %v changes missed payout sum", txnIndex, i)
			}
			ephemeralFC[fcr.ParentID] = fcr.Revision
		}
	}
	return nil
}

func (vc ValidationContext) validateSiacoinInputs(txn types.Transaction) error {
	for i, sci := range txn.SiacoinInputs {
		if sci.UnlockConditions.Timelock > vc.State.childHeight() {
			return fmt.Errorf("siacoin input %v has timelocked parent", i)
		}
	}
	return nil
}

func (vc ValidationContext) validateSiafundInputs(txn types.Transaction) error {
	for i, sfi := range txn.SiafundInputs {
		if sfi.UnlockConditions.Timelock > vc.State.childHeight() {
			return fmt.Errorf("siafund input %v has timelocked parent", i)
		}
	}
	return nil
}

func (vc ValidationContext) validateFileContracts(txn types.Transaction) error {
	for i, fc := range txn.FileContracts {
		if fc.WindowStart < vc.State.childHeight() {
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
		} else if !fc.Payout.Equals(validSum.Add(vc.State.FileContractTax(fc))) {
			return fmt.Errorf("file contract %v has payout with incorrect tax", i)
		}
	}
	return nil
}

func (vc ValidationContext) validateFileContractRevisions(txn types.Transaction) error {
	seen := make(map[types.FileContractID]bool)
	for _, sp := range txn.StorageProofs {
		seen[sp.ParentID] = true
	}
	for i, fcr := range txn.FileContractRevisions {
		if seen[fcr.ParentID] {
			return fmt.Errorf("file contract revision %v conflicts with previous proof or revision in same transaction", i)
		}
		seen[fcr.ParentID] = true

		if fcr.UnlockConditions.Timelock > vc.State.childHeight() {
			return fmt.Errorf("file contract revision %v has timelocked parent", i)
		} else if fcr.Revision.WindowStart < vc.State.childHeight() {
			return fmt.Errorf("file contract revision %v has window that starts in the past", i)
		} else if fcr.Revision.WindowEnd <= fcr.Revision.WindowStart {
			return fmt.Errorf("file contract revision %v has window that ends before it begins", i)
		}
	}
	return nil
}

func (vc ValidationContext) validateStorageProofs(txn types.Transaction) error {
	const leafSize = uint64(len(types.StorageProof{}.Leaf))

	// Storage proofs are height-sensitive, and thus can be invalidated by
	// shallow reorgs; to minimize disruption, we require that transactions
	// containing a storage proof do not contain siacoin outputs, siafund
	// outputs, new file contracts, or file contract revisions.
	numOutputs := len(txn.SiacoinOutputs) + len(txn.SiafundOutputs) + len(txn.FileContracts) + len(txn.FileContractRevisions)
	if len(txn.StorageProofs) > 0 && numOutputs > 0 {
		return errors.New("transaction has both a storage proof and other outputs")
	}

	storageProofRoot := func(leafIndex uint64, totalLeaves uint64, leaf []byte, proof []types.Hash256) types.Hash256 {
		buf := make([]byte, 1+leafSize)
		buf[0] = 0 // leaf hash prefix
		copy(buf[1:], leaf)
		root := types.HashBytes(buf)
		subtreeHeight := bits.Len64(leafIndex ^ (totalLeaves - 1))
		for i, h := range proof {
			if leafIndex&(1<<i) != 0 || i >= subtreeHeight {
				root = blake2b.SumPair(h, root)
			} else {
				root = blake2b.SumPair(root, h)
			}
		}
		return root
	}

	seen := make(map[types.FileContractID]bool)
	for _, fcr := range txn.FileContractRevisions {
		seen[fcr.ParentID] = true
	}
	for i, sp := range txn.StorageProofs {
		if seen[sp.ParentID] {
			return fmt.Errorf("storage proof %v conflicts with previous proof or revision in same transaction", i)
		}
		seen[sp.ParentID] = true

		fc, ok := vc.Store.FileContract(sp.ParentID)
		if !ok {
			return fmt.Errorf("storage proof %v references nonexistent file contract", i)
		}
		windowStart, ok := vc.Store.BestIndex(fc.WindowStart - 1)
		if !ok {
			return fmt.Errorf("missing index for contract window start %v", fc.WindowStart)
		}
		leafIndex := vc.State.StorageProofLeafIndex(fc.Filesize, windowStart, sp.ParentID)
		totalLeaves := fc.Filesize / leafSize
		if fc.Filesize%leafSize != 0 {
			totalLeaves++
		}
		var leafLen uint64
		if vc.State.childHeight() < hardforkTax {
			leafLen = leafSize
		} else if vc.State.childHeight() < hardforkStorageProof {
			leafLen = leafSize
			if leafIndex == totalLeaves-1 {
				leafLen = fc.Filesize % leafSize
			}
		} else {
			if fc.Filesize == 0 {
				continue // proof is not checked
			}
			leafLen = leafSize
			if leafIndex == totalLeaves-1 && fc.Filesize%leafSize != 0 {
				leafLen = fc.Filesize % leafSize
			}
		}
		if storageProofRoot(leafIndex, totalLeaves, sp.Leaf[:leafLen], sp.Proof) != fc.FileMerkleRoot {
			return fmt.Errorf("storage proof %v has root that does not match contract Merkle root", i)
		}
	}

	return nil
}

func (vc ValidationContext) validateArbitraryData(txn types.Transaction) error {
	if vc.State.childHeight() < hardforkFoundation {
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
				if uh := sci.UnlockConditions.UnlockHash(); uh != vc.State.FoundationPrimaryAddress && uh != vc.State.FoundationFailsafeAddress {
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

func (vc ValidationContext) validateSignatures(txn types.Transaction) error {
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
		} else if sig.Timelock > vc.State.childHeight() {
			return fmt.Errorf("timelock of signature %v has not expired", i)
		}
		e.used[sig.PublicKeyIndex] = true
		e.need--

		switch pk := e.keys[sig.PublicKeyIndex]; pk.Algorithm {
		case types.SpecifierEd25519:
			if len(pk.Key) != len(types.PublicKey{}) {
				return fmt.Errorf("signature %v has invalid public key length", i)
			} else if len(sig.Signature) < len(types.Signature{}) {
				return fmt.Errorf("signature %v has invalid signature length (%v)", i, len(sig.Signature))
			}
			epk := (*types.PublicKey)(pk.Key)
			esig := *(*types.Signature)(sig.Signature)
			var sigHash types.Hash256
			if sig.CoveredFields.WholeTransaction {
				sigHash = vc.State.WholeSigHash(txn, sig.ParentID, sig.PublicKeyIndex, sig.Timelock, sig.CoveredFields.Signatures)
			} else {
				sigHash = vc.State.PartialSigHash(txn, sig.CoveredFields)
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

func (vc ValidationContext) validateTransaction(txn types.Transaction) error {
	if err := vc.validateMinimumValues(txn); err != nil {
		return err
	} else if err := vc.validateSiacoinInputs(txn); err != nil {
		return err
	} else if err := vc.validateSiafundInputs(txn); err != nil {
		return err
	} else if err := vc.validateFileContracts(txn); err != nil {
		return err
	} else if err := vc.validateFileContractRevisions(txn); err != nil {
		return err
	} else if err := vc.validateStorageProofs(txn); err != nil {
		return err
	} else if err := vc.validateArbitraryData(txn); err != nil {
		return err
	} else if err := vc.validateArbitraryData(txn); err != nil {
		return err
	} else if err := vc.validateSignatures(txn); err != nil {
		return err
	}
	return nil
}

// ValidateTransactionSet validates txns within the context of vc.
func (vc ValidationContext) ValidateTransactionSet(txns []types.Transaction) error {
	if err := vc.validateCurrencyOverflow(txns); err != nil {
		return err
	} else if err := vc.validateDoubleSpends(txns); err != nil {
		return err
	} else if err := vc.validateSiacoins(txns); err != nil {
		return err
	} else if err := vc.validateSiafunds(txns); err != nil {
		return err
	} else if err := vc.validateContracts(txns); err != nil {
		return err
	}
	for i, txn := range txns {
		if err := vc.validateTransaction(txn); err != nil {
			return fmt.Errorf("transaction %v is invalid: %w", i, err)
		}
	}
	return nil
}

// ValidateBlock validates b in the context of vc.
//
// This function does not check whether the header's timestamp is too far in the
// future. That check should be performed at the time the block is received,
// e.g. in p2p networking code; see MaxFutureTimestamp.
func (vc ValidationContext) ValidateBlock(b types.Block) error {
	// TODO: calculate size more efficiently
	if types.EncodedLen(b) > vc.State.MaxBlockWeight() {
		return errors.New("block exceeds maximum weight")
	} else if err := vc.validateHeader(b.Header()); err != nil {
		return err
	} else if err := vc.validateMinerPayouts(b); err != nil {
		return err
	} else if err := vc.ValidateTransactionSet(b.Transactions); err != nil {
		return err
	}
	return nil
}

// MaxFutureTimestamp returns the maximum allowed timestamp for a block.
func (vc ValidationContext) MaxFutureTimestamp(currentTime time.Time) time.Time {
	return currentTime.Add(2 * time.Hour)
}
