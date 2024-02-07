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

func validateHeader(s State, parentID types.BlockID, timestamp time.Time, nonce uint64, id types.BlockID) error {
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
	var overflow bool
	for _, txn := range b.Transactions {
		for _, fee := range txn.MinerFees {
			// NOTE: it's unclear why this check was implemented in siad; the
			// length of txn.MinerFees isn't checked, so it's still possible for
			// a transaction to have zero total fees. There's never a *reason*
			// to specify a zero-valued miner fee -- it's a developer error --
			// but it's also not invalid or dangerous with regard to consensus.
			// Most likely, this check stems from a general policy against
			// creating zero-valued outputs, even though the miner payout output
			// is an aggregate of *all* fees (plus the block reward) and thus
			// will never be zero-valued anyway. In any case, this check is moot
			// in v2, where transactions have a single MinerFee, not a slice.
			if fee.IsZero() {
				return errors.New("transaction fee has zero value")
			}
			expectedSum, overflow = expectedSum.AddWithOverflow(fee)
			if overflow {
				return errors.New("transaction fees overflow")
			}
		}
	}
	if b.V2 != nil {
		for _, txn := range b.V2.Transactions {
			expectedSum, overflow = expectedSum.AddWithOverflow(txn.MinerFee)
			if overflow {
				return errors.New("transaction fees overflow")
			}
		}
		if len(b.MinerPayouts) != 1 {
			return errors.New("block must have exactly one miner payout")
		}
	}

	var sum types.Currency
	for _, mp := range b.MinerPayouts {
		if mp.Value.IsZero() {
			return errors.New("miner payout has zero value")
		}
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
	var weight uint64
	for _, txn := range b.Transactions {
		weight += s.TransactionWeight(txn)
	}
	for _, txn := range b.V2Transactions() {
		weight += s.V2TransactionWeight(txn)
	}
	if weight > s.MaxBlockWeight() {
		return fmt.Errorf("block exceeds maximum weight (%v > %v)", weight, s.MaxBlockWeight())
	} else if err := validateMinerPayouts(s, b); err != nil {
		return err
	} else if err := validateHeader(s, b.ParentID, b.Timestamp, b.Nonce, b.ID()); err != nil {
		return err
	}
	if b.V2 != nil {
		if b.V2.Height != s.Index.Height+1 {
			return errors.New("block height does not increment parent height")
		}
	}
	return nil
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

func validateSiacoins(ms *MidState, txn types.Transaction, ts V1TransactionSupplement) error {
	var inputSum types.Currency
	for i, sci := range txn.SiacoinInputs {
		if sci.UnlockConditions.Timelock > ms.base.childHeight() {
			return fmt.Errorf("siacoin input %v has timelocked parent", i)
		} else if txid, ok := ms.spent(types.Hash256(sci.ParentID)); ok {
			return fmt.Errorf("siacoin input %v double-spends parent output (previously spent in %v)", i, txid)
		}
		parent, ok := ms.siacoinElement(ts, sci.ParentID)
		if !ok {
			return fmt.Errorf("siacoin input %v spends nonexistent siacoin output %v", i, sci.ParentID)
		} else if sci.UnlockConditions.UnlockHash() != parent.SiacoinOutput.Address {
			return fmt.Errorf("siacoin input %v claims incorrect unlock conditions for siacoin output %v", i, sci.ParentID)
		} else if parent.MaturityHeight > ms.base.childHeight() {
			return fmt.Errorf("siacoin input %v has immature parent", i)
		}
		inputSum = inputSum.Add(parent.SiacoinOutput.Value)
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

func validateSiafunds(ms *MidState, txn types.Transaction, ts V1TransactionSupplement) error {
	var inputSum uint64
	for i, sfi := range txn.SiafundInputs {
		if sfi.UnlockConditions.Timelock > ms.base.childHeight() {
			return fmt.Errorf("siafund input %v has timelocked parent", i)
		} else if txid, ok := ms.spent(types.Hash256(sfi.ParentID)); ok {
			return fmt.Errorf("siafund input %v double-spends parent output (previously spent in %v)", i, txid)
		}
		parent, ok := ms.siafundElement(ts, sfi.ParentID)
		if !ok {
			return fmt.Errorf("siafund input %v spends nonexistent siafund output %v", i, sfi.ParentID)
		} else if sfi.UnlockConditions.UnlockHash() != parent.SiafundOutput.Address &&
			// override old developer siafund address
			!(ms.base.childHeight() >= ms.base.Network.HardforkDevAddr.Height &&
				parent.SiafundOutput.Address == ms.base.Network.HardforkDevAddr.OldAddress &&
				sfi.UnlockConditions.UnlockHash() == ms.base.Network.HardforkDevAddr.NewAddress) {
			return fmt.Errorf("siafund input %v claims incorrect unlock conditions for siafund output %v", i, sfi.ParentID)
		}
		inputSum += parent.SiafundOutput.Value
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

func validateFileContracts(ms *MidState, txn types.Transaction, ts V1TransactionSupplement) error {
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
		parent, ok := ms.fileContractElement(ts, fcr.ParentID)
		if !ok {
			return fmt.Errorf("file contract revision %v revises nonexistent file contract %v", i, fcr.ParentID)
		}
		if fcr.FileContract.RevisionNumber <= parent.FileContract.RevisionNumber {
			return fmt.Errorf("file contract revision %v does not have a higher revision number than its parent", i)
		} else if types.Hash256(fcr.UnlockConditions.UnlockHash()) != parent.FileContract.UnlockHash {
			return fmt.Errorf("file contract revision %v claims incorrect unlock conditions", i)
		}
		outputSum := func(outputs []types.SiacoinOutput) (sum types.Currency) {
			for _, output := range outputs {
				sum = sum.Add(output.Value)
			}
			return sum
		}
		if outputSum(fcr.FileContract.ValidProofOutputs) != outputSum(parent.FileContract.ValidProofOutputs) {
			return fmt.Errorf("file contract revision %v changes valid payout sum", i)
		} else if outputSum(fcr.FileContract.MissedProofOutputs) != outputSum(parent.FileContract.MissedProofOutputs) {
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
			return fmt.Errorf("storage proof %v conflicts with previous proof (in %v)", i, txid)
		}
		fce, ok := ms.fileContractElement(ts, sp.ParentID)
		if !ok {
			return fmt.Errorf("storage proof %v references nonexistent file contract", i)
		}
		fc := fce.FileContract
		windowID := ts.storageProofWindowID(sp.ParentID)
		leafIndex := ms.base.StorageProofLeafIndex(fc.Filesize, windowID, sp.ParentID)
		leaf := storageProofLeaf(leafIndex, fc.Filesize, sp.Leaf)
		if leaf == nil {
			continue
		} else if storageProofRoot(leafIndex, fc.Filesize, leaf, sp.Proof) != fc.FileMerkleRoot {
			return fmt.Errorf("storage proof %v has root that does not match contract Merkle root", i)
		}
	}

	return nil
}

func validateArbitraryData(ms *MidState, txn types.Transaction) error {
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
	// NOTE: we also check for intra-transaction double-spends here
	type sigMapEntry struct {
		need uint64
		keys []types.UnlockKey
		used []bool
	}
	sigMap := make(map[types.Hash256]*sigMapEntry)
	addEntry := func(id types.Hash256, uc types.UnlockConditions) bool {
		if _, ok := sigMap[id]; ok {
			return false
		}
		sigMap[id] = &sigMapEntry{
			need: uc.SignaturesRequired,
			keys: uc.PublicKeys,
			used: make([]bool, len(uc.PublicKeys)),
		}
		return true
	}
	for _, sci := range txn.SiacoinInputs {
		if !addEntry(types.Hash256(sci.ParentID), sci.UnlockConditions) {
			return fmt.Errorf("transaction spends siacoin input %v more than once", sci.ParentID)
		}
	}
	for _, sfi := range txn.SiafundInputs {
		if !addEntry(types.Hash256(sfi.ParentID), sfi.UnlockConditions) {
			return fmt.Errorf("transaction spends siafund input %v more than once", sfi.ParentID)
		}
	}
	for _, fcr := range txn.FileContractRevisions {
		if !addEntry(types.Hash256(fcr.ParentID), fcr.UnlockConditions) {
			return fmt.Errorf("transaction revises file contract %v more than once", fcr.ParentID)
		}
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
func ValidateTransaction(ms *MidState, txn types.Transaction, ts V1TransactionSupplement) error {
	if ms.base.childHeight() >= ms.base.Network.HardforkV2.RequireHeight {
		return errors.New("v1 transactions are not allowed after v2 hardfork is complete")
	} else if err := validateCurrencyOverflow(ms, txn); err != nil {
		return err
	} else if err := validateMinimumValues(ms, txn); err != nil {
		return err
	} else if err := validateSiacoins(ms, txn, ts); err != nil {
		return err
	} else if err := validateSiafunds(ms, txn, ts); err != nil {
		return err
	} else if err := validateFileContracts(ms, txn, ts); err != nil {
		return err
	} else if err := validateArbitraryData(ms, txn); err != nil {
		return err
	} else if err := validateSignatures(ms, txn); err != nil {
		return err
	}
	return nil
}

func validateV2CurrencyValues(ms *MidState, txn types.V2Transaction) error {
	// Add up all of the currency values in the transaction and check for
	// overflow. This allows us to freely add any currency values in later
	// validation functions without worrying about overflow.

	var sum types.Currency
	var overflow bool
	add := func(x types.Currency) {
		if !overflow {
			sum, overflow = sum.AddWithOverflow(x)
		}
	}
	addContract := func(fc types.V2FileContract) {
		add(fc.RenterOutput.Value)
		add(fc.HostOutput.Value)
		add(fc.MissedHostValue)
		add(fc.TotalCollateral)
		add(ms.base.V2FileContractTax(fc))
	}

	for i, sco := range txn.SiacoinOutputs {
		if sco.Value.IsZero() {
			return fmt.Errorf("siacoin output %v has zero value", i)
		}
		add(sco.Value)
	}
	for i, sfo := range txn.SiafundOutputs {
		if sfo.Value == 0 {
			return fmt.Errorf("siafund output %v has zero value", i)
		}
		overflow = overflow || sfo.Value > ms.base.SiafundCount()
	}
	for i, fc := range txn.FileContracts {
		if fc.RenterOutput.Value.IsZero() && fc.HostOutput.Value.IsZero() {
			return fmt.Errorf("file contract %v has zero value", i)
		}
		addContract(fc)
	}
	for _, fc := range txn.FileContractRevisions {
		addContract(fc.Revision)
	}
	for i, fcr := range txn.FileContractResolutions {
		switch r := fcr.Resolution.(type) {
		case *types.V2FileContractRenewal:
			if r.NewContract.RenterOutput.Value.IsZero() && r.NewContract.HostOutput.Value.IsZero() {
				return fmt.Errorf("file contract renewal %v creates contract with zero value", i)
			}
			addContract(r.NewContract)
			add(r.RenterRollover)
			add(r.HostRollover)
		case *types.V2FileContractFinalization:
			addContract(types.V2FileContract(*r))
		}
	}
	add(txn.MinerFee)
	if overflow {
		return errors.New("transaction outputs exceed inputs") // technically true
	}
	return nil
}

func validateV2Siacoins(ms *MidState, txn types.V2Transaction) error {
	sigHash := ms.base.InputSigHash(txn)
	spent := make(map[types.Hash256]int)
	for i, sci := range txn.SiacoinInputs {
		if txid, ok := ms.spent(sci.Parent.ID); ok {
			return fmt.Errorf("siacoin input %v double-spends parent output (previously spent in %v)", i, txid)
		} else if j, ok := spent[sci.Parent.ID]; ok {
			return fmt.Errorf("siacoin input %v double-spends parent output (previously spent by input %v)", i, j)
		}
		spent[sci.Parent.ID] = i

		// check accumulator
		if sci.Parent.LeafIndex == types.EphemeralLeafIndex {
			if _, ok := ms.ephemeral[sci.Parent.ID]; !ok {
				return fmt.Errorf("siacoin input %v spends nonexistent ephemeral output %v", i, sci.Parent.ID)
			}
		} else if !ms.base.Elements.containsUnspentSiacoinElement(sci.Parent) {
			if ms.base.Elements.containsSpentSiacoinElement(sci.Parent) {
				return fmt.Errorf("siacoin input %v double-spends output %v", i, sci.Parent.ID)
			}
			return fmt.Errorf("siacoin input %v spends output (%v) not present in the accumulator", i, sci.Parent.ID)
		}

		// check spend policy
		sp := sci.SatisfiedPolicy
		if sp.Policy.Address() != sci.Parent.SiacoinOutput.Address {
			return fmt.Errorf("siacoin input %v claims incorrect policy for parent address", i)
		} else if err := sp.Policy.Verify(ms.base.Index.Height, ms.base.medianTimestamp(), sigHash, sp.Signatures, sp.Preimages); err != nil {
			return fmt.Errorf("siacoin input %v failed to satisfy spend policy: %w", i, err)
		}
	}

	var inputSum, outputSum types.Currency
	for _, sci := range txn.SiacoinInputs {
		inputSum = inputSum.Add(sci.Parent.SiacoinOutput.Value)
	}
	for _, out := range txn.SiacoinOutputs {
		outputSum = outputSum.Add(out.Value)
	}
	for _, fc := range txn.FileContracts {
		outputSum = outputSum.Add(fc.RenterOutput.Value).Add(fc.HostOutput.Value).Add(ms.base.V2FileContractTax(fc))
	}
	for _, fcr := range txn.FileContractResolutions {
		if r, ok := fcr.Resolution.(*types.V2FileContractRenewal); ok {
			// a renewal creates a new contract, optionally "rolling over" funds
			// from the old contract
			inputSum = inputSum.Add(r.RenterRollover)
			inputSum = inputSum.Add(r.HostRollover)

			rev := r.NewContract
			outputSum = outputSum.Add(rev.RenterOutput.Value).Add(rev.HostOutput.Value).Add(ms.base.V2FileContractTax(rev))
		}
	}
	outputSum = outputSum.Add(txn.MinerFee)
	if inputSum != outputSum {
		return fmt.Errorf("siacoin inputs (%d H) do not equal outputs (%d H)", inputSum, outputSum)
	}

	return nil
}

func validateV2Siafunds(ms *MidState, txn types.V2Transaction) error {
	sigHash := ms.base.InputSigHash(txn)
	spent := make(map[types.Hash256]int)
	for i, sfi := range txn.SiafundInputs {
		if txid, ok := ms.spent(sfi.Parent.ID); ok {
			return fmt.Errorf("siafund input %v double-spends parent output (previously spent in %v)", i, txid)
		} else if j, ok := spent[sfi.Parent.ID]; ok {
			return fmt.Errorf("siafund input %v double-spends parent output (previously spent by input %v)", i, j)
		}
		spent[sfi.Parent.ID] = i

		// check accumulator
		if sfi.Parent.LeafIndex == types.EphemeralLeafIndex {
			if _, ok := ms.ephemeral[sfi.Parent.ID]; !ok {
				return fmt.Errorf("siafund input %v spends nonexistent ephemeral output %v", i, sfi.Parent.ID)
			}
		} else if !ms.base.Elements.containsUnspentSiafundElement(sfi.Parent) {
			if ms.base.Elements.containsSpentSiafundElement(sfi.Parent) {
				return fmt.Errorf("siafund input %v double-spends output %v", i, sfi.Parent.ID)
			}
			return fmt.Errorf("siafund input %v spends output (%v) not present in the accumulator", i, sfi.Parent.ID)
		}

		// check spend policy
		sp := sfi.SatisfiedPolicy
		if sp.Policy.Address() != sfi.Parent.SiafundOutput.Address {
			return fmt.Errorf("siafund input %v claims incorrect policy for parent address", i)
		} else if err := sp.Policy.Verify(ms.base.Index.Height, ms.base.medianTimestamp(), sigHash, sp.Signatures, sp.Preimages); err != nil {
			return fmt.Errorf("siafund input %v failed to satisfy spend policy: %w", i, err)
		}
	}

	var inputSum, outputSum uint64
	for _, in := range txn.SiafundInputs {
		inputSum += in.Parent.SiafundOutput.Value
	}
	for _, out := range txn.SiafundOutputs {
		outputSum += out.Value
	}
	if inputSum != outputSum {
		return fmt.Errorf("siafund inputs (%d SF) do not equal outputs (%d SF)", inputSum, outputSum)
	}
	return nil
}

func validateV2FileContracts(ms *MidState, txn types.V2Transaction) error {
	// Contract resolutions are height-sensitive, and thus can be invalidated by
	// shallow reorgs; to minimize disruption, we require that transactions
	// containing a resolution do not create new outputs. Creating, revising or
	// resolving contracts *is* permitted, as these effects are generally not
	// "built upon" as quickly as outputs, and therefore cause less disruption.
	if len(txn.FileContractResolutions) > 0 &&
		(len(txn.SiacoinOutputs) > 0 || len(txn.SiafundOutputs) > 0) {
		return errors.New("transaction both resolves a file contract and creates new outputs")
	}

	revised := make(map[types.Hash256]int)
	resolved := make(map[types.Hash256]int)
	validateParent := func(fce types.V2FileContractElement) error {
		if txid, ok := ms.spent(fce.ID); ok {
			return fmt.Errorf("has already been resolved in transaction %v", txid)
		} else if i, ok := revised[fce.ID]; ok {
			return fmt.Errorf("has already been revised by contract revision %v", i)
		} else if i, ok := resolved[fce.ID]; ok {
			return fmt.Errorf("has already been resolved by contract resolution %v", i)
		} else if !ms.base.Elements.containsUnresolvedV2FileContractElement(fce) {
			if ms.base.Elements.containsResolvedV2FileContractElement(fce) {
				return errors.New("has already been resolved in a previous block")
			}
			return errors.New("is not present in the accumulator")
		}
		return nil
	}

	validateSignatures := func(fc types.V2FileContract, renter, host types.PublicKey, renewal bool) error {
		if renewal {
			// The sub-contracts of a renewal must have empty signatures;
			// otherwise they would be independently valid, i.e. the atomicity
			// of the renewal could be violated. Consider a host who has lost or
			// deleted their contract data; all they have to do is wait for a
			// renter to initiate a renewal, then broadcast just the
			// finalization of the old contract, allowing them to successfully
			// resolve the contract without a storage proof.
			if fc.RenterSignature != (types.Signature{}) {
				return errors.New("has non-empty renter signature")
			} else if fc.HostSignature != (types.Signature{}) {
				return errors.New("has non-empty host signature")
			}
		} else {
			contractHash := ms.base.ContractSigHash(fc)
			if !renter.VerifyHash(contractHash, fc.RenterSignature) {
				return errors.New("has invalid renter signature")
			} else if !host.VerifyHash(contractHash, fc.HostSignature) {
				return errors.New("has invalid host signature")
			}
		}
		return nil
	}

	validateContract := func(fc types.V2FileContract, renewal bool) error {
		switch {
		case fc.ProofHeight < ms.base.childHeight():
			return fmt.Errorf("has proof height (%v) that has already passed", fc.ProofHeight)
		case fc.ExpirationHeight <= fc.ProofHeight:
			return fmt.Errorf("leaves no time between proof height (%v) and expiration height (%v)", fc.ProofHeight, fc.ExpirationHeight)
		case fc.MissedHostValue.Cmp(fc.HostOutput.Value) > 0:
			return fmt.Errorf("has missed host value (%d H) exceeding valid host value (%d H)", fc.MissedHostValue, fc.HostOutput.Value)
		case fc.TotalCollateral.Cmp(fc.HostOutput.Value) > 0:
			return fmt.Errorf("has total collateral (%d H) exceeding valid host value (%d H)", fc.TotalCollateral, fc.HostOutput.Value)
		}
		return validateSignatures(fc, fc.RenterPublicKey, fc.HostPublicKey, renewal)
	}

	validateRevision := func(cur, rev types.V2FileContract, renewal bool) error {
		curOutputSum := cur.RenterOutput.Value.Add(cur.HostOutput.Value)
		revOutputSum := rev.RenterOutput.Value.Add(rev.HostOutput.Value)
		switch {
		case rev.RevisionNumber <= cur.RevisionNumber:
			return fmt.Errorf("does not increase revision number (%v -> %v)", cur.RevisionNumber, rev.RevisionNumber)
		case !revOutputSum.Equals(curOutputSum):
			return fmt.Errorf("modifies output sum (%d H -> %d H)", curOutputSum, revOutputSum)
		case rev.TotalCollateral != cur.TotalCollateral:
			return errors.New("modifies total collateral")
		case rev.ProofHeight < ms.base.childHeight():
			return fmt.Errorf("has proof height (%v) that has already passed", rev.ProofHeight)
		case rev.ExpirationHeight <= rev.ProofHeight:
			return fmt.Errorf("leaves no time between proof height (%v) and expiration height (%v)", rev.ProofHeight, rev.ExpirationHeight)
		}
		// NOTE: very important that we verify with the *current* keys!
		return validateSignatures(rev, cur.RenterPublicKey, cur.HostPublicKey, renewal)
	}

	for i, fc := range txn.FileContracts {
		if err := validateContract(fc, false); err != nil {
			return fmt.Errorf("file contract %v %s", i, err)
		}
	}

	for i, fcr := range txn.FileContractRevisions {
		cur, rev := fcr.Parent.V2FileContract, fcr.Revision
		if err := validateParent(fcr.Parent); err != nil {
			return fmt.Errorf("file contract revision %v parent (%v) %s", i, fcr.Parent.ID, err)
		} else if cur.ProofHeight < ms.base.childHeight() {
			return fmt.Errorf("file contract revision %v cannot be applied to contract after proof height (%v)", i, cur.ProofHeight)
		} else if rev.RevisionNumber == types.MaxRevisionNumber {
			// NOTE: disallowing this means that resolutions always take
			// precedence over revisions
			return fmt.Errorf("file contract revision %v resolves contract", i)
		} else if err := validateRevision(cur, rev, false); err != nil {
			return fmt.Errorf("file contract revision %v %s", i, err)
		}
		revised[fcr.Parent.ID] = i
	}

	for i, fcr := range txn.FileContractResolutions {
		if err := validateParent(fcr.Parent); err != nil {
			return fmt.Errorf("file contract renewal %v parent (%v) %s", i, fcr.Parent.ID, err)
		}
		fc := fcr.Parent.V2FileContract
		switch r := fcr.Resolution.(type) {
		case *types.V2FileContractRenewal:
			renewal := *r
			old, renewed := renewal.FinalRevision, renewal.NewContract
			if old.RevisionNumber != types.MaxRevisionNumber {
				return fmt.Errorf("file contract renewal %v does not finalize old contract", i)
			} else if err := validateRevision(fc, old, true); err != nil {
				return fmt.Errorf("file contract renewal %v final revision %s", i, err)
			} else if err := validateContract(renewed, true); err != nil {
				return fmt.Errorf("file contract renewal %v initial revision %s", i, err)
			}

			rollover := renewal.RenterRollover.Add(renewal.HostRollover)
			newContractCost := renewed.RenterOutput.Value.Add(renewed.HostOutput.Value).Add(ms.base.V2FileContractTax(renewed))
			if renewal.RenterRollover.Cmp(old.RenterOutput.Value) > 0 {
				return fmt.Errorf("file contract renewal %v has renter rollover (%d H) exceeding old output (%d H)", i, renewal.RenterRollover, old.RenterOutput.Value)
			} else if renewal.HostRollover.Cmp(old.HostOutput.Value) > 0 {
				return fmt.Errorf("file contract renewal %v has host rollover (%d H) exceeding old output (%d H)", i, renewal.HostRollover, old.HostOutput.Value)
			} else if rollover.Cmp(newContractCost) > 0 {
				return fmt.Errorf("file contract renewal %v has rollover (%d H) exceeding new contract cost (%d H)", i, rollover, newContractCost)
			}

			renewalHash := ms.base.RenewalSigHash(renewal)
			if !fc.RenterPublicKey.VerifyHash(renewalHash, renewal.RenterSignature) {
				return fmt.Errorf("file contract renewal %v has invalid renter signature", i)
			} else if !fc.HostPublicKey.VerifyHash(renewalHash, renewal.HostSignature) {
				return fmt.Errorf("file contract renewal %v has invalid host signature", i)
			}
		case *types.V2FileContractFinalization:
			finalRevision := types.V2FileContract(*r)
			if finalRevision.RevisionNumber != types.MaxRevisionNumber {
				return fmt.Errorf("file contract finalization %v does not set maximum revision number", i)
			} else if err := validateRevision(fc, finalRevision, false); err != nil {
				return fmt.Errorf("file contract finalization %v %s", i, err)
			}
		case *types.V2StorageProof:
			sp := *r
			if ms.base.childHeight() < fc.ProofHeight {
				return fmt.Errorf("file contract storage proof %v cannot be submitted until after proof height (%v)", i, fc.ProofHeight)
			} else if sp.ProofIndex.ChainIndex.Height != fc.ProofHeight {
				// see note on this field in types.StorageProof
				return fmt.Errorf("file contract storage proof %v has ProofIndex height (%v) that does not match contract ProofHeight (%v)", i, sp.ProofIndex.ChainIndex.Height, fc.ProofHeight)
			} else if ms.base.Elements.containsChainIndex(sp.ProofIndex) {
				return fmt.Errorf("file contract storage proof %v has invalid history proof", i)
			}
			leafIndex := ms.base.StorageProofLeafIndex(fc.Filesize, sp.ProofIndex.ChainIndex.ID, types.FileContractID(fcr.Parent.ID))
			if storageProofRoot(ms.base.StorageProofLeafHash(sp.Leaf[:]), leafIndex, fc.Filesize, sp.Proof) != fc.FileMerkleRoot {
				return fmt.Errorf("file contract storage proof %v has root that does not match contract Merkle root", i)
			}
		case *types.V2FileContractExpiration:
			if ms.base.childHeight() <= fc.ExpirationHeight {
				return fmt.Errorf("file contract expiration %v cannot be submitted until after expiration height (%v) ", i, fc.ExpirationHeight)
			}
		}
		resolved[fcr.Parent.ID] = i
	}

	return nil
}

func validateAttestations(ms *MidState, txn types.V2Transaction) error {
	for i, a := range txn.Attestations {
		switch {
		case len(a.Key) == 0:
			return fmt.Errorf("attestation %v has empty key", i)
		case !a.PublicKey.VerifyHash(ms.base.AttestationSigHash(a), a.Signature):
			return fmt.Errorf("attestation %v has invalid signature", i)
		}
	}
	return nil
}

func validateFoundationUpdate(ms *MidState, txn types.V2Transaction) error {
	if txn.NewFoundationAddress == nil {
		return nil
	}
	for _, in := range txn.SiacoinInputs {
		if in.Parent.SiacoinOutput.Address == ms.base.FoundationPrimaryAddress {
			return nil
		}
	}
	return errors.New("transaction changes Foundation address, but does not spend an input controlled by current address")
}

// ValidateV2Transaction validates txn within the context of ms.
func ValidateV2Transaction(ms *MidState, txn types.V2Transaction) error {
	if ms.base.childHeight() < ms.base.Network.HardforkV2.AllowHeight {
		return errors.New("v2 transactions are not allowed until v2 hardfork begins")
	} else if err := validateV2CurrencyValues(ms, txn); err != nil {
		return err
	} else if err := validateV2Siacoins(ms, txn); err != nil {
		return err
	} else if err := validateV2Siafunds(ms, txn); err != nil {
		return err
	} else if err := validateV2FileContracts(ms, txn); err != nil {
		return err
	} else if err := validateAttestations(ms, txn); err != nil {
		return err
	} else if err := validateFoundationUpdate(ms, txn); err != nil {
		return err
	}
	return nil
}

// ValidateBlock validates b in the context of s.
//
// This function does not check whether the header's timestamp is too far in the
// future. That check should be performed at the time the block is received,
// e.g. in p2p networking code; see MaxFutureTimestamp.
func ValidateBlock(s State, b types.Block, bs V1BlockSupplement) error {
	if err := ValidateOrphan(s, b); err != nil {
		return err
	}
	if b.V2 != nil {
		if b.V2.Commitment != s.Commitment(s.TransactionsCommitment(b.Transactions, b.V2Transactions()), b.MinerPayouts[0].Address) {
			return errors.New("commitment hash mismatch")
		}
	}
	ms := NewMidState(s)
	for i, txn := range b.Transactions {
		if err := ValidateTransaction(ms, txn, bs.Transactions[i]); err != nil {
			return fmt.Errorf("transaction %v is invalid: %w", i, err)
		}
		ms.ApplyTransaction(txn, bs.Transactions[i])
	}
	for i, txn := range b.V2Transactions() {
		if err := ValidateV2Transaction(ms, txn); err != nil {
			return fmt.Errorf("v2 transaction %v is invalid: %w", i, err)
		}
		ms.ApplyV2Transaction(txn)
	}
	return nil
}
