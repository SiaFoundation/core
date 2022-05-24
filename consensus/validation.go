// Package consensus implements the Sia consensus algorithms.
package consensus

import (
	"errors"
	"fmt"
	"math/bits"
	"sort"
	"time"

	"go.sia.tech/core/merkle"
	"go.sia.tech/core/types"
)

var (
	// ErrOverweight is returned when a block's weight exceeds MaxBlockWeight.
	ErrOverweight = errors.New("block is too heavy")

	// ErrOverflow is returned when the sum of a transaction's inputs and/or
	// outputs overflows the Currency representation.
	ErrOverflow = errors.New("sum of currency values overflowed")
)

func (s State) medianTimestamp() time.Time {
	prevCopy := s.PrevTimestamps
	ts := prevCopy[:s.numTimestamps()]
	sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
	if len(ts)%2 != 0 {
		return ts[len(ts)/2]
	}
	l, r := ts[len(ts)/2-1], ts[len(ts)/2]
	return l.Add(r.Sub(l) / 2)
}

func (s State) validateHeader(h types.BlockHeader) error {
	if h.Height != s.Index.Height+1 {
		return errors.New("wrong height")
	} else if h.ParentID != s.Index.ID {
		return errors.New("wrong parent ID")
	} else if h.Timestamp.Before(s.medianTimestamp()) {
		return errors.New("timestamp is too far in the past")
	} else if h.Nonce%s.NonceFactor() != 0 {
		return errors.New("nonce is not divisible by required factor")
	} else if types.WorkRequiredForHash(h.ID()).Cmp(s.Difficulty) < 0 {
		return errors.New("insufficient work")
	}
	return nil
}

func (s State) validateCurrencyValues(txn types.Transaction) error {
	// Add up all of the currency values in the transaction and check for
	// overflow. This allows us to freely add any currency values in later
	// validation functions without worrying about overflow.
	//
	// NOTE: This check could be a little more "tolerant" -- currently it adds
	// both the input and output values to the same sum, and it double-counts
	// some value in file contracts. Even so, it won't be possible to construct
	// a valid transaction that fails this check for ~50,000 years.

	var sum types.Currency
	var sum64 uint64
	var overflowed bool
	add := func(x types.Currency) {
		if !overflowed {
			sum, overflowed = sum.AddWithOverflow(x)
		}
	}
	add64 := func(x uint64) {
		if !overflowed {
			s, carry := bits.Add64(sum64, x, 0)
			sum64, overflowed = s, carry > 0
		}
	}
	addContract := func(fc types.FileContract) {
		add(fc.RenterOutput.Value)
		add(fc.HostOutput.Value)
		add(fc.MissedHostValue)
		add(fc.TotalCollateral)
		add(s.FileContractTax(fc))
	}

	for _, in := range txn.SiacoinInputs {
		add(in.Parent.Value)
	}
	for i, out := range txn.SiacoinOutputs {
		if out.Value.IsZero() {
			return fmt.Errorf("siacoin output %v has zero value", i)
		}
		add(out.Value)
	}
	for _, in := range txn.SiafundInputs {
		add64(in.Parent.Value)
	}
	for i, out := range txn.SiafundOutputs {
		if out.Value == 0 {
			return fmt.Errorf("siafund output %v has zero value", i)
		}
		add64(out.Value)
	}
	for _, fc := range txn.FileContracts {
		addContract(fc)
	}
	for _, fc := range txn.FileContractRevisions {
		addContract(fc.Revision)
	}
	for _, fcr := range txn.FileContractResolutions {
		if fcr.HasRenewal() {
			add(fcr.Renewal.RenterRollover)
			add(fcr.Renewal.HostRollover)
			addContract(fcr.Renewal.InitialRevision)
		} else if fcr.HasFinalization() {
			addContract(fcr.Finalization)
		}
	}
	add(txn.MinerFee)
	if overflowed {
		return ErrOverflow
	}
	return nil
}

func (s State) validateTimeLocks(txn types.Transaction) error {
	blockHeight := s.Index.Height + 1
	for i, in := range txn.SiacoinInputs {
		if in.Parent.MaturityHeight > blockHeight {
			return fmt.Errorf("siacoin input %v does not mature until block %v", i, in.Parent.MaturityHeight)
		}
	}
	return nil
}

func (s State) validateContract(fc types.FileContract) error {
	switch {
	case fc.WindowEnd <= s.Index.Height:
		return fmt.Errorf("has proof window (%v-%v) that ends in the past", fc.WindowStart, fc.WindowEnd)
	case fc.WindowEnd <= fc.WindowStart:
		return fmt.Errorf("has proof window (%v-%v) that ends before it begins", fc.WindowStart, fc.WindowEnd)
	case fc.MissedHostValue.Cmp(fc.HostOutput.Value) > 0:
		return fmt.Errorf("has missed host value (%v SC) exceeding valid host value (%v SC)", fc.MissedHostValue, fc.HostOutput.Value)
	case fc.TotalCollateral.Cmp(fc.HostOutput.Value) > 0:
		return fmt.Errorf("has total collateral (%v SC) exceeding valid host value (%v SC)", fc.TotalCollateral, fc.HostOutput.Value)
	}
	contractHash := s.ContractSigHash(fc)
	if !fc.RenterPublicKey.VerifyHash(contractHash, fc.RenterSignature) {
		return fmt.Errorf("has invalid renter signature")
	} else if !fc.HostPublicKey.VerifyHash(contractHash, fc.HostSignature) {
		return fmt.Errorf("has invalid host signature")
	}
	return nil
}

func (s State) validateRevision(cur, rev types.FileContract) error {
	curOutputSum := cur.RenterOutput.Value.Add(cur.HostOutput.Value)
	revOutputSum := rev.RenterOutput.Value.Add(rev.HostOutput.Value)
	switch {
	case rev.RevisionNumber <= cur.RevisionNumber:
		return fmt.Errorf("does not increase revision number (%v -> %v)", cur.RevisionNumber, rev.RevisionNumber)
	case !revOutputSum.Equals(curOutputSum):
		return fmt.Errorf("modifies output sum (%v SC -> %v SC)", curOutputSum, revOutputSum)
	case rev.TotalCollateral != cur.TotalCollateral:
		return fmt.Errorf("modifies total collateral")
	case rev.WindowEnd <= s.Index.Height:
		return fmt.Errorf("has proof window (%v-%v) that ends in the past", rev.WindowStart, rev.WindowEnd)
	case rev.WindowEnd <= rev.WindowStart:
		return fmt.Errorf("has proof window (%v - %v) that ends before it begins", rev.WindowStart, rev.WindowEnd)
	}

	// verify signatures
	//
	// NOTE: very important that we verify with the *current* keys!
	contractHash := s.ContractSigHash(rev)
	if !cur.RenterPublicKey.VerifyHash(contractHash, rev.RenterSignature) {
		return fmt.Errorf("has invalid renter signature")
	} else if !cur.HostPublicKey.VerifyHash(contractHash, rev.HostSignature) {
		return fmt.Errorf("has invalid host signature")
	}
	return nil
}

func (s State) validateFileContracts(txn types.Transaction) error {
	for i, fc := range txn.FileContracts {
		if err := s.validateContract(fc); err != nil {
			return fmt.Errorf("file contract %v %s", i, err)
		}
	}
	return nil
}

func (s State) validateFileContractRevisions(txn types.Transaction) error {
	for i, fcr := range txn.FileContractRevisions {
		cur, rev := fcr.Parent.FileContract, fcr.Revision
		if s.Index.Height > cur.WindowStart {
			return fmt.Errorf("file contract revision %v cannot be applied to contract whose proof window (%v - %v) has already begun", i, cur.WindowStart, cur.WindowEnd)
		} else if err := s.validateRevision(cur, rev); err != nil {
			return fmt.Errorf("file contract revision %v %s", i, err)
		}
	}
	return nil
}

func (s State) validateFileContractResolutions(txn types.Transaction) error {
	for i, fcr := range txn.FileContractResolutions {
		// only one resolution type should be present
		var typs int
		for _, b := range [...]bool{
			fcr.HasRenewal(),
			fcr.HasStorageProof(),
			fcr.HasFinalization(),
		} {
			if b {
				typs++
			}
		}
		if typs > 1 {
			return fmt.Errorf("file contract resolution %v has multiple resolution types", i)
		}

		fc := fcr.Parent.FileContract
		if fcr.HasRenewal() {
			// renter and host want to renew the contract, carrying over some
			// funds and releasing the rest; this can be done at any point
			// before WindowEnd (even before WindowStart)
			old, renewed := fcr.Renewal.FinalRevision, fcr.Renewal.InitialRevision
			if fc.WindowEnd < s.Index.Height {
				return fmt.Errorf("file contract renewal %v cannot be applied to contract whose proof window (%v - %v) has expired", i, fc.WindowStart, fc.WindowEnd)
			} else if old.RevisionNumber != types.MaxRevisionNumber {
				return fmt.Errorf("file contract renewal %v does not finalize old contract", i)
			} else if err := s.validateRevision(fc, old); err != nil {
				return fmt.Errorf("file contract renewal %v has final revision that %s", i, err)
			} else if err := s.validateContract(renewed); err != nil {
				return fmt.Errorf("file contract renewal %v has initial revision that %s", i, err)
			}

			// rollover must not exceed total contract value
			rollover := fcr.Renewal.RenterRollover.Add(fcr.Renewal.HostRollover)
			newContractCost := renewed.RenterOutput.Value.Add(renewed.HostOutput.Value).Add(s.FileContractTax(renewed))
			if fcr.Renewal.RenterRollover.Cmp(old.RenterOutput.Value) > 0 {
				return fmt.Errorf("file contract renewal %v has renter rollover (%v SC) exceeding old output (%v SC)", i, fcr.Renewal.RenterRollover, old.RenterOutput.Value)
			} else if fcr.Renewal.HostRollover.Cmp(old.HostOutput.Value) > 0 {
				return fmt.Errorf("file contract renewal %v has host rollover (%v SC) exceeding old output (%v SC)", i, fcr.Renewal.HostRollover, old.HostOutput.Value)
			} else if rollover.Cmp(newContractCost) > 0 {
				return fmt.Errorf("file contract renewal %v has rollover (%v SC) exceeding new contract cost (%v SC)", i, rollover, newContractCost)
			}

			renewalHash := s.RenewalSigHash(fcr.Renewal)
			if !fc.RenterPublicKey.VerifyHash(renewalHash, fcr.Renewal.RenterSignature) {
				return fmt.Errorf("file contract renewal %v has invalid renter signature", i)
			} else if !fc.HostPublicKey.VerifyHash(renewalHash, fcr.Renewal.HostSignature) {
				return fmt.Errorf("file contract renewal %v has invalid host signature", i)
			}
		} else if fcr.HasFinalization() {
			// renter and host have agreed upon an explicit final contract
			// state; this can be done at any point before WindowEnd (even
			// before WindowStart)
			if fc.WindowEnd < s.Index.Height {
				return fmt.Errorf("file contract finalization %v cannot be applied to contract whose proof window (%v - %v) has expired", i, fc.WindowStart, fc.WindowEnd)
			} else if fcr.Finalization.RevisionNumber != types.MaxRevisionNumber {
				return fmt.Errorf("file contract finalization %v does not set maximum revision number", i)
			} else if err := s.validateRevision(fc, fcr.Finalization); err != nil {
				return fmt.Errorf("file contract finalization %v %s", i, err)
			}
		} else if fcr.HasStorageProof() {
			// we must be within the proof window
			if s.Index.Height < fc.WindowStart || fc.WindowEnd < s.Index.Height {
				return fmt.Errorf("storage proof %v attempts to claim valid outputs outside the proof window (%v - %v)", i, fc.WindowStart, fc.WindowEnd)
			} else if fcr.StorageProof.WindowStart.Height != fc.WindowStart {
				// see note on this field in types.StorageProof
				return fmt.Errorf("storage proof %v has WindowStart (%v) that does not match contract WindowStart (%v)", i, fcr.StorageProof.WindowStart.Height, fc.WindowStart)
			}
			leafIndex := s.StorageProofLeafIndex(fc.Filesize, fcr.StorageProof.WindowStart, fcr.Parent.ID)
			if merkle.StorageProofRoot(fcr.StorageProof, leafIndex) != fc.FileMerkleRoot {
				return fmt.Errorf("storage proof %v has root that does not match contract Merkle root", i)
			}
		} else if fc.Filesize == 0 {
			// empty contract; can claim valid outputs after WindowStart
			if s.Index.Height < fc.WindowStart {
				return fmt.Errorf("file contract expiration %v attempts to claim valid outputs, but proof window (%v - %v) has not begun", i, fc.WindowStart, fc.WindowEnd)
			}
		} else {
			// non-empty contract; can claim missed outputs after WindowEnd
			if s.Index.Height <= fc.WindowEnd {
				return fmt.Errorf("file contract expiration %v attempts to claim missed outputs, but proof window (%v - %v) has not expired", i, fc.WindowStart, fc.WindowEnd)
			}
		}
	}
	return nil
}

func (s State) validateAttestations(txn types.Transaction) error {
	for i, a := range txn.Attestations {
		switch {
		case len(a.Key) == 0:
			return fmt.Errorf("attestation %v has empty key", i)
		case !a.PublicKey.VerifyHash(s.AttestationSigHash(a), a.Signature):
			return fmt.Errorf("attestation %v has invalid signature", i)
		}
	}
	return nil
}

func (s State) outputsEqualInputs(txn types.Transaction) error {
	var inputSC, outputSC types.Currency
	for _, in := range txn.SiacoinInputs {
		inputSC = inputSC.Add(in.Parent.Value)
	}
	for _, out := range txn.SiacoinOutputs {
		outputSC = outputSC.Add(out.Value)
	}
	for _, fc := range txn.FileContracts {
		outputSC = outputSC.Add(fc.RenterOutput.Value).Add(fc.HostOutput.Value).Add(s.FileContractTax(fc))
	}
	for _, fcr := range txn.FileContractResolutions {
		if fcr.HasRenewal() {
			// a renewal creates a new contract, optionally "rolling over" funds
			// from the old contract
			inputSC = inputSC.Add(fcr.Renewal.RenterRollover)
			inputSC = inputSC.Add(fcr.Renewal.HostRollover)

			rev := fcr.Renewal.InitialRevision
			outputSC = outputSC.Add(rev.RenterOutput.Value).Add(rev.HostOutput.Value).Add(s.FileContractTax(rev))
		}
	}

	outputSC = outputSC.Add(txn.MinerFee)
	if inputSC != outputSC {
		return fmt.Errorf("siacoin inputs (%v SC) do not equal siacoin outputs (%v SC)", inputSC, outputSC)
	}

	var inputSF, outputSF uint64
	for _, in := range txn.SiafundInputs {
		inputSF += in.Parent.Value
	}
	for _, out := range txn.SiafundOutputs {
		outputSF += out.Value
	}
	if inputSF != outputSF {
		return fmt.Errorf("siafund inputs (%d SF) do not equal siafund outputs (%d SF)", inputSF, outputSF)
	}

	return nil
}

func (s State) validateStateProofs(txn types.Transaction) error {
	for i, in := range txn.SiacoinInputs {
		switch {
		case in.Parent.LeafIndex == types.EphemeralLeafIndex:
			continue
		case s.Elements.ContainsUnspentSiacoinElement(in.Parent):
			continue
		case s.Elements.ContainsSpentSiacoinElement(in.Parent):
			return fmt.Errorf("siacoin input %v double-spends output %v", i, in.Parent.ID)
		default:
			return fmt.Errorf("siacoin input %v spends output (%v) not present in the accumulator", i, in.Parent.ID)
		}
	}
	for i, in := range txn.SiafundInputs {
		switch {
		case s.Elements.ContainsUnspentSiafundElement(in.Parent):
			continue
		case s.Elements.ContainsSpentSiafundElement(in.Parent):
			return fmt.Errorf("siafund input %v double-spends output %v", i, in.Parent.ID)
		default:
			return fmt.Errorf("siafund input %v spends output (%v) not present in the accumulator", i, in.Parent.ID)
		}
	}
	for i, fcr := range txn.FileContractRevisions {
		switch {
		case s.Elements.ContainsUnresolvedFileContractElement(fcr.Parent):
			continue
		case s.Elements.ContainsResolvedFileContractElement(fcr.Parent):
			return fmt.Errorf("file contract revision %v revises a contract (%v) that has already resolved", i, fcr.Parent.ID)
		default:
			return fmt.Errorf("file contract revision %v revises a contract (%v) not present in the accumulator", i, fcr.Parent.ID)
		}
	}
	for i, fcr := range txn.FileContractResolutions {
		switch {
		case s.Elements.ContainsUnresolvedFileContractElement(fcr.Parent):
			continue
		case s.Elements.ContainsResolvedFileContractElement(fcr.Parent):
			return fmt.Errorf("file contract resolution %v resolves a contract (%v) that has already resolved", i, fcr.Parent.ID)
		default:
			return fmt.Errorf("file contract resolution %v resolves a contract (%v) not present in the accumulator", i, fcr.Parent.ID)
		}
	}
	return nil
}

func (s State) validateHistoryProofs(txn types.Transaction) error {
	for i, fcr := range txn.FileContractResolutions {
		if fcr.HasStorageProof() && !s.History.Contains(fcr.StorageProof.WindowStart, fcr.StorageProof.WindowProof) {
			return fmt.Errorf("file contract resolution %v has storage proof with invalid history proof", i)
		}
	}
	return nil
}

func (s State) validateFoundationUpdate(txn types.Transaction) error {
	if txn.NewFoundationAddress == types.VoidAddress {
		return nil
	}
	for _, in := range txn.SiacoinInputs {
		if in.Parent.Address == s.FoundationAddress {
			return nil
		}
	}
	return errors.New("transaction changes Foundation address, but does not spend an input controlled by current address")
}

func (s State) validateSpendPolicies(txn types.Transaction) error {
	sigHash := s.InputSigHash(txn)
	verifyPolicy := func(p types.SpendPolicy, sigs []types.Signature) error {
		var verify func(types.SpendPolicy) error
		verify = func(p types.SpendPolicy) error {
			switch p := p.Type.(type) {
			case types.PolicyTypeAbove:
				if s.Index.Height > uint64(p) {
					return nil
				}
				return fmt.Errorf("height not above %v", uint64(p))
			case types.PolicyTypePublicKey:
				for i := range sigs {
					if types.PublicKey(p).VerifyHash(sigHash, sigs[i]) {
						sigs = sigs[i+1:]
						return nil
					}
				}
				return errors.New("no signatures matching pubkey")
			case types.PolicyTypeThreshold:
				for i := 0; i < len(p.Of) && p.N > 0 && len(p.Of[i:]) >= int(p.N); i++ {
					if verify(p.Of[i]) == nil {
						p.N--
					}
				}
				if p.N != 0 {
					return errors.New("threshold not reached")
				}
				return nil
			case types.PolicyTypeUnlockConditions:
				if err := verify(types.PolicyAbove(p.Timelock)); err != nil {
					return err
				}
				n := p.SignaturesRequired
				of := make([]types.SpendPolicy, len(p.PublicKeys))
				for i, pk := range p.PublicKeys {
					of[i] = types.PolicyPublicKey(pk)
				}
				return verify(types.PolicyThreshold(n, of))
			}
			panic("invalid policy type") // developer error
		}
		return verify(p)
	}

	for i, in := range txn.SiacoinInputs {
		if in.SpendPolicy.Address() != in.Parent.Address {
			return fmt.Errorf("siacoin input %v claims incorrect policy for parent address", i)
		} else if err := verifyPolicy(in.SpendPolicy, in.Signatures); err != nil {
			return fmt.Errorf("siacoin input %v failed to satisfy spend policy: %w", i, err)
		}
	}
	for i, in := range txn.SiafundInputs {
		if in.SpendPolicy.Address() != in.Parent.Address {
			return fmt.Errorf("siafund input %v claims incorrect policy for parent address", i)
		} else if err := verifyPolicy(in.SpendPolicy, in.Signatures); err != nil {
			return fmt.Errorf("siafund input %v failed to satisfy spend policy: %w", i, err)
		}
	}
	return nil
}

// ValidateTransaction partially validates txn for inclusion in a child block.
// It does not validate ephemeral outputs.
func (s State) ValidateTransaction(txn types.Transaction) error {
	// check proofs first; that way, subsequent checks can assume that all
	// parent StateElements are valid
	if err := s.validateStateProofs(txn); err != nil {
		return err
	} else if err := s.validateHistoryProofs(txn); err != nil {
		return err
	}

	if err := s.validateCurrencyValues(txn); err != nil {
		return err
	} else if err := s.validateTimeLocks(txn); err != nil {
		return err
	} else if err := s.outputsEqualInputs(txn); err != nil {
		return err
	} else if err := s.validateFoundationUpdate(txn); err != nil {
		return err
	} else if err := s.validateFileContracts(txn); err != nil {
		return err
	} else if err := s.validateFileContractRevisions(txn); err != nil {
		return err
	} else if err := s.validateFileContractResolutions(txn); err != nil {
		return err
	} else if err := s.validateAttestations(txn); err != nil {
		return err
	} else if err := s.validateSpendPolicies(txn); err != nil {
		return err
	}
	return nil
}

func (s State) validateEphemeralOutputs(txns []types.Transaction) error {
	// skip this check if no ephemeral outputs are present
	for _, txn := range txns {
		for _, in := range txn.SiacoinInputs {
			if in.Parent.LeafIndex == types.EphemeralLeafIndex {
				goto validate
			}
		}
	}
	return nil

validate:
	available := make(map[types.ElementID]types.SiacoinOutput)
	for txnIndex, txn := range txns {
		txid := txn.ID()
		var index uint64
		nextID := func() types.ElementID {
			id := types.ElementID{
				Source: types.Hash256(txid),
				Index:  index,
			}
			index++
			return id
		}

		for _, in := range txn.SiacoinInputs {
			if in.Parent.LeafIndex == types.EphemeralLeafIndex {
				if out, ok := available[in.Parent.ID]; !ok {
					return fmt.Errorf("transaction set is invalid: transaction %v claims non-existent ephemeral output %v", txnIndex, in.Parent.ID)
				} else if in.Parent.Value != out.Value {
					return fmt.Errorf("transaction set is invalid: transaction %v claims wrong value for ephemeral output %v", txnIndex, in.Parent.ID)
				} else if in.Parent.Address != out.Address {
					return fmt.Errorf("transaction set is invalid: transaction %v claims wrong address for ephemeral output %v", txnIndex, in.Parent.ID)
				}
				delete(available, in.Parent.ID)
			}
		}
		for _, out := range txn.SiacoinOutputs {
			available[nextID()] = out
		}
	}
	return nil
}

func (s State) noDoubleSpends(txns []types.Transaction) error {
	spent := make(map[types.ElementID]int)
	for i, txn := range txns {
		for _, in := range txn.SiacoinInputs {
			if prev, ok := spent[in.Parent.ID]; ok {
				return fmt.Errorf("transaction set is invalid: transaction %v double-spends siacoin output %v (previously spent in transaction %v)", i, in.Parent.ID, prev)
			}
			spent[in.Parent.ID] = i
		}
		for prev, in := range txn.SiafundInputs {
			if _, ok := spent[in.Parent.ID]; ok {
				return fmt.Errorf("transaction set is invalid: transaction %v double-spends siafund output %v (previously spent in transaction %v)", i, in.Parent.ID, prev)
			}
			spent[in.Parent.ID] = i
		}
	}
	return nil
}

func (s State) noDoubleContractUpdates(txns []types.Transaction) error {
	updated := make(map[types.ElementID]int)
	for i, txn := range txns {
		for _, in := range txn.FileContractRevisions {
			if prev, ok := updated[in.Parent.ID]; ok {
				return fmt.Errorf("transaction set is invalid: transaction %v updates contract %v multiple times (previously updated in transaction %v)", i, in.Parent.ID, prev)
			}
			updated[in.Parent.ID] = i
		}
		for _, in := range txn.FileContractResolutions {
			if prev, ok := updated[in.Parent.ID]; ok {
				return fmt.Errorf("transaction set is invalid: transaction %v updates contract %v multiple times (previously updated in transaction %v)", i, in.Parent.ID, prev)
			}
			updated[in.Parent.ID] = i
		}
	}
	return nil
}

// ValidateTransactionSet validates txns within the context of s.
func (s State) ValidateTransactionSet(txns []types.Transaction) error {
	if s.BlockWeight(txns) > s.MaxBlockWeight() {
		return ErrOverweight
	} else if err := s.validateEphemeralOutputs(txns); err != nil {
		return err
	} else if err := s.noDoubleSpends(txns); err != nil {
		return err
	} else if err := s.noDoubleContractUpdates(txns); err != nil {
		return err
	}
	for i, txn := range txns {
		if err := s.ValidateTransaction(txn); err != nil {
			return fmt.Errorf("transaction %v is invalid: %w", i, err)
		}
	}
	return nil
}

// ValidateBlock validates b in the context of s.
//
// This function does not check whether the header's timestamp is too far in the
// future. This check should be performed at the time the block is received,
// e.g. in p2p networking code; see MaxFutureTimestamp.
func (s State) ValidateBlock(b types.Block) error {
	h := b.Header
	if err := s.validateHeader(h); err != nil {
		return err
	} else if s.Commitment(h.MinerAddress, b.Transactions) != h.Commitment {
		return errors.New("commitment hash does not match header")
	} else if err := s.ValidateTransactionSet(b.Transactions); err != nil {
		return err
	}
	return nil
}

// MaxFutureTimestamp returns the maximum allowed timestamp for a block.
func (s State) MaxFutureTimestamp(currentTime time.Time) time.Time {
	return currentTime.Add(2 * time.Hour)
}
