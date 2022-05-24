package consensus

import (
	"math"
	"testing"
	"time"

	"go.sia.tech/core/types"

	"lukechampine.com/frand"
)

// copied from chainutil (can't import due to cycle)
func findBlockNonce(sc State, h *types.BlockHeader, target types.BlockID) {
	h.Nonce = frand.Uint64n(math.MaxUint32) * sc.NonceFactor()
	for !h.ID().MeetsTarget(target) {
		h.Nonce += sc.NonceFactor()
	}
}

func mineBlock(s State, parent types.Block, txns ...types.Transaction) types.Block {
	b := types.Block{
		Header: types.BlockHeader{
			Height:    parent.Header.Height + 1,
			ParentID:  parent.Header.ID(),
			Timestamp: parent.Header.Timestamp.Add(time.Second),
		},
		Transactions: txns,
	}
	b.Header.Commitment = s.Commitment(b.Header.MinerAddress, b.Transactions)
	findBlockNonce(s, &b.Header, types.HashRequiringWork(s.Difficulty))
	return b
}

func TestScratchChain(t *testing.T) {
	pubkey, privkey := testingKeypair(0)
	ourAddr := types.StandardAddress(pubkey)

	b := genesisWithSiacoinOutputs([]types.SiacoinOutput{
		{Value: types.Siacoins(1), Address: ourAddr},
		{Value: types.Siacoins(2), Address: ourAddr},
		{Value: types.Siacoins(3), Address: ourAddr},
		{Value: types.Siacoins(4), Address: ourAddr},
		{Value: types.Siacoins(5), Address: ourAddr},
		{Value: types.Siacoins(6), Address: ourAddr},
		{Value: types.Siacoins(7), Address: ourAddr},
		{Value: types.Siacoins(8), Address: ourAddr},
		{Value: types.Siacoins(9), Address: ourAddr},
		{Value: types.Siacoins(10), Address: ourAddr},
		{Value: types.Siacoins(11), Address: ourAddr},
		{Value: types.Siacoins(12), Address: ourAddr},
		{Value: types.Siacoins(13), Address: ourAddr},
	}...)
	sau := GenesisUpdate(b, testingDifficulty)

	sc := NewScratchChain(sau.State)
	if sc.Base() != sau.State.Index {
		t.Fatal("wrong base:", sc.Base())
	} else if sc.Tip() != sau.State.Index {
		t.Fatal("wrong tip:", sc.Tip())
	} else if sc.UnvalidatedBase() != sau.State.Index {
		t.Fatal("wrong unvalidated base:", sc.UnvalidatedBase())
	}
	var blocks []types.Block
	origOutputs := sau.NewSiacoinElements
	toSpend := origOutputs[5:10]
	var spendTotal types.Currency
	for _, o := range toSpend {
		spendTotal = spendTotal.Add(o.Value)
	}
	txn := types.Transaction{
		SiacoinOutputs: []types.SiacoinOutput{{
			Value:   spendTotal.Sub(types.Siacoins(1)),
			Address: ourAddr,
		}},
		MinerFee: types.Siacoins(1),
	}
	for _, o := range toSpend {
		txn.SiacoinInputs = append(txn.SiacoinInputs, types.SiacoinInput{
			Parent:      o,
			SpendPolicy: types.PolicyPublicKey(pubkey),
		})
	}
	signAllInputs(&txn, sau.State, privkey)

	b = mineBlock(sau.State, b, txn)
	if sc.Contains(b.Index()) {
		t.Fatal("scratch chain should not contain the header yet")
	} else if _, err := sc.ApplyBlock(b); err == nil {
		t.Fatal("shouldn't be able to apply a block without a corresponding header")
	} else if err := sc.AppendHeader(b.Header); err != nil {
		t.Fatal(err)
	} else if sc.Tip() != b.Index() {
		t.Fatal("wrong tip:", sc.Tip())
	} else if sc.UnvalidatedBase() != sc.Base() {
		t.Fatal("wrong unvalidated base:", sc.UnvalidatedBase())
	} else if !sc.Contains(b.Index()) {
		t.Fatal("scratch chain should contain the header")
	} else if sc.TotalWork() != testingDifficulty {
		t.Fatal("wrong total work:", sc.TotalWork())
	}
	blocks = append(blocks, b)

	sau = ApplyBlock(sau.State, b)
	sau.UpdateElementProof(&origOutputs[2].StateElement)
	newOutputs := sau.NewSiacoinElements

	txn = types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			Parent:      newOutputs[1],
			SpendPolicy: types.PolicyPublicKey(pubkey),
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Value:   newOutputs[1].Value.Sub(types.Siacoins(1)),
			Address: ourAddr,
		}},
		MinerFee: types.Siacoins(1),
	}
	signAllInputs(&txn, sau.State, privkey)

	b = mineBlock(sau.State, b, txn)
	if err := sc.AppendHeader(b.Header); err != nil {
		t.Fatal(err)
	}
	blocks = append(blocks, b)
	sau = ApplyBlock(sau.State, b)
	for i := range origOutputs {
		sau.UpdateElementProof(&origOutputs[i].StateElement)
	}
	toSpend = origOutputs[2:3]
	spendTotal = types.ZeroCurrency
	for _, o := range toSpend {
		spendTotal = spendTotal.Add(o.Value)
	}
	parentTxn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			Parent:      toSpend[0],
			SpendPolicy: types.PolicyPublicKey(pubkey),
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Value:   spendTotal,
			Address: ourAddr,
		}},
	}
	signAllInputs(&parentTxn, sau.State, privkey)
	childTxn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			Parent: types.SiacoinElement{
				StateElement: types.StateElement{
					ID: types.ElementID{
						Source: types.Hash256(parentTxn.ID()),
						Index:  0,
					},
					LeafIndex: types.EphemeralLeafIndex,
				},
				SiacoinOutput: types.SiacoinOutput{
					Value:   spendTotal,
					Address: ourAddr,
				},
			},
			SpendPolicy: types.PolicyPublicKey(pubkey),
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Value:   spendTotal.Sub(types.Siacoins(1)),
			Address: ourAddr,
		}},
		MinerFee: types.Siacoins(1),
	}
	signAllInputs(&childTxn, sau.State, privkey)

	b = mineBlock(sau.State, b, parentTxn, childTxn)
	if err := sc.AppendHeader(b.Header); err != nil {
		t.Fatal(err)
	}
	blocks = append(blocks, b)

	// should have one unvalidated header for each block
	if sc.FullyValidated() {
		t.Fatal("scratch chain should not be fully validated yet")
	} else if len(sc.Unvalidated()) != len(blocks) {
		t.Fatal("unvalidated headers not equal to blocks")
	}
	for i, index := range sc.Unvalidated() {
		if index != blocks[i].Index() {
			t.Fatal("unvalidated header not equal to block")
		} else if sc.Index(index.Height) != index {
			t.Fatal("inconsistent index:", sc.Index(index.Height), index)
		}
	}

	// validate all blocks
	for _, b := range blocks {
		if _, err := sc.ApplyBlock(b); err != nil {
			t.Fatal(err)
		} else if sc.ValidTip() != b.Index() {
			t.Fatal("wrong valid tip:", sc.ValidTip())
		} else if len(sc.Unvalidated()) > 0 && sc.UnvalidatedBase() != sc.Index(b.Header.Height+1) {
			t.Fatal("wrong unvalidated base:", sc.UnvalidatedBase())
		}
	}
	if !sc.FullyValidated() {
		t.Fatal("scratch chain should be fully validated")
	} else if len(sc.Unvalidated()) != 0 {
		t.Fatal("scratch chain should not have any unvalidated headers")
	}
}

func TestScratchChainDifficultyAdjustment(t *testing.T) {
	b := genesisWithSiacoinOutputs()
	s := GenesisUpdate(b, testingDifficulty).State

	// mine a block, triggering adjustment
	sc := NewScratchChain(s)
	b = mineBlock(s, b)
	if err := sc.AppendHeader(b.Header); err != nil {
		t.Fatal(err)
	} else if _, err := sc.ApplyBlock(b); err != nil {
		t.Fatal(err)
	}
	s = ApplyBlock(s, b).State

	// difficulty should have changed
	currentDifficulty := sc.ts.Difficulty
	if currentDifficulty.Cmp(testingDifficulty) <= 0 {
		t.Fatal("difficulty should have increased")
	}

	// mine a block with less than the minimum work; it should be rejected
	b = mineBlock(s, b)
	for types.WorkRequiredForHash(b.ID()).Cmp(currentDifficulty) >= 0 {
		b.Header.Nonce = frand.Uint64n(math.MaxUint32) * s.NonceFactor()
	}
	if err := sc.AppendHeader(b.Header); err == nil {
		t.Fatal("expected block to be rejected")
	}

	// mine at actual difficulty
	findBlockNonce(s, &b.Header, types.HashRequiringWork(s.Difficulty))
	if err := sc.AppendHeader(b.Header); err != nil {
		t.Fatal(err)
	} else if _, err := sc.ApplyBlock(b); err != nil {
		t.Fatal(err)
	}
	s = ApplyBlock(s, b).State
}
