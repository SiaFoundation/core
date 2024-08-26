package consensus

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"go.sia.tech/core/types"
)

func checkApplyUpdate(t *testing.T, cs State, au ApplyUpdate) {
	t.Helper()

	ms := au.ms
	for _, sce := range ms.sces {
		if !cs.Elements.containsLeaf(siacoinLeaf(&sce, ms.isSpent(sce.ID))) {
			t.Fatal("consensus: siacoin element not found in accumulator after apply")
		}
	}
	for _, sfe := range ms.sfes {
		if !cs.Elements.containsLeaf(siafundLeaf(&sfe, ms.isSpent(sfe.ID))) {
			t.Fatal("consensus: siafund element not found in accumulator after apply")
		}
	}
	for _, fce := range ms.fces {
		if !cs.Elements.containsLeaf(fileContractLeaf(&fce, ms.isSpent(fce.ID))) {
			t.Fatal("consensus: file contract element leaf not found in accumulator after apply")
		}
	}
	for _, fce := range ms.v2fces {
		leaf := v2FileContractLeaf(&fce, ms.isSpent(fce.ID))
		if r, ok := ms.v2revs[fce.ID]; ok {
			leaf = v2FileContractLeaf(r, ms.isSpent(fce.ID))
		}

		if !cs.Elements.containsLeaf(leaf) {
			t.Fatal("consensus: v2 file contract element leaf not found in accumulator after apply")
		}
	}
	for _, ae := range ms.aes {
		if !cs.Elements.containsLeaf(attestationLeaf(&ae)) {
			t.Fatal("consensus: attestation element leaf not found in accumulator after apply")
		}
	}
}

func checkRevertUpdate(t *testing.T, cs State, ru RevertUpdate) {
	t.Helper()

	ms := ru.ms
	for _, sce := range ms.sces {
		if cs.Elements.containsLeaf(siacoinLeaf(&sce, ms.isSpent(sce.ID))) {
			t.Fatal("consensus: siacoin element found in accumulator after revert")
		}
	}
	for _, sfe := range ms.sfes {
		if cs.Elements.containsLeaf(siafundLeaf(&sfe, ms.isSpent(sfe.ID))) {
			t.Fatal("consensus: siafund element found in accumulator after revert")
		}
	}
	for _, fce := range ms.fces {
		if cs.Elements.containsLeaf(fileContractLeaf(&fce, ms.isSpent(fce.ID))) {
			t.Fatal("consensus: file contract element leaf found in accumulator after revert")
		}
	}
	for _, fce := range ms.v2fces {
		leaf := v2FileContractLeaf(&fce, ms.isSpent(fce.ID))
		if r, ok := ms.v2revs[fce.ID]; ok {
			leaf = v2FileContractLeaf(r, ms.isSpent(fce.ID))
		}

		if cs.Elements.containsLeaf(leaf) {
			t.Fatal("consensus: v2 file contract element leaf found in accumulator after revert")
		}
	}
	for _, ae := range ms.aes {
		if cs.Elements.containsLeaf(attestationLeaf(&ae)) {
			t.Fatal("consensus: attestation element leaf found in accumulator after revert")
		}
	}
}

func TestApplyBlock(t *testing.T) {
	n, genesisBlock := testnet()

	giftPrivateKey := types.GeneratePrivateKey()
	giftPublicKey := giftPrivateKey.PublicKey()
	giftAddress := types.StandardUnlockHash(giftPublicKey)
	giftAmountSC := types.Siacoins(100)
	giftAmountSF := uint64(100)
	giftTxn := types.Transaction{
		SiacoinOutputs: []types.SiacoinOutput{
			{Address: giftAddress, Value: giftAmountSC},
		},
		SiafundOutputs: []types.SiafundOutput{
			{Address: giftAddress, Value: giftAmountSF},
		},
	}
	genesisBlock.Transactions = []types.Transaction{giftTxn}
	db, cs := newConsensusDB(n, genesisBlock)

	signTxn := func(txn *types.Transaction) {
		appendSig := func(parentID types.Hash256) {
			sig := giftPrivateKey.SignHash(cs.WholeSigHash(*txn, parentID, 0, 0, nil))
			txn.Signatures = append(txn.Signatures, types.TransactionSignature{
				ParentID:       parentID,
				CoveredFields:  types.CoveredFields{WholeTransaction: true},
				PublicKeyIndex: 0,
				Signature:      sig[:],
			})
		}
		for i := range txn.SiacoinInputs {
			appendSig(types.Hash256(txn.SiacoinInputs[i].ParentID))
		}
		for i := range txn.SiafundInputs {
			appendSig(types.Hash256(txn.SiafundInputs[i].ParentID))
		}
		for i := range txn.FileContractRevisions {
			appendSig(types.Hash256(txn.FileContractRevisions[i].ParentID))
		}
	}
	addBlock := func(b *types.Block) (au ApplyUpdate, err error) {
		bs := db.supplementTipBlock(*b)
		findBlockNonce(cs, b)
		if err = ValidateBlock(cs, *b, bs); err != nil {
			return
		}
		cs, au = ApplyBlock(cs, *b, bs, db.ancestorTimestamp(b.ParentID))
		// test update marshalling while we're at it
		{
			js, _ := au.MarshalJSON()
			var au2 ApplyUpdate
			if err = au2.UnmarshalJSON(js); err != nil {
				panic(err)
			}
			au = au2
		}
		db.applyBlock(au)
		return
	}
	checkUpdateElements := func(au ApplyUpdate, addedSCEs, spentSCEs []types.SiacoinElement, addedSFEs, spentSFEs []types.SiafundElement) {
		au.ForEachSiacoinElement(func(sce types.SiacoinElement, created, spent bool) {
			sces := &addedSCEs
			if spent {
				sces = &spentSCEs
			}
			if len(*sces) == 0 {
				t.Fatal("unexpected spent siacoin element")
			}
			sce.StateElement = types.StateElement{}
			if !reflect.DeepEqual(sce, (*sces)[0]) {
				t.Fatalf("siacoin element doesn't match:\n%v\nvs\n%v\n", sce, (*sces)[0])
			}
			*sces = (*sces)[1:]
		})
		au.ForEachSiafundElement(func(sfe types.SiafundElement, created, spent bool) {
			sfes := &addedSFEs
			if spent {
				sfes = &spentSFEs
			}
			if len(*sfes) == 0 {
				t.Fatal("unexpected spent siafund element")
			}
			sfe.StateElement = types.StateElement{}
			if !reflect.DeepEqual(sfe, (*sfes)[0]) {
				t.Fatalf("siafund element doesn't match:\n%v\nvs\n%v\n", sfe, (*sfes)[0])
			}
			*sfes = (*sfes)[1:]
		})
		if len(addedSCEs)+len(spentSCEs)+len(addedSFEs)+len(spentSFEs) > 0 {
			t.Fatal("extraneous elements")
		}
	}
	checkRevertElements := func(ru RevertUpdate, addedSCEs, spentSCEs []types.SiacoinElement, addedSFEs, spentSFEs []types.SiafundElement) {
		ru.ForEachSiacoinElement(func(sce types.SiacoinElement, created, spent bool) {
			sces := &addedSCEs
			if spent {
				sces = &spentSCEs
			}
			if len(*sces) == 0 {
				t.Fatal("unexpected spent siacoin element")
			}
			sce.StateElement = types.StateElement{}
			if !reflect.DeepEqual(sce, (*sces)[len(*sces)-1]) {
				t.Fatalf("siacoin element doesn't match:\n%v\nvs\n%v\n", sce, (*sces)[len(*sces)-1])
			}
			*sces = (*sces)[:len(*sces)-1]
		})
		ru.ForEachSiafundElement(func(sfe types.SiafundElement, created, spent bool) {
			sfes := &addedSFEs
			if spent {
				sfes = &spentSFEs
			}
			if len(*sfes) == 0 {
				t.Fatal("unexpected spent siafund element")
			}
			sfe.StateElement = types.StateElement{}
			if !reflect.DeepEqual(sfe, (*sfes)[len(*sfes)-1]) {
				t.Fatalf("siafund element doesn't match:\n%v\nvs\n%v\n", sfe, (*sfes)[len(*sfes)-1])
			}
			*sfes = (*sfes)[:len(*sfes)-1]
		})
		if len(addedSCEs)+len(spentSCEs)+len(addedSFEs)+len(spentSFEs) > 0 {
			t.Fatal("extraneous elements")
		}
	}

	// block with nothing except block reward
	b1 := types.Block{
		ParentID:     genesisBlock.ID(),
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.SiacoinOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
	}
	addedSCEs := []types.SiacoinElement{
		{SiacoinOutput: b1.MinerPayouts[0], MaturityHeight: cs.MaturityHeight()},
	}
	spentSCEs := []types.SiacoinElement{}
	addedSFEs := []types.SiafundElement{}
	spentSFEs := []types.SiafundElement{}
	if au, err := addBlock(&b1); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(au, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
	}

	// block that spends part of the gift transaction
	txnB2 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         giftTxn.SiacoinOutputID(0),
			UnlockConditions: types.StandardUnlockConditions(giftPublicKey),
		}},
		SiafundInputs: []types.SiafundInput{{
			ParentID:         giftTxn.SiafundOutputID(0),
			ClaimAddress:     types.VoidAddress,
			UnlockConditions: types.StandardUnlockConditions(giftPublicKey),
		}},
		SiacoinOutputs: []types.SiacoinOutput{
			{Value: giftAmountSC.Div64(2), Address: giftAddress},
			{Value: giftAmountSC.Div64(2), Address: types.VoidAddress},
		},
		SiafundOutputs: []types.SiafundOutput{
			{Value: giftAmountSF / 2, Address: giftAddress},
			{Value: giftAmountSF / 2, Address: types.VoidAddress},
		},
	}
	signTxn(&txnB2)
	b2 := types.Block{
		ParentID:     b1.ID(),
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.SiacoinOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
		Transactions: []types.Transaction{txnB2},
	}
	addedSCEs = []types.SiacoinElement{
		{SiacoinOutput: txnB2.SiacoinOutputs[0]},
		{SiacoinOutput: txnB2.SiacoinOutputs[1]},
		{SiacoinOutput: types.SiacoinOutput{Value: types.ZeroCurrency, Address: txnB2.SiafundInputs[0].ClaimAddress}, MaturityHeight: cs.MaturityHeight()},
		{SiacoinOutput: b2.MinerPayouts[0], MaturityHeight: cs.MaturityHeight()},
	}
	spentSCEs = []types.SiacoinElement{
		{SiacoinOutput: giftTxn.SiacoinOutputs[0]},
	}
	addedSFEs = []types.SiafundElement{
		{SiafundOutput: txnB2.SiafundOutputs[0]},
		{SiafundOutput: txnB2.SiafundOutputs[1]},
	}
	spentSFEs = []types.SiafundElement{
		{SiafundOutput: giftTxn.SiafundOutputs[0]},
	}

	prev := cs
	bs := db.supplementTipBlock(b2)
	if au, err := addBlock(&b2); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(au, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
	}

	ru := RevertBlock(prev, b2, bs)
	// test update marshalling while we're at it
	{
		js, _ := ru.MarshalJSON()
		var ru2 RevertUpdate
		if err := ru2.UnmarshalJSON(js); err != nil {
			panic(err)
		}
		ru = ru2
	}

	checkRevertElements(ru, addedSCEs, spentSCEs, addedSFEs, spentSFEs)

	// reverting a non-child block should trigger a panic
	func() {
		defer func() { recover() }()
		RevertBlock(cs, b2, bs)
		t.Error("did not panic on reverting non-child block")
	}()
}

func TestWorkEncoding(t *testing.T) {
	for _, test := range []struct {
		val       string
		err       bool
		roundtrip string
	}{
		{val: "0"},
		{val: "12345"},
		{val: "115792089237316195423570985008687907853269984665640564039457584007913129639935"}, // 1<<256 - 1
		{val: "01", roundtrip: "1"},
		{val: "-0", roundtrip: "0"},
		{err: true, val: ""},
		{err: true, val: "-1"},
		{err: true, val: " 1"},
		{err: true, val: "1 "},
		{err: true, val: "1157920892373161954235709850086879078532699846656405640394575840079131296399366"},
		{err: true, val: "not a number"},
	} {
		for _, codec := range []struct {
			name string
			enc  func(Work) (string, error)
			dec  func(string) (Work, error)
		}{
			{
				name: "String",
				enc: func(w Work) (string, error) {
					return w.String(), nil
				},
				dec: func(s string) (w Work, err error) {
					err = w.UnmarshalText([]byte(s))
					return
				},
			},
			{
				name: "MarshalText",
				enc: func(w Work) (string, error) {
					v, err := w.MarshalText()
					return string(v), err
				},
				dec: func(s string) (w Work, err error) {
					err = w.UnmarshalText([]byte(s))
					return
				},
			},
			{
				name: "MarshalJSON",
				enc: func(w Work) (string, error) {
					v, err := w.MarshalJSON()
					return strings.Trim(string(v), `"`), err
				},
				dec: func(s string) (w Work, err error) {
					err = w.UnmarshalJSON([]byte(strings.Trim(s, `"`)))
					return
				},
			},
		} {
			w, err := codec.dec(test.val)
			if err != nil {
				if !test.err {
					t.Errorf("%v: unexpected error for %v: %v", codec.name, test.val, err)
				}
				continue
			} else if test.err {
				t.Errorf("%v: expected error for %v, got nil", codec.name, test.val)
				continue
			}
			exp := test.roundtrip
			if exp == "" {
				exp = test.val
			}
			got, err := codec.enc(w)
			if err != nil {
				t.Fatal(err)
			} else if string(got) != exp {
				t.Errorf("%v: %q failed roundtrip (got %q)", codec.name, test.val, got)
				continue
			}
		}
	}
}

func TestRevertedRevisionLeaf(t *testing.T) {
	// Regression test for a1a2c3fd (consensus: Add (*MidState).forEachRevertedElement)
	//
	// NOTE: this is a tricky bug to reproduce. We can't directly observe it by
	// looking at the contract element itself; instead, we have to look at the
	// leaf *adjacent* to it in the accumulator (in this case, the chain index
	// element).

	n, genesisBlock := testnet()
	genesisBlock.Transactions = []types.Transaction{{
		FileContracts: []types.FileContract{{
			Filesize:       123,
			Payout:         types.Siacoins(1),
			WindowStart:    1000,
			WindowEnd:      1001,
			RevisionNumber: 0,
		}},
	}}
	bs := V1BlockSupplement{Transactions: make([]V1TransactionSupplement, len(genesisBlock.Transactions))}
	cs, cau := ApplyBlock(n.GenesisState(), genesisBlock, bs, time.Time{})
	cie := cau.ms.cie
	fce := cau.ms.fces[0]
	if !cs.Elements.containsChainIndex(cie) {
		t.Error("chain index element should be present in accumulator")
	}
	if !cs.Elements.containsUnresolvedFileContractElement(fce) {
		t.Error("unrevised contract should be present in accumulator")
	}

	// revise the contract
	b := types.Block{
		ParentID: cs.Index.ID,
		Transactions: []types.Transaction{{
			FileContractRevisions: []types.FileContractRevision{{
				ParentID: types.FileContractID(fce.ID),
				FileContract: types.FileContract{
					Filesize:       456,
					Payout:         types.Siacoins(2),
					WindowStart:    1000,
					WindowEnd:      1001,
					RevisionNumber: 1,
				},
			}},
		}},
	}
	bs = V1BlockSupplement{
		Transactions: []V1TransactionSupplement{{
			RevisedFileContracts: []types.FileContractElement{fce},
		}},
	}
	prev := cs
	cs, cau = ApplyBlock(cs, b, bs, time.Time{})

	cau.UpdateElementProof(&cie.StateElement)
	if !cs.Elements.containsChainIndex(cie) {
		t.Fatal("chain index element should be present in accumulator")
	}
	rev := *cau.ms.revs[fce.ID]
	if !cs.Elements.containsUnresolvedFileContractElement(rev) {
		t.Error("revised contract should be present in accumulator")
	}
	cau.UpdateElementProof(&fce.StateElement)
	if cs.Elements.containsUnresolvedFileContractElement(fce) {
		t.Error("unrevised contract should not be present in accumulator")
	}

	// revert the block
	cru := RevertBlock(prev, b, bs)
	cs = prev

	cru.UpdateElementProof(&cie.StateElement)
	if !cs.Elements.containsChainIndex(cie) {
		t.Error("chain index element should be present in accumulator")
	}
	cru.UpdateElementProof(&rev.StateElement)
	if cs.Elements.containsUnresolvedFileContractElement(rev) {
		t.Error("revised contract should not be present in accumulator")
	}
	cru.UpdateElementProof(&fce.StateElement)
	if !cs.Elements.containsUnresolvedFileContractElement(fce) {
		t.Error("unrevised contract should be present in accumulator")
	}
}
