package consensus_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"go.sia.tech/core/chain"
	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

func TestApplyBlock(t *testing.T) {
	n, genesisBlock := chain.TestnetZen()

	n.InitialTarget = types.BlockID{0xFF}

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

	dbStore, tipState, err := chain.NewDBStore(chain.NewMemDB(), n, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}
	defer dbStore.Close()
	cs := tipState

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
	addBlock := func(b types.Block) (au consensus.ApplyUpdate, err error) {
		bs := dbStore.SupplementTipBlock(b)
		if err = consensus.ValidateBlock(cs, b, bs); err != nil {
			return
		}
		ancestorTimestamp, _ := dbStore.AncestorTimestamp(b.ParentID)
		cs, au = consensus.ApplyBlock(cs, b, bs, ancestorTimestamp)
		dbStore.AddState(cs)
		dbStore.AddBlock(b, &bs)
		dbStore.ApplyBlock(cs, au, true)
		return
	}
	checkUpdateElements := func(au consensus.ApplyUpdate, addedSCEs, spentSCEs []types.SiacoinElement, addedSFEs, spentSFEs []types.SiafundElement) {
		au.ForEachSiacoinElement(func(sce types.SiacoinElement, spent bool) {
			sces := &addedSCEs
			if spent {
				sces = &spentSCEs
			}
			if len(*sces) == 0 {
				t.Fatal("unexpected spent siacoin element")
			}
			sce.StateElement = types.StateElement{}
			if !reflect.DeepEqual(sce, (*sces)[0]) {
				js1, _ := json.MarshalIndent(sce, "", "  ")
				js2, _ := json.MarshalIndent((*sces)[0], "", "  ")
				t.Fatalf("siacoin element doesn't match:\n%s\nvs\n%s\n", js1, js2)
			}
			*sces = (*sces)[1:]
		})
		au.ForEachSiafundElement(func(sfe types.SiafundElement, spent bool) {
			sfes := &addedSFEs
			if spent {
				sfes = &spentSFEs
			}
			if len(*sfes) == 0 {
				t.Fatal("unexpected spent siafund element")
			}
			sfe.StateElement = types.StateElement{}
			if !reflect.DeepEqual(sfe, (*sfes)[0]) {
				js1, _ := json.MarshalIndent(sfe, "", "  ")
				js2, _ := json.MarshalIndent((*sfes)[0], "", "  ")
				t.Fatalf("siafund element doesn't match:\n%s\nvs\n%s\n", js1, js2)
			}
			*sfes = (*sfes)[1:]
		})
		if len(addedSCEs)+len(spentSCEs)+len(addedSFEs)+len(spentSFEs) > 0 {
			t.Fatal("extraneous elements")
		}
	}
	checkRevertElements := func(ru consensus.RevertUpdate, addedSCEs, spentSCEs []types.SiacoinElement, addedSFEs, spentSFEs []types.SiafundElement) {
		ru.ForEachSiacoinElement(func(sce types.SiacoinElement, spent bool) {
			sces := &addedSCEs
			if spent {
				sces = &spentSCEs
			}
			if len(*sces) == 0 {
				t.Fatal("unexpected spent siacoin element")
			}
			sce.StateElement = types.StateElement{}
			if !reflect.DeepEqual(sce, (*sces)[len(*sces)-1]) {
				js1, _ := json.MarshalIndent(sce, "", "  ")
				js2, _ := json.MarshalIndent((*sces)[len(*sces)-1], "", "  ")
				t.Fatalf("siacoin element doesn't match:\n%s\nvs\n%s\n", js1, js2)
			}
			*sces = (*sces)[:len(*sces)-1]
		})
		ru.ForEachSiafundElement(func(sfe types.SiafundElement, spent bool) {
			sfes := &addedSFEs
			if spent {
				sfes = &spentSFEs
			}
			if len(*sfes) == 0 {
				t.Fatal("unexpected spent siafund element")
			}
			sfe.StateElement = types.StateElement{}
			if !reflect.DeepEqual(sfe, (*sfes)[len(*sfes)-1]) {
				js1, _ := json.MarshalIndent(sfe, "", "  ")
				js2, _ := json.MarshalIndent((*sfes)[len(*sfes)-1], "", "  ")
				t.Fatalf("siafund element doesn't match:\n%s\nvs\n%s\n", js1, js2)
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
	if au, err := addBlock(b1); err != nil {
		t.Fatal(err)
	} else {
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
	bs := dbStore.SupplementTipBlock(b2)
	if au, err := addBlock(b2); err != nil {
		t.Fatal(err)
	} else {
		checkUpdateElements(au, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
	}

	ru := consensus.RevertBlock(prev, b2, bs)
	dbStore.RevertBlock(cs, ru)
	checkRevertElements(ru, addedSCEs, spentSCEs, addedSFEs, spentSFEs)

	// reverting a non-child block should trigger a panic
	func() {
		defer func() { recover() }()
		consensus.RevertBlock(cs, b2, bs)
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
			enc  func(consensus.Work) (string, error)
			dec  func(string) (consensus.Work, error)
		}{
			{
				name: "String",
				enc: func(w consensus.Work) (string, error) {
					return w.String(), nil
				},
				dec: func(s string) (w consensus.Work, err error) {
					err = w.UnmarshalText([]byte(s))
					return
				},
			},
			{
				name: "MarshalText",
				enc: func(w consensus.Work) (string, error) {
					v, err := w.MarshalText()
					return string(v), err
				},
				dec: func(s string) (w consensus.Work, err error) {
					err = w.UnmarshalText([]byte(s))
					return
				},
			},
			{
				name: "MarshalJSON",
				enc: func(w consensus.Work) (string, error) {
					v, err := w.MarshalJSON()
					return strings.Trim(string(v), `"`), err
				},
				dec: func(s string) (w consensus.Work, err error) {
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
