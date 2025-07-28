package consensus

import (
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.sia.tech/core/blake2b"
	"go.sia.tech/core/types"
	"lukechampine.com/frand"
)

func checkApplyUpdate(t *testing.T, cs State, au ApplyUpdate) {
	t.Helper()

	for _, sce := range au.sces {
		if !cs.Elements.containsLeaf(siacoinLeaf(&sce.SiacoinElement, sce.Spent)) {
			t.Fatalf("consensus: siacoin element %v %v not found in accumulator after apply", sce.Spent, sce.SiacoinElement.ID)
		}
	}
	for _, sfe := range au.sfes {
		if !cs.Elements.containsLeaf(siafundLeaf(&sfe.SiafundElement, sfe.Spent)) {
			t.Fatalf("consensus: siafund element %v not found in accumulator after apply", sfe.SiafundElement.ID)
		}
	}
	for _, fce := range au.fces {
		if !cs.Elements.containsLeaf(fileContractLeaf(&fce.FileContractElement, fce.Revision, fce.Resolved)) {
			t.Fatal("consensus: file contract element leaf not found in accumulator after apply")
		}
	}
	for _, fce := range au.v2fces {
		if !cs.Elements.containsLeaf(v2FileContractLeaf(&fce.V2FileContractElement, fce.Revision, fce.Resolution != nil)) {
			t.Fatal("consensus: v2 file contract element leaf not found in accumulator after apply")
		}
	}
	for _, ae := range au.aes {
		if !cs.Elements.containsLeaf(attestationLeaf(&ae)) {
			t.Fatal("consensus: attestation element leaf not found in accumulator after apply")
		}
	}
}

func checkRevertUpdate(t *testing.T, cs State, ru RevertUpdate) {
	t.Helper()

	for _, sce := range ru.sces {
		if cs.Elements.containsLeaf(siacoinLeaf(&sce.SiacoinElement, sce.Spent)) {
			t.Fatal("consensus: siacoin element found in accumulator after revert")
		}
	}
	for _, sfe := range ru.sfes {
		if cs.Elements.containsLeaf(siafundLeaf(&sfe.SiafundElement, sfe.Spent)) {
			t.Fatal("consensus: siafund element found in accumulator after revert")
		}
	}
	for _, fce := range ru.fces {
		if cs.Elements.containsLeaf(fileContractLeaf(&fce.FileContractElement, fce.Revision, fce.Resolved)) {
			t.Fatal("consensus: file contract element leaf found in accumulator after revert")
		}
	}
	for _, fce := range ru.v2fces {
		if cs.Elements.containsLeaf(v2FileContractLeaf(&fce.V2FileContractElement, fce.Revision, fce.Resolution != nil)) {
			t.Fatal("consensus: v2 file contract element leaf found in accumulator after revert")
		}
	}
	for _, ae := range ru.aes {
		if cs.Elements.containsLeaf(attestationLeaf(&ae)) {
			t.Fatal("consensus: attestation element leaf found in accumulator after revert")
		}
	}
}
func checkUpdateElements(t *testing.T, au ApplyUpdate, addedSCEs, spentSCEs []types.SiacoinElement, addedSFEs, spentSFEs []types.SiafundElement) {
	for _, sced := range au.SiacoinElementDiffs() {
		sces := &addedSCEs
		if sced.Spent {
			sces = &spentSCEs
		}
		if len(*sces) == 0 {
			t.Fatal("unexpected spent siacoin element")
		}
		sce := sced.SiacoinElement.Move()
		sce.StateElement = types.StateElement{}
		sce.ID = types.SiacoinOutputID{}
		if !reflect.DeepEqual(sce.Move(), (*sces)[0].Copy()) {
			t.Fatalf("siacoin element doesn't match:\n%v\nvs\n%v\n", sce.Move(), (*sces)[0].Copy())
		}
		*sces = (*sces)[1:]
	}
	for _, sfed := range au.SiafundElementDiffs() {
		sfes := &addedSFEs
		if sfed.Spent {
			sfes = &spentSFEs
		}
		if len(*sfes) == 0 {
			t.Fatal("unexpected spent siafund element")
		}
		sfe := sfed.SiafundElement.Move()
		sfe.StateElement = types.StateElement{}
		sfe.ID = types.SiafundOutputID{}
		if !reflect.DeepEqual(sfe.Move(), (*sfes)[0].Copy()) {
			t.Fatalf("siafund element doesn't match:\n%v\nvs\n%v\n", sfe.Move(), (*sfes)[0].Copy())
		}
		*sfes = (*sfes)[1:]
	}
	if len(addedSCEs)+len(spentSCEs)+len(addedSFEs)+len(spentSFEs) > 0 {
		t.Fatal("extraneous elements")
	}
}

func checkRevertElements(t *testing.T, ru RevertUpdate, addedSCEs, spentSCEs []types.SiacoinElement, addedSFEs, spentSFEs []types.SiafundElement) {
	for _, sced := range ru.SiacoinElementDiffs() {
		sces := &addedSCEs
		if sced.Spent {
			sces = &spentSCEs
		}
		if len(*sces) == 0 {
			t.Fatal("unexpected spent siacoin element")
		}
		sce := sced.SiacoinElement.Move()
		sce.StateElement = types.StateElement{}
		sce.ID = types.SiacoinOutputID{}
		if !reflect.DeepEqual(sce.Move(), (*sces)[len(*sces)-1].Copy()) {
			t.Fatalf("siacoin element doesn't match:\n%v\nvs\n%v\n", sce.Move(), (*sces)[len(*sces)-1].Copy())
		}
		*sces = (*sces)[:len(*sces)-1]
	}
	for _, sfed := range ru.SiafundElementDiffs() {
		sfes := &addedSFEs
		if sfed.Spent {
			sfes = &spentSFEs
		}
		if len(*sfes) == 0 {
			t.Fatal("unexpected spent siafund element")
		}
		sfe := sfed.SiafundElement.Move()
		sfe.StateElement = types.StateElement{}
		sfe.ID = types.SiafundOutputID{}
		if !reflect.DeepEqual(sfe.Move(), (*sfes)[len(*sfes)-1].Copy()) {
			t.Fatalf("siafund element doesn't match:\n%v\nvs\n%v\n", sfe.Move(), (*sfes)[len(*sfes)-1].Copy())
		}
		*sfes = (*sfes)[:len(*sfes)-1]
	}
	if len(addedSCEs)+len(spentSCEs)+len(addedSFEs)+len(spentSFEs) > 0 {
		t.Fatal("extraneous elements")
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
		checkUpdateElements(t, au, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
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
		checkUpdateElements(t, au, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
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

	checkRevertUpdate(t, cs, ru)
	checkRevertElements(t, ru, addedSCEs, spentSCEs, addedSFEs, spentSFEs)

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
	cie := cau.ChainIndexElement()
	fced := cau.FileContractElementDiffs()[0]
	if !cs.Elements.containsChainIndex(cie.Share()) {
		t.Error("chain index element should be present in accumulator")
	}
	if !cs.Elements.containsUnresolvedFileContractElement(fced.FileContractElement.Share()) {
		t.Error("unrevised contract should be present in accumulator")
	}

	// revise the contract
	b := types.Block{
		ParentID: cs.Index.ID,
		Transactions: []types.Transaction{{
			FileContractRevisions: []types.FileContractRevision{{
				ParentID: fced.FileContractElement.ID,
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
			RevisedFileContracts: []types.FileContractElement{fced.FileContractElement},
		}},
	}
	prev := cs
	cs, cau = ApplyBlock(cs, b, bs, time.Time{})

	cau.UpdateElementProof(&cie.StateElement)
	if !cs.Elements.containsChainIndex(cie.Share()) {
		t.Fatal("chain index element should be present in accumulator")
	}
	revFCE := cau.FileContractElementDiffs()[0].FileContractElement.Copy()
	revFCE.FileContract = *cau.FileContractElementDiffs()[0].Revision
	if !cs.Elements.containsUnresolvedFileContractElement(revFCE.Share()) {
		t.Error("revised contract should be present in accumulator")
	}
	cau.UpdateElementProof(&fced.FileContractElement.StateElement)
	if cs.Elements.containsUnresolvedFileContractElement(fced.FileContractElement.Share()) {
		t.Error("unrevised contract should not be present in accumulator")
	}

	// revert the block
	cru := RevertBlock(prev, b, bs)
	cs = prev

	cru.UpdateElementProof(&cie.StateElement)
	if !cs.Elements.containsChainIndex(cie.Share()) {
		t.Error("chain index element should be present in accumulator")
	}
	cru.UpdateElementProof(&revFCE.StateElement)
	if cs.Elements.containsUnresolvedFileContractElement(revFCE.Share()) {
		t.Error("revised contract should not be present in accumulator")
	}
	cru.UpdateElementProof(&fced.FileContractElement.StateElement)
	if !cs.Elements.containsUnresolvedFileContractElement(fced.FileContractElement.Share()) {
		t.Error("unrevised contract should be present in accumulator")
	}
}

func TestApplyRevertBlockV1(t *testing.T) {
	n, genesisBlock := testnet()

	giftPrivateKey := types.GeneratePrivateKey()
	giftPublicKey := giftPrivateKey.PublicKey()

	renterPrivateKey := types.GeneratePrivateKey()
	renterPublicKey := renterPrivateKey.PublicKey()

	hostPrivateKey := types.GeneratePrivateKey()
	hostPublicKey := hostPrivateKey.PublicKey()

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
		appendSig := func(key types.PrivateKey, pubkeyIndex uint64, parentID types.Hash256) {
			sig := key.SignHash(cs.WholeSigHash(*txn, parentID, pubkeyIndex, 0, nil))
			txn.Signatures = append(txn.Signatures, types.TransactionSignature{
				ParentID:       parentID,
				CoveredFields:  types.CoveredFields{WholeTransaction: true},
				PublicKeyIndex: pubkeyIndex,
				Signature:      sig[:],
			})
		}
		for i := range txn.SiacoinInputs {
			appendSig(giftPrivateKey, 0, types.Hash256(txn.SiacoinInputs[i].ParentID))
		}
		for i := range txn.SiafundInputs {
			appendSig(giftPrivateKey, 0, types.Hash256(txn.SiafundInputs[i].ParentID))
		}
		for i := range txn.FileContractRevisions {
			appendSig(renterPrivateKey, 0, types.Hash256(txn.FileContractRevisions[i].ParentID))
			appendSig(hostPrivateKey, 1, types.Hash256(txn.FileContractRevisions[i].ParentID))
		}
	}
	addBlock := func(b *types.Block, bs V1BlockSupplement) (au ApplyUpdate, err error) {
		findBlockNonce(cs, b)
		if err = ValidateBlock(cs, *b, bs); err != nil {
			return
		}
		cs, au = ApplyBlock(cs, *b, bs, db.ancestorTimestamp(b.ParentID))
		db.applyBlock(au)
		return
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
	if au, err := addBlock(&b1, db.supplementTipBlock(b1)); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
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
	if au, err := addBlock(&b2, bs); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
	}

	// revert block spending sc and sf
	ru := RevertBlock(prev, b2, bs)
	cs = prev
	checkRevertUpdate(t, cs, ru)
	checkRevertElements(t, ru, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
	db.revertBlock(ru)

	// block that creates a file contract
	fc := prepareContractFormation(renterPublicKey, hostPublicKey, types.Siacoins(1), types.Siacoins(1), 100, 105, types.VoidAddress)
	txnB3 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         giftTxn.SiacoinOutputID(0),
			UnlockConditions: types.StandardUnlockConditions(giftPublicKey),
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: giftAddress,
			Value:   giftAmountSC.Sub(fc.Payout),
		}},
		FileContracts: []types.FileContract{fc},
	}
	signTxn(&txnB3)

	b3 := types.Block{
		ParentID:     b1.ID(),
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.SiacoinOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
		Transactions: []types.Transaction{txnB3},
	}
	addedSCEs = []types.SiacoinElement{
		{SiacoinOutput: txnB3.SiacoinOutputs[0]},
		{SiacoinOutput: b3.MinerPayouts[0], MaturityHeight: cs.MaturityHeight()},
	}
	spentSCEs = []types.SiacoinElement{
		{SiacoinOutput: giftTxn.SiacoinOutputs[0]},
	}
	addedSFEs = nil
	spentSFEs = nil

	// add block creating fc
	bs = db.supplementTipBlock(b3)
	if au, err := addBlock(&b3, bs); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
	}

	// revert block creating fc
	ru = RevertBlock(prev, b3, bs)
	cs = prev
	checkRevertUpdate(t, cs, ru)
	checkRevertElements(t, ru, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
	db.revertBlock(ru)

	// readd block creating fc
	if au, err := addBlock(&b3, bs); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
	}

	// block creating file contract revision
	fcr := fc
	fcr.RevisionNumber++
	fcr.Filesize = 65
	fcr.WindowStart = 4
	fcr.WindowEnd = 20
	fcr.FileMerkleRoot = blake2b.SumPair((State{}).StorageProofLeafHash([]byte{1}), (State{}).StorageProofLeafHash([]byte{2}))

	uc := types.UnlockConditions{
		PublicKeys: []types.UnlockKey{
			{Algorithm: types.SpecifierEd25519, Key: renterPublicKey[:]},
			{Algorithm: types.SpecifierEd25519, Key: hostPublicKey[:]},
		},
		SignaturesRequired: 2,
	}
	txnB4 := types.Transaction{
		FileContractRevisions: []types.FileContractRevision{{
			ParentID:         txnB3.FileContractID(0),
			UnlockConditions: uc,
			FileContract:     fcr,
		}},
	}
	signTxn(&txnB4)
	b4 := types.Block{
		ParentID:     b3.ID(),
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.SiacoinOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
		Transactions: []types.Transaction{txnB4},
	}
	addedSCEs = []types.SiacoinElement{
		{SiacoinOutput: b4.MinerPayouts[0], MaturityHeight: cs.MaturityHeight()},
	}
	spentSCEs = []types.SiacoinElement{}
	addedSFEs = nil
	spentSFEs = nil

	prev = cs
	bs = db.supplementTipBlock(b4)
	if au, err := addBlock(&b4, bs); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
	}

	// revert block revising fc
	ru = RevertBlock(prev, b4, bs)
	cs = prev
	checkRevertUpdate(t, cs, ru)
	checkRevertElements(t, ru, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
	db.revertBlock(ru)

	// readd block revising fc
	if au, err := addBlock(&b4, bs); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
	}

	// block with storage proof
	txnB5 := types.Transaction{
		StorageProofs: []types.StorageProof{{
			ParentID: txnB3.FileContractID(0),
			Leaf:     [64]byte{1},
			Proof:    []types.Hash256{cs.StorageProofLeafHash([]byte{2})},
		}},
	}
	signTxn(&txnB5)
	b5 := types.Block{
		ParentID:     b4.ID(),
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.SiacoinOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
		Transactions: []types.Transaction{txnB5},
	}
	if cs.StorageProofLeafIndex(fcr.Filesize, b3.ID(), types.FileContractID(txnB3.FileContractID(0))) == 1 {
		b5.Transactions[0].StorageProofs[0] = types.StorageProof{
			ParentID: txnB3.FileContractID(0),
			Leaf:     [64]byte{2},
			Proof:    []types.Hash256{cs.StorageProofLeafHash([]byte{1})},
		}
	}
	addedSCEs = []types.SiacoinElement{
		{SiacoinOutput: txnB3.FileContracts[0].ValidProofOutputs[1], MaturityHeight: cs.MaturityHeight()},
		{SiacoinOutput: txnB3.FileContracts[0].ValidProofOutputs[0], MaturityHeight: cs.MaturityHeight()},
		{SiacoinOutput: b5.MinerPayouts[0], MaturityHeight: cs.MaturityHeight()},
	}
	spentSCEs = nil
	addedSFEs = nil
	spentSFEs = nil

	// add block with storage proof
	bs = db.supplementTipBlock(b5)
	bs.Transactions[0].StorageProofs = append(bs.Transactions[0].StorageProofs, V1StorageProofSupplement{
		FileContract: db.fces[txnB5.StorageProofs[0].ParentID].Copy(),
		WindowID:     b3.ID(),
	})
	prev = cs
	if au, err := addBlock(&b5, bs); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
	}

	// revert block with storage proof
	ru = RevertBlock(prev, b5, bs)
	cs = prev
	checkRevertUpdate(t, cs, ru)
	checkRevertElements(t, ru, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
	db.revertBlock(ru)

	// readd block with storage proof
	if au, err := addBlock(&b5, bs); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
	}
}

func TestApplyRevertBlockV2(t *testing.T) {
	n, genesisBlock := testnet()
	n.HardforkV2.AllowHeight = 1
	n.HardforkV2.RequireHeight = 2

	giftPrivateKey := types.GeneratePrivateKey()
	giftPublicKey := giftPrivateKey.PublicKey()

	renterPrivateKey := types.GeneratePrivateKey()
	renterPublicKey := renterPrivateKey.PublicKey()

	hostPrivateKey := types.GeneratePrivateKey()
	hostPublicKey := hostPrivateKey.PublicKey()

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

	signTxn := func(cs State, txn *types.V2Transaction) {
		for i := range txn.Attestations {
			txn.Attestations[i].Signature = giftPrivateKey.SignHash(cs.AttestationSigHash(txn.Attestations[i]))
		}
		for i := range txn.SiacoinInputs {
			txn.SiacoinInputs[i].SatisfiedPolicy.Signatures = []types.Signature{giftPrivateKey.SignHash(cs.InputSigHash(*txn))}
		}
		for i := range txn.SiafundInputs {
			txn.SiafundInputs[i].SatisfiedPolicy.Signatures = []types.Signature{giftPrivateKey.SignHash(cs.InputSigHash(*txn))}
		}
		for i := range txn.FileContracts {
			txn.FileContracts[i].RenterSignature = renterPrivateKey.SignHash(cs.ContractSigHash(txn.FileContracts[i]))
			txn.FileContracts[i].HostSignature = hostPrivateKey.SignHash(cs.ContractSigHash(txn.FileContracts[i]))
		}
		for i := range txn.FileContractRevisions {
			txn.FileContractRevisions[i].Revision.RenterSignature = renterPrivateKey.SignHash(cs.ContractSigHash(txn.FileContractRevisions[i].Revision))
			txn.FileContractRevisions[i].Revision.HostSignature = hostPrivateKey.SignHash(cs.ContractSigHash(txn.FileContractRevisions[i].Revision))
		}
		for i := range txn.FileContractResolutions {
			r, ok := txn.FileContractResolutions[i].Resolution.(*types.V2FileContractRenewal)
			if !ok {
				continue
			}
			r.RenterSignature = renterPrivateKey.SignHash(cs.RenewalSigHash(*r))
			r.HostSignature = hostPrivateKey.SignHash(cs.RenewalSigHash(*r))
		}
	}
	addBlock := func(b *types.Block) (au ApplyUpdate, err error) {
		if b.V2 != nil {
			b.V2.Commitment = cs.Commitment(b.MinerPayouts[0].Address, b.Transactions, b.V2Transactions())
		}
		findBlockNonce(cs, b)
		if err = ValidateBlock(cs, *b, V1BlockSupplement{}); err != nil {
			return
		}
		cs, au = ApplyBlock(cs, *b, V1BlockSupplement{}, db.ancestorTimestamp(b.ParentID))
		db.applyBlock(au)
		return
	}
	satisfiedPolicy := func(uc types.UnlockConditions) types.SatisfiedPolicy {
		return types.SatisfiedPolicy{
			Policy: types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc)},
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
		checkUpdateElements(t, au, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
	}
	// block that spends part of the gift transaction
	txnB2 := types.V2Transaction{
		Attestations: []types.Attestation{
			{
				PublicKey: giftPublicKey,
				Key:       hex.EncodeToString(frand.Bytes(16)),
				Value:     frand.Bytes(16),
			},
		},
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          db.sces[giftTxn.SiacoinOutputID(0)].Copy(),
			SatisfiedPolicy: satisfiedPolicy(types.StandardUnlockConditions(giftPublicKey)),
		}},
		SiafundInputs: []types.V2SiafundInput{{
			Parent:          db.sfes[giftTxn.SiafundOutputID(0)].Copy(),
			ClaimAddress:    types.VoidAddress,
			SatisfiedPolicy: satisfiedPolicy(types.StandardUnlockConditions(giftPublicKey)),
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
	signTxn(cs, &txnB2)
	b2 := types.Block{
		ParentID:     b1.ID(),
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.SiacoinOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
		V2: &types.V2BlockData{
			Height:       2,
			Transactions: []types.V2Transaction{txnB2},
		},
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
	if au, err := addBlock(&b2); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
	}

	// revert block spending sc and sf
	ru := RevertBlock(prev, b2, V1BlockSupplement{})
	cs = prev
	checkRevertUpdate(t, cs, ru)
	checkRevertElements(t, ru, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
	db.revertBlock(ru)

	// block that creates a file contract
	v1FC := prepareContractFormation(renterPublicKey, hostPublicKey, types.Siacoins(1), types.Siacoins(1), 100, 105, types.VoidAddress)
	v1FC.Filesize = 65
	v1FC.FileMerkleRoot = blake2b.SumPair((State{}).StorageProofLeafHash([]byte{1}), (State{}).StorageProofLeafHash([]byte{2}))
	v2FC := types.V2FileContract{
		Capacity:         v1FC.Filesize,
		Filesize:         v1FC.Filesize,
		FileMerkleRoot:   v1FC.FileMerkleRoot,
		ProofHeight:      20,
		ExpirationHeight: 30,
		RenterOutput:     v1FC.ValidProofOutputs[0],
		HostOutput:       v1FC.ValidProofOutputs[1],
		MissedHostValue:  v1FC.MissedProofOutputs[1].Value,
		TotalCollateral:  v1FC.ValidProofOutputs[0].Value,
		RenterPublicKey:  renterPublicKey,
		HostPublicKey:    hostPublicKey,
	}
	fcOut := v2FC.RenterOutput.Value.Add(v2FC.HostOutput.Value).Add(cs.V2FileContractTax(v2FC))

	txnB3 := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent:          db.sces[giftTxn.SiacoinOutputID(0)].Copy(),
			SatisfiedPolicy: satisfiedPolicy(types.StandardUnlockConditions(giftPublicKey)),
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: giftAddress,
			Value:   giftAmountSC.Sub(fcOut),
		}},
		FileContracts: []types.V2FileContract{v2FC},
	}
	signTxn(cs, &txnB3)

	b3 := types.Block{
		ParentID:     b1.ID(),
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.SiacoinOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
		V2: &types.V2BlockData{
			Height:       2,
			Transactions: []types.V2Transaction{txnB3},
		},
	}
	addedSCEs = []types.SiacoinElement{
		{SiacoinOutput: txnB3.SiacoinOutputs[0]},
		{SiacoinOutput: b3.MinerPayouts[0], MaturityHeight: cs.MaturityHeight()},
	}
	spentSCEs = []types.SiacoinElement{
		{SiacoinOutput: giftTxn.SiacoinOutputs[0]},
	}
	addedSFEs = nil
	spentSFEs = nil

	// add block creating fc
	if au, err := addBlock(&b3); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
	}

	// revert block creating fc
	ru = RevertBlock(prev, b3, V1BlockSupplement{})
	cs = prev
	checkRevertUpdate(t, cs, ru)
	checkRevertElements(t, ru, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
	db.revertBlock(ru)

	// readd block creating fc
	if au, err := addBlock(&b3); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
	}

	// block creating file contract revision
	fcr := v2FC
	fcr.RevisionNumber++
	fcr.Filesize = 65
	fcr.ProofHeight = 3
	fcr.ExpirationHeight = 20
	fcr.FileMerkleRoot = blake2b.SumPair((State{}).StorageProofLeafHash([]byte{1}), (State{}).StorageProofLeafHash([]byte{2}))

	txnB4 := types.V2Transaction{
		FileContractRevisions: []types.V2FileContractRevision{{
			Parent:   db.v2fces[txnB3.V2FileContractID(txnB3.ID(), 0)].Copy(),
			Revision: fcr,
		}},
	}
	signTxn(cs, &txnB4)
	b4 := types.Block{
		ParentID:     b3.ID(),
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.SiacoinOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
		V2: &types.V2BlockData{
			Height:       3,
			Transactions: []types.V2Transaction{txnB4},
		},
	}
	addedSCEs = []types.SiacoinElement{
		{SiacoinOutput: b4.MinerPayouts[0], MaturityHeight: cs.MaturityHeight()},
	}
	spentSCEs = []types.SiacoinElement{
		// {SiacoinOutput: giftTxn.SiacoinOutputs[0]},
	}
	addedSFEs = nil
	spentSFEs = nil

	var cie types.ChainIndexElement
	prev = cs
	if au, err := addBlock(&b4); err != nil {
		t.Fatal(err)
	} else {
		cie = au.ChainIndexElement()
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
	}

	// revert block revising fc
	ru = RevertBlock(prev, b4, V1BlockSupplement{})
	cs = prev
	checkRevertUpdate(t, cs, ru)
	checkRevertElements(t, ru, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
	db.revertBlock(ru)

	// readd block revising fc
	if au, err := addBlock(&b4); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
	}

	// block with storage proof
	fce := db.v2fces[txnB3.V2FileContractID(txnB3.ID(), 0)].Copy()
	txnB5 := types.V2Transaction{
		FileContractResolutions: []types.V2FileContractResolution{{
			Parent: fce.Copy(),
			Resolution: &types.V2StorageProof{
				ProofIndex: cie.Copy(),
				Leaf:       [64]byte{1},
				Proof:      []types.Hash256{cs.StorageProofLeafHash([]byte{2})},
			},
		}},
	}
	signTxn(cs, &txnB5)
	b5 := types.Block{
		ParentID:     b4.ID(),
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.SiacoinOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
		V2: &types.V2BlockData{
			Height:       4,
			Transactions: []types.V2Transaction{txnB5},
		},
	}
	if cs.StorageProofLeafIndex(fce.V2FileContract.Filesize, cie.ChainIndex.ID, types.FileContractID(fce.ID)) == 1 {
		b5.V2.Transactions[0].FileContractResolutions[0].Resolution = &types.V2StorageProof{
			ProofIndex: cie.Copy(),
			Leaf:       [64]byte{2},
			Proof:      []types.Hash256{cs.StorageProofLeafHash([]byte{1})},
		}
	}

	addedSCEs = []types.SiacoinElement{
		{SiacoinOutput: txnB3.FileContracts[0].RenterOutput, MaturityHeight: cs.MaturityHeight()},
		{SiacoinOutput: txnB3.FileContracts[0].HostOutput, MaturityHeight: cs.MaturityHeight()},
		{SiacoinOutput: b5.MinerPayouts[0], MaturityHeight: cs.MaturityHeight()},
	}
	spentSCEs = nil
	addedSFEs = nil
	spentSFEs = nil

	// add block with storage proof
	prev = cs
	if au, err := addBlock(&b5); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
	}

	// revert block with storage proof
	ru = RevertBlock(prev, b5, V1BlockSupplement{})
	cs = prev
	checkRevertUpdate(t, cs, ru)
	checkRevertElements(t, ru, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
	db.revertBlock(ru)

	// readd block with storage proof
	if au, err := addBlock(&b5); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedSCEs, spentSCEs, addedSFEs, spentSFEs)
	}
}

func TestSiafunds(t *testing.T) {
	n, genesisBlock := testnet()
	n.HardforkV2.AllowHeight = 1
	n.HardforkV2.RequireHeight = 2

	key := types.GeneratePrivateKey()

	giftAddress := types.StandardAddress(key.PublicKey())
	giftAmountSC := types.Siacoins(100e3)
	giftAmountSF := uint64(1000)
	giftTxn := types.Transaction{
		SiacoinOutputs: []types.SiacoinOutput{
			{Address: giftAddress, Value: giftAmountSC},
		},
		SiafundOutputs: []types.SiafundOutput{
			{Address: giftAddress, Value: giftAmountSF},
		},
	}
	genesisBlock.Transactions = []types.Transaction{giftTxn}
	genesisBlock.V2 = &types.V2BlockData{
		Transactions: []types.V2Transaction{{
			FileContracts: []types.V2FileContract{{
				RenterOutput: types.SiacoinOutput{
					Value: types.Siacoins(1000), // ensure initial SiafundTaxRevenue is not 0
				},
			}},
		}},
	}
	db, cs := newConsensusDB(n, genesisBlock)

	signTxn := func(cs State, txn *types.V2Transaction) {
		for i := range txn.SiacoinInputs {
			txn.SiacoinInputs[i].SatisfiedPolicy = types.SatisfiedPolicy{
				Policy:     types.PolicyPublicKey(key.PublicKey()),
				Signatures: []types.Signature{key.SignHash(cs.InputSigHash(*txn))},
			}
		}
		for i := range txn.SiafundInputs {
			txn.SiafundInputs[i].SatisfiedPolicy = types.SatisfiedPolicy{
				Policy:     types.PolicyPublicKey(key.PublicKey()),
				Signatures: []types.Signature{key.SignHash(cs.InputSigHash(*txn))},
			}
		}
		for i := range txn.FileContracts {
			txn.FileContracts[i].RenterSignature = key.SignHash(cs.ContractSigHash(txn.FileContracts[i]))
			txn.FileContracts[i].HostSignature = key.SignHash(cs.ContractSigHash(txn.FileContracts[i]))
		}
	}
	mineTxns := func(txns []types.Transaction, v2txns []types.V2Transaction) (au ApplyUpdate, err error) {
		b := types.Block{
			ParentID:     cs.Index.ID,
			Timestamp:    types.CurrentTimestamp(),
			MinerPayouts: []types.SiacoinOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
			Transactions: txns,
		}
		if len(v2txns) > 0 {
			b.V2 = &types.V2BlockData{
				Height:       cs.Index.Height + 1,
				Commitment:   cs.Commitment(b.MinerPayouts[0].Address, txns, v2txns),
				Transactions: v2txns,
			}
		}
		findBlockNonce(cs, &b)
		if err = ValidateBlock(cs, b, V1BlockSupplement{}); err != nil {
			return
		}
		cs, au = ApplyBlock(cs, b, V1BlockSupplement{}, db.ancestorTimestamp(b.ParentID))
		db.applyBlock(au)
		return
	}

	// roundtrip SF output, to reset its ClaimStart
	sfoid := giftTxn.SiafundOutputID(0)
	txn := types.V2Transaction{
		SiafundInputs: []types.V2SiafundInput{{
			Parent:       db.sfes[sfoid].Copy(),
			ClaimAddress: giftAddress,
		}},
		SiafundOutputs: []types.SiafundOutput{{
			Address: giftAddress,
			Value:   giftAmountSF,
		}},
	}
	signTxn(cs, &txn)
	if _, err := mineTxns(nil, []types.V2Transaction{txn}); err != nil {
		t.Fatal(err)
	}
	sfoid = txn.SiafundOutputID(txn.ID(), 0)

	fc := types.V2FileContract{
		ProofHeight:      20,
		ExpirationHeight: 30,
		RenterOutput:     types.SiacoinOutput{Value: types.Siacoins(5000)},
		HostOutput:       types.SiacoinOutput{Value: types.Siacoins(5000)},
		RenterPublicKey:  key.PublicKey(),
		HostPublicKey:    key.PublicKey(),
	}
	fcValue := fc.RenterOutput.Value.Add(fc.HostOutput.Value).Add(cs.V2FileContractTax(fc))

	txn = types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent: db.sces[giftTxn.SiacoinOutputID(0)].Copy(),
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: giftAddress,
			Value:   giftAmountSC.Sub(fcValue),
		}},
		FileContracts: []types.V2FileContract{fc},
	}
	signTxn(cs, &txn)
	prev := cs
	if _, err := mineTxns(nil, []types.V2Transaction{txn}); err != nil {
		t.Fatal(err)
	}
	// siafund revenue should have increased
	if cs.SiafundTaxRevenue != prev.SiafundTaxRevenue.Add(cs.V2FileContractTax(fc)) {
		t.Fatalf("expected %v siafund revenue, got %v", prev.SiafundTaxRevenue.Add(cs.V2FileContractTax(fc)), cs.SiafundTaxRevenue)
	}

	// make a siafund claim
	txn = types.V2Transaction{
		SiafundInputs: []types.V2SiafundInput{{
			Parent:       db.sfes[sfoid].Copy(),
			ClaimAddress: giftAddress,
		}},
		SiafundOutputs: []types.SiafundOutput{{
			Address: giftAddress,
			Value:   giftAmountSF,
		}},
	}
	signTxn(cs, &txn)
	prev = cs
	if au, err := mineTxns(nil, []types.V2Transaction{txn}); err != nil {
		t.Fatal(err)
	} else {
		// siafund revenue should be unchanged
		if cs.SiafundTaxRevenue != prev.SiafundTaxRevenue {
			t.Fatalf("expected %v siafund revenue, got %v", prev.SiafundTaxRevenue, cs.SiafundTaxRevenue)
		}
		// should have received a timelocked siafund claim output
		var claimOutput *types.SiacoinElement
		for _, sce := range au.SiacoinElementDiffs() {
			if sce.SiacoinElement.ID == txn.SiafundInputs[0].Parent.ID.V2ClaimOutputID() {
				claimOutput = &sce.SiacoinElement
				break
			}
		}
		if claimOutput == nil {
			t.Fatal("expected siafund claim output")
		} else if claimOutput.MaturityHeight != cs.MaturityHeight()-1 {
			t.Fatalf("expected siafund claim output to mature at height %v, got %v", cs.MaturityHeight()-1, claimOutput.MaturityHeight)
		} else if exp := cs.V2FileContractTax(fc).Div64(cs.SiafundCount() / giftAmountSF); claimOutput.SiacoinOutput.Value != exp {
			t.Fatalf("expected siafund claim output value %v, got %v", exp, claimOutput.SiacoinOutput.Value)
		}
	}
}

func TestFoundationSubsidy(t *testing.T) {
	key := types.GeneratePrivateKey()
	addr := types.StandardAddress(key.PublicKey())
	n, genesisBlock := testnet()
	n.HardforkFoundation.Height = 1
	n.HardforkFoundation.PrimaryAddress = addr
	n.HardforkFoundation.FailsafeAddress = addr
	n.HardforkV2.AllowHeight = 1
	n.HardforkV2.RequireHeight = 1
	n.BlockInterval = 10 * time.Hour // subsidies every 10 blocks
	subsidyInterval := uint64(365 * 24 * time.Hour / n.BlockInterval / 12)
	genesisBlock.Transactions = []types.Transaction{{
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr,
			Value:   types.Siacoins(1), // funds for changing address later
		}},
	}}
	scoid := genesisBlock.Transactions[0].SiacoinOutputID(0)

	db, cs := newConsensusDB(n, genesisBlock)
	mineBlock := func(txns []types.V2Transaction) (subsidy types.SiacoinElement, exists bool) {
		b := types.Block{
			ParentID:     cs.Index.ID,
			Timestamp:    types.CurrentTimestamp(),
			MinerPayouts: []types.SiacoinOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
			V2: &types.V2BlockData{
				Height:       cs.Index.Height + 1,
				Commitment:   cs.Commitment(types.VoidAddress, nil, txns),
				Transactions: txns,
			},
		}
		bs := db.supplementTipBlock(b)
		findBlockNonce(cs, &b)
		if err := ValidateBlock(cs, b, bs); err != nil {
			t.Fatal(err)
			return
		}
		var au ApplyUpdate
		cs, au = ApplyBlock(cs, b, bs, db.ancestorTimestamp(b.ParentID))
		db.applyBlock(au)
		for _, sce := range au.SiacoinElementDiffs() {
			if sce.Created && sce.SiacoinElement.SiacoinOutput.Address == addr {
				subsidy = sce.SiacoinElement.Copy()
				exists = true
			}
		}
		return
	}

	// receive initial subsidy
	initialSubsidy, ok := mineBlock(nil)
	if !ok {
		t.Fatal("expected subsidy")
	}

	// mine until we receive a normal subsidy
	for range subsidyInterval - 1 {
		if _, ok := mineBlock(nil); ok {
			t.Fatal("unexpected subsidy")
		}
	}
	subsidy, ok := mineBlock(nil)
	if !ok {
		t.Fatal("expected subsidy")
	} else if subsidy.SiacoinOutput.Value != initialSubsidy.SiacoinOutput.Value.Div64(12) {
		t.Fatal("expected subsidy to be 1/12 of initial subsidy")
	}
	// disable subsidy
	txn := types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent: db.sces[scoid].Copy(),
			SatisfiedPolicy: types.SatisfiedPolicy{
				Policy: types.PolicyPublicKey(key.PublicKey()),
			},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr,
			Value:   db.sces[scoid].SiacoinOutput.Value,
		}},
		NewFoundationAddress: &types.VoidAddress,
	}
	txn.SiacoinInputs[0].SatisfiedPolicy.Signatures = []types.Signature{key.SignHash(cs.InputSigHash(txn))}
	scoid = txn.SiacoinOutputID(txn.ID(), 0)
	mineBlock([]types.V2Transaction{txn})

	// mine until we would receive another subsidy
	for range subsidyInterval {
		if _, ok := mineBlock(nil); ok {
			t.Fatal("unexpected subsidy")
		}
	}

	// re-enable subsidy
	txn = types.V2Transaction{
		SiacoinInputs: []types.V2SiacoinInput{{
			Parent: db.sces[scoid].Copy(),
			SatisfiedPolicy: types.SatisfiedPolicy{
				Policy: types.PolicyPublicKey(key.PublicKey()),
			},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: addr,
			Value:   db.sces[scoid].SiacoinOutput.Value,
		}},
		NewFoundationAddress: &addr,
	}
	txn.SiacoinInputs[0].SatisfiedPolicy.Signatures = []types.Signature{key.SignHash(cs.InputSigHash(txn))}
	mineBlock([]types.V2Transaction{txn})

	// mine until we would receive another subsidy
	for range subsidyInterval - 3 {
		if _, ok := mineBlock(nil); ok {
			t.Fatal("unexpected subsidy")
		}
	}
	if _, ok := mineBlock(nil); !ok {
		t.Fatal("expected subsidy")
	}
}

func TestAdjustDifficulty(t *testing.T) {
	n, _ := testnet()
	n.BlockInterval = 10 * time.Minute
	cs := n.GenesisState()
	cs.Index.Height = n.HardforkV2.RequireHeight + 100

	// ensure median timestamp is above final cut time
	for i := range cs.PrevTimestamps {
		cs.PrevTimestamps[i] = n.HardforkV2.FinalCutTime.Add(time.Second)
	}

	cs.Difficulty.UnmarshalText([]byte("18000000000"))
	cs.ChildTarget = invTarget(cs.Difficulty.n)
	cs.OakTime = n.BlockInterval
	cs.OakWork = cs.Difficulty
	cs.OakTarget = invTarget(cs.OakWork.n)

	maxAdjust := cs.Difficulty.div64(250)

	adjustments := func(d time.Duration) (Work, Work) {
		exp := n.HardforkOak.GenesisTimestamp.Add(time.Duration(cs.childHeight()) * n.BlockInterval)
		difficulty := adjustDifficultyFinalCut(cs, exp.Add(d))
		cs := cs
		cs.PrevTimestamps[0] = exp.Add(d - n.BlockInterval)
		return difficulty, Work{invTarget(adjustTarget(cs, time.Time{}, time.Time{}))}
	}

	t.Run("no adjustment", func(t *testing.T) {
		d1, d2 := adjustments(0)
		if d1 != cs.Difficulty {
			t.Errorf("Expected no adjustment (%v), got %v", cs.Difficulty, d1)
		}
		if d1 != d2 {
			t.Errorf("Algorithms differ: %v != %v", d1, d2)
		}
	})

	t.Run("maximum increase", func(t *testing.T) {
		d1, d2 := adjustments(-10000 * time.Second)
		if exp := cs.Difficulty.add(maxAdjust); d1 != exp {
			t.Errorf("Expected maximum increase (%v), got %v", exp, d1)
		}
		if d1 != d2 {
			t.Errorf("Algorithms differ: %v != %v", d1, d2)
		}
	})

	t.Run("maximum decrease", func(t *testing.T) {
		d1, d2 := adjustments(10000 * time.Second)
		if exp := cs.Difficulty.sub(maxAdjust); d1 != exp {
			t.Errorf("Expected maximum decrease (%v), got %v", exp, d1)
		}
		// old algorithm is slightly different: it divides by 1.004 instead of multiplying by 0.996
		if exp := (Work{invTarget(mulTargetFrac(cs.ChildTarget, 1004, 1000))}); d2 != exp {
			t.Errorf("Expected maximum decrease (%v), got %v", exp, d2)
		}
	})

	t.Run("normal adjustments", func(t *testing.T) {
		// a range of adjustments between -0.4% and +0.4%
		maxDelta := (n.BlockInterval / 250) * 1000
		for i := range 19 {
			delta := (maxDelta / 10) * time.Duration(i-9)
			d1, d2 := adjustments(delta)
			if d1.Cmp(cs.Difficulty.sub(maxAdjust)) <= 0 {
				t.Errorf("Expected adjustment for %v to be greater than minimum: %v <= %v", delta, d1, cs.Difficulty.sub(maxAdjust))
			} else if d1.Cmp(cs.Difficulty.add(maxAdjust)) >= 0 {
				t.Errorf("Expected adjustment for %v to be less than maximum: %v >= %v", delta, d1, cs.Difficulty.add(maxAdjust))
			} else {
				t.Logf("Adjustment for %v: %v", delta, d1)
			}
			maxDiff := d2.div64(100)
			if d1.Cmp(d2.sub(maxDiff)) < 0 || d1.Cmp(d2.add(maxDiff)) > 0 {
				t.Errorf("Expected adjustment to be within 1%% of old adjustment: %v vs %v", d1, d2)
			}
		}
	})
}
