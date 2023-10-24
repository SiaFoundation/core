package consensus_test

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"go.sia.tech/core/chain"
	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

func ancestorTimestamp(s chain.Store, id types.BlockID, n uint64) time.Time {
	b, _, _ := s.Block(id)
	cs, _ := s.State(id)
	for i := uint64(1); i < n; i++ {
		// if we're on the best path, we can jump to the n'th block directly
		if index, _ := s.BestIndex(cs.Index.Height); index.ID == id {
			height := cs.Index.Height - (n - i)
			if cs.Index.Height < (n - i) {
				height = 0
			}
			ancestorIndex, _ := s.BestIndex(height)
			b, _, _ = s.Block(ancestorIndex.ID)
			break
		}
		b, _, _ = s.Block(b.ParentID)
		cs, _ = s.State(b.ParentID)
	}
	return b.Timestamp
}

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
		prev := cs
		cs, au = consensus.ApplyBlock(prev, b, bs, ancestorTimestamp(dbStore, b.ParentID, cs.AncestorDepth()))
		dbStore.ApplyBlock(prev, au, true)
		dbStore.AddBlock(b, &bs)
		dbStore.AddState(cs)
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
}

/*
func TestWork_UnmarshalText(t *testing.T) {
	type fields struct {
		n [32]byte
	}
	type args struct {
		b []byte
	}

	negTen := big.NewInt(-111111)

	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
			{
				name:    "failure math/big: cannot unmarshal \"\" into a *big.Int",
				fields:  fields{},
				args:    args{},
				wantErr: true,
			},
		{
			name: "failure value cannot be negative",
			fields: fields{
				n: types.HashBytes(negTen.Bytes()),
			},
			args: args{
				b: negTen.Bytes(),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := consensus.NewWork(tt.fields.n)
			if err := w.UnmarshalText(tt.args.b); (err != nil) != tt.wantErr {
				t.Log("!!!", tt.args.b, "!@", "@@@", string(tt.fields.n[:]))
				t.Errorf("Work.UnmarshalText() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
*/

func TestWorkMarshalText(t *testing.T) {
	type fields struct {
		n [32]byte
	}
	one := [32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	tests := []struct {
		name    string
		fields  fields
		want    []byte
		wantErr bool
	}{
		{
			name: "success",
			fields: fields{
				n: one,
			},
			want:    []byte{49},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := consensus.NewWork(tt.fields.n)
			got, err := w.MarshalText()
			if (err != nil) != tt.wantErr {
				t.Errorf("Work.MarshalText() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Log(string(got), "!!!", string(tt.want))
				t.Errorf("Work.MarshalText() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWork_MarshalJSON(t *testing.T) {
	type fields struct {
		n [32]byte
	}
	one := [32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	tests := []struct {
		name    string
		fields  fields
		want    []byte
		wantErr bool
	}{
		{
			name: "success",
			fields: fields{
				n: one,
			},
			want:    []byte(`"1"`),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := consensus.NewWork(tt.fields.n)
			got, err := w.MarshalJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("Work.MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Work.MarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRevertBlock(t *testing.T) {
	type args struct {
		s  consensus.State
		b  types.Block
		bs consensus.V1BlockSupplement
	}
	tests := []struct {
		name string
		args args
		want consensus.RevertUpdate
	}{
		{
			name: "panic",
			args: args{
				s: consensus.State{
					Index: types.ChainIndex{
						ID: types.BlockID{1},
					},
				},
				b: types.Block{
					ParentID: types.BlockID{10},
				},
			},
			want: consensus.RevertUpdate{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Error("should have panicked")
				}
			}()
			if got := consensus.RevertBlock(tt.args.s, tt.args.b, tt.args.bs); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RevertBlock() = %v, want %v", got, tt.want)
			}
		})
	}
}
