package chain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"testing"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"lukechampine.com/frand"
)

// AppendTransactionSignature appends a TransactionSignature to txn and signs it
// with key.
func AppendTransactionSignature(cs consensus.State, key types.PrivateKey, parentID types.Hash256, txn *types.Transaction) {
	sig := types.TransactionSignature{
		ParentID:       parentID,
		CoveredFields:  types.CoveredFields{WholeTransaction: true},
		PublicKeyIndex: 0,
	}
	sigHash := key.SignHash(cs.WholeSigHash(*txn, sig.ParentID, sig.PublicKeyIndex, sig.Timelock, sig.CoveredFields.Signatures))
	sig.Signature = sigHash[:]

	txn.Signatures = append(txn.Signatures, sig)
}

// FindBlockNonce finds a block nonce meeting current target.
func FindBlockNonce(cs consensus.State, b *types.Block) {
	// ensure nonce meets factor requirement
	for b.Nonce%cs.NonceFactor() != 0 {
		b.Nonce++
	}
	for b.ID().CmpWork(cs.ChildTarget) < 0 {
		b.Nonce += cs.NonceFactor()
	}
}

func addBlock(cm *Manager, b *types.Block) error {
	var minerAddress types.Address
	frand.Read(minerAddress[:])

	cs := cm.TipState()
	b.MinerPayouts = []types.SiacoinOutput{{Address: minerAddress, Value: cs.BlockReward()}}
	FindBlockNonce(cs, b)
	return cm.AddBlocks([]types.Block{*b})
}

func deepCopyBlock(block types.Block) (types.Block, error) {
	b, err := json.Marshal(block)
	if err != nil {
		return types.Block{}, err
	}

	var result types.Block
	err = json.Unmarshal(b, &result)
	return result, err
}

func signTxn(cs consensus.State, privateKey types.PrivateKey, txn *types.Transaction) {
	for i := range txn.SiacoinInputs {
		AppendTransactionSignature(cs, privateKey, types.Hash256(txn.SiacoinInputs[i].ParentID), txn)
	}
	for i := range txn.SiafundInputs {
		AppendTransactionSignature(cs, privateKey, types.Hash256(txn.SiafundInputs[i].ParentID), txn)
	}
}

type diffSubscriber struct {
	cau *consensus.BlockDiff
	cru *consensus.BlockDiff
}

func (s *diffSubscriber) ProcessChainApplyUpdate(cau *ApplyUpdate, mayCommit bool) error {
	s.cau = &cau.Diff
	s.cru = nil
	return nil
}

func (s *diffSubscriber) ProcessChainRevertUpdate(cru *RevertUpdate) error {
	s.cau = nil
	s.cru = &cru.Diff
	return nil
}

func checkDBOutputs(txns ...types.Transaction) func(DBTx) error {
	return func(tx DBTx) error {
		dtx := &dbTx{tx: tx}
		for _, txn := range txns {
			for i := range txn.SiacoinOutputs {
				out, ok := dtx.SiacoinOutput(txn.SiacoinOutputID(i))
				if !ok {
					return fmt.Errorf("expected output %v", txn.SiacoinOutputs[i])
				}
				if out != txn.SiacoinOutputs[i] {
					return fmt.Errorf("outputs don't match: %v vs %v", txn.SiacoinOutputs[i], out)
				}
			}
			for i := range txn.SiafundOutputs {
				out, _, ok := dtx.SiafundOutput(txn.SiafundOutputID(i))
				if !ok {
					return fmt.Errorf("expected output %v", txn.SiafundOutputs[i])
				}
				if out != txn.SiafundOutputs[i] {
					return fmt.Errorf("outputs don't match: %v vs %v", txn.SiafundOutputs[i], out)
				}
			}
		}
		return dtx.err
	}
}

func TestChainManager(t *testing.T) {
	db := NewMemDB()

	privateKey := types.GeneratePrivateKey()

	cc, _ := TestnetZen()
	cc.InitialTarget = types.BlockID{0xFF}
	giftAddress := privateKey.PublicKey().StandardAddress()
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
	genesisBlock := types.Block{
		Transactions: []types.Transaction{giftTxn},
	}
	dbStore, checkpoint, err := NewDBStore(db, cc, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}

	cm := NewManager(dbStore, checkpoint.State)

	if err := db.View(checkDBOutputs(giftTxn)); err != nil {
		t.Fatal(err)
	}

	var s diffSubscriber
	if err := cm.AddSubscriber(&s, cm.Tip()); err != nil {
		t.Fatal(err)
	}

	// block with nothing except block reward
	b1 := types.Block{
		ParentID:  genesisBlock.ID(),
		Timestamp: time.Now(),
	}
	if err := addBlock(cm, &b1); err != nil {
		t.Fatal(err)
	}

	{
		expect := &consensus.BlockDiff{
			ImmatureSiacoinOutputs: []consensus.DelayedSiacoinOutputDiff{
				{
					ID:             b1.ID().MinerOutputID(0),
					Output:         b1.MinerPayouts[0],
					MaturityHeight: cm.TipState().MaturityHeight() - 1,
					Source:         consensus.OutputSourceMiner,
				},
			},
		}
		if !reflect.DeepEqual(s.cau, expect) {
			t.Fatalf("diff doesn't match: %v vs %v", s.cau, expect)
		}
	}

	// block that spends part of the gift transaction
	txn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{
				ParentID:         giftTxn.SiacoinOutputID(0),
				UnlockConditions: privateKey.PublicKey().StandardUnlockConditions(),
			},
		},
		SiafundInputs: []types.SiafundInput{
			{
				ParentID:         giftTxn.SiafundOutputID(0),
				ClaimAddress:     types.VoidAddress,
				UnlockConditions: privateKey.PublicKey().StandardUnlockConditions(),
			},
		},
		SiacoinOutputs: []types.SiacoinOutput{
			{Value: giftAmountSC.Div64(2), Address: giftAddress},
			{Value: giftAmountSC.Div64(2), Address: types.VoidAddress},
		},
		SiafundOutputs: []types.SiafundOutput{
			{Value: giftAmountSF / 2, Address: giftAddress},
			{Value: giftAmountSF / 2, Address: types.VoidAddress},
		},
	}
	signTxn(cm.TipState(), privateKey, &txn)

	b2 := types.Block{
		ParentID:     b1.ID(),
		Timestamp:    time.Now(),
		Transactions: []types.Transaction{txn},
	}
	if err := addBlock(cm, &b2); err != nil {
		t.Fatal(err)
	}

	{
		expect := &consensus.BlockDiff{
			Transactions: []consensus.TransactionDiff{{
				CreatedSiacoinOutputs: []consensus.SiacoinOutputDiff{
					{
						ID:     txn.SiacoinOutputID(0),
						Output: txn.SiacoinOutputs[0],
					},
					{
						ID:     txn.SiacoinOutputID(1),
						Output: txn.SiacoinOutputs[1],
					},
				},
				SpentSiacoinOutputs: []consensus.SiacoinOutputDiff{
					{
						ID:     giftTxn.SiacoinOutputID(0),
						Output: giftTxn.SiacoinOutputs[0],
					},
				},
				CreatedSiafundOutputs: []consensus.SiafundOutputDiff{
					{
						ID:     txn.SiafundOutputID(0),
						Output: txn.SiafundOutputs[0],
					},
					{
						ID:     txn.SiafundOutputID(1),
						Output: txn.SiafundOutputs[1],
					},
				},
				SpentSiafundOutputs: []consensus.SiafundOutputDiff{
					{
						ID:     giftTxn.SiafundOutputID(0),
						Output: giftTxn.SiafundOutputs[0],
					},
				},
				ImmatureSiacoinOutputs: []consensus.DelayedSiacoinOutputDiff{{
					ID: giftTxn.SiafundOutputID(0).ClaimOutputID(),
					Output: types.SiacoinOutput{
						Value:   types.NewCurrency64(0),
						Address: txn.SiafundInputs[0].ClaimAddress,
					},
					MaturityHeight: cm.TipState().MaturityHeight() - 1,
					Source:         consensus.OutputSourceSiafundClaim,
				}},
			}},
			ImmatureSiacoinOutputs: []consensus.DelayedSiacoinOutputDiff{
				{
					ID:             b2.ID().MinerOutputID(0),
					Output:         b2.MinerPayouts[0],
					MaturityHeight: cm.TipState().MaturityHeight() - 1,
					Source:         consensus.OutputSourceMiner,
				},
			},
		}
		if !reflect.DeepEqual(s.cau, expect) {
			t.Fatalf("diff doesn't match: %v vs %v", s.cau, expect)
		}
	}

	if err := db.View(checkDBOutputs(txn)); err != nil {
		t.Fatal(err)
	}

	if err := dbStore.RevertDiff(cm.TipState(), *s.cau); err != nil {
		t.Fatal(err)
	}

	if err := db.View(checkDBOutputs(txn)); err == nil {
		t.Fatal("should be missing siacoin/siafund outputs from reverted block")
	}
}

func TestConsensusValidate(t *testing.T) {
	db := NewMemDB()

	privateKey := types.GeneratePrivateKey()

	giftAddress := privateKey.PublicKey().StandardAddress()
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
	genesisBlock := types.Block{
		Transactions: []types.Transaction{giftTxn},
	}

	cc, _ := TestnetZen()
	// speed up getting to the foundation hardfork point
	cc.HardforkASIC.OakTarget = types.BlockID{0: 1}
	cc.InitialTarget = types.BlockID{0xFF}

	dbStore, checkpoint, err := NewDBStore(db, cc, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}

	cm := NewManager(dbStore, checkpoint.State)
	if err := db.View(checkDBOutputs(giftTxn)); err != nil {
		t.Fatal(err)
	}

	var s diffSubscriber
	if err := cm.AddSubscriber(&s, cm.Tip()); err != nil {
		t.Fatal(err)
	}

	// block with nothing except block reward
	b1 := types.Block{
		ParentID:  genesisBlock.ID(),
		Timestamp: time.Now(),
	}
	if err := addBlock(cm, &b1); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		b1 = types.Block{
			ParentID:  b1.ID(),
			Timestamp: time.Now(),
		}
		if err := addBlock(cm, &b1); err != nil {
			t.Fatal(err)
		}
	}

	// block that spends part of the gift transaction
	txnB2 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{
				ParentID:         giftTxn.SiacoinOutputID(0),
				UnlockConditions: privateKey.PublicKey().StandardUnlockConditions(),
			},
		},
		SiafundInputs: []types.SiafundInput{
			{
				ParentID:         giftTxn.SiafundOutputID(0),
				ClaimAddress:     types.VoidAddress,
				UnlockConditions: privateKey.PublicKey().StandardUnlockConditions(),
			},
		},
		SiacoinOutputs: []types.SiacoinOutput{
			{Value: giftAmountSC.Div64(2), Address: giftAddress},
			{Value: giftAmountSC.Div64(2), Address: types.VoidAddress},
		},
		SiafundOutputs: []types.SiafundOutput{
			{Value: giftAmountSF / 2, Address: giftAddress},
			{Value: giftAmountSF / 2, Address: types.VoidAddress},
		},
	}
	signTxn(cm.TipState(), privateKey, &txnB2)

	cs := cm.TipState()
	b2 := types.Block{
		ParentID:     b1.ID(),
		Timestamp:    time.Now(),
		Transactions: []types.Transaction{txnB2},
	}
	if err := addBlock(cm, &b2); err != nil {
		t.Fatal(err)
	}
	if err := db.View(checkDBOutputs(txnB2)); err != nil {
		t.Fatal(err)
	}

	cs = cm.TipState()
	txnB3 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{
				ParentID:         txnB2.SiacoinOutputID(0),
				UnlockConditions: privateKey.PublicKey().StandardUnlockConditions(),
			},
		},
		SiafundInputs: []types.SiafundInput{
			{
				ParentID:         txnB2.SiafundOutputID(0),
				ClaimAddress:     types.VoidAddress,
				UnlockConditions: privateKey.PublicKey().StandardUnlockConditions(),
			},
		},
		SiacoinOutputs: []types.SiacoinOutput{
			{Value: giftAmountSC.Div64(4), Address: giftAddress},
			{Value: giftAmountSC.Div64(4), Address: types.VoidAddress},
		},
		SiafundOutputs: []types.SiafundOutput{
			{Value: giftAmountSF / 4, Address: giftAddress},
			{Value: giftAmountSF / 4, Address: types.VoidAddress},
		},
	}

	b3 := types.Block{
		ParentID:     b2.ID(),
		Timestamp:    time.Now(),
		Transactions: []types.Transaction{txnB3},
		MinerPayouts: []types.SiacoinOutput{{
			Address: types.VoidAddress,
			Value:   cs.BlockReward(),
		}},
	}

	{
		tests := []struct {
			desc    string
			corrupt func(*types.Block)
		}{
			{
				"wrong parent ID",
				func(b *types.Block) {
					b.ParentID[0] ^= 255
				},
			},
			{
				"wrong timestamp",
				func(b *types.Block) {
					b.Timestamp = b.Timestamp.AddDate(-1, 0, 0)
				},
			},
			{
				"no miner payout",
				func(b *types.Block) {
					b.MinerPayouts = nil
				},
			},
			{
				"zero miner payout",
				func(b *types.Block) {
					b.MinerPayouts = []types.SiacoinOutput{{
						Address: types.VoidAddress,
						Value:   types.ZeroCurrency,
					}}
				},
			},
			{
				"incorrect miner payout",
				func(b *types.Block) {
					b.MinerPayouts = []types.SiacoinOutput{{
						Address: types.VoidAddress,
						Value:   cs.BlockReward().Div64(2),
					}}
				},
			},
			{
				"overflowing miner payout",
				func(b *types.Block) {
					b.MinerPayouts = []types.SiacoinOutput{{
						Address: types.VoidAddress,
						Value:   types.Currency{math.MaxUint64, math.MaxUint64},
					}, {
						Address: types.VoidAddress,
						Value:   types.Currency{math.MaxUint64, math.MaxUint64},
					}}
				},
			},
		}
		for _, test := range tests {
			corruptBlock, err := deepCopyBlock(b3)
			if err != nil {
				t.Fatal(err)
			}
			test.corrupt(&corruptBlock)
			signTxn(cm.TipState(), privateKey, &corruptBlock.Transactions[0])
			FindBlockNonce(cs, &corruptBlock)

			if err := dbStore.WithConsensus(func(cstore consensus.Store) error {
				if err := consensus.ValidateBlock(cs, cstore, corruptBlock); err == nil {
					return fmt.Errorf("accepted block with %v", test.desc)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	{
		tests := []struct {
			desc    string
			corrupt func(*types.Transaction)
		}{
			{
				"zero-valued SiacoinOutput",
				func(txn *types.Transaction) {
					for i := range txn.SiacoinOutputs {
						txn.SiacoinOutputs[i].Value = types.ZeroCurrency
					}
					txn.SiacoinInputs = nil
					return
				},
			},
			{
				"zero-valued SiafundOutput",
				func(txn *types.Transaction) {
					for i := range txn.SiafundOutputs {
						txn.SiafundOutputs[i].Value = 0
					}
					txn.SiafundInputs = nil
					return
				},
			},
			{
				"zero-valued MinerFee",
				func(txn *types.Transaction) {
					txn.MinerFees = append(txn.MinerFees, types.ZeroCurrency)
					return
				},
			},
			{
				"overflowing MinerFees",
				func(txn *types.Transaction) {
					txn.MinerFees = append(txn.MinerFees, types.Currency{math.MaxUint64, math.MaxUint64})
					txn.MinerFees = append(txn.MinerFees, types.Currency{math.MaxUint64, math.MaxUint64})
					return
				},
			},
			{
				"siacoin outputs exceed inputs",
				func(txn *types.Transaction) {
					txn.SiacoinOutputs[0].Value = txn.SiacoinOutputs[0].Value.Add(types.NewCurrency64(1))
					return
				},
			},
			{
				"siacoin outputs less than inputs",
				func(txn *types.Transaction) {
					txn.SiacoinOutputs[0].Value = txn.SiacoinOutputs[0].Value.Sub(types.NewCurrency64(1))
					return
				},
			},
			{
				"siafund outputs exceed inputs",
				func(txn *types.Transaction) {
					txn.SiafundOutputs[0].Value = txn.SiafundOutputs[0].Value + 1
					return
				},
			},
			{
				"siafund outputs less than inputs",
				func(txn *types.Transaction) {
					txn.SiafundOutputs[0].Value = txn.SiafundOutputs[0].Value - 1
					return
				},
			},
			{
				"two of the same siacoin input",
				func(txn *types.Transaction) {
					txn.SiacoinInputs = append(txn.SiacoinInputs, txn.SiacoinInputs[0])
					return
				},
			},
			{
				"two of the same siafund input",
				func(txn *types.Transaction) {
					txn.SiafundInputs = append(txn.SiafundInputs, txn.SiafundInputs[0])
					return
				},
			},
			{
				"already spent siacoin input",
				func(txn *types.Transaction) {
					txn.SiacoinInputs = append([]types.SiacoinInput(nil), txnB2.SiacoinInputs...)
					return
				},
			},
			{
				"already spent siafund input",
				func(txn *types.Transaction) {
					txn.SiafundInputs = append([]types.SiafundInput(nil), txnB2.SiafundInputs...)
					return
				},
			},
			{
				"siacoin input claiming incorrect unlock conditions",
				func(txn *types.Transaction) {
					txn.SiacoinInputs[0].UnlockConditions.PublicKeys[0].Key[0] ^= 255
					return
				},
			},
			{
				"siafund input claiming incorrect unlock conditions",
				func(txn *types.Transaction) {
					txn.SiafundInputs[0].UnlockConditions.PublicKeys[0].Key[0] ^= 255
					return
				},
			},
			{
				"improperly-encoded FoundationAddressUpdate",
				func(txn *types.Transaction) {
					txn.ArbitraryData = append(txn.ArbitraryData, append(types.SpecifierFoundation[:], []byte{255, 255, 255, 255, 255}...))
					return
				},
			},
			{
				"uninitialized FoundationAddressUpdate",
				func(txn *types.Transaction) {
					var buf bytes.Buffer
					e := types.NewEncoder(&buf)
					types.FoundationAddressUpdate{}.EncodeTo(e)
					e.Flush()
					txn.ArbitraryData = append(txn.ArbitraryData, append(types.SpecifierFoundation[:], buf.Bytes()...))
					return
				},
			},
			{
				"unsigned FoundationAddressUpdate",
				func(txn *types.Transaction) {
					var buf bytes.Buffer
					e := types.NewEncoder(&buf)
					types.FoundationAddressUpdate{giftAddress, giftAddress}.EncodeTo(e)
					e.Flush()
					txn.ArbitraryData = append(txn.ArbitraryData, append(types.SpecifierFoundation[:], buf.Bytes()...))
					return
				},
			},
		}
		for _, test := range tests {
			corruptBlock, err := deepCopyBlock(b3)
			if err != nil {
				t.Fatal(err)
			}
			test.corrupt(&corruptBlock.Transactions[0])
			signTxn(cm.TipState(), privateKey, &corruptBlock.Transactions[0])
			FindBlockNonce(cs, &corruptBlock)

			if err := dbStore.WithConsensus(func(cstore consensus.Store) error {
				if err := consensus.ValidateBlock(cs, cstore, corruptBlock); err == nil {
					return fmt.Errorf("accepted block with %v", test.desc)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
}
