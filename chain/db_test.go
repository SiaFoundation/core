package chain

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"go.sia.tech/core/consensus"
	rhpv2 "go.sia.tech/core/rhp/v2"
	"go.sia.tech/core/types"
)

func findBlockNonce(cs consensus.State, b *types.Block) {
	// ensure nonce meets factor requirement
	for b.Nonce%cs.NonceFactor() != 0 {
		b.Nonce++
	}
	for b.ID().CmpWork(cs.ChildTarget) < 0 {
		b.Nonce += cs.NonceFactor()
	}
}

func addBlock(cm *Manager, b types.Block) error {
	findBlockNonce(cm.TipState(), &b)
	return cm.AddBlocks([]types.Block{b})
}

func deepCopyBlock(b types.Block) (b2 types.Block) {
	var buf bytes.Buffer
	e := types.NewEncoder(&buf)
	b.EncodeTo(e)
	e.Flush()
	d := types.NewBufDecoder(buf.Bytes())
	b2.DecodeFrom(d)
	return
}

func signTxn(cs consensus.State, key types.PrivateKey, txn *types.Transaction) {
	appendSig := func(parentID types.Hash256) {
		sig := key.SignHash(cs.WholeSigHash(*txn, parentID, 0, 0, nil))
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
		ParentID:     genesisBlock.ID(),
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.SiacoinOutput{{Address: types.VoidAddress, Value: cm.TipState().BlockReward()}},
	}
	if err := addBlock(cm, b1); err != nil {
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
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.SiacoinOutput{{Address: types.VoidAddress, Value: cm.TipState().BlockReward()}},
		Transactions: []types.Transaction{txn},
	}
	if err := addBlock(cm, b2); err != nil {
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

	dbStore.RevertDiff(cm.TipState(), *s.cau)

	if err := db.View(checkDBOutputs(txn)); err == nil {
		t.Fatal("should be missing siacoin/siafund outputs from reverted block")
	}
}

func TestConsensusValidate(t *testing.T) {
	db := NewMemDB()

	giftPrivateKey := types.GeneratePrivateKey()
	hostPrivateKey := types.GeneratePrivateKey()
	renterPrivateKey := types.GeneratePrivateKey()

	giftPublicKey := giftPrivateKey.PublicKey()
	hostPublicKey := hostPrivateKey.PublicKey()

	giftAddress := giftPublicKey.StandardAddress()
	giftAmountSC := types.Siacoins(100)
	giftAmountSF := uint64(100)

	giftFC := rhpv2.PrepareContractFormation(renterPrivateKey, hostPublicKey, types.Siacoins(1), types.Siacoins(1), 0, rhpv2.HostSettings{}, types.VoidAddress)
	giftFC.WindowEnd += 100
	giftFC.UnlockHash = types.Hash256(giftPublicKey.StandardUnlockConditions().UnlockHash())

	giftTxn := types.Transaction{
		SiacoinOutputs: []types.SiacoinOutput{
			{Address: giftAddress, Value: giftAmountSC},
		},
		SiafundOutputs: []types.SiafundOutput{
			{Address: giftAddress, Value: giftAmountSF},
		},
		FileContracts: []types.FileContract{giftFC},
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
		ParentID:     genesisBlock.ID(),
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.SiacoinOutput{{Address: types.VoidAddress, Value: cm.TipState().BlockReward()}},
	}
	if err := addBlock(cm, b1); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		b1 = types.Block{
			ParentID:     b1.ID(),
			Timestamp:    types.CurrentTimestamp(),
			MinerPayouts: []types.SiacoinOutput{{Address: types.VoidAddress, Value: cm.TipState().BlockReward()}},
		}
		if err := addBlock(cm, b1); err != nil {
			t.Fatal(err)
		}
	}

	// block that spends part of the gift transaction
	txnB2 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{
				ParentID:         giftTxn.SiacoinOutputID(0),
				UnlockConditions: giftPublicKey.StandardUnlockConditions(),
			},
		},
		SiafundInputs: []types.SiafundInput{
			{
				ParentID:         giftTxn.SiafundOutputID(0),
				ClaimAddress:     types.VoidAddress,
				UnlockConditions: giftPublicKey.StandardUnlockConditions(),
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
	signTxn(cm.TipState(), giftPrivateKey, &txnB2)

	cs := cm.TipState()
	b2 := types.Block{
		ParentID:     b1.ID(),
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.SiacoinOutput{{Address: types.VoidAddress, Value: cm.TipState().BlockReward()}},
		Transactions: []types.Transaction{txnB2},
	}
	if err := addBlock(cm, b2); err != nil {
		t.Fatal(err)
	}
	if err := db.View(checkDBOutputs(txnB2)); err != nil {
		t.Fatal(err)
	}

	cs = cm.TipState()
	fc := rhpv2.PrepareContractFormation(renterPrivateKey, hostPublicKey, types.Siacoins(1), types.Siacoins(1), cs.Index.Height+1, rhpv2.HostSettings{}, types.VoidAddress)
	fc.WindowEnd += 100
	fc.UnlockHash = types.Hash256(giftPublicKey.StandardUnlockConditions().UnlockHash())

	revision := giftFC
	revision.RevisionNumber++
	revision.WindowStart = cs.Index.Height + 1
	revision.WindowEnd = revision.WindowStart + 100

	txnB3 := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{
				ParentID:         txnB2.SiacoinOutputID(0),
				UnlockConditions: giftPublicKey.StandardUnlockConditions(),
			},
		},
		SiafundInputs: []types.SiafundInput{
			{
				ParentID:         txnB2.SiafundOutputID(0),
				ClaimAddress:     types.VoidAddress,
				UnlockConditions: giftPublicKey.StandardUnlockConditions(),
			},
		},
		SiacoinOutputs: []types.SiacoinOutput{
			{Value: giftAmountSC.Div64(2).Sub(fc.Payout), Address: giftAddress},
		},
		SiafundOutputs: []types.SiafundOutput{
			{Value: giftAmountSF / 4, Address: giftAddress},
			{Value: giftAmountSF / 4, Address: types.VoidAddress},
		},
		FileContracts: []types.FileContract{fc},
		FileContractRevisions: []types.FileContractRevision{
			{
				ParentID:         giftTxn.FileContractID(0),
				UnlockConditions: giftPublicKey.StandardUnlockConditions(),
				FileContract:     revision,
			},
		},
	}

	b3 := types.Block{
		ParentID:     b2.ID(),
		Timestamp:    types.CurrentTimestamp(),
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
				"weight that exceeds the limit",
				func(b *types.Block) {
					data := make([]byte, cs.MaxBlockWeight())
					b.Transactions = append(b.Transactions, types.Transaction{
						ArbitraryData: [][]byte{data},
					})
				},
			},
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
					b.MinerPayouts = []types.SiacoinOutput{
						{Address: types.VoidAddress, Value: types.MaxCurrency},
						{Address: types.VoidAddress, Value: types.MaxCurrency},
					}
				},
			},
		}
		for _, test := range tests {
			corruptBlock := deepCopyBlock(b3)
			test.corrupt(&corruptBlock)
			signTxn(cm.TipState(), giftPrivateKey, &corruptBlock.Transactions[0])
			findBlockNonce(cs, &corruptBlock)

			dbStore.WithConsensus(func(cstore consensus.Store) {
				if err := consensus.ValidateBlock(cs, cstore, corruptBlock); err == nil {
					t.Fatalf("accepted block with %v", test.desc)
				}
			})
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
					txn.FileContracts = nil
				},
			},
			{
				"zero-valued SiafundOutput",
				func(txn *types.Transaction) {
					for i := range txn.SiafundOutputs {
						txn.SiafundOutputs[i].Value = 0
					}
					txn.SiafundInputs = nil
				},
			},
			{
				"zero-valued MinerFee",
				func(txn *types.Transaction) {
					txn.MinerFees = append(txn.MinerFees, types.ZeroCurrency)
				},
			},
			{
				"overflowing MinerFees",
				func(txn *types.Transaction) {
					txn.MinerFees = append(txn.MinerFees, types.MaxCurrency)
					txn.MinerFees = append(txn.MinerFees, types.MaxCurrency)
				},
			},
			{
				"siacoin outputs exceed inputs",
				func(txn *types.Transaction) {
					txn.SiacoinOutputs[0].Value = txn.SiacoinOutputs[0].Value.Add(types.NewCurrency64(1))
				},
			},
			{
				"siacoin outputs less than inputs",
				func(txn *types.Transaction) {
					txn.SiacoinOutputs[0].Value = txn.SiacoinOutputs[0].Value.Sub(types.NewCurrency64(1))
				},
			},
			{
				"siafund outputs exceed inputs",
				func(txn *types.Transaction) {
					txn.SiafundOutputs[0].Value = txn.SiafundOutputs[0].Value + 1
				},
			},
			{
				"siafund outputs less than inputs",
				func(txn *types.Transaction) {
					txn.SiafundOutputs[0].Value = txn.SiafundOutputs[0].Value - 1
				},
			},
			{
				"two of the same siacoin input",
				func(txn *types.Transaction) {
					txn.SiacoinInputs = append(txn.SiacoinInputs, txn.SiacoinInputs[0])
				},
			},
			{
				"two of the same siafund input",
				func(txn *types.Transaction) {
					txn.SiafundInputs = append(txn.SiafundInputs, txn.SiafundInputs[0])
				},
			},
			{
				"already spent siacoin input",
				func(txn *types.Transaction) {
					txn.SiacoinInputs = append([]types.SiacoinInput(nil), txnB2.SiacoinInputs...)
				},
			},
			{
				"already spent siafund input",
				func(txn *types.Transaction) {
					txn.SiafundInputs = append([]types.SiafundInput(nil), txnB2.SiafundInputs...)
				},
			},
			{
				"siacoin input claiming incorrect unlock conditions",
				func(txn *types.Transaction) {
					txn.SiacoinInputs[0].UnlockConditions.PublicKeys[0].Key[0] ^= 255
				},
			},
			{
				"siafund input claiming incorrect unlock conditions",
				func(txn *types.Transaction) {
					txn.SiafundInputs[0].UnlockConditions.PublicKeys[0].Key[0] ^= 255
				},
			},
			{
				"improperly-encoded FoundationAddressUpdate",
				func(txn *types.Transaction) {
					txn.ArbitraryData = append(txn.ArbitraryData, append(types.SpecifierFoundation[:], []byte{255, 255, 255, 255, 255}...))
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
				},
			},
			{
				"unsigned FoundationAddressUpdate",
				func(txn *types.Transaction) {
					var buf bytes.Buffer
					e := types.NewEncoder(&buf)
					types.FoundationAddressUpdate{
						NewPrimary:  giftAddress,
						NewFailsafe: giftAddress,
					}.EncodeTo(e)
					e.Flush()
					txn.ArbitraryData = append(txn.ArbitraryData, append(types.SpecifierFoundation[:], buf.Bytes()...))
				},
			},
			{
				"window that starts in the past",
				func(txn *types.Transaction) {
					txn.FileContracts[0].WindowStart = 0
				},
			},
			{
				"window that ends before it begins",
				func(txn *types.Transaction) {
					txn.FileContracts[0].WindowStart = txn.FileContracts[0].WindowEnd
				},
			},
			{
				"valid payout that does not equal missed payout",
				func(txn *types.Transaction) {
					txn.FileContracts[0].ValidProofOutputs[0].Value = txn.FileContracts[0].ValidProofOutputs[0].Value.Add(types.Siacoins(1))
				},
			},
			{
				"incorrect payout tax",
				func(txn *types.Transaction) {
					txn.SiacoinOutputs[0].Value = txn.SiacoinOutputs[0].Value.Add(types.Siacoins(1))
					txn.FileContracts[0].Payout = txn.FileContracts[0].Payout.Sub(types.Siacoins(1))
				},
			},
			{
				"revision with window that starts in past",
				func(txn *types.Transaction) {
					txn.FileContractRevisions[0].WindowStart = cs.Index.Height
				},
			},
			{
				"revision with window that ends before it begins",
				func(txn *types.Transaction) {
					txn.FileContractRevisions[0].WindowStart = txn.FileContractRevisions[0].WindowEnd
				},
			},
			{
				"revision with lower revision number than its parent",
				func(txn *types.Transaction) {
					txn.FileContractRevisions[0].RevisionNumber = 0
				},
			},
			{
				"revision claiming incorrect unlock conditions",
				func(txn *types.Transaction) {
					txn.FileContractRevisions[0].UnlockConditions.PublicKeys[0].Key[0] ^= 255
				},
			},
			{
				"revision having different valid payout sum",
				func(txn *types.Transaction) {
					txn.FileContractRevisions[0].ValidProofOutputs = append(txn.FileContractRevisions[0].ValidProofOutputs, types.SiacoinOutput{
						Value: types.Siacoins(1),
					})
				},
			},
			{
				"revision having different missed payout sum",
				func(txn *types.Transaction) {
					txn.FileContractRevisions[0].MissedProofOutputs = append(txn.FileContractRevisions[0].MissedProofOutputs, types.SiacoinOutput{
						Value: types.Siacoins(1),
					})
				},
			},
			{
				"conflicting revisions in same transaction",
				func(txn *types.Transaction) {
					newRevision := txn.FileContractRevisions[0]
					newRevision.RevisionNumber++
					txn.FileContractRevisions = append(txn.FileContractRevisions, newRevision)
				},
			},
		}
		for _, test := range tests {
			corruptBlock := deepCopyBlock(b3)
			test.corrupt(&corruptBlock.Transactions[0])
			signTxn(cm.TipState(), giftPrivateKey, &corruptBlock.Transactions[0])
			findBlockNonce(cs, &corruptBlock)

			dbStore.WithConsensus(func(cstore consensus.Store) {
				if err := consensus.ValidateBlock(cs, cstore, corruptBlock); err == nil {
					t.Fatalf("accepted block with %v", test.desc)
				}
			})
		}
	}
}
