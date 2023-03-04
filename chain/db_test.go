package chain

import (
	"fmt"
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

	cc, _ := Mainnet()
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

	chainStates := []consensus.State{cm.TipState()}

	// block with nothing except block reward
	b1 := types.Block{
		ParentID:  genesisBlock.ID(),
		Timestamp: time.Now(),
	}
	if err := addBlock(cm, &b1); err != nil {
		t.Fatal(err)
	}
	chainStates = append(chainStates, cm.TipState())

	{
		expect := &consensus.BlockDiff{
			ImmatureSiacoinOutputs: []consensus.DelayedSiacoinOutputDiff{
				{
					ID:             b1.ID().MinerOutputID(0),
					Output:         b1.MinerPayouts[0],
					MaturityHeight: chainStates[len(chainStates)-1-1].MaturityHeight(),
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
	for i := range txn.SiacoinInputs {
		AppendTransactionSignature(cm.TipState(), privateKey, types.Hash256(txn.SiacoinInputs[i].ParentID), &txn)
	}
	for i := range txn.SiafundInputs {
		AppendTransactionSignature(cm.TipState(), privateKey, types.Hash256(txn.SiafundInputs[i].ParentID), &txn)
	}

	b2 := types.Block{
		ParentID:     b1.ID(),
		Timestamp:    time.Now(),
		Transactions: []types.Transaction{txn},
	}
	if err := addBlock(cm, &b2); err != nil {
		t.Fatal(err)
	}
	chainStates = append(chainStates, cm.TipState())

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
					MaturityHeight: chainStates[len(chainStates)-1-1].MaturityHeight(),
					Source:         consensus.OutputSourceSiafundClaim,
				}},
			}},
			ImmatureSiacoinOutputs: []consensus.DelayedSiacoinOutputDiff{
				{
					ID:             b2.ID().MinerOutputID(0),
					Output:         b2.MinerPayouts[0],
					MaturityHeight: chainStates[len(chainStates)-1-1].MaturityHeight(),
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
		t.Fatal("should be missing siacoin outputs from reverted block")
	}
}
