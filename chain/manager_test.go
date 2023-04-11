package chain

import (
	"reflect"
	"testing"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"lukechampine.com/frand"
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

type historySubscriber struct {
	revertHistory []uint64
	applyHistory  []uint64
}

func (hs *historySubscriber) ProcessChainApplyUpdate(cau *ApplyUpdate, _ bool) error {
	hs.applyHistory = append(hs.applyHistory, cau.State.Index.Height)
	return nil
}

func (hs *historySubscriber) ProcessChainRevertUpdate(cru *RevertUpdate) error {
	hs.revertHistory = append(hs.revertHistory, cru.State.Index.Height)
	return nil
}

func TestManager(t *testing.T) {
	n, genesisBlock := TestnetZen()

	n.InitialTarget = types.BlockID{0xFF}

	store, checkpoint, err := NewDBStore(NewMemDB(), n, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}
	cm := NewManager(store, checkpoint.State)

	var hs historySubscriber
	cm.AddSubscriber(&hs, cm.Tip())

	mine := func(cs consensus.State, n int) (blocks []types.Block) {
		for i := 0; i < n; i++ {
			b := types.Block{
				ParentID:  cs.Index.ID,
				Timestamp: types.CurrentTimestamp(),
				MinerPayouts: []types.SiacoinOutput{{
					Value:   cs.BlockReward(),
					Address: types.Address(frand.Entropy256()),
				}},
			}
			findBlockNonce(cs, &b)
			store.WithConsensus(func(cstore consensus.Store) {
				cs = consensus.ApplyState(cs, cstore, b)
			})
			blocks = append(blocks, b)
		}
		return
	}

	// mine two chains
	chain1 := mine(cm.TipState(), 5)
	chain2 := mine(cm.TipState(), 7)

	// give the lighter chain to the manager, then the heavier chain
	if err := cm.AddBlocks(chain1); err != nil {
		t.Fatal(err)
	}
	if err := cm.AddBlocks(chain2); err != nil {
		t.Fatal(err)
	}

	// subscriber history should show the reorg
	if !reflect.DeepEqual(hs.revertHistory, []uint64{4, 3, 2, 1, 0}) {
		t.Error("lighter chain should have been reverted:", hs.revertHistory)
	} else if !reflect.DeepEqual(hs.applyHistory, []uint64{1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6, 7}) {
		t.Error("both chains should have been applied:", hs.applyHistory)
	}

	// add a subscriber whose tip is in the middle of the lighter chain
	subTip := types.ChainIndex{Height: 3, ID: chain1[3].ParentID}
	var hs2 historySubscriber
	if err := cm.AddSubscriber(&hs2, subTip); err != nil {
		t.Fatal(err)
	}
	// check that the subscriber was properly synced
	if !reflect.DeepEqual(hs2.revertHistory, []uint64{2, 1, 0}) {
		t.Fatal("3 blocks should have been reverted:", hs2.revertHistory)
	} else if !reflect.DeepEqual(hs2.applyHistory, []uint64{1, 2, 3, 4, 5, 6, 7}) {
		t.Fatal("7 blocks should have been applied:", hs2.applyHistory)
	}
}

func TestTxPool(t *testing.T) {
	n, genesisBlock := TestnetZen()

	n.InitialTarget = types.BlockID{0xFF}

	giftPrivateKey := types.GeneratePrivateKey()
	giftPublicKey := giftPrivateKey.PublicKey()
	giftAddress := giftPublicKey.StandardAddress()
	giftAmountSC := types.Siacoins(100)
	giftTxn := types.Transaction{
		SiacoinOutputs: []types.SiacoinOutput{
			{Address: giftAddress, Value: giftAmountSC},
		},
	}
	genesisBlock.Transactions = []types.Transaction{giftTxn}

	store, checkpoint, err := NewDBStore(NewMemDB(), n, genesisBlock)
	if err != nil {
		t.Fatal(err)
	}
	cm := NewManager(store, checkpoint.State)

	signTxn := func(txn *types.Transaction) {
		for _, sci := range txn.SiacoinInputs {
			sig := giftPrivateKey.SignHash(cm.TipState().WholeSigHash(*txn, types.Hash256(sci.ParentID), 0, 0, nil))
			txn.Signatures = append(txn.Signatures, types.TransactionSignature{
				ParentID:       types.Hash256(sci.ParentID),
				CoveredFields:  types.CoveredFields{WholeTransaction: true},
				PublicKeyIndex: 0,
				Signature:      sig[:],
			})
		}
	}

	// add a transaction to the pool
	parentTxn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         giftTxn.SiacoinOutputID(0),
			UnlockConditions: giftPublicKey.StandardUnlockConditions(),
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Address: giftAddress,
			Value:   giftAmountSC,
		}},
	}
	signTxn(&parentTxn)
	if err := cm.AddPoolTransactions([]types.Transaction{parentTxn}); err != nil {
		t.Fatal(err)
	} else if _, ok := cm.PoolTransaction(parentTxn.ID()); !ok {
		t.Fatal("pool should contain parent transaction")
	}

	// add another transaction, dependent on the first
	childTxn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			ParentID:         parentTxn.SiacoinOutputID(0),
			UnlockConditions: giftPublicKey.StandardUnlockConditions(),
		}},
		MinerFees: []types.Currency{giftAmountSC},
	}
	signTxn(&childTxn)
	// submitted alone, it should be rejected
	if err := cm.AddPoolTransactions([]types.Transaction{childTxn}); err == nil {
		t.Fatal("child transaction without parent should be rejected")
	} else if _, ok := cm.PoolTransaction(childTxn.ID()); ok {
		t.Fatal("pool should not contain child transaction")
	}
	// the pool should identify the parent
	if parents := cm.UnconfirmedParents(childTxn); len(parents) != 1 || parents[0].ID() != parentTxn.ID() {
		t.Fatal("pool should identify parent of child transaction")
	}
	// submitted together, the set should be accepted
	if err := cm.AddPoolTransactions([]types.Transaction{parentTxn, childTxn}); err != nil {
		t.Fatal(err)
	} else if _, ok := cm.PoolTransaction(childTxn.ID()); !ok {
		t.Fatal("pool should contain child transaction")
	} else if len(cm.PoolTransactions()) != 2 {
		t.Fatal("pool should contain both transactions")
	}

	// mine a block containing the transactions
	b := types.Block{
		ParentID:  cm.TipState().Index.ID,
		Timestamp: types.CurrentTimestamp(),
		MinerPayouts: []types.SiacoinOutput{{
			Value:   cm.TipState().BlockReward().Add(giftAmountSC),
			Address: types.Address(frand.Entropy256()),
		}},
		Transactions: cm.PoolTransactions(),
	}
	findBlockNonce(cm.TipState(), &b)
	if err := cm.AddBlocks([]types.Block{b}); err != nil {
		t.Fatal(err)
	}

	// the pool should be empty
	if len(cm.PoolTransactions()) != 0 {
		t.Fatal("pool should be empty after mining")
	}
}
