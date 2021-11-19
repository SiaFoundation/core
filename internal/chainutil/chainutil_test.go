package chainutil

import (
	"go.sia.tech/core/types"
	"lukechampine.com/frand"
	"reflect"
	"testing"
)

func TestJust(t *testing.T) {
	headers := []types.BlockHeader{{Height: 0}, {Height: 1}}
	chainIndexes := []types.ChainIndex{headers[0].Index(), headers[1].Index()}
	transactions := [][]types.Transaction{{{ArbitraryData: []byte("test")}}, {{MinerFee: types.NewCurrency64(1)}}}
	transactionIDs := [][]types.TransactionID{{transactions[0][0].ID()}, {transactions[1][0].ID()}}
	blocks := []types.Block{
		{Header: headers[0], Transactions: transactions[0]},
		{Header: headers[1], Transactions: transactions[1]},
	}

	if !reflect.DeepEqual(headers, JustHeaders(blocks)) {
		t.Fatal("block header slice does not equal slice returned by JustHeaders")
	}
	if !reflect.DeepEqual(transactions, JustTransactions(blocks)) {
		t.Fatal("transactions slice does not equal slice returned by JustTransactions")
	}
	if !reflect.DeepEqual(transactionIDs, JustTransactionIDs(blocks)) {
		t.Fatal("transactionIDs slice does not equal slice returned by JustTransactionIDs")
	}
	if !reflect.DeepEqual(chainIndexes, JustChainIndexes(blocks)) {
		t.Fatal("chainIndexes slice does not equal slice returned by JustChainIndexes")
	}
}

func TestChainSim(t *testing.T) {
	sim := NewChainSim()

	for i := 0; i < 5; i++ {
		height := uint64(i + 1)
		block := sim.MineBlock()

		if height != block.Header.Height {
			t.Fatalf("invalid block height: expected %d, got %d", height, block.Header.Height)
		}
		if block.Index() != sim.Context.Index {
			t.Fatalf("simulation index not updated, expected %v, got %v", block.Index(), sim.Context.Index)
		}
	}

	var address types.Address
	frand.Read(address[:])

	// these amounts are below the gift amounts specified in NewChainSim
	outputs := []types.SiacoinOutput{{Address: address, Value: types.NewCurrency64(1)}, {Address: address, Value: types.NewCurrency64(10)}}
	block := sim.MineBlockWithSiacoinOutputs(outputs...)
	found := false
	for _, txn := range block.Transactions {
		for _, output := range txn.SiacoinOutputs {
			if output.Address == address {
				found = true
				break
			}
		}
	}
	if !found {
		t.Fatal("siacoinoutputs to address were not found despite block being mined")
	}

	fork := sim.Fork()
	if sim.Context.Index != fork.Context.Index {
		t.Fatalf("forked chain did not have same index as original chain, expected %v, got %v", sim.Context.Index, fork.Context.Index)
	}

	lastIndex := sim.Context.Index
	sim.MineBlock()
	if sim.Context.Index == fork.Context.Index {
		t.Fatalf("fork incorrectly updated along with original chain, expected %v, got %v", lastIndex, fork.Context.Index)
	}

	lastIndex = sim.Context.Index
	fork.MineBlocks(2)
	if sim.Context.Index == fork.Context.Index {
		t.Fatalf("original chain incorrectly updated along with fork chain, expected %v, got %v", lastIndex, sim.Context.Index)
	}
}
