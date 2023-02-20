package chainutil

import (
	"time"

	"go.sia.tech/core/v2/consensus"
	"go.sia.tech/core/v2/types"
)

// FindBlockNonce finds a block nonce meeting the target.
func FindBlockNonce(cs consensus.State, h *types.BlockHeader, target types.BlockID) {
	// ensure nonce meets factor requirement
	for h.Nonce%cs.NonceFactor() != 0 {
		h.Nonce++
	}
	for !h.ID().MeetsTarget(target) {
		h.Nonce += cs.NonceFactor()
	}
}

// JustHeaders renters only the headers of each block.
func JustHeaders(blocks []types.Block) []types.BlockHeader {
	headers := make([]types.BlockHeader, len(blocks))
	for i := range headers {
		headers[i] = blocks[i].Header
	}
	return headers
}

// JustTransactions returns only the transactions of each block.
func JustTransactions(blocks []types.Block) [][]types.Transaction {
	txns := make([][]types.Transaction, len(blocks))
	for i := range txns {
		txns[i] = blocks[i].Transactions
	}
	return txns
}

// JustTransactionIDs returns only the transaction ids included in each block.
func JustTransactionIDs(blocks []types.Block) [][]types.TransactionID {
	txns := make([][]types.TransactionID, len(blocks))
	for i := range txns {
		txns[i] = make([]types.TransactionID, len(blocks[i].Transactions))
		for j := range txns[i] {
			txns[i][j] = blocks[i].Transactions[j].ID()
		}
	}
	return txns
}

// JustChainIndexes returns only the chain index of each block.
func JustChainIndexes(blocks []types.Block) []types.ChainIndex {
	cis := make([]types.ChainIndex, len(blocks))
	for i := range cis {
		cis[i] = blocks[i].Index()
	}
	return cis
}

// ChainSim represents a simulation of a blockchain.
type ChainSim struct {
	Genesis consensus.Checkpoint
	Chain   []types.Block
	State   consensus.State

	nonce uint64 // for distinguishing forks

	// for simulating transactions
	pubkey  types.PublicKey
	privkey types.PrivateKey
	outputs []types.SiacoinElement
}

// Fork forks the current chain.
func (cs *ChainSim) Fork() *ChainSim {
	cs2 := *cs
	cs2.Chain = append([]types.Block(nil), cs2.Chain...)
	cs2.outputs = append([]types.SiacoinElement(nil), cs2.outputs...)
	cs.nonce += 1 << 48
	return &cs2
}

// MineBlockWithTxns mine a block with the given transaction.
func (cs *ChainSim) MineBlockWithTxns(txns ...types.Transaction) types.Block {
	prev := cs.Genesis.Block.Header
	if len(cs.Chain) > 0 {
		prev = cs.Chain[len(cs.Chain)-1].Header
	}
	b := types.Block{
		Header: types.BlockHeader{
			Height:       prev.Height + 1,
			ParentID:     prev.ID(),
			Nonce:        cs.nonce,
			Timestamp:    prev.Timestamp.Add(time.Second),
			MinerAddress: types.VoidAddress,
		},
		Transactions: txns,
	}
	b.Header.Commitment = cs.State.Commitment(b.Header.MinerAddress, b.Transactions)
	FindBlockNonce(cs.State, &b.Header, types.HashRequiringWork(cs.State.Difficulty))

	sau := consensus.ApplyBlock(cs.State, b)
	cs.State = sau.State
	cs.Chain = append(cs.Chain, b)

	// update our outputs
	for i := range cs.outputs {
		sau.UpdateElementProof(&cs.outputs[i].StateElement)
	}
	for _, out := range sau.NewSiacoinElements {
		if out.Address == types.StandardAddress(cs.pubkey) {
			cs.outputs = append(cs.outputs, out)
		}
	}

	return b
}

// MineBlockWithSiacoinOutputs mines a block with a transaction containing the
// specified siacoin outputs. The ChainSim must have funds equal to or exceeding
// the sum of the outputs.
func (cs *ChainSim) MineBlockWithSiacoinOutputs(scos ...types.SiacoinOutput) types.Block {
	txn := types.Transaction{
		SiacoinOutputs: scos,
		MinerFee:       types.NewCurrency64(cs.State.Index.Height),
	}

	totalOut := txn.MinerFee
	for _, b := range scos {
		totalOut = totalOut.Add(b.Value)
	}

	// select inputs and compute change output
	var totalIn types.Currency
	for i, out := range cs.outputs {
		txn.SiacoinInputs = append(txn.SiacoinInputs, types.SiacoinInput{
			Parent:      out,
			SpendPolicy: types.PolicyPublicKey(cs.pubkey),
		})
		totalIn = totalIn.Add(out.Value)
		if totalIn.Cmp(totalOut) >= 0 {
			cs.outputs = cs.outputs[i+1:]
			break
		}
	}

	if totalIn.Cmp(totalOut) < 0 {
		panic("insufficient funds")
	} else if totalIn.Cmp(totalOut) > 0 {
		// add change output
		txn.SiacoinOutputs = append(txn.SiacoinOutputs, types.SiacoinOutput{
			Address: types.StandardAddress(cs.pubkey),
			Value:   totalIn.Sub(totalOut),
		})
	}

	// sign and mine
	sigHash := cs.State.InputSigHash(txn)
	for i := range txn.SiacoinInputs {
		txn.SiacoinInputs[i].Signatures = []types.Signature{cs.privkey.SignHash(sigHash)}
	}
	return cs.MineBlockWithTxns(txn)
}

// MineBlock mine an empty block.
func (cs *ChainSim) MineBlock() types.Block {
	// simulate chain activity by sending our existing outputs to new addresses
	var txns []types.Transaction
	for _, out := range cs.outputs {
		txn := types.Transaction{
			SiacoinInputs: []types.SiacoinInput{{
				Parent:      out,
				SpendPolicy: types.PolicyPublicKey(cs.pubkey),
			}},
			SiacoinOutputs: []types.SiacoinOutput{
				{Address: types.StandardAddress(cs.pubkey), Value: out.Value.Sub(types.NewCurrency64(cs.State.Index.Height + 1))},
				{Address: types.Address{byte(cs.nonce >> 48), byte(cs.nonce >> 56), 1, 2, 3}, Value: types.NewCurrency64(1)},
			},
			MinerFee: types.NewCurrency64(cs.State.Index.Height),
		}
		sigHash := cs.State.InputSigHash(txn)
		for i := range txn.SiacoinInputs {
			txn.SiacoinInputs[i].Signatures = []types.Signature{cs.privkey.SignHash(sigHash)}
		}

		txns = append(txns, txn)
	}
	cs.outputs = cs.outputs[:0]
	return cs.MineBlockWithTxns(txns...)
}

// MineBlocks mine a number of blocks.
func (cs *ChainSim) MineBlocks(n int) []types.Block {
	blocks := make([]types.Block, n)
	for i := range blocks {
		blocks[i] = cs.MineBlock()
	}
	return blocks
}

// NewChainSim returns a new ChainSim useful for simulating forks.
func NewChainSim() *ChainSim {
	// gift ourselves some coins in the genesis block
	privkey := types.GeneratePrivateKey()
	pubkey := privkey.PublicKey()
	ourAddr := types.StandardAddress(pubkey)
	gift := make([]types.SiacoinOutput, 10)
	for i := range gift {
		gift[i] = types.SiacoinOutput{
			Address: ourAddr,
			Value:   types.Siacoins(10 * uint32(i+1)),
		}
	}
	genesisTxns := []types.Transaction{{SiacoinOutputs: gift}}
	genesis := types.Block{
		Header: types.BlockHeader{
			Timestamp: time.Unix(734600000, 0).UTC(),
		},
		Transactions: genesisTxns,
	}
	sau := consensus.GenesisUpdate(genesis, types.Work{NumHashes: [32]byte{31: 4}})
	var outputs []types.SiacoinElement
	for _, out := range sau.NewSiacoinElements {
		if out.Address == types.StandardAddress(pubkey) {
			outputs = append(outputs, out)
		}
	}
	return &ChainSim{
		Genesis: consensus.Checkpoint{
			Block: genesis,
			State: sau.State,
		},
		State:   sau.State,
		privkey: privkey,
		pubkey:  pubkey,
		outputs: outputs,
	}
}
