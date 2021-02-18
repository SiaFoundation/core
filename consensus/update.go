package consensus

import (
	"math/big"
	"time"

	"go.sia.tech/core/types"
)

// BlockInterval is the expected wall clock time between consecutive blocks.
const BlockInterval = 10 * time.Minute

// DifficultyAdjustmentInterval is the number of blocks between adjustments to
// the block mining target.
const DifficultyAdjustmentInterval = 2016

func adjustDifficulty(w types.Work, interval time.Duration) types.Work {
	if interval.Round(time.Second) != interval {
		// developer error; interval should be the difference between two Unix
		// timestamps
		panic("interval not rounded to nearest second")
	}
	const maxInterval = BlockInterval * DifficultyAdjustmentInterval * 4
	const minInterval = BlockInterval * DifficultyAdjustmentInterval / 4
	if interval > maxInterval {
		interval = maxInterval
	} else if interval < minInterval {
		interval = minInterval
	}
	workInt := new(big.Int).SetBytes(w.NumHashes[:])
	workInt.Mul(workInt, big.NewInt(int64(BlockInterval*DifficultyAdjustmentInterval)))
	workInt.Div(workInt, big.NewInt(int64(interval)))
	quo := workInt.Bytes()
	copy(w.NumHashes[32-len(quo):], quo)
	return w
}

func applyHeader(vc ValidationContext, h types.BlockHeader) ValidationContext {
	blockWork := types.WorkRequiredForHash(h.ID())
	if h.Height > 0 && h.Height%DifficultyAdjustmentInterval == 0 {
		vc.Difficulty = adjustDifficulty(vc.Difficulty, h.Timestamp.Sub(vc.LastAdjust))
		vc.LastAdjust = h.Timestamp
	}
	vc.TotalWork = vc.TotalWork.Add(blockWork)
	if vc.numTimestamps() == len(vc.PrevTimestamps) {
		copy(vc.PrevTimestamps[:], vc.PrevTimestamps[1:])
	}
	vc.PrevTimestamps[vc.numTimestamps()-1] = h.Timestamp
	vc.Index = h.Index()
	vc.History.AppendLeaf(vc.Index)
	return vc
}

func updatedInBlock(vc ValidationContext, b types.Block) (scos []types.SiacoinOutput, objects []stateObject) {
	addObject := func(so stateObject) {
		// copy proofs so we don't mutate transaction data
		so.proof = append([]types.Hash256(nil), so.proof...)
		objects = append(objects, so)
	}

	for _, txn := range b.Transactions {
		for _, in := range txn.SiacoinInputs {
			scos = append(scos, in.Parent)
			if in.Parent.LeafIndex != types.EphemeralLeafIndex {
				addObject(siacoinOutputStateObject(in.Parent, flagSpent))
			}
		}
	}

	return
}

func createdInBlock(vc ValidationContext, b types.Block) (scos []types.SiacoinOutput, objects []stateObject) {
	flags := make(map[types.OutputID]uint64)
	for _, txn := range b.Transactions {
		for _, in := range txn.SiacoinInputs {
			if in.Parent.LeafIndex == types.EphemeralLeafIndex {
				flags[in.Parent.ID] = flagSpent
			}
		}
	}
	addSiacoinOutput := func(o types.SiacoinOutput) {
		scos = append(scos, o)
		objects = append(objects, siacoinOutputStateObject(o, flags[o.ID]))
	}

	addSiacoinOutput(types.SiacoinOutput{
		ID: types.OutputID{
			TransactionID: types.TransactionID(b.ID()),
			Index:         0,
		},
		Value:    vc.BlockReward(),
		Address:  b.Header.MinerAddress,
		Timelock: vc.BlockRewardTimelock(),
	})
	for _, txn := range b.Transactions {
		txid := txn.ID()
		var index uint64
		nextID := func() types.OutputID {
			id := types.OutputID{
				TransactionID: txid,
				Index:         index,
			}
			index++
			return id
		}

		for _, out := range txn.SiacoinOutputs {
			addSiacoinOutput(types.SiacoinOutput{
				ID:       nextID(),
				Value:    out.Value,
				Address:  out.Address,
				Timelock: 0,
			})
		}
	}

	return
}

// A StateApplyUpdate reflects the changes to consensus state resulting from the
// application of a block.
type StateApplyUpdate struct {
	Context             ValidationContext
	SpentSiacoinOutputs []types.SiacoinOutput
	NewSiacoinOutputs   []types.SiacoinOutput
	updatedObjects      [64][]stateObject
	treeGrowth          [64][]types.Hash256
}

// SiacoinOutputWasSpent returns true if the given SiacoinOutput was spent.
func (sau *StateApplyUpdate) SiacoinOutputWasSpent(o types.SiacoinOutput) bool {
	for i := range sau.SpentSiacoinOutputs {
		if sau.SpentSiacoinOutputs[i].LeafIndex == o.LeafIndex {
			return true
		}
	}
	return false
}

// UpdateSiacoinOutputProof updates the Merkle proof of the supplied output to
// incorporate the changes made to the state tree. The output's proof must be
// up-to-date; if it is not, UpdateSiacoinOutputProof may panic.
func (sau *StateApplyUpdate) UpdateSiacoinOutputProof(o *types.SiacoinOutput) {
	updateProof(o.MerkleProof, o.LeafIndex, &sau.updatedObjects)
	o.MerkleProof = append(o.MerkleProof, sau.treeGrowth[len(o.MerkleProof)]...)
}

// ApplyBlock integrates a block into the current consensus state, producing
// a StateApplyUpdate detailing the resulting changes. The block is assumed to
// be fully validated.
func ApplyBlock(vc ValidationContext, b types.Block) (sau StateApplyUpdate) {
	sau.Context = applyHeader(vc, b.Header)

	var updated, created []stateObject
	sau.SpentSiacoinOutputs, updated = updatedInBlock(vc, b)
	sau.NewSiacoinOutputs, created = createdInBlock(vc, b)

	sau.updatedObjects = sau.Context.State.updateExistingObjects(updated)
	sau.treeGrowth = sau.Context.State.addNewObjects(created)
	for i := range sau.NewSiacoinOutputs {
		sau.NewSiacoinOutputs[i].LeafIndex = created[0].leafIndex
		sau.NewSiacoinOutputs[i].MerkleProof = created[0].proof
		created = created[1:]
	}

	return
}

// GenesisUpdate returns the StateApplyUpdate for the genesis block b.
func GenesisUpdate(b types.Block, initialDifficulty types.Work) StateApplyUpdate {
	return ApplyBlock(ValidationContext{
		Difficulty: initialDifficulty,
		LastAdjust: b.Header.Timestamp,
	}, b)
}

// A StateRevertUpdate reflects the changes to consensus state resulting from the
// removal of a block.
type StateRevertUpdate struct {
	Context             ValidationContext
	SpentSiacoinOutputs []types.SiacoinOutput
	NewSiacoinOutputs   []types.SiacoinOutput
	updatedObjects      [64][]stateObject
}

// SiacoinOutputWasRemoved returns true if the specified SiacoinOutput was
// reverted.
func (sru *StateRevertUpdate) SiacoinOutputWasRemoved(o types.SiacoinOutput) bool {
	return o.LeafIndex >= sru.Context.State.NumLeaves
}

// UpdateSiacoinOutputProof updates the Merkle proof of the supplied output to
// incorporate the changes made to the state tree. The output's proof must be
// up-to-date; if it is not, UpdateSiacoinOutputProof may panic.
func (sru *StateRevertUpdate) UpdateSiacoinOutputProof(o *types.SiacoinOutput) {
	if mh := mergeHeight(sru.Context.State.NumLeaves, o.LeafIndex); mh <= len(o.MerkleProof) {
		o.MerkleProof = o.MerkleProof[:mh-1]
	}
	updateProof(o.MerkleProof, o.LeafIndex, &sru.updatedObjects)
}

// RevertBlock produces a StateRevertUpdate from a block and the
// ValidationContext prior to that block.
func RevertBlock(vc ValidationContext, b types.Block) (sru StateRevertUpdate) {
	sru.Context = vc
	sru.SpentSiacoinOutputs, _ = updatedInBlock(vc, b)
	sru.NewSiacoinOutputs, _ = createdInBlock(vc, b)
	sru.updatedObjects = objectsByTree(b.Transactions)
	return
}
