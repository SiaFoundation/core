package consensus

import (
	"math"
	"reflect"
	"testing"

	"go.sia.tech/core/types"
	"lukechampine.com/frand"
)

func randAddr() types.Address {
	return frand.Entropy256()
}

func randAmount() types.Currency {
	return types.NewCurrency(
		frand.Uint64n(math.MaxUint64),
		frand.Uint64n(math.MaxUint64),
	)
}

func TestBlockRewardValue(t *testing.T) {
	reward := func(height uint64) types.Currency {
		return (&ValidationContext{Index: types.ChainIndex{Height: height - 1}}).BlockReward()
	}

	tests := []struct {
		height uint64
		exp    string
	}{
		{0, "300000"},
		{1, "299999"},
		{100000, "200000"},
		{269999, "30001"},
		{270000, "30000"},
		{270001, "30000"},
		{1e6, "30000"},
	}
	for _, test := range tests {
		got := reward(test.height)
		if got.String() != test.exp {
			t.Errorf("expected %v, got %v", test.exp, got)
		}
	}
}

func TestAccumulator(t *testing.T) {
	containsOutput := func(sa StateAccumulator, o types.SiacoinOutput, flags uint64) bool {
		return sa.containsObject(siacoinOutputStateObject(o, flags))
	}

	b := genesisWithBeneficiaries([]types.Beneficiary{
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
	}...)
	update1 := GenesisUpdate(b, testingDifficulty)
	origOutputs := update1.NewSiacoinOutputs
	if len(origOutputs) != len(b.Transactions[0].SiacoinOutputs)+1 {
		t.Fatalf("expected %v new outputs, got %v", len(b.Transactions[0].SiacoinOutputs)+1, len(origOutputs))
	}
	// none of the outputs should be marked as spent
	for _, o := range origOutputs {
		if update1.SiacoinOutputWasSpent(o) {
			t.Error("update should not mark output as spent:", o)
		}
		if containsOutput(update1.Context.State, o, flagSpent) || !containsOutput(update1.Context.State, o, 0) {
			t.Error("accumulator should contain unspent output:", o)
		}
	}

	// apply a block that spends some outputs
	txn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{Parent: origOutputs[6], SpendPolicy: types.AnyoneCanSpend()},
			{Parent: origOutputs[7], SpendPolicy: types.AnyoneCanSpend()},
			{Parent: origOutputs[8], SpendPolicy: types.AnyoneCanSpend()},
			{Parent: origOutputs[9], SpendPolicy: types.AnyoneCanSpend()},
		},
		SiacoinOutputs: []types.Beneficiary{{
			Value:   randAmount(),
			Address: randAddr(),
		}},
		MinerFee: randAmount(),
	}
	b = types.Block{
		Header: types.BlockHeader{
			Height:       b.Header.Height + 1,
			ParentID:     b.ID(),
			MinerAddress: randAddr(),
		},
		Transactions: []types.Transaction{txn},
	}

	update2 := ApplyBlock(update1.Context, b)
	for i := range origOutputs {
		update2.UpdateSiacoinOutputProof(&origOutputs[i])
	}

	// the update should mark each input as spent
	for _, in := range txn.SiacoinInputs {
		if !update2.SiacoinOutputWasSpent(in.Parent) {
			t.Error("update should mark input as spent:", in)
		}
	}
	// the new accumulator should contain both the spent and unspent outputs
	for _, o := range origOutputs {
		if update2.SiacoinOutputWasSpent(o) {
			if containsOutput(update2.Context.State, o, 0) || !containsOutput(update2.Context.State, o, flagSpent) {
				t.Error("accumulator should contain spent output:", o)
			}
		} else {
			if containsOutput(update2.Context.State, o, flagSpent) || !containsOutput(update2.Context.State, o, 0) {
				t.Error("accumulator should contain unspent output:", o)
			}
		}
	}

	// if we reverted that block, we should see the inputs being "created" again
	// and the outputs being destroyed
	revertUpdate := RevertBlock(update1.Context, b)
	if len(revertUpdate.SpentSiacoinOutputs) != len(txn.SiacoinInputs) {
		t.Error("number of spent outputs after revert should equal number of inputs")
	}
	for _, o := range update2.NewSiacoinOutputs {
		if !revertUpdate.SiacoinOutputWasRemoved(o) {
			t.Error("output created in reverted block should be marked as removed")
		}
	}
	// update (a copy of) the proofs to reflect the revert
	outputsWithRevert := append([]types.SiacoinOutput(nil), origOutputs...)
	for i := range outputsWithRevert {
		outputsWithRevert[i].MerkleProof = append([]types.Hash256(nil), outputsWithRevert[i].MerkleProof...)
		revertUpdate.UpdateSiacoinOutputProof(&outputsWithRevert[i])
	}
	// the reverted proofs should be identical to the proofs prior to b
	for _, o := range outputsWithRevert {
		if update1.SiacoinOutputWasSpent(o) {
			t.Error("update should not mark output as spent:", o)
		}
		if containsOutput(update1.Context.State, o, flagSpent) {
			t.Error("output should not be marked as spent:", o)
		}
	}

	// spend one of the outputs whose proof we've been maintaining,
	// using an intermediary transaction to test "ephemeral" outputs
	parentTxn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{Parent: origOutputs[2], SpendPolicy: types.AnyoneCanSpend()},
		},
		SiacoinOutputs: []types.Beneficiary{{
			Value:   randAmount(),
			Address: randAddr(),
		}},
	}
	childTxn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			Parent: types.SiacoinOutput{
				ID: types.OutputID{
					TransactionID: parentTxn.ID(),
					Index:         0,
				},
				Value:     randAmount(),
				Address:   randAddr(),
				LeafIndex: types.EphemeralLeafIndex,
			},
			SpendPolicy: types.AnyoneCanSpend(),
		}},
		SiacoinOutputs: []types.Beneficiary{{
			Value:   randAmount(),
			Address: randAddr(),
		}},
		MinerFee: randAmount(),
	}

	b = types.Block{
		Header: types.BlockHeader{
			Height:       b.Header.Height + 1,
			ParentID:     b.ID(),
			MinerAddress: randAddr(),
		},
		Transactions: []types.Transaction{parentTxn, childTxn},
	}

	update3 := ApplyBlock(update2.Context, b)
	for i := range origOutputs {
		update3.UpdateSiacoinOutputProof(&origOutputs[i])
	}

	// the update should mark each input as spent
	for _, in := range parentTxn.SiacoinInputs {
		if !update3.SiacoinOutputWasSpent(in.Parent) {
			t.Error("update should mark input as spent:", in)
		}
	}
	// the new accumulator should contain both the spent and unspent outputs
	for _, o := range origOutputs {
		if update2.SiacoinOutputWasSpent(o) || update3.SiacoinOutputWasSpent(o) {
			if containsOutput(update3.Context.State, o, 0) || !containsOutput(update3.Context.State, o, flagSpent) {
				t.Error("accumulator should contain spent output:", o)
			}
		} else {
			if containsOutput(update3.Context.State, o, flagSpent) || !containsOutput(update3.Context.State, o, 0) {
				t.Error("accumulator should contain unspent output:", o)
			}
		}
	}

	// TODO: we should also be checking childTxn, but we can't check the
	// ephemeral output without knowing its index
}

func TestAccumulatorRevert(t *testing.T) {
	containsOutput := func(sa StateAccumulator, o types.SiacoinOutput, flags uint64) bool {
		return sa.containsObject(siacoinOutputStateObject(o, flags))
	}
	b := genesisWithBeneficiaries([]types.Beneficiary{
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
		{Value: randAmount(), Address: randAddr()},
	}...)
	update1 := GenesisUpdate(b, testingDifficulty)
	origOutputs := update1.NewSiacoinOutputs
	if len(origOutputs) != len(b.Transactions[0].SiacoinOutputs)+1 {
		t.Fatalf("expected %v new outputs, got %v", len(b.Transactions[0].SiacoinOutputs)+1, len(origOutputs))
	}

	txn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{
			{Parent: origOutputs[5], SpendPolicy: types.AnyoneCanSpend()},
		},
		SiacoinOutputs: []types.Beneficiary{{
			Value:   randAmount(),
			Address: randAddr(),
		}},
		MinerFee: randAmount(),
	}
	b = types.Block{
		Header: types.BlockHeader{
			Height:       b.Header.Height + 1,
			ParentID:     b.ID(),
			MinerAddress: randAddr(),
		},
		Transactions: []types.Transaction{txn},
	}

	update2 := ApplyBlock(update1.Context, b)
	for i := range origOutputs {
		update2.UpdateSiacoinOutputProof(&origOutputs[i])
	}

	// revert the block. We should see the inputs being "created" again
	// and the outputs being destroyed
	revertUpdate := RevertBlock(update1.Context, b)
	if len(revertUpdate.SpentSiacoinOutputs) != len(txn.SiacoinInputs) {
		t.Error("number of spent outputs after revert should equal number of inputs")
	}
	for _, o := range update2.NewSiacoinOutputs {
		if !revertUpdate.SiacoinOutputWasRemoved(o) {
			t.Error("output created in reverted block should be marked as removed")
		}
	}
	// update the proofs to reflect the revert
	for i := range origOutputs {
		revertUpdate.UpdateSiacoinOutputProof(&origOutputs[i])
	}
	// the reverted proofs should be identical to the proofs prior to b
	for _, o := range origOutputs {
		if update1.SiacoinOutputWasSpent(o) {
			t.Error("update should not mark output as spent:", o)
		}
		if !containsOutput(update1.Context.State, o, 0) {
			t.Error("output should be in the accumulator, marked as unspent:", o)
		}
	}
}

func TestUpdateExistingObjects(t *testing.T) {
	outputs := make([]types.SiacoinOutput, 8)
	objects := make([]stateObject, len(outputs))
	for i := range outputs {
		objects[i] = siacoinOutputStateObject(outputs[i], 0)
	}
	var acc StateAccumulator
	acc.addNewObjects(objects)
	for i := range outputs {
		outputs[i].LeafIndex = objects[i].leafIndex
		outputs[i].MerkleProof = objects[i].proof
	}

	updated := []stateObject{
		siacoinOutputStateObject(outputs[0], flagSpent),
		siacoinOutputStateObject(outputs[2], flagSpent),
		siacoinOutputStateObject(outputs[3], flagSpent),
		siacoinOutputStateObject(outputs[5], flagSpent),
		siacoinOutputStateObject(outputs[6], flagSpent),
	}

	acc.updateExistingObjects(updated)

	var acc2 StateAccumulator
	addOutput := func(o types.SiacoinOutput, flags uint64) {
		// seek to first open slot, merging nodes as we go
		root := siacoinOutputStateObject(o, flags).leafHash()
		i := 0
		for ; acc2.HasTreeAtHeight(i); i++ {
			root = merkleNodeHash(acc2.Trees[i], root)
		}
		acc2.Trees[i] = root
		acc2.NumLeaves++
	}
	for i, o := range outputs {
		switch i {
		case 0, 2, 3, 5, 6:
			addOutput(o, flagSpent)
		default:
			addOutput(o, 0)
		}
	}
	for i := range acc2.Trees {
		if acc2.HasTreeAtHeight(i) {
			if !acc2.HasTreeAtHeight(i) {
				t.Fatal("mismatch")
			}
			if acc2.Trees[i] != acc.Trees[i] {
				t.Fatal("mismatch")
			}
		}
	}
}

func TestMultiproof(t *testing.T) {
	outputs := make([]types.SiacoinOutput, 8)
	leaves := make([]types.Hash256, len(outputs))
	for i := range outputs {
		outputs[i].LeafIndex = uint64(i)
		outputs[i].ID.Index = uint64(i)
		leaves[i] = siacoinOutputStateObject(outputs[i], 0).leafHash()
	}
	node01 := merkleNodeHash(leaves[0], leaves[1])
	node23 := merkleNodeHash(leaves[2], leaves[3])
	node45 := merkleNodeHash(leaves[4], leaves[5])
	node67 := merkleNodeHash(leaves[6], leaves[7])
	node03 := merkleNodeHash(node01, node23)
	node47 := merkleNodeHash(node45, node67)
	outputs[0].MerkleProof = []types.Hash256{leaves[1], node23, node47}
	outputs[1].MerkleProof = []types.Hash256{leaves[0], node23, node47}
	outputs[2].MerkleProof = []types.Hash256{leaves[3], node01, node47}
	outputs[3].MerkleProof = []types.Hash256{leaves[2], node01, node47}
	outputs[4].MerkleProof = []types.Hash256{leaves[5], node67, node03}
	outputs[5].MerkleProof = []types.Hash256{leaves[4], node67, node03}
	outputs[6].MerkleProof = []types.Hash256{leaves[7], node45, node03}
	outputs[7].MerkleProof = []types.Hash256{leaves[6], node45, node03}

	tests := []struct {
		inputs []int
		proof  []types.Hash256
	}{
		{
			inputs: []int{0},
			proof:  []types.Hash256{leaves[1], node23, node47},
		},
		{
			inputs: []int{1, 2, 3},
			proof:  []types.Hash256{leaves[0], node47},
		},
		{
			inputs: []int{7, 6, 0, 2, 3},
			proof:  []types.Hash256{leaves[1], node45},
		},
		{
			inputs: []int{7, 6, 5, 4, 3, 2, 1, 0},
			proof:  nil,
		},
	}
	for _, test := range tests {
		txns := []types.Transaction{{SiacoinInputs: make([]types.SiacoinInput, len(test.inputs))}}
		for i, j := range test.inputs {
			txns[0].SiacoinInputs[i].Parent = outputs[j]
		}

		old := txns[0].DeepCopy()
		// compute multiproof
		proof := ComputeMultiproof(txns)
		if !reflect.DeepEqual(proof, test.proof) {
			t.Error("wrong proof generated")
		}
		for _, txn := range txns {
			for i := range txn.SiacoinInputs {
				txn.SiacoinInputs[i].Parent.MerkleProof = make([]types.Hash256, len(txn.SiacoinInputs[i].Parent.MerkleProof))
			}
		}
		// expand multiproof and check roundtrip
		ExpandMultiproof(txns, proof)
		if !reflect.DeepEqual(txns[0], old) {
			t.Fatal("\n", txns[0], "\n", old)
		}
	}
}

func BenchmarkOutputLeafHash(b *testing.B) {
	var o types.SiacoinOutput
	for i := 0; i < b.N; i++ {
		siacoinOutputStateObject(o, 0).leafHash()
	}
}

func BenchmarkApplyBlock(b *testing.B) {
	block := types.Block{
		Transactions: []types.Transaction{{
			SiacoinInputs: []types.SiacoinInput{{
				Parent: types.SiacoinOutput{
					LeafIndex: types.EphemeralLeafIndex,
				},
				SpendPolicy: types.AnyoneCanSpend(),
			}},
			SiacoinOutputs: make([]types.Beneficiary, 1000),
		}},
	}
	for i := 0; i < b.N; i++ {
		ApplyBlock(ValidationContext{}, block)
	}
}

func BenchmarkUpdateExistingObjects(b *testing.B) {
	outputs := make([]types.SiacoinOutput, 1000)
	objects := make([]stateObject, len(outputs))
	for i := range outputs {
		objects[i] = siacoinOutputStateObject(outputs[i], 0)
	}
	var acc StateAccumulator
	acc.addNewObjects(objects)
	for i := range outputs {
		outputs[i].LeafIndex = objects[i].leafIndex
		outputs[i].MerkleProof = objects[i].proof
	}

	proofs := make([][]types.Hash256, len(outputs))
	for i := range proofs {
		proofs[i] = append([]types.Hash256(nil), outputs[i].MerkleProof...)
	}
	indices := frand.Perm(len(outputs))[:len(outputs)/2]
	updated := make([]stateObject, len(indices))
	for i, j := range indices {
		updated[i] = siacoinOutputStateObject(outputs[j], flagSpent)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// reset everything
		b.StopTimer()
		acc2 := acc
		for i, j := range indices {
			copy(updated[i].proof, proofs[j])
		}
		b.StartTimer()

		acc2.updateExistingObjects(updated)
	}
}
