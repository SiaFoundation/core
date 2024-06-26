package consensus

import (
	"bytes"
	"testing"

	"go.sia.tech/core/types"
)

func TestElementAccumulatorEncoding(t *testing.T) {
	for _, test := range []struct {
		numLeaves uint64
		exp       string
	}{
		{0, `{"numLeaves":0,"trees":[]}`},
		{1, `{"numLeaves":1,"trees":["h:0000000000000000000000000000000000000000000000000000000000000000"]}`},
		{2, `{"numLeaves":2,"trees":["h:0100000000000000000000000000000000000000000000000000000000000000"]}`},
		{3, `{"numLeaves":3,"trees":["h:0000000000000000000000000000000000000000000000000000000000000000","h:0100000000000000000000000000000000000000000000000000000000000000"]}`},
		{10, `{"numLeaves":10,"trees":["h:0100000000000000000000000000000000000000000000000000000000000000","h:0300000000000000000000000000000000000000000000000000000000000000"]}`},
		{1 << 16, `{"numLeaves":65536,"trees":["h:1000000000000000000000000000000000000000000000000000000000000000"]}`},
		{1 << 32, `{"numLeaves":4294967296,"trees":["h:2000000000000000000000000000000000000000000000000000000000000000"]}`},
	} {
		acc := ElementAccumulator{NumLeaves: test.numLeaves}
		for i := range acc.Trees {
			if acc.hasTreeAtHeight(i) {
				acc.Trees[i][0] = byte(i)
			}
		}
		js, err := acc.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		if string(js) != test.exp {
			t.Errorf("expected %s, got %s", test.exp, js)
		}
		var acc2 ElementAccumulator
		if err := acc2.UnmarshalJSON(js); err != nil {
			t.Fatal(err)
		}
		if acc2 != acc {
			t.Fatal("round trip failed: expected", acc, "got", acc2)
		}
	}
}

func TestElementAccumulatorRoundTrip(t *testing.T) {
	leafData := []byte{0x01, 0x02, 0x03, 0x0A, 0x0B, 0x0C}
	leafHash := types.HashBytes(leafData)

	for _, numLeaves := range []uint64{0, 1, 2, 3, 10, 1 << 16, 1 << 32, 1 << 63} {
		acc := ElementAccumulator{NumLeaves: numLeaves}

		for i := 0; i < 64; i++ {
			if acc.hasTreeAtHeight(i) {
				acc.Trees[i] = leafHash
			}
		}

		var buf bytes.Buffer
		e := types.NewEncoder(&buf)
		acc.EncodeTo(e)
		if err := e.Flush(); err != nil {
			t.Fatalf("Unexpected error during encoding: %v", err)
		}

		encodedData := buf.Bytes()

		d := types.NewBufDecoder(encodedData)
		var decodedAcc ElementAccumulator
		decodedAcc.DecodeFrom(d)

		if decodedAcc.NumLeaves != acc.NumLeaves {
			t.Errorf("NumLeaves mismatch: got %d, expected %d", decodedAcc.NumLeaves, acc.NumLeaves)
		}

		for i, tree := range decodedAcc.Trees {
			if tree != acc.Trees[i] {
				t.Errorf("Tree mismatch at %d: got %v, expected %v", i, tree, acc.Trees[i])
			}
		}
	}
}

func TestUpdateElementProof(t *testing.T) {
	tests := []struct {
		name           string
		leafIndex      uint64
		numLeaves      uint64
		expectPanic    bool
		expectProofLen int
	}{
		{
			name:        "UnassignedLeafIndexPanic",
			leafIndex:   types.UnassignedLeafIndex,
			numLeaves:   5,
			expectPanic: true,
		},
		{
			name:        "LeafIndexOutOfRangePanic",
			leafIndex:   10,
			numLeaves:   5,
			expectPanic: true,
		},
		{
			name:           "ValidUpdate",
			leafIndex:      3,
			numLeaves:      5,
			expectPanic:    false,
			expectProofLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &types.StateElement{
				LeafIndex:   tt.leafIndex,
				MerkleProof: make([]types.Hash256, 3),
			}
			eru := &elementRevertUpdate{
				numLeaves: tt.numLeaves,
				updated:   [64][]elementLeaf{},
			}

			var didPanic bool
			func() {
				defer func() { didPanic = recover() != nil }()
				eru.updateElementProof(e)
			}()

			if didPanic != tt.expectPanic {
				t.Errorf("updateElementProof() didPanic = %v, want %v for %s", didPanic, tt.expectPanic, tt.name)
			}

			if !tt.expectPanic {
				if len(e.MerkleProof) != tt.expectProofLen {
					t.Errorf("%s: expected MerkleProof length %d, got %d", tt.name, tt.expectProofLen, len(e.MerkleProof))
				}
			}
		})
	}
}
