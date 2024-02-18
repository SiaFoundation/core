package consensus

import (
    "testing"
    "bytes"

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

func TestStorageProofRoot(t *testing.T) {
    leafHash := types.Hash256{0x01, 0x02, 0x03}
    proof := []types.Hash256{
        {0x04, 0x05, 0x06},
        {0x07, 0x08, 0x09},
    }

    tests := []struct {
        name       string
        leafHash   types.Hash256
        leafIndex  uint64
        filesize   uint64
        proof      []types.Hash256
        wantRoot   types.Hash256
        wantErr    bool
    }{
        {
            name:      "ValidProof",
            leafHash:  leafHash,
            leafIndex: 0,
            filesize:  1024,
            proof:     proof,
            wantRoot:  types.Hash256{},
            wantErr:   false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            gotRoot := storageProofRoot(tt.leafHash, tt.leafIndex, tt.filesize, tt.proof)
            if !bytes.Equal(gotRoot[:], tt.wantRoot[:]) && !tt.wantErr {
                t.Errorf("storageProofRoot() = %v, want %v", gotRoot, tt.wantRoot)
            }
        })
    }
}

func TestUpdateElementProof(t *testing.T) {
    tests := []struct {
        name          string
        leafIndex     uint64
        numLeaves     uint64
        expectPanic   bool
        expectProofLen int
    }{
        {
            name:        "EphemeralLeafIndexPanic",
            leafIndex:   types.EphemeralLeafIndex,
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
            name:          "ValidUpdate",
            leafIndex:     3,
            numLeaves:     5,
            expectPanic:   false,
            expectProofLen: 2,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            e := &types.StateElement{
                LeafIndex: tt.leafIndex,
                MerkleProof: make([]types.Hash256, 3),
            }
            eru := &elementRevertUpdate{
                numLeaves: tt.numLeaves,
                updated:   [64][]elementLeaf{},
            }

            if tt.expectPanic {
                defer func() {
                    if r := recover(); r == nil {
                        t.Errorf("The code did not panic for %s", tt.name)
                    }
                }()
            }

            eru.updateElementProof(e)

            if !tt.expectPanic {
                if len(e.MerkleProof) != tt.expectProofLen {
                    t.Errorf("%s: expected MerkleProof length %d, got %d", tt.name, tt.expectProofLen, len(e.MerkleProof))
                }
            }
        })
    }
}
