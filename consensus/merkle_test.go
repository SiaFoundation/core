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
    validProof := []types.Hash256{
        {0x0A, 0x0B, 0x0C},
        {0x0D, 0x0E, 0x0F},
        {0x10, 0x11, 0x12},
        {0x13, 0x14, 0x15},
    }
    longProof := append(validProof, types.Hash256{0x16, 0x17, 0x18})
    shortProof := validProof[:2]

    validWantRoot := types.Hash256{0xa8, 0x9d, 0xbb, 0xb5, 0x45, 0xaa, 0x4b, 0x46, 0x69, 0x62, 0x30, 0xd1, 0x04, 0x07, 0x6f, 0x06, 0xb5, 0x7a, 0x6a, 0xb0, 0x8b, 0x23, 0x41, 0xc3, 0xd0, 0x12, 0xbd, 0xc1, 0x3e, 0x23, 0xeb, 0x35}

    tests := []struct {
        name      string
        leafHash  types.Hash256
        leafIndex uint64
        filesize  uint64
        proof     []types.Hash256
        wantRoot  types.Hash256
        valid     bool
    }{
        {
            name:      "ValidProof",
            leafHash:  leafHash,
            leafIndex: 10,
            filesize:  829,
            proof:     validProof,
            wantRoot:  validWantRoot,
            valid:     true,
        },
        {
            name:      "TooLongProof",
            leafHash:  leafHash,
            leafIndex: 10,
            filesize:  829,
            proof:     longProof,
            wantRoot:  validWantRoot,
            valid:     false,
        },
        {
            name:      "TooShortProof",
            leafHash:  leafHash,
            leafIndex: 10,
            filesize:  829,
            proof:     shortProof,
            wantRoot:  validWantRoot,
            valid:     false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            gotRoot := storageProofRoot(tt.leafHash, tt.leafIndex, tt.filesize, tt.proof)
            if tt.valid {
                if !bytes.Equal(gotRoot[:], tt.wantRoot[:]) {
                    t.Errorf("%s failed: got %v, want %v", tt.name, gotRoot, tt.wantRoot)
                }
            } else {
                if bytes.Equal(gotRoot[:], tt.wantRoot[:]) {
                    t.Errorf("%s failed: got a valid root for an invalid proof", tt.name)
                }
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
