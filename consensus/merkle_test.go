package consensus

import "testing"

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
