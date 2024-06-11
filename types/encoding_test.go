package types_test

import (
	"bytes"
	"fmt"
	"testing"

	"go.sia.tech/core/types"
)

func TestEncodeSlice(t *testing.T) {
	txns := multiproofTxns(10, 10)
	var buf bytes.Buffer
	e := types.NewEncoder(&buf)
	types.EncodeSlice(e, txns)
	e.Flush()

	var txns2 []types.V2Transaction
	d := types.NewBufDecoder(buf.Bytes())
	types.DecodeSlice(d, &txns2)
	if err := d.Err(); err != nil {
		t.Fatal(err)
	} else if fmt.Sprint(txns) != fmt.Sprint(txns2) {
		t.Fatal("mismatch:", txns, txns2)
	}

	buf.Reset()
	cs := []types.Currency{types.Siacoins(1), types.Siacoins(2), types.MaxCurrency}
	types.EncodeSliceCast[types.V1Currency](e, cs)
	types.EncodeSliceCast[types.V2Currency](e, cs)
	e.Flush()
	var cs1 []types.Currency
	var cs2 []types.Currency
	d = types.NewBufDecoder(buf.Bytes())
	types.DecodeSliceCast[types.V1Currency](d, &cs1)
	types.DecodeSliceCast[types.V2Currency](d, &cs2)
	if err := d.Err(); err != nil {
		t.Fatal(err)
	} else if fmt.Sprint(cs) != fmt.Sprint(cs1) {
		t.Fatal("mismatch:", cs, cs1)
	} else if fmt.Sprint(cs) != fmt.Sprint(cs2) {
		t.Fatal("mismatch:", cs, cs2)
	}

	// 0-length cast should not panic
	d = types.NewBufDecoder(make([]byte, 8))
	types.DecodeSliceCast[types.V1Currency](d, new([]types.Currency))
	if err := d.Err(); err != nil {
		t.Fatal(err)
	}
}
