package types_test

import (
	"bytes"
	"fmt"
	"math"
	"testing"
	"time"

	"go.sia.tech/core/types"
	"lukechampine.com/frand"
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

func FuzzSpendPolicy(f *testing.F) {
	encode := func(x types.EncoderTo) []byte {
		var buf bytes.Buffer
		e := types.NewEncoder(&buf)
		x.EncodeTo(e)
		e.Flush()
		return buf.Bytes()
	}

	privateKey := types.GeneratePrivateKey()
	publicKey := privateKey.PublicKey()

	var hash types.Hash256
	frand.Read(hash[:])

	seeds := []types.SpendPolicy{
		types.PolicyAbove(0),
		types.PolicyAbove(math.MaxUint64),
		types.PolicyAfter(time.Time{}),
		types.PolicyAfter(time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)),
		types.PolicyPublicKey(types.PublicKey{}),
		types.PolicyPublicKey(publicKey),
		types.PolicyHash(types.Hash256{}),
		types.PolicyHash(hash),
		types.AnyoneCanSpend(),
	}
	for _, seed := range seeds {
		f.Add(encode(seed))
		f.Add(encode(types.PolicyOpaque(seed)))
	}

	for i := 0; i < 10; i++ {
		rng := frand.Uint64n(uint64(len(seeds)) / 2)
		frand.Shuffle(len(seeds), func(i, j int) {
			seeds[i], seeds[j] = seeds[j], seeds[i]
		})
		sp := types.PolicyThreshold(uint8(rng), seeds[:rng])

		f.Add(encode(sp))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		d := types.NewBufDecoder(data)

		var sp types.SpendPolicy
		sp.DecodeFrom(d)
	})
}
