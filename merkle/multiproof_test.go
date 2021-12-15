package merkle

import (
	"bytes"
	"io"
	"math"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"

	"go.sia.tech/core/types"
)

func TestEncoding(t *testing.T) {
	var quickValue func(t reflect.Type, rand *rand.Rand) reflect.Value
	quickValue = func(t reflect.Type, rand *rand.Rand) reflect.Value {
		if t.String() == "types.SpendPolicy" {
			return reflect.ValueOf(types.PolicyAbove(0))
		}

		v := reflect.New(t).Elem()
		switch t.Kind() {
		default:
			v, _ = quick.Value(t, rand)
		case reflect.Slice:
			v.Set(reflect.MakeSlice(t, 1, 1))
			for i := 0; i < v.Len(); i++ {
				v.Index(i).Set(quickValue(t.Elem(), rand))
			}
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if t.Field(i).Name == "MerkleProof" {
					// compressed versions don't have MerkleProofs
					v.Field(i).Set(reflect.ValueOf(make([]types.Hash256, 0)))
				} else {
					v.Field(i).Set(quickValue(t.Field(i).Type, rand))
				}
			}
		}
		return v
	}

	var buf bytes.Buffer
	e := types.NewEncoder(&buf)
	d := types.NewDecoder(io.LimitedReader{R: &buf, N: math.MaxInt64})

	var block CompressedBlock
	for i := 0; i < 10; i++ {
		block.Transactions = append(block.Transactions, quickValue(reflect.TypeOf(types.Transaction{}), rand.New(rand.NewSource(0))).Interface().(types.Transaction))
	}
	block.EncodeTo(e)
	if err := e.Flush(); err != nil {
		t.Fatal(err)
	}

	var read CompressedBlock
	read.DecodeFrom(d)
	if err := d.Err(); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(block, read) {
		t.Fatalf("CompressedBlock did not survive roundtrip: expected %v, got %v", block, read)
	}
}
