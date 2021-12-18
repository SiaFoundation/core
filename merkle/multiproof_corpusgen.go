// +build ignore

package main

import (
	"bytes"
	"errors"
	"math/rand"
	"os"
	"reflect"
	"strconv"
	"testing/quick"

	"go.sia.tech/core/merkle"
	"go.sia.tech/core/types"
	"lukechampine.com/frand"
)

func main() {
	var buf bytes.Buffer
	e := types.NewEncoder(&buf)

	const outputDirectory = "corpus"
	if err := os.Mkdir(outputDirectory, 0755); err != nil && !errors.Is(err, os.ErrExist) {
		panic(err)
	}

	randomTxn := func() types.Transaction {
		var valueFn func(t reflect.Type, r *rand.Rand) reflect.Value
		valueFn = func(t reflect.Type, r *rand.Rand) reflect.Value {
			if t.String() == "types.SpendPolicy" {
				return reflect.ValueOf(types.AnyoneCanSpend())
			}
			v := reflect.New(t).Elem()
			switch t.Kind() {
			default:
				v, _ = quick.Value(t, r)
			case reflect.Slice:
				// 3 elements per slice to prevent generating giant objects
				v.Set(reflect.MakeSlice(t, 3, 3))
				for i := 0; i < v.Len(); i++ {
					v.Index(i).Set(valueFn(t.Elem(), r))
				}
			case reflect.Struct:
				for i := 0; i < v.NumField(); i++ {
					v.Field(i).Set(valueFn(t.Field(i).Type, r))
				}
			}
			return v
		}
		r := rand.New(frand.NewSource())
		txn := valueFn(reflect.TypeOf(types.Transaction{}), r)
		return txn.Interface().(types.Transaction)
	}

	for i := 0; i < 10; i++ {
		merkle.CompressedBlock(types.Block{Transactions: []types.Transaction{randomTxn(), randomTxn(), randomTxn()}}).EncodeTo(e)
		e.Flush()
		os.WriteFile(outputDirectory+"/"+strconv.Itoa(i), buf.Bytes(), 0664)
		buf.Reset()
	}
}
