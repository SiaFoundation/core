package types

import (
	"bytes"
	"io"
	"math"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"

	"lukechampine.com/frand"
)

// testing/quick isn't able to generate random spend policies; we have to do
// that ourselves
func randPolicy(rand *rand.Rand) SpendPolicy {
	switch rand.Intn(4) + 1 {
	case opAbove:
		return PolicyAbove(rand.Uint64())
	case opPublicKey:
		var p PublicKey
		rand.Read(p[:])
		return PolicyPublicKey(p)
	case opThreshold:
		var p PolicyThreshold
		p.Of = make([]SpendPolicy, rand.Intn(5))
		if len(p.Of) > 0 {
			p.N = uint8(rand.Intn(len(p.Of)))
			for i := range p.Of {
				p.Of[i] = randPolicy(rand)
			}
		}
		return p
	case opUnlockConditions:
		var p PolicyUnlockConditions
		p.Timelock = rand.Uint64()
		p.PublicKeys = make([]PublicKey, rand.Intn(5)+1)
		p.SignaturesRequired = uint8(rand.Intn(len(p.PublicKeys)))
		for i := range p.PublicKeys {
			rand.Read(p.PublicKeys[i][:])
		}
		return p
	}
	panic("unreachable")
}

func quickValue(t reflect.Type, rand *rand.Rand) reflect.Value {
	if t.String() == "types.SpendPolicy" {
		return reflect.ValueOf(randPolicy(rand))
	}
	v := reflect.New(t).Elem()
	switch t.Kind() {
	default:
		v, _ = quick.Value(t, rand)
	case reflect.Slice:
		v.Set(reflect.MakeSlice(t, 10, 10))
		for i := 0; i < v.Len(); i++ {
			v.Index(i).Set(quickValue(t.Elem(), rand))
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			v.Field(i).Set(quickValue(t.Field(i).Type, rand))
		}
	}
	return v
}

func TestEncoderRoundtrip(t *testing.T) {
	tests := []EncoderTo{
		Hash256{0: 0xAA, 31: 0xBB},
		InputSignature{0: 0xAA, 63: 0xBB},
		Work{NumHashes: [32]byte{0: 0xAA, 31: 0xBB}},
		NewCurrency(5, 5),
		ChainIndex{
			Height: 555,
			ID:     BlockID{0: 0xAA, 31: 0xBB},
		},
		ElementID{
			Source: Hash256{0: 0xAA, 31: 0xBB},
			Index:  5000,
		},
		SiacoinOutput{
			Value:   NewCurrency(1000, 1000),
			Address: Address{0: 0xAA, 31: 0xBB},
		},
		FileContract{
			Filesize:       1000,
			FileMerkleRoot: Hash256{0: 0xAA, 31: 0xBB},
			WindowStart:    5000,
			WindowEnd:      5000,
		},
	}
	for _, val := range tests {
		var buf bytes.Buffer
		e := NewEncoder(&buf)
		val.EncodeTo(e)
		e.Flush()
		decptr := reflect.New(reflect.TypeOf(val))
		decptr.Interface().(DecoderFrom).DecodeFrom(NewBufDecoder(buf.Bytes()))
		dec := decptr.Elem().Interface()
		if !reflect.DeepEqual(dec, val) {
			t.Fatalf("value did not survive roundtrip: expected %v, got %v", val, dec)
		}
	}
}

func TestEncoderCompleteness(t *testing.T) {
	// this test ensures that we keep the encoder in sync with the Transaction
	// type by populating its fields with reflection
	seed := int64(frand.Uint64n(math.MaxInt64))
	cfg := &quick.Config{
		Rand: rand.New(rand.NewSource(seed)),
		Values: func(v []reflect.Value, r *rand.Rand) {
			v[0] = quickValue(reflect.TypeOf(Transaction{}), r)
		},
	}
	checkFn := func(txn Transaction) bool {
		var buf bytes.Buffer
		e := NewEncoder(&buf)
		txn.EncodeTo(e)
		e.Flush()
		var decTxn Transaction
		decTxn.DecodeFrom(NewBufDecoder(buf.Bytes()))
		return reflect.DeepEqual(txn, decTxn)
	}
	if quick.Check(checkFn, cfg) != nil {
		t.Fatalf("roundtrip test failed; did you forget to update transaction encoder? (seed = %v)", seed)
	}
}

func BenchmarkEncoding(b *testing.B) {
	txn := quickValue(reflect.TypeOf(Transaction{}), rand.New(rand.NewSource(0))).Interface().(Transaction)
	e := NewEncoder(io.Discard)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		txn.EncodeTo(e)
	}
}
