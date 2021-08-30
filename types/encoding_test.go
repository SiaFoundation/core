package types

import (
	"bytes"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
)

func TestEncoderRoundtrip(t *testing.T) {
	tests := []struct {
		val interface{}
		enc interface{}
		dec interface{}
	}{
		{
			val: Hash256{0: 0xAA, 31: 0xBB},
			enc: (*Encoder).WriteHash,
			dec: (*Decoder).ReadHash,
		},
		{
			val: InputSignature{0: 0xAA, 63: 0xBB},
			enc: (*Encoder).WriteSignature,
			dec: (*Decoder).ReadSignature,
		},
		{
			val: uint8(100),
			enc: (*Encoder).WriteUint8,
			dec: (*Decoder).ReadUint8,
		},
		{
			val: uint64(100),
			enc: (*Encoder).WriteUint64,
			dec: (*Decoder).ReadUint64,
		},
		{
			val: int(100),
			enc: (*Encoder).WriteInt,
			dec: (*Decoder).ReadInt,
		},
		{
			val: CurrentTimestamp(),
			enc: (*Encoder).WriteTime,
			dec: (*Decoder).ReadTime,
		},
		{
			val: Work{NumHashes: [32]byte{0: 0xAA, 31: 0xBB}},
			enc: (*Encoder).WriteWork,
			dec: (*Decoder).ReadWork,
		},
		{
			val: NewCurrency(5, 5),
			enc: (*Encoder).WriteCurrency,
			dec: (*Decoder).ReadCurrency,
		},
		{
			val: ChainIndex{
				Height: 555,
				ID:     BlockID{0: 0xAA, 31: 0xBB},
			},
			enc: (*Encoder).WriteChainIndex,
			dec: (*Decoder).ReadChainIndex,
		},
		{
			val: OutputID{
				TransactionID: TransactionID{0: 0xAA, 31: 0xBB},
				Index:         5000,
			},
			enc: (*Encoder).WriteOutputID,
			dec: (*Decoder).ReadOutputID,
		},
		{
			val: Beneficiary{
				Value:   NewCurrency(1000, 1000),
				Address: Address{0: 0xAA, 31: 0xBB},
			},
			enc: (*Encoder).WriteBeneficiary,
			dec: (*Decoder).ReadBeneficiary,
		},
		{
			val: FileContractState{
				Filesize:       1000,
				FileMerkleRoot: Hash256{0: 0xAA, 31: 0xBB},
				WindowStart:    5000,
				WindowEnd:      5000,
			},
			enc: (*Encoder).WriteFileContractState,
			dec: (*Decoder).ReadFileContractState,
		},
	}
	for _, test := range tests {
		var buf bytes.Buffer
		e := NewEncoder(&buf)
		reflect.ValueOf(test.enc).Call([]reflect.Value{reflect.ValueOf(e), reflect.ValueOf(test.val)})
		e.Flush()
		val := reflect.ValueOf(test.dec).Call([]reflect.Value{reflect.ValueOf(NewDecoder(&buf))})[0].Interface()
		if !reflect.DeepEqual(test.val, val) {
			t.Fatalf("value did not survive roundtrip: expected %v, got %v", test.val, val)
		}
	}
}

func TestEncoderCompleteness(t *testing.T) {
	// this test ensures that we keep the encoder in sync with the Transaction
	// type by populating its fields with reflection

	// testing/quick isn't able to generate random spend policies; we have to do
	// that ourselves
	var randPolicy func(rand *rand.Rand) SpendPolicy
	randPolicy = func(rand *rand.Rand) SpendPolicy {
		switch rand.Intn(4) + 1 {
		case opAbove:
			return PolicyAbove(rand.Uint64())
		case opPublicKey:
			var p PublicKey
			rand.Read(p[:])
			return PolicyPublicKey(p)
		case opThreshold:
			var p PolicyThreshold
			p.Of = make([]SpendPolicy, rand.Intn(5)+1)
			p.N = uint8(rand.Intn(len(p.Of)))
			for i := range p.Of {
				p.Of[i] = randPolicy(rand)
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

	// override the default testing/quick generator with one that special-cases
	// SpendPolicy
	var valueFn func(t reflect.Type, r *rand.Rand) reflect.Value
	valueFn = func(t reflect.Type, r *rand.Rand) reflect.Value {
		if t.String() == "types.SpendPolicy" {
			return reflect.ValueOf(randPolicy(r))
		}
		v := reflect.New(t).Elem()
		switch t.Kind() {
		default:
			v, _ = quick.Value(t, r)
		case reflect.Slice:
			v.Set(reflect.MakeSlice(t, 10, 10))
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

	cfg := &quick.Config{
		Values: func(v []reflect.Value, r *rand.Rand) {
			v[0] = valueFn(reflect.TypeOf(Transaction{}), r)
		},
	}

	checkFn := func(txn Transaction) bool {
		var buf bytes.Buffer
		e := NewEncoder(&buf)
		e.WriteTransaction(txn)
		e.Flush()
		decTxn := NewDecoder(&buf).ReadTransaction()
		return reflect.DeepEqual(txn, decTxn)
	}

	if quick.Check(checkFn, cfg) != nil {
		t.Fatal("roundtrip test failed; did you forget to update transaction encoder?")
	}
}
