package types

import (
	"bytes"
	"encoding"
	"io"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
)

// Generate implements quick.Generator.
func (p SpendPolicy) Generate(rand *rand.Rand, size int) reflect.Value {
	switch rand.Intn(4) + 1 {
	case opAbove:
		return reflect.ValueOf(PolicyAbove(rand.Uint64()))
	case opPublicKey:
		var p PublicKey
		rand.Read(p[:])
		return reflect.ValueOf(PolicyPublicKey(p))
	case opThreshold:
		n := uint8(0)
		of := make([]SpendPolicy, rand.Intn(5))
		if len(of) > 0 {
			n = uint8(rand.Intn(len(of)))
			for i := range of {
				of[i] = p.Generate(rand, size).Interface().(SpendPolicy)
			}
		}
		return reflect.ValueOf(PolicyThreshold(n, of))
	case opUnlockConditions:
		var p PolicyTypeUnlockConditions
		p.Timelock = rand.Uint64()
		p.PublicKeys = make([]PublicKey, rand.Intn(5)+1)
		p.SignaturesRequired = uint8(rand.Intn(len(p.PublicKeys)))
		for i := range p.PublicKeys {
			rand.Read(p.PublicKeys[i][:])
		}
		return reflect.ValueOf(SpendPolicy{p})
	}
	panic("unreachable")
}

func TestEncoderRoundtrip(t *testing.T) {
	tests := []EncoderTo{
		Hash256{0: 0xAA, 31: 0xBB},
		Signature{0: 0xAA, 63: 0xBB},
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
	checkFn := func(txn Transaction) bool {
		// NOTE: the compressed Transaction encoding will cause 0-length slices
		// to decode as nil, so normalize any 0-length slices to nil now to
		// ensure that DeepEqual will work.
		txn.SiacoinInputs = append([]SiacoinInput(nil), txn.SiacoinInputs...)
		txn.SiacoinOutputs = append([]SiacoinOutput(nil), txn.SiacoinOutputs...)
		txn.SiafundInputs = append([]SiafundInput(nil), txn.SiafundInputs...)
		txn.SiafundOutputs = append([]SiafundOutput(nil), txn.SiafundOutputs...)
		txn.FileContracts = append([]FileContract(nil), txn.FileContracts...)
		txn.FileContractRevisions = append([]FileContractRevision(nil), txn.FileContractRevisions...)
		txn.FileContractResolutions = append([]FileContractResolution(nil), txn.FileContractResolutions...)
		txn.Attestations = append([]Attestation(nil), txn.Attestations...)
		txn.ArbitraryData = append([]byte(nil), txn.ArbitraryData...)

		var buf bytes.Buffer
		e := NewEncoder(&buf)
		txn.EncodeTo(e)
		e.Flush()
		var decTxn Transaction
		decTxn.DecodeFrom(NewBufDecoder(buf.Bytes()))
		return reflect.DeepEqual(txn, decTxn)
	}
	if quick.Check(checkFn, nil) != nil {
		t.Fatal("roundtrip test failed; did you forget to update transaction encoder?")
	}
}

func BenchmarkEncoding(b *testing.B) {
	v, ok := quick.Value(reflect.TypeOf(Transaction{}), rand.New(rand.NewSource(0)))
	if !ok {
		b.Fatal("could not generate value")
	}
	txn := v.Interface().(Transaction)
	e := NewEncoder(io.Discard)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		txn.EncodeTo(e)
	}
}

func TestMarshalTextRoundtrip(t *testing.T) {
	tests := []encoding.TextMarshaler{
		Hash256{0: 0xAA, 31: 0xBB},
		ChainIndex{
			Height: 555,
			ID:     BlockID{0: 0xAA, 31: 0xBB},
		},
		ElementID{
			Source: Hash256{0: 0xAA, 31: 0xBB},
			Index:  5000,
		},
		Address{0: 0xAA, 31: 0xBB},
		BlockID{0: 0xAA, 31: 0xBB},
		PublicKey{0: 0xAA, 31: 0xBB},
		TransactionID{0: 0xAA, 31: 0xBB},
		Signature{0: 0xAA, 31: 0xBB},
	}
	for _, val := range tests {
		b, _ := val.MarshalText()
		decptr := reflect.New(reflect.TypeOf(val))
		if err := decptr.Interface().(encoding.TextUnmarshaler).UnmarshalText(b); err != nil {
			t.Errorf("could not decode %T value: %v", val, err)
			continue
		}
		dec := decptr.Elem().Interface()
		if !reflect.DeepEqual(dec, val) {
			t.Errorf("%T value did not survive roundtrip: expected %v, got %v", val, val, dec)
		}
	}
}
