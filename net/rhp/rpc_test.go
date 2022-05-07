package rhp

import (
	"bytes"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"

	"go.sia.tech/core/types"
)

func randStruct(t reflect.Type, rand *rand.Rand) reflect.Value {
	v := reflect.New(t)
	for i := 0; i < v.Elem().NumField(); i++ {
		// time.Time contains unexported fields which makes testing/quick not
		// work so we have to have custom Generate function that skips over
		// fields containing it
		tStr := t.Field(i).Type.String()
		if tStr == "time.Time" || tStr == "error" {
			continue
		} else if tStr == "[]rhp.Instruction" {
			v.Elem().Field(i).Set(reflect.ValueOf([]Instruction{}))
			continue
		}
		elem, ok := quick.Value(t.Field(i).Type, rand)
		if !ok {
			return reflect.Value{}
		}
		v.Elem().Field(i).Set(elem)
	}
	return v
}

// Generate implements quick.Generator.
func (*HostSettings) Generate(rand *rand.Rand, size int) reflect.Value {
	return randStruct(reflect.TypeOf(HostSettings{}), rand)
}

// Generate implements quick.Generator.
func (*RPCExecuteProgramRequest) Generate(rand *rand.Rand, size int) reflect.Value {
	return randStruct(reflect.TypeOf(RPCExecuteProgramRequest{}), rand)
}

// Generate implements quick.Generator.
func (*RPCExecuteInstrResponse) Generate(rand *rand.Rand, size int) reflect.Value {
	return randStruct(reflect.TypeOf(RPCExecuteInstrResponse{}), rand)
}

func TestEncoderRoundtrip(t *testing.T) {
	tests := []types.EncoderTo{
		&RPCContractSignatures{},
		&RPCRenewContractRenterSignatures{},
		&RPCLockRequest{},
		&RPCLockResponse{},
		&RPCReadRequest{},
		&RPCReadResponse{},
		&RPCSectorRootsRequest{},
		&RPCSectorRootsResponse{},
		&RPCWriteAction{},
		&RPCWriteRequest{},
		&RPCWriteMerkleProof{},
		&RPCWriteResponse{},
		&RPCSettingsResponse{},
		&RPCLatestRevisionRequest{},
		&RPCLatestRevisionResponse{},
		&RPCSettingsRegisteredResponse{},
		&RPCExecuteProgramRequest{},
		&WithdrawalMessage{},
		&PayByEphemeralAccountRequest{},
		&PayByContractRequest{},
		&RPCRevisionSigningResponse{},
		&RPCAccountBalanceResponse{},
		&RPCAccountBalanceRequest{},
		&RPCFundAccountRequest{},
		&RPCExecuteInstrResponse{},
		&RPCFinalizeProgramRequest{},
		&SettingsID{},
		&HostSettings{},
	}

	for _, val := range tests {
		var buf bytes.Buffer
		e := types.NewEncoder(&buf)
		typ := reflect.TypeOf(val)
		randVal, ok := quick.Value(typ, rand.New(rand.NewSource(0)))
		if !ok {
			t.Errorf("could not generate random value for type %s", typ)
		}
		newVal := randVal.Interface()
		newVal.(types.EncoderTo).EncodeTo(e)
		e.Flush()

		decval := reflect.New(typ.Elem())
		decval.Interface().(types.DecoderFrom).DecodeFrom(types.NewBufDecoder(buf.Bytes()))
		dec := decval.Interface()

		if !reflect.DeepEqual(dec, newVal) {
			t.Fatalf("value did not survive roundtrip: expected %v, got %v", newVal, dec)
		}
	}
}
