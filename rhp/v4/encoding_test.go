package rhp

import (
	"bytes"
	"math"
	"reflect"
	"testing"
	"time"

	"go.sia.tech/core/types"
	"lukechampine.com/frand"
)

type rhpEncodable[T any] interface {
	*T
	encodeTo(*types.Encoder)
	decodeFrom(*types.Decoder)
}

func testRoundtrip[T any, PT rhpEncodable[T]](a PT) func(t *testing.T) {
	return func(t *testing.T) {
		buf := bytes.NewBuffer(nil)
		enc := types.NewEncoder(buf)

		a.encodeTo(enc)
		if err := enc.Flush(); err != nil {
			t.Fatal(err)
		}

		b := new(T)
		dec := types.NewBufDecoder(buf.Bytes())
		PT(b).decodeFrom(dec)

		if !reflect.DeepEqual(a, b) {
			t.Log(a)
			t.Log(reflect.ValueOf(b).Elem())
			t.Fatal("expected rountrip to match")
		}
	}
}

func TestEncodingRoundtrip(t *testing.T) {
	t.Run("AccountToken", testRoundtrip(&AccountToken{
		HostKey:    frand.Entropy256(),
		Account:    frand.Entropy256(),
		ValidUntil: time.Unix(int64(frand.Intn(math.MaxInt)), 0),
		Signature:  types.Signature(frand.Bytes(64)),
	}))
}
