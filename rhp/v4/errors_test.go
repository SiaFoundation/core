package rhp

import (
	"bytes"
	"errors"
	"testing"

	"go.sia.tech/core/types"
)

func TestRPCErrorRoundTrip(t *testing.T) {
	tests := []error{
		ErrNotAcceptingContracts,
		ErrPricesExpired,
		ErrSectorNotFound,
	}

	buf := bytes.NewBuffer(nil)
	enc := types.NewEncoder(buf)
	for _, expected := range tests {
		buf.Reset()

		expected.(*RPCError).encodeTo(enc)
		if err := enc.Flush(); err != nil {
			t.Fatalf("failed to encode %v: %v", expected, err)
		}
		dec := types.NewBufDecoder(buf.Bytes())

		err := new(RPCError)
		if err.decodeFrom(dec); dec.Err() != nil {
			t.Fatalf("failed to decode %v: %v", expected, dec.Err())
		} else if !errors.Is(err, expected) {
			t.Errorf("expected %v to be equal to %v", expected, err)
		}
	}
}
