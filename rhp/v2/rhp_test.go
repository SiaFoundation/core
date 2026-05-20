package rhp

import (
	"errors"
	"math"
	"testing"
)

func TestValidateOverflow(t *testing.T) {
	var hs HostSettings

	_, err := hs.RPCReadCost([]RPCReadRequestSection{
		{Offset: math.MaxUint64, Length: 129},
	}, false)
	if !errors.Is(err, ErrOffsetOutOfBounds) {
		t.Fatalf("expected ErrOffsetOutOfBounds, got %v", err)
	}

	_, err = hs.RPCReadCost([]RPCReadRequestSection{
		{Offset: 129, Length: math.MaxUint64},
	}, false)
	if !errors.Is(err, ErrOffsetOutOfBounds) {
		t.Fatalf("expected ErrOffsetOutOfBounds, got %v", err)
	}

	_, err = hs.RPCWriteCost([]RPCWriteAction{
		{Type: RPCWriteActionUpdate, A: 0, B: math.MaxUint64, Data: make([]byte, 129)},
	}, 1, 1, false)
	if !errors.Is(err, ErrOffsetOutOfBounds) {
		t.Fatalf("expected ErrOffsetOutOfBounds, got %v", err)
	}
}
