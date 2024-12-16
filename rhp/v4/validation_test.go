package rhp

import (
	"errors"
	"strings"
	"testing"
	"time"

	"go.sia.tech/core/types"
	"lukechampine.com/frand"
)

func TestValidateAccountToken(t *testing.T) {
	hostKey := types.GeneratePrivateKey().PublicKey()
	renterKey := types.GeneratePrivateKey()
	account := Account(renterKey.PublicKey())

	ac := AccountToken{
		HostKey:    hostKey,
		Account:    account,
		ValidUntil: time.Now().Add(-time.Minute),
	}

	if err := ac.Validate(frand.Entropy256()); !strings.Contains(err.Error(), "host key mismatch") {
		t.Fatalf("expected host key mismatch, got %v", err)
	} else if err := ac.Validate(hostKey); !strings.Contains(err.Error(), "token expired") {
		t.Fatalf("expected token expired, got %v", err)
	}

	ac.ValidUntil = time.Now().Add(time.Minute)
	if err := ac.Validate(hostKey); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}

	ac.Signature = renterKey.SignHash(ac.SigHash())

	if err := ac.Validate(hostKey); err != nil {
		t.Fatal(err)
	}
}
