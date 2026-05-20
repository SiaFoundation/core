package rhp

import (
	"errors"
	"math"
	"testing"
	"time"

	"go.sia.tech/core/types"
	"lukechampine.com/frand"
)

func assertRequestError(t *testing.T, err, expected error) {
	t.Helper()

	if !errors.Is(err, expected) {
		t.Fatalf("expected %v, got %v", expected, err)
	} else if ErrorCode(err) != ErrorCodeBadRequest {
		t.Fatalf("expected ErrorCodeBadRequest, got %v", ErrorCode(err))
	}
}

func TestValidateAccountToken(t *testing.T) {
	hostKey := types.GeneratePrivateKey().PublicKey()
	renterKey := types.GeneratePrivateKey()
	account := Account(renterKey.PublicKey())

	ac := AccountToken{
		HostKey:    hostKey,
		Account:    account,
		ValidUntil: time.Now().Add(-time.Minute),
	}

	assertRequestError(t, ac.Validate(frand.Entropy256()), ErrHostKeyMismatch)
	assertRequestError(t, ac.Validate(hostKey), ErrTokenExpired)

	ac.ValidUntil = time.Now().Add(time.Minute)
	assertRequestError(t, ac.Validate(hostKey), ErrInvalidSignature)

	ac.Signature = renterKey.SignHash(ac.SigHash())
	if err := ac.Validate(hostKey); err != nil {
		t.Fatal(err)
	}
}

func TestValidateOverflow(t *testing.T) {
	hostKey := types.GeneratePrivateKey()
	pk := hostKey.PublicKey()
	renterKey := types.GeneratePrivateKey()
	token := NewAccountToken(renterKey, pk)
	prices := HostPrices{ValidUntil: time.Now().Add(5 * time.Minute)}
	prices.Signature = hostKey.SignHash(prices.SigHash())

	readReq := RPCReadSectorRequest{Token: token, Prices: prices, Offset: 129, Length: math.MaxUint64}
	if err := readReq.Validate(pk); err == nil {
		t.Fatal("expected error for overflowing read sector length")
	}

	readReq = RPCReadSectorRequest{Token: token, Prices: prices, Offset: math.MaxUint64, Length: 129}
	if err := readReq.Validate(pk); err == nil {
		t.Fatal("expected error for overflowing read sector offset")
	}

	rootsReq := RPCSectorRootsRequest{Prices: prices, Offset: math.MaxUint64, Length: 129}
	if err := rootsReq.Validate(pk, types.V2FileContract{Filesize: SectorSize * 200}); err == nil {
		t.Fatal("expected error for overflowing sector roots offset")
	}

	rootsReq = RPCSectorRootsRequest{Prices: prices, Offset: 1, Length: math.MaxUint64}
	if err := rootsReq.Validate(pk, types.V2FileContract{Filesize: SectorSize * 200}); err == nil {
		t.Fatal("expected error for overflowing sector roots length")
	}
}

func TestValidatePrices(t *testing.T) {
	hostKey := types.GeneratePrivateKey()
	prices := HostPrices{
		ContractPrice:   types.NewCurrency64(1),
		StoragePrice:    types.NewCurrency64(2),
		IngressPrice:    types.NewCurrency64(3),
		EgressPrice:     types.NewCurrency64(4),
		Collateral:      types.NewCurrency64(5),
		FreeSectorPrice: types.NewCurrency64(6),
		TipHeight:       7,
		ValidUntil:      time.Now().Add(time.Minute),
	}
	prices.Signature = hostKey.SignHash(prices.SigHash())

	if err := prices.Validate(hostKey.PublicKey()); err != nil {
		t.Fatal(err)
	}

	prices.StoragePrice = types.ZeroCurrency
	assertRequestError(t, prices.Validate(hostKey.PublicKey()), ErrInvalidSignature)

	prices.ValidUntil = time.Now().Add(-time.Minute)
	prices.Signature = hostKey.SignHash(prices.SigHash())
	assertRequestError(t, prices.Validate(hostKey.PublicKey()), ErrPricesExpired)
}
