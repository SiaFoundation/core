package rhp

import (
	"testing"

	"go.sia.tech/core/types"
)

func TestMinRenterAllowance(t *testing.T) {
	hp := HostPrices{
		StoragePrice: types.NewCurrency64(1), // 1 H per byte per block
		Collateral:   types.NewCurrency64(2), // 2 H per byte per block
	}

	collateral := types.Siacoins(2)
	minAllowance := MinRenterAllowance(hp, 1, collateral)
	expected := types.Siacoins(1)
	if !minAllowance.Equals(expected) {
		t.Fatalf("expected %v, got %v", expected, minAllowance)
	}
}
