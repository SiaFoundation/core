package rhp

import (
	"testing"

	"go.sia.tech/core/consensus"
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

func TestRenewalCost(t *testing.T) {
	// contract for renewal
	contract := types.V2FileContract{
		Capacity:         1000 * SectorSize,
		Filesize:         900 * SectorSize,
		FileMerkleRoot:   types.Hash256{1, 1, 1},
		ProofHeight:      500000,        // block 500k
		ExpirationHeight: 500000 + 1000, // 1000 block window
		RenterOutput:     types.SiacoinOutput{Value: types.Siacoins(300)},
		HostOutput:       types.SiacoinOutput{Value: types.Siacoins(400)},
		MissedHostValue:  types.Siacoins(700),
		TotalCollateral:  types.Siacoins(100),
		RevisionNumber:   99999999,
	}

	cs := consensus.State{}
	prices := HostPrices{
		TipHeight:       40000,
		ContractPrice:   types.NewCurrency64(100),
		Collateral:      types.NewCurrency64(200),
		StoragePrice:    types.NewCurrency64(300),
		IngressPrice:    types.NewCurrency64(400),
		EgressPrice:     types.NewCurrency64(500),
		FreeSectorPrice: types.NewCurrency64(600),
	}

	// renew contract
	renewal, _ := RenewContract(contract, prices, RPCRenewContractParams{
		Allowance:   contract.RenterOutput.Value.Add(types.Siacoins(20)), // 20 SC more than renter output
		Collateral:  contract.MissedHostValue.Add(types.Siacoins(10)),    // 10 SC more than before
		ProofHeight: contract.ExpirationHeight + 1000,
	})

	minerFee := types.NewCurrency64(700)
	prevExpirationHeight := uint64(900) // 100 blocks before

	// assert expected results
	renter, host := RenewalCost(cs, prices, renewal, minerFee, prevExpirationHeight)
	expectedRenter := types.NewCurrency(12531552842177053476, 3317658)
	expectedHost := types.NewCurrency(7783457943256563812, 71557343)
	if !renter.Equals(expectedRenter) {
		t.Fatalf("expected %v, got %v", expectedRenter, renter)
	} else if !host.Equals(expectedHost) {
		t.Fatalf("expected %v, got %v", expectedHost, host)
	}

	// make sure the sums match
	fc := renewal.NewContract
	inputSum := renter.Add(host)
	outputSum := fc.RenterOutput.Value.
		Add(fc.HostOutput.Value).
		Add(cs.V2FileContractTax(fc)).
		Add(minerFee)
	if !inputSum.Equals(outputSum) {
		t.Fatalf("expected %v, got %v", inputSum, outputSum)
	}
}
