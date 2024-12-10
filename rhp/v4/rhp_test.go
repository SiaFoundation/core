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
	const (
		initialProofHeight = 1000
		initialExpiration  = initialProofHeight + ProofWindow

		renewalHeight      = 150
		extension          = 10
		renewalProofHeight = initialProofHeight + extension
		renewalExpiration  = renewalProofHeight + ProofWindow
		renewalDuration    = renewalExpiration - renewalHeight
	)
	cs := consensus.State{}
	prices := HostPrices{
		ContractPrice:   types.NewCurrency64(100),
		Collateral:      types.NewCurrency64(200),
		StoragePrice:    types.NewCurrency64(300),
		IngressPrice:    types.NewCurrency64(400),
		EgressPrice:     types.NewCurrency64(500),
		FreeSectorPrice: types.NewCurrency64(600),
	}
	renterKey, hostKey := types.GeneratePrivateKey().PublicKey(), types.GeneratePrivateKey().PublicKey()

	type testCase struct {
		Description string
		Modify      func(*types.V2FileContract, *RPCRenewContractParams)
		RenterCost  types.Currency
		HostCost    types.Currency
	}

	cases := []testCase{
		{
			Description: "empty",
			Modify:      func(*types.V2FileContract, *RPCRenewContractParams) {},
			RenterCost:  prices.ContractPrice,
		},
		{
			Description: "no storage",
			Modify: func(rev *types.V2FileContract, p *RPCRenewContractParams) {
				p.Allowance = rev.RenterOutput.Value.Add(types.Siacoins(20))
				p.Collateral = rev.TotalCollateral.Add(types.Siacoins(10))
			},
			RenterCost: types.Siacoins(20).Add(prices.ContractPrice),
			HostCost:   types.Siacoins(10),
		},
		{
			Description: "no storage - no renter rollover",
			Modify: func(rev *types.V2FileContract, p *RPCRenewContractParams) {
				p.Allowance = rev.RenterOutput.Value.Add(types.Siacoins(20))
				p.Collateral = rev.TotalCollateral.Add(types.Siacoins(10))
				// transfer all of the renter funds to the host so the renter will need to put up the entire allowance
				rev.HostOutput.Value, rev.RenterOutput.Value = rev.HostOutput.Value.Add(rev.RenterOutput.Value), types.ZeroCurrency
			},
			RenterCost: types.Siacoins(320).Add(prices.ContractPrice),
			HostCost:   types.Siacoins(10),
		},
		{
			Description: "renewed storage - no additional funds",
			Modify: func(rev *types.V2FileContract, p *RPCRenewContractParams) {
				// add storage
				rev.Capacity = SectorSize
				rev.Filesize = SectorSize
			},
			RenterCost: prices.ContractPrice.Add(prices.StoragePrice.Mul64(SectorSize).Mul64(extension)), // storage cost is calculated for just the extension
			HostCost:   types.ZeroCurrency,                                                               // collateral lock up is less than rollover
		},
		{
			Description: "renewed storage",
			Modify: func(rev *types.V2FileContract, p *RPCRenewContractParams) {
				// add storage
				rev.Capacity = SectorSize
				rev.Filesize = SectorSize

				// adjust the renewal params
				p.Allowance = rev.RenterOutput.Value.Add(types.Siacoins(20))
				p.Collateral = rev.TotalCollateral.Add(types.Siacoins(10))
			},
			RenterCost: types.Siacoins(20).Add(prices.ContractPrice).Add(prices.StoragePrice.Mul64(SectorSize).Mul64(extension)), // storage cost is calculated for just the extension
			HostCost:   types.Siacoins(10).Add(prices.Collateral.Mul64(SectorSize).Mul64(renewalDuration)),                       // collateral is calculated for the full duration
		},
		{
			Description: "renewed storage - no renter rollover",
			Modify: func(rev *types.V2FileContract, p *RPCRenewContractParams) {
				// adjust the renewal params
				p.Allowance = rev.RenterOutput.Value.Add(types.Siacoins(20))
				p.Collateral = rev.TotalCollateral.Add(types.Siacoins(10))

				// add storage
				rev.Capacity = SectorSize
				rev.Filesize = SectorSize
				// transfer all the renter funds to the host so the renter will need to put up more allowance
				rev.HostOutput.Value, rev.RenterOutput.Value = rev.HostOutput.Value.Add(rev.RenterOutput.Value), types.ZeroCurrency
			},
			RenterCost: types.Siacoins(320).Add(prices.ContractPrice).Add(prices.StoragePrice.Mul64(SectorSize).Mul64(extension)), // storage cost is calculated for just the extension
			HostCost:   types.Siacoins(10).Add(prices.Collateral.Mul64(SectorSize).Mul64(renewalDuration)),                        // collateral is calculated for the full duration
		},
	}
	for _, tc := range cases {
		t.Run(tc.Description, func(t *testing.T) {
			contract, _ := NewContract(prices, RPCFormContractParams{
				RenterPublicKey: renterKey,
				RenterAddress:   types.StandardAddress(renterKey),
				Allowance:       types.Siacoins(300),
				Collateral:      types.Siacoins(400),
				ProofHeight:     initialProofHeight,
			}, hostKey, types.StandardAddress(hostKey))

			params := RPCRenewContractParams{
				ProofHeight: renewalProofHeight,
			}
			tc.Modify(&contract, &params)

			prices.TipHeight = renewalHeight
			renewal, _ := RenewContract(contract, prices, params)
			tax := cs.V2FileContractTax(renewal.NewContract)
			renter, host := RenewalCost(cs, prices, renewal, types.ZeroCurrency)
			if !renter.Equals(tc.RenterCost.Add(tax)) {
				t.Errorf("expected renter cost %v, got %v", tc.RenterCost, renter.Sub(tax))
			} else if !host.Equals(tc.HostCost) {
				t.Errorf("expected host cost %v, got %v", tc.HostCost, host)
			}
		})
	}
}

func TestRefreshCost(t *testing.T) {
	const initialProofHeight = 1000

	cs := consensus.State{}
	prices := HostPrices{
		ContractPrice:   types.NewCurrency64(100),
		Collateral:      types.NewCurrency64(200),
		StoragePrice:    types.NewCurrency64(300),
		IngressPrice:    types.NewCurrency64(400),
		EgressPrice:     types.NewCurrency64(500),
		FreeSectorPrice: types.NewCurrency64(600),
	}
	renterKey, hostKey := types.GeneratePrivateKey().PublicKey(), types.GeneratePrivateKey().PublicKey()

	type testCase struct {
		Description string
		Modify      func(*types.V2FileContract)
	}

	cases := []testCase{
		{
			Description: "no storage",
			Modify:      func(rev *types.V2FileContract) {},
		},
		{
			Description: "no storage - no renter rollover",
			Modify: func(rev *types.V2FileContract) {
				// transfer all of the renter funds to the host so the renter rolls over nothing
				rev.HostOutput.Value, rev.RenterOutput.Value = rev.HostOutput.Value.Add(rev.RenterOutput.Value), types.ZeroCurrency
			},
		},
		{
			Description: "renewed storage",
			Modify: func(rev *types.V2FileContract) {
				// add storage
				rev.Capacity = SectorSize
				rev.Filesize = SectorSize
			},
		},
		{
			Description: "renewed storage - no renter rollover",
			Modify: func(rev *types.V2FileContract) {
				// add storage
				rev.Capacity = SectorSize
				rev.Filesize = SectorSize
				// transfer all the renter funds to the host
				rev.HostOutput.Value, rev.RenterOutput.Value = rev.HostOutput.Value.Add(rev.RenterOutput.Value), types.ZeroCurrency
			},
		},
	}

	// the actual cost to the renter and host should always be the additional allowance and collateral
	// on top of the existing contract costs
	additionalAllowance, additionalCollateral := types.Siacoins(20), types.Siacoins(10)
	renterCost := additionalAllowance.Add(prices.ContractPrice)
	hostCost := additionalCollateral

	for _, tc := range cases {
		t.Run(tc.Description, func(t *testing.T) {
			contract, _ := NewContract(prices, RPCFormContractParams{
				RenterPublicKey: renterKey,
				RenterAddress:   types.StandardAddress(renterKey),
				Allowance:       types.Siacoins(300),
				Collateral:      types.Siacoins(400),
				ProofHeight:     initialProofHeight,
			}, hostKey, types.StandardAddress(hostKey))

			params := RPCRefreshContractParams{
				Allowance:  additionalAllowance,
				Collateral: additionalCollateral,
			}
			tc.Modify(&contract)

			refresh, _ := RefreshContract(contract, prices, params)
			tax := cs.V2FileContractTax(refresh.NewContract)
			renter, host := RefreshCost(cs, prices, refresh, types.ZeroCurrency)
			if !renter.Equals(renterCost.Add(tax)) {
				t.Errorf("expected renter cost %v, got %v", renterCost, renter.Sub(tax))
			} else if !host.Equals(hostCost) {
				t.Errorf("expected host cost %v, got %v", hostCost, host)
			}
		})
	}
}
