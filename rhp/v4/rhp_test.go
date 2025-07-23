package rhp

import (
	"math"
	"testing"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
	"lukechampine.com/frand"
)

func TestMinRenterAllowanceMaxHostCollateral(t *testing.T) {
	hp := HostPrices{
		StoragePrice: types.NewCurrency64(1), // 1 H per byte per block
		Collateral:   types.NewCurrency64(2), // 2 H per byte per block
	}

	collateral := types.Siacoins(2)
	minAllowance := MinRenterAllowance(hp, collateral)
	expected := types.Siacoins(1)
	if !minAllowance.Equals(expected) {
		t.Fatalf("expected %v, got %v", expected, minAllowance)
	}

	maxCollateral := MaxHostCollateral(hp, minAllowance)
	if !maxCollateral.Equals(collateral) {
		t.Fatalf("expected %v, got %v", collateral, maxCollateral)
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
	minerFee := types.NewCurrency64(frand.Uint64n(math.MaxUint64))
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
			Description: "renewed storage - greater capacity",
			Modify: func(rev *types.V2FileContract, p *RPCRenewContractParams) {
				// add storage
				rev.Capacity = SectorSize * 2
				rev.Filesize = SectorSize
			},
			RenterCost: prices.ContractPrice.Add(prices.StoragePrice.Mul64(SectorSize).Mul64(extension)), // storage cost is calculated for just the filesize & extension
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
			renter, host := RenewalCost(cs, renewal, minerFee)
			if !renter.Equals(tc.RenterCost.Add(tax).Add(minerFee)) {
				t.Errorf("expected renter cost %v, got %v", tc.RenterCost, renter.Sub(tax).Sub(minerFee))
			} else if !host.Equals(tc.HostCost) {
				t.Errorf("expected host cost %v, got %v", tc.HostCost, host)
			}

			contractTotal := renewal.NewContract.HostOutput.Value.Add(renewal.NewContract.RenterOutput.Value)
			totalCost := renter.Add(host).Add(renewal.HostRollover).Add(renewal.RenterRollover).Sub(tax).Sub(minerFee)
			switch {
			case !contractTotal.Equals(totalCost):
				t.Fatalf("expected contract sum %v, got %v", contractTotal, totalCost)
			case contract.Filesize != renewal.NewContract.Filesize:
				t.Fatalf("expected contract size %d, got %d", contract.Filesize, renewal.NewContract.Filesize)
			case contract.Filesize != renewal.NewContract.Capacity: // renewals reset capacity
				t.Fatalf("expected contract capacity %d, got %d", contract.Filesize, renewal.NewContract.Capacity)
			}
		})
	}
}

func TestRefreshFullRolloverCost(t *testing.T) {
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
	minerFee := types.NewCurrency64(frand.Uint64n(math.MaxUint64))

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
			Description: "renewed storage - greater capacity",
			Modify: func(rev *types.V2FileContract) {
				// add storage
				rev.Capacity = SectorSize * 4
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

			refresh, _ := RefreshContractFullRollover(contract, prices, params)
			tax := cs.V2FileContractTax(refresh.NewContract)
			renter, host := RefreshCost(cs, prices, refresh, minerFee)
			if !renter.Equals(renterCost.Add(tax).Add(minerFee)) {
				t.Errorf("expected renter cost %v, got %v", renterCost, renter.Sub(tax).Sub(minerFee))
			} else if !host.Equals(hostCost) {
				t.Errorf("expected host cost %v, got %v", hostCost, host)
			}

			contractTotal := refresh.NewContract.HostOutput.Value.Add(refresh.NewContract.RenterOutput.Value)
			totalCost := renter.Add(host).Add(refresh.HostRollover).Add(refresh.RenterRollover).Sub(tax).Sub(minerFee)

			switch {
			case !contractTotal.Equals(totalCost):
				t.Fatalf("expected contract sum %v, got %v", contractTotal, totalCost)
			case contract.Filesize != refresh.NewContract.Filesize:
				t.Fatalf("expected contract size %d, got %d", contract.Filesize, refresh.NewContract.Filesize)
			case contract.Capacity != refresh.NewContract.Capacity:
				t.Fatalf("expected contract capacity %d, got %d", contract.Capacity, refresh.NewContract.Capacity)
			}
		})
	}
}

func TestRefreshPartialRolloverCost(t *testing.T) {
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
	minerFee := types.NewCurrency64(frand.Uint64n(math.MaxUint64))

	// the actual cost to the renter and host should always be the additional allowance and collateral
	// on top of the existing contract costs
	newAllowance, additionalCollateral := types.Siacoins(20), types.Siacoins(10)

	type testCase struct {
		Description string
		Modify      func(*types.V2FileContract)
		RenterCost  types.Currency
		HostCost    types.Currency
	}

	cases := []testCase{
		{
			Description: "no storage",
			Modify:      func(rev *types.V2FileContract) {},
			RenterCost:  types.ZeroCurrency,
			HostCost:    types.ZeroCurrency,
		},
		{
			Description: "no storage - no renter rollover",
			Modify: func(rev *types.V2FileContract) {
				// transfer all of the renter funds to the host so the renter rolls over nothing
				rev.HostOutput.Value, rev.RenterOutput.Value = rev.HostOutput.Value.Add(rev.RenterOutput.Value), types.ZeroCurrency
			},
			RenterCost: prices.ContractPrice.Add(newAllowance), // the renter will need to fund the entire allowance
			HostCost:   types.ZeroCurrency,                     // the host will need to fund the entire collateral

		},
		{
			Description: "no storage - all collateral used",
			Modify: func(rev *types.V2FileContract) {
				rev.MissedHostValue = types.ZeroCurrency // the host is "risking" all of its collateral
			},
			RenterCost: types.ZeroCurrency,
			HostCost:   additionalCollateral, // the host will need to fund the new collateral
		},
		{
			Description: "partial renter rollover",
			Modify: func(rev *types.V2FileContract) {
				// transfer all but half the additional allowance to the host so the renter
				// will fund the difference
				transfer := rev.RenterOutput.Value.Sub(newAllowance.Div64(2))
				rev.HostOutput.Value, rev.RenterOutput.Value = rev.HostOutput.Value.Add(transfer), rev.RenterOutput.Value.Sub(transfer)
			},
			RenterCost: prices.ContractPrice.Add(newAllowance.Div64(2)), // the renter will need to fund half the allowance
		},
		{
			Description: "partial host rollover",
			Modify: func(rev *types.V2FileContract) {
				rev.MissedHostValue = additionalCollateral.Div64(2) // the host is risking almost all of its collateral
			},
			RenterCost: types.ZeroCurrency,            // the renter will not need to fund any additional allowance
			HostCost:   additionalCollateral.Div64(2), // the host will need to fund half the new collateral
		},
		{
			Description: "renewed storage",
			Modify: func(rev *types.V2FileContract) {
				// add storage
				rev.Capacity = SectorSize
				rev.Filesize = SectorSize
			},
			RenterCost: types.ZeroCurrency, // existing allowance should cover
		},
		{
			Description: "renewed storage - greater capacity",
			Modify: func(rev *types.V2FileContract) {
				// add storage
				rev.Capacity = SectorSize * 4
				rev.Filesize = SectorSize
			},
			RenterCost: types.ZeroCurrency, // existing allowance should cover
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
			RenterCost: prices.ContractPrice.Add(newAllowance), // the renter will need to fund the new allowance
		},
		{
			Description: "renewed storage - no host rollover",
			Modify: func(rev *types.V2FileContract) {
				// add storage
				rev.Capacity = SectorSize
				rev.Filesize = SectorSize
				rev.MissedHostValue = types.ZeroCurrency // the host is risking all of its collateral
			},
			RenterCost: types.ZeroCurrency,
			HostCost:   additionalCollateral, // the host will need to fund the new collateral
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

			params := RPCRefreshContractParams{
				Allowance:  newAllowance,
				Collateral: additionalCollateral,
			}
			tc.Modify(&contract)

			refresh, usage := RefreshContractPartialRollover(contract, prices, params)
			tax := cs.V2FileContractTax(refresh.NewContract)
			renter, host := RefreshCost(cs, prices, refresh, minerFee)
			if !renter.Equals(tc.RenterCost.Add(tax).Add(minerFee)) {
				t.Fatalf("expected renter cost %v, got %v", tc.RenterCost, renter.Sub(tax).Sub(minerFee))
			} else if !host.Equals(tc.HostCost) {
				t.Fatalf("expected host cost %v, got %v", tc.HostCost, host)
			} else if refresh.NewContract.RevisionNumber != 0 {
				t.Fatalf("expected new contract revision number to be 0, got %d", refresh.NewContract.RevisionNumber)
			} else if !usage.RPC.Equals(prices.ContractPrice) {
				t.Fatalf("expected RPC usage %v, got %v", prices.ContractPrice, usage.RPC)
			} else if !usage.Storage.IsZero() {
				t.Fatalf("expected storage usage to be zero, got %v", usage.Storage)
			} else if !usage.Ingress.IsZero() {
				t.Fatalf("expected ingress usage to be zero, got %v", usage.Ingress)
			} else if !usage.Egress.IsZero() {
				t.Fatalf("expected egress usage to be zero, got %v", usage.Egress)
			} else if !usage.RiskedCollateral.Equals(contract.TotalCollateral.Sub(contract.MissedHostValue)) {
				t.Fatalf("expected risked collateral %v, got %v", contract.TotalCollateral.Sub(contract.MissedHostValue), usage.RiskedCollateral)
			} else if refresh.HostSignature != (types.Signature{}) {
				t.Fatal("expected host signature to be unset")
			} else if refresh.RenterSignature != (types.Signature{}) {
				t.Fatal("expected renter signature to be unset")
			} else if refresh.NewContract.HostSignature != (types.Signature{}) {
				t.Fatal("expected new contract host signature to be unset")
			} else if refresh.NewContract.RenterSignature != (types.Signature{}) {
				t.Fatal("expected new contract renter signature to be unset")
			}

			contractTotal := refresh.NewContract.HostOutput.Value.Add(refresh.NewContract.RenterOutput.Value)
			totalCost := renter.Add(host).Add(refresh.HostRollover).Add(refresh.RenterRollover).Sub(tax).Sub(minerFee)

			switch {
			case !contractTotal.Equals(totalCost):
				t.Fatalf("expected contract sum %v, got %v", contractTotal, totalCost)
			case contract.Filesize != refresh.NewContract.Filesize:
				t.Fatalf("expected contract size %d, got %d", contract.Filesize, refresh.NewContract.Filesize)
			case contract.Capacity != refresh.NewContract.Capacity:
				t.Fatalf("expected contract capacity %d, got %d", contract.Capacity, refresh.NewContract.Capacity)
			}
		})
	}
}
