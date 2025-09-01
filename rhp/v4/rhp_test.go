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
			Description: "no storage - some renter rollover",
			Modify: func(rev *types.V2FileContract) {
				// transfer all but the new allowance and half the contract price to the host.
				// the renter will need to fund half the contract price
				transfer := rev.RenterOutput.Value.Sub(newAllowance.Add(prices.ContractPrice.Div64(2)))
				rev.HostOutput.Value, rev.RenterOutput.Value = rev.HostOutput.Value.Add(transfer), rev.RenterOutput.Value.Sub(transfer)
			},
			RenterCost: prices.ContractPrice.Div64(2),
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
			} else if !usage.RiskedCollateral.Equals(contract.RiskedCollateral()) {
				t.Fatalf("expected risked collateral %v, got %v", contract.RiskedCollateral(), usage.RiskedCollateral)
			} else if refresh.HostSignature != (types.Signature{}) {
				t.Fatal("expected host signature to be unset")
			} else if refresh.RenterSignature != (types.Signature{}) {
				t.Fatal("expected renter signature to be unset")
			} else if refresh.NewContract.HostSignature != (types.Signature{}) {
				t.Fatal("expected new contract host signature to be unset")
			} else if refresh.NewContract.RenterSignature != (types.Signature{}) {
				t.Fatal("expected new contract renter signature to be unset")
			} else if !refresh.FinalRenterOutput.Value.Add(refresh.RenterRollover).Equals(contract.RenterOutput.Value) {
				t.Fatalf("expected final renter output %v + rollover %v to equal original renter output %v, got %v",
					refresh.FinalRenterOutput.Value, refresh.RenterRollover, contract.RenterOutput.Value, refresh.FinalRenterOutput.Value.Add(refresh.RenterRollover))
			} else if !refresh.FinalHostOutput.Value.Add(refresh.HostRollover).Equals(contract.HostOutput.Value) {
				t.Fatalf("expected final host output %v + rollover %v to equal original host output %v, got %v",
					refresh.FinalHostOutput.Value, refresh.HostRollover, contract.HostOutput.Value, refresh.FinalHostOutput.Value.Add(refresh.HostRollover))
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

func TestProtocolVersionCmp(t *testing.T) {
	for i := range 3 {
		v1 := ProtocolVersion{1, 1, 1}
		v2 := ProtocolVersion{1, 1, 1}

		// both should be equal
		if v1.Cmp(v2) != 0 {
			t.Error("expected versions to be equal")
		} else if v2.Cmp(v1) != 0 {
			t.Error("expected versions to be equal")
		}

		// update one of the version bytes and make sure that's no longer the
		// case
		v1[i] = 2
		if v1.Cmp(v2) != 1 {
			t.Errorf("expected %v to be greater than %v", v1, v2)
		} else if v2.Cmp(v1) != -1 {
			t.Errorf("expected %v to be less than %v", v2, v1)
		}
	}
}

func TestProtocolVersionMarshalling(t *testing.T) {
	v := ProtocolVersion{1, 2, 3}
	expected := "v1.2.3"
	if v.String() != expected {
		t.Errorf("expected %s, got %s", expected, v.String())
	}

	b, err := v.MarshalText()
	if err != nil {
		t.Fatal(err)
	} else if string(b) != expected {
		t.Fatalf("expected %s, got %s", expected, string(b))
	}

	var v2 ProtocolVersion
	if err := v2.UnmarshalText(b); err != nil {
		t.Fatal(err)
	} else if v2 != v {
		t.Fatalf("expected %v, got %v", v, v2)
	}
}

func TestProtocolVersionCompatMarshalling(t *testing.T) {
	tests := []struct {
		json     string
		expected ProtocolVersion
		hasError bool
	}{
		{
			json:     `[0, 1, 2]`,
			expected: ProtocolVersion{0, 1, 2},
		},
		{
			json: `[
			0, 1, 2]`,
			expected: ProtocolVersion{0, 1, 2},
		},
		{
			json: `[
			0,
			1,
			2
]`,
			expected: ProtocolVersion{0, 1, 2},
		},
		{
			json:     `[1, 2, 3, 4]`,
			expected: ProtocolVersion{1, 2, 3}, // json ignores extra elements
		},
		{
			json:     `"v1.0.0"`,
			hasError: false,
			expected: ProtocolVersion{1, 0, 0},
		},
		{
			json:     `[foo, bar, baz]`,
			hasError: true,
		},
		{
			json:     `[-1, 2, 3]`,
			hasError: true,
		},
	}
	for _, test := range tests {
		t.Run(test.json, func(t *testing.T) {
			var v ProtocolVersion
			if err := v.UnmarshalJSON([]byte(test.json)); err == nil && test.hasError {
				t.Fatal("expected error")
			} else if err != nil && !test.hasError {
				t.Fatal("unexpected error:", err)
			} else if err != nil {
				return // expected error
			} else if v != test.expected {
				t.Fatalf("expected %v, got %v", test.expected, v)
			}
		})
	}
}
