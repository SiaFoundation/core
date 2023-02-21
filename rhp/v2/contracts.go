package rhp

import (
	"math/bits"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

// ContractFormationCost returns the cost of forming a contract.
func ContractFormationCost(fc types.FileContract, contractFee types.Currency) (types.Currency, error) {
	return fc.ValidRenterPayout().Intermediate().Add(contractFee.Intermediate()).Add(contractTax(fc).Intermediate()).Result()
}

// ContractFormationCollateral returns the amount of collateral we add when
// forming a contract where expectedStorage is the amount of storage we expect
// to upload to the contract.
func ContractFormationCollateral(period uint64, expectedStorage uint64, host HostSettings) (types.Currency, error) {
	// calculate the collateral
	collateral := host.Collateral.Intermediate().Mul64(expectedStorage).Mul64(period)
	if collateral.Cmp(host.MaxCollateral.Intermediate()) > 0 {
		return host.MaxCollateral, nil
	}
	return collateral.Result()
}

// PrepareContractFormation constructs a contract formation transaction.
func PrepareContractFormation(renterKey types.PrivateKey, hostKey types.PublicKey, renterPayout, hostCollateral types.Currency, endHeight uint64, host HostSettings, refundAddr types.Address) (types.FileContract, error) {
	renterPubkey := renterKey.PublicKey()
	uc := types.UnlockConditions{
		PublicKeys: []types.UnlockKey{
			{Algorithm: types.SpecifierEd25519, Key: renterPubkey[:]},
			{Algorithm: types.SpecifierEd25519, Key: hostKey[:]},
		},
		SignaturesRequired: 2,
	}

	hostPayout, err := host.ContractPrice.Intermediate().Add(hostCollateral.Intermediate()).Result()
	if err != nil {
		return types.FileContract{}, err
	}
	totalPayout, err := renterPayout.Intermediate().Add(hostPayout.Intermediate()).Result()
	if err != nil {
		return types.FileContract{}, err
	}
	payout, err := taxAdjustedPayout(totalPayout)
	if err != nil {
		return types.FileContract{}, err
	}

	return types.FileContract{
		Filesize:       0,
		FileMerkleRoot: types.Hash256{},
		WindowStart:    uint64(endHeight),
		WindowEnd:      uint64(endHeight + host.WindowSize),
		Payout:         payout,
		UnlockHash:     types.Hash256(uc.UnlockHash()),
		RevisionNumber: 0,
		ValidProofOutputs: []types.SiacoinOutput{
			// outputs need to account for tax
			{Value: renterPayout, Address: refundAddr},
			// collateral is returned to host
			{Value: hostPayout, Address: host.Address},
		},
		MissedProofOutputs: []types.SiacoinOutput{
			// same as above
			{Value: renterPayout, Address: refundAddr},
			// same as above
			{Value: hostPayout, Address: host.Address},
			// once we start doing revisions, we'll move some coins to the host and some to the void
			{Value: types.ZeroCurrency, Address: types.Address{}},
		},
	}, nil
}

// ContractRenewalCost returns the cost of renewing a contract.
func ContractRenewalCost(fc types.FileContract, contractFee types.Currency) (types.Currency, error) {
	return fc.ValidRenterPayout().Intermediate().Add(contractFee.Intermediate()).Add(contractTax(fc).Intermediate()).Result()
}

// ContractRenewalCollateral returns the amount of collateral we add on top of
// the baseCollateral when renewing a contract. It takes into account the host's
// max collateral setting and ensures the total collateral does not exceed it.
// expectedNewStorage is the amount of storage we expect to be uploaded
// additionally to the amount of storage already in the contract.
func ContractRenewalCollateral(fc types.FileContract, expectedNewStorage uint64, host HostSettings, blockHeight, endHeight uint64) (types.Currency, error) {
	if endHeight < fc.EndHeight() {
		panic("endHeight should be at least the current end height of the contract")
	}
	extension := endHeight - fc.EndHeight()
	if endHeight < blockHeight {
		panic("current blockHeight should be lower than the endHeight")
	}
	duration := endHeight - blockHeight

	// calculate the base collateral - if it exceeds MaxCollateral we can't add more collateral
	baseCollateral := host.Collateral.Intermediate().Mul64(fc.Filesize).Mul64(extension)
	if baseCollateral.Cmp(host.MaxCollateral.Intermediate()) >= 0 {
		return types.ZeroCurrency, nil
	}

	// calculate the new collateral
	newCollateral := host.Collateral.Intermediate().Mul64(expectedNewStorage).Mul64(duration)

	// if the total collateral is more than the MaxCollateral subtract the
	// delta.
	totalCollateral := baseCollateral.Add(newCollateral)
	if totalCollateral.Cmp(host.MaxCollateral.Intermediate()) > 0 {
		delta := totalCollateral.Sub(host.MaxCollateral.Intermediate())
		if delta.Cmp(newCollateral) > 0 {
			newCollateral = types.ZeroCurrency.Intermediate()
		} else {
			newCollateral = newCollateral.Sub(delta)
		}
	}
	return newCollateral.Result()
}

// PrepareContractRenewal constructs a contract renewal transaction.
func PrepareContractRenewal(currentRevision types.FileContractRevision, renterAddress types.Address, renterKey types.PrivateKey, renterPayout, newCollateral types.Currency, hostKey types.PublicKey, host HostSettings, endHeight uint64) (types.FileContract, error) {
	hostValidPayout, hostMissedPayout, voidMissedPayout, err := CalculateHostPayouts(currentRevision.FileContract, newCollateral, host, endHeight)
	if err != nil {
		return types.FileContract{}, err
	}

	totalPayout, err := renterPayout.Intermediate().Add(hostValidPayout.Intermediate()).Result()
	if err != nil {
		return types.FileContract{}, err
	}
	taxAdjustedPayout, err := taxAdjustedPayout(totalPayout)
	if err != nil {
		return types.FileContract{}, err
	}
	return types.FileContract{
		Filesize:       currentRevision.Filesize,
		FileMerkleRoot: currentRevision.FileMerkleRoot,
		WindowStart:    uint64(endHeight),
		WindowEnd:      uint64(endHeight + host.WindowSize),
		Payout:         taxAdjustedPayout,
		UnlockHash:     currentRevision.UnlockHash,
		RevisionNumber: 0,
		ValidProofOutputs: []types.SiacoinOutput{
			{Value: renterPayout, Address: renterAddress},
			{Value: hostValidPayout, Address: host.Address},
		},
		MissedProofOutputs: []types.SiacoinOutput{
			{Value: renterPayout, Address: renterAddress},
			{Value: hostMissedPayout, Address: host.Address},
			{Value: voidMissedPayout, Address: types.Address{}},
		},
	}, nil
}

// CalculateHostPayouts calculates the contract payouts for the host.
func CalculateHostPayouts(fc types.FileContract, newCollateral types.Currency, settings HostSettings, endHeight uint64) (types.Currency, types.Currency, types.Currency, error) {
	// The host gets their contract fee, plus the cost of the data already in the
	// contract, plus their collateral. In the event of a missed payout, the cost
	// and collateral of the data already in the contract is subtracted from the
	// host, and sent to the void instead.
	//
	// However, it is possible for this subtraction to underflow: this can happen if
	// baseCollateral is large and MaxCollateral is small. We cannot simply replace
	// the underflow with a zero, because the host performs the same subtraction and
	// returns an error on underflow. Nor can we increase the valid payout, because
	// the host calculates its collateral contribution by subtracting the contract
	// price and base price from this payout, and we're already at MaxCollateral.
	// Thus the host has conflicting requirements, and renewing the contract is
	// impossible until they change their settings.

	// calculate base price and collateral
	var basePrice, baseCollateral = types.ZeroCurrency.Intermediate(), types.ZeroCurrency.Intermediate()

	// if the contract height did not increase both prices are zero
	if contractEnd := uint64(endHeight + settings.WindowSize); contractEnd > fc.WindowEnd {
		timeExtension := uint64(contractEnd - fc.WindowEnd)
		basePrice = settings.StoragePrice.Intermediate().Mul64(fc.Filesize).Mul64(timeExtension)
		baseCollateral = settings.Collateral.Intermediate().Mul64(fc.Filesize).Mul64(timeExtension)
	}

	// calculate payouts
	hostValidPayout := settings.ContractPrice.Intermediate().Add(basePrice).Add(baseCollateral).Add(newCollateral.Intermediate())
	voidMissedPayout := basePrice.Add(baseCollateral)
	if hostValidPayout.Cmp(voidMissedPayout) < 0 {
		// TODO: detect this elsewhere
		panic("host's settings are unsatisfiable")
	}
	hostMissedPayout := hostValidPayout.Sub(voidMissedPayout)
	hvp, err := hostValidPayout.Result()
	if err != nil {
		return types.Currency{}, types.Currency{}, types.Currency{}, err
	}
	hmp, err := hostMissedPayout.Result()
	if err != nil {
		return types.Currency{}, types.Currency{}, types.Currency{}, err
	}
	vmp, err := voidMissedPayout.Result()
	if err != nil {
		return types.Currency{}, types.Currency{}, types.Currency{}, err
	}
	return hvp, hmp, vmp, nil
}

// NOTE: due to a bug in the transaction validation code, calculating payouts
// is way harder than it needs to be. Tax is calculated on the post-tax
// contract payout (instead of the sum of the renter and host payouts). So the
// equation for the payout is:
//
//	   payout = renterPayout + hostPayout + payout*tax
//	∴  payout = (renterPayout + hostPayout) / (1 - tax)
//
// This would work if 'tax' were a simple fraction, but because the tax must
// be evenly distributed among siafund holders, 'tax' is actually a function
// that multiplies by a fraction and then rounds down to the nearest multiple
// of the siafund count. Thus, when inverting the function, we have to make an
// initial guess and then fix the rounding error.
func taxAdjustedPayout(target types.Currency) (types.Currency, error) {
	// compute initial guess as target * (1 / 1-tax); since this does not take
	// the siafund rounding into account, the guess will be up to
	// types.SiafundCount greater than the actual payout value.
	guess, err := target.Intermediate().Mul64(1000).Div64(961).Result()
	if err != nil {
		return types.Currency{}, err
	}

	// now, adjust the guess to remove the rounding error. We know that:
	//
	//   (target % types.SiafundCount) == (payout % types.SiafundCount)
	//
	// therefore, we can simply adjust the guess to have this remainder as
	// well. The only wrinkle is that, since we know guess >= payout, if the
	// guess remainder is smaller than the target remainder, we must subtract
	// an extra types.SiafundCount.
	//
	// for example, if target = 87654321 and types.SiafundCount = 10000, then:
	//
	//   initial_guess  = 87654321 * (1 / (1 - tax))
	//                  = 91211572
	//   target % 10000 =     4321
	//   adjusted_guess = 91204321

	mod64 := func(c types.Currency, v uint64) types.Currency {
		var r uint64
		if c.Hi < v {
			_, r = bits.Div64(c.Hi, c.Lo, v)
		} else {
			_, r = bits.Div64(0, c.Hi, v)
			_, r = bits.Div64(r, c.Lo, v)
		}
		return types.NewCurrency64(r)
	}
	sfc := (consensus.State{}).SiafundCount()
	tm := mod64(target, sfc).Intermediate()
	gm := mod64(guess, sfc).Intermediate()
	if gm.Cmp(tm) < 0 {
		guess, err = guess.Intermediate().Sub(types.NewCurrency64(sfc).Intermediate()).Result()
		if err != nil {
			return types.Currency{}, err
		}
	}
	return guess.Intermediate().Add(tm).Sub(gm).Result()
}
