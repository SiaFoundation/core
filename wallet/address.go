package wallet

import "go.sia.tech/core/types"

// StandardUnlockConditions returns the standard unlock conditions for a single
// Ed25519 key.
func StandardUnlockConditions(pub types.PublicKey) types.UnlockConditions {
	return types.UnlockConditions{
		PublicKeys: []types.UnlockKey{{
			Algorithm: types.SpecifierEd25519,
			Key:       pub[:],
		}},
		SignaturesRequired: 1,
	}
}

// StandardAddress returns the standard address for an Ed25519 key.
func StandardAddress(pub types.PublicKey) types.Address {
	return StandardUnlockConditions(pub).UnlockHash()
}
