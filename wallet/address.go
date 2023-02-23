package wallet

import (
	"encoding/binary"

	"go.sia.tech/core/types"
)

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
	// An Address is the Merkle root of UnlockConditions. Since the standard
	// UnlockConditions use a single public key, the Merkle tree is:
	//
	//           ┌─────────┴──────────┐
	//     ┌─────┴─────┐              │
	//  timelock     pubkey     sigsrequired
	//
	// This implies a total of 5 blake2b hashes: 3 leaves and 2 nodes. However,
	// in standard UnlockConditions, the timelock and sigsrequired are always
	// the same (0 and 1, respectively), so we can precompute these hashes,
	// bringing the total down to 3 blake2b hashes.

	// calculate the leaf hash for the pubkey.
	buf := make([]byte, 1+16+8+32, 65)
	buf[0] = 0x00 // Merkle tree leaf prefix
	copy(buf[1:], types.SpecifierEd25519[:])
	binary.LittleEndian.PutUint64(buf[17:], 32)
	copy(buf[25:], pub[:])
	pubkeyHash := types.HashBytes(buf)

	// blake2b(0x00 | uint64(0))
	timelockHash := []byte{
		0x51, 0x87, 0xb7, 0xa8, 0x02, 0x1b, 0xf4, 0xf2,
		0xc0, 0x04, 0xea, 0x3a, 0x54, 0xcf, 0xec, 0xe1,
		0x75, 0x4f, 0x11, 0xc7, 0x62, 0x4d, 0x23, 0x63,
		0xc7, 0xf4, 0xcf, 0x4f, 0xdd, 0xd1, 0x44, 0x1e,
	}
	// blake2b(0x00 | uint64(1))
	sigsrequiredHash := []byte{
		0xb3, 0x60, 0x10, 0xeb, 0x28, 0x5c, 0x15, 0x4a,
		0x8c, 0xd6, 0x30, 0x84, 0xac, 0xbe, 0x7e, 0xac,
		0x0c, 0x4d, 0x62, 0x5a, 0xb4, 0xe1, 0xa7, 0x6e,
		0x62, 0x4a, 0x87, 0x98, 0xcb, 0x63, 0x49, 0x7b,
	}

	buf = buf[:65]
	buf[0] = 0x01 // Merkle tree node prefix
	copy(buf[1:], timelockHash)
	copy(buf[33:], pubkeyHash[:])
	tlpkHash := types.HashBytes(buf)
	copy(buf[1:], tlpkHash[:])
	copy(buf[33:], sigsrequiredHash)
	return types.Address(types.HashBytes(buf))
}
