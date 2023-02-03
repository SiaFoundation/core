//go:build !testing

package rhp

import (
	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

// SectorSize is the size of one sector in bytes.
const SectorSize = 1 << 22 // 4 MiB

func contractTax(fc types.FileContract) types.Currency {
	// NOTE: siad uses different hardfork heights when -tags=testing is set,
	// so we have to alter cs accordingly.
	// TODO: remove this
	cs := consensus.State{Index: types.ChainIndex{Height: fc.WindowStart}}
	return cs.FileContractTax(fc)
}
