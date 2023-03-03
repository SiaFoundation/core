//go:build !testnet

package consensus

import (
	"time"

	"go.sia.tech/core/types"
)

const (
	hardforkHeightDevAddr      = 10000
	hardforkHeightTax          = 21000
	hardforkHeightStorageProof = 100000
	hardforkHeightOak          = 135000
	hardforkHeightOakFix       = 139000
	hardforkHeightASIC         = 179000
	hardforkHeightFoundation   = 298000

	hardforkASICTotalTime = 120000 * time.Second
	minimumCoinbase       = 30000
)

var hardforkASICTotalTarget = types.BlockID{8: 32}
