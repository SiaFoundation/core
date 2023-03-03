//go:build testnet

package consensus

import (
	"time"

	"go.sia.tech/core/types"
)

const (
	hardforkHeightDevAddr      = 1
	hardforkHeightTax          = 2
	hardforkHeightStorageProof = 5
	hardforkHeightOak          = 10
	hardforkHeightOakFix       = 12
	hardforkHeightASIC         = 20
	hardforkHeightFoundation   = 30

	hardforkASICTotalTime = 10000 * time.Second
	minimumCoinbase       = 300000
)

var hardforkASICTotalTarget = types.BlockID{4: 1}
