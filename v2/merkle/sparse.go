package merkle

import (
	"math"
	"math/bits"
	"sort"

	"go.sia.tech/core/v2/types"
)

var hashOne = types.HashBytes([]byte{leafHashPrefix, 1})

var hashZero = func() (hs [64]types.Hash256) {
	hs[0] = types.HashBytes([]byte{leafHashPrefix, 0})
	for i := range hs[1:] {
		hs[i+1] = NodeHash(hs[i], hs[i])
	}
	return
}()

func SparseRoot(elems []uint64) types.Hash256 {
	var recompute func(i, j uint64, leaves []uint64) types.Hash256
	recompute = func(i, j uint64, leaves []uint64) types.Hash256 {
		height := bits.TrailingZeros64(j - i)
		if len(leaves) == 0 {
			return hashZero[height]
		} else if len(leaves) == 1 && height == 0 {
			return hashOne
		}
		mid := (i + j) / 2
		split := sort.Search(len(leaves), func(i int) bool { return leaves[i] >= mid })
		return NodeHash(
			recompute(i, mid, leaves[:split]),
			recompute(mid, j, leaves[split:]),
		)
	}
	return recompute(0, math.MaxUint64, elems)
}
