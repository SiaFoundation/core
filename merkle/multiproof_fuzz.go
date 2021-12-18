//go:build gofuzz
// +build gofuzz

package merkle

import "go.sia.tech/core/types"

func Fuzz(data []byte) int {
	var block CompressedBlock
	d := types.NewBufDecoder(data)
	block.DecodeFrom(d)
	if d.Err() != nil {
		return -1
	}
	return 0
}
