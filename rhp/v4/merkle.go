package rhp

import (
	"io"

	rhp2 "go.sia.tech/core/rhp/v2"
	"go.sia.tech/core/types"
)

const (
	// LeafSize is the size of one leaf in bytes.
	LeafSize = rhp2.LeafSize

	// LeavesPerSector is the number of leaves in one sector.
	LeavesPerSector = rhp2.LeavesPerSector
)

// SectorRoot computes the Merkle root of a sector.
func SectorRoot(sector *[SectorSize]byte) types.Hash256 {
	return rhp2.SectorRoot(sector)
}

// ReaderRoot returns the Merkle root of the supplied stream, which must contain
// an integer multiple of leaves.
func ReaderRoot(r io.Reader) (types.Hash256, error) {
	return rhp2.ReaderRoot(r)
}

// ReadSector reads a single sector from r and calculates its root.
func ReadSector(r io.Reader) (types.Hash256, *[SectorSize]byte, error) {
	return rhp2.ReadSector(r)
}

// MetaRoot calculates the root of a set of existing Merkle roots.
func MetaRoot(roots []types.Hash256) types.Hash256 {
	return rhp2.MetaRoot(roots)
}
