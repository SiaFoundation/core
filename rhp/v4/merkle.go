package rhp

import (
	"io"
	"math/bits"

	"go.sia.tech/core/blake2b"
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

// BuildSectorProof builds a Merkle proof for a given range within a sector.
func BuildSectorProof(sector *[SectorSize]byte, start, end uint64) []types.Hash256 {
	return rhp2.BuildProof(sector, start, end, nil)
}

// A RangeProofVerifier allows range proofs to be verified in streaming fashion.
type RangeProofVerifier = rhp2.RangeProofVerifier

// NewRangeProofVerifier returns a RangeProofVerifier for the sector range
// [start, end).
func NewRangeProofVerifier(start, end uint64) *RangeProofVerifier {
	return rhp2.NewRangeProofVerifier(start, end)
}

// VerifyLeafProof verifies the Merkle proof for a given leaf within a sector.
func VerifyLeafProof(proof []types.Hash256, leaf [64]byte, leafIndex uint64, root types.Hash256) bool {
	return rhp2.VerifySectorRangeProof(proof, []types.Hash256{blake2b.SumLeaf(&leaf)}, leafIndex, leafIndex+1, LeavesPerSector, root)
}

// BuildAppendProof builds a Merkle proof for appending a set of sectors to a
// contract.
func BuildAppendProof(sectorRoots, appended []types.Hash256) ([]types.Hash256, types.Hash256) {
	var acc blake2b.Accumulator
	for _, h := range sectorRoots {
		acc.AddLeaf(h)
	}
	var subtreeRoots []types.Hash256
	for i, h := range acc.Trees {
		if acc.NumLeaves&(1<<i) != 0 {
			subtreeRoots = append(subtreeRoots, h)
		}
	}
	for _, h := range appended {
		acc.AddLeaf(h)
	}
	return subtreeRoots, acc.Root()
}

// VerifyAppendSectorsProof verifies a Merkle proof produced by BuildAppendProof.
func VerifyAppendSectorsProof(numSectors uint64, subtreeRoots []types.Hash256, appended []types.Hash256, oldRoot, newRoot types.Hash256) bool {
	acc := blake2b.Accumulator{NumLeaves: numSectors}
	for i := 0; i < bits.Len64(numSectors); i++ {
		if numSectors&(1<<i) != 0 && len(subtreeRoots) > 0 {
			acc.Trees[i] = subtreeRoots[0]
			subtreeRoots = subtreeRoots[1:]
		}
	}
	if acc.Root() != oldRoot {
		return false
	}
	for _, h := range appended {
		acc.AddLeaf(h)
	}
	return acc.Root() == newRoot
}

// BuildSectorRootsProof builds a Merkle proof for a range of sectors within a
// contract.
func BuildSectorRootsProof(sectorRoots []types.Hash256, start, end uint64) []types.Hash256 {
	return rhp2.BuildSectorRangeProof(sectorRoots, start, end)
}

// VerifySectorRootsProof verifies a Merkle proof produced by
// BuildSectorRootsProof.
func VerifySectorRootsProof(proof, sectorRoots []types.Hash256, numSectors, start, end uint64, root types.Hash256) bool {
	return rhp2.VerifySectorRangeProof(proof, sectorRoots, start, end, numSectors, root)
}

func convertFreeActions(freed []uint64, numSectors uint64) []rhp2.RPCWriteAction {
	as := make([]rhp2.RPCWriteAction, 0, len(freed)+1)
	// swap
	for i, n := range freed {
		as = append(as, rhp2.RPCWriteAction{
			Type: rhp2.RPCWriteActionSwap,
			A:    n,
			B:    numSectors - uint64(i) - 1,
		})
	}
	// trim
	return append(as, rhp2.RPCWriteAction{
		Type: rhp2.RPCWriteActionTrim,
		A:    uint64(len(freed)),
	})
}

// BuildFreeSectorsProof builds a Merkle proof for freeing a set of sectors.
func BuildFreeSectorsProof(sectorRoots []types.Hash256, freed []uint64) (treeHashes, leafHashes []types.Hash256) {
	return rhp2.BuildDiffProof(convertFreeActions(freed, uint64(len(sectorRoots))), sectorRoots)
}

// VerifyFreeSectorsProof verifies a Merkle proof produced by
// BuildFreeSectorsProof.
func VerifyFreeSectorsProof(treeHashes, leafHashes []types.Hash256, freed []uint64, numSectors uint64, oldRoot types.Hash256, newRoot types.Hash256) bool {
	return rhp2.VerifyDiffProof(convertFreeActions(freed, numSectors), numSectors, treeHashes, leafHashes, oldRoot, newRoot, nil)
}
