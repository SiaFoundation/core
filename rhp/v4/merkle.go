package rhp

import (
	"io"
	"math/bits"

	"go.sia.tech/core/internal/blake2b"
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

// VerifyAppendProof verifies a Merkle proof produced by BuildAppendProof.
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

func convertActions(actions []ModifyAction) []rhp2.RPCWriteAction {
	rhp2Actions := make([]rhp2.RPCWriteAction, len(actions))
	for i, a := range actions {
		switch a.Type {
		case ActionSwap:
			rhp2Actions[i] = rhp2.RPCWriteAction{
				Type: rhp2.RPCWriteActionSwap,
				A:    a.A,
				B:    a.B,
			}
		case ActionTrim:
			rhp2Actions[i] = rhp2.RPCWriteAction{
				Type: rhp2.RPCWriteActionTrim,
				A:    a.N,
			}
		case ActionUpdate:
			rhp2Actions[i] = rhp2.RPCWriteAction{
				Type: rhp2.RPCWriteActionUpdate,
				A:    a.N,
				Data: nil, // TODO
			}
		}
	}
	return rhp2Actions
}

// BuildModifySectorsProof builds a Merkle proof for modifying a set of sectors.
func BuildModifySectorsProof(actions []ModifyAction, sectorRoots []types.Hash256) (treeHashes, leafHashes []types.Hash256) {
	return rhp2.BuildDiffProof(convertActions(actions), sectorRoots)
}

// VerifyModifySectorsProof verifies a Merkle proof produced by
// BuildModifySectorsProof.
func VerifyModifySectorsProof(actions []ModifyAction, numSectors uint64, treeHashes, leafHashes []types.Hash256, oldRoot types.Hash256, newRoot types.Hash256) bool {
	return rhp2.VerifyDiffProof(convertActions(actions), numSectors, treeHashes, leafHashes, oldRoot, newRoot, nil)
}
