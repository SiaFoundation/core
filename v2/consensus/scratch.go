package consensus

import (
	"errors"

	"go.sia.tech/core/v2/types"
)

// A ScratchChain processes a potential extension or fork of the best chain,
// first validating its headers, then its transactions.
type ScratchChain struct {
	base    types.ChainIndex
	headers []types.BlockHeader

	hs State // for validating headers
	ts State // for validating transactions
}

// AppendHeader validates the supplied header and appends it to the chain.
// Headers must be appended before their transactions can be filled in with
// AppendBlockTransactions.
func (sc *ScratchChain) AppendHeader(h types.BlockHeader) error {
	if err := sc.hs.validateHeader(h); err != nil {
		return err
	}
	applyHeader(&sc.hs, h)
	sc.headers = append(sc.headers, h)
	return nil
}

// ApplyBlock applies b to the chain. The block's validated header must already
// exist in the chain.
func (sc *ScratchChain) ApplyBlock(b types.Block) (Checkpoint, error) {
	if sc.ts.Index.Height+1 > sc.hs.Index.Height {
		return Checkpoint{}, errors.New("more blocks than headers")
	} else if err := sc.ts.ValidateBlock(b); err != nil {
		return Checkpoint{}, err
	}
	sc.ts = ApplyBlock(sc.ts, b).State
	return Checkpoint{
		Block: b,
		State: sc.ts,
	}, nil
}

// Index returns the chain index at the specified height. The index may or may
// not have a corresponding validated block.
func (sc *ScratchChain) Index(height uint64) types.ChainIndex {
	// if the height matches our current tip, return that
	if height == sc.Tip().Height {
		return sc.Tip()
	}
	// otherwise, we should have a child header, so we can use its ParentIndex
	// instead of re-hashing the actual header
	return sc.headers[height-sc.Base().Height].ParentIndex()
}

// Base returns the base of the header chain, i.e. the parent of the first
// header.
func (sc *ScratchChain) Base() types.ChainIndex {
	return sc.base
}

// Tip returns the tip of the header chain, which may or may not have a
// corresponding validated block.
func (sc *ScratchChain) Tip() types.ChainIndex {
	return sc.hs.Index
}

// UnvalidatedBase returns the base of the unvalidated header chain, i.e. the
// lowest index for which there is no validated block. If all of the blocks have
// been validated, UnvalidatedBase panics.
func (sc *ScratchChain) UnvalidatedBase() types.ChainIndex {
	if sc.ts.Index.Height == sc.base.Height {
		return sc.base
	}
	return sc.Index(sc.ts.Index.Height + 1)
}

// ValidTip returns the tip of the validated header chain, i.e. the highest
// index for which there is a known validated block.
func (sc *ScratchChain) ValidTip() types.ChainIndex {
	return sc.ts.Index
}

// FullyValidated is equivalent to sc.Tip() == sc.ValidTip().
func (sc *ScratchChain) FullyValidated() bool {
	return sc.ts.Index == sc.hs.Index
}

// TotalWork returns the total work of the header chain.
func (sc *ScratchChain) TotalWork() types.Work {
	return sc.hs.TotalWork
}

// Contains returns whether the chain contains the specified index. It does not
// indicate whether the transactions for that index have been validated.
func (sc *ScratchChain) Contains(index types.ChainIndex) bool {
	if !(sc.Base().Height < index.Height && index.Height <= sc.Tip().Height) {
		return false
	}
	return sc.Index(index.Height) == index
}

// Unvalidated returns the indexes of all the unvalidated blocks in the chain.
func (sc *ScratchChain) Unvalidated() []types.ChainIndex {
	headers := sc.headers[sc.ts.Index.Height-sc.Base().Height:]
	indices := make([]types.ChainIndex, len(headers))
	for i := range indices {
		indices[i] = sc.Index(headers[i].Height)
	}
	return indices
}

// NewScratchChain initializes a ScratchChain with the provided State.
func NewScratchChain(s State) *ScratchChain {
	return &ScratchChain{
		base: s.Index,
		hs:   s,
		ts:   s,
	}
}
