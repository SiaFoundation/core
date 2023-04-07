package chain

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

var (
	// ErrFutureBlock is returned when a block's timestamp is too far in the future.
	ErrFutureBlock = errors.New("block's timestamp is too far in the future")
)

// A Checkpoint pairs a block with its resulting chain state.
type Checkpoint struct {
	Block types.Block
	State consensus.State
	Diff  *consensus.BlockDiff // nil if the block has not been validated
}

// EncodeTo implements types.EncoderTo.
func (c Checkpoint) EncodeTo(e *types.Encoder) {
	c.Block.EncodeTo(e)
	c.State.EncodeTo(e)
	e.WriteBool(c.Diff != nil)
	if c.Diff != nil {
		c.Diff.EncodeTo(e)
	}
}

// DecodeFrom implements types.DecoderFrom.
func (c *Checkpoint) DecodeFrom(d *types.Decoder) {
	c.Block.DecodeFrom(d)
	c.State.DecodeFrom(d)
	if d.ReadBool() {
		c.Diff = new(consensus.BlockDiff)
		c.Diff.DecodeFrom(d)
	}
}

// An ApplyUpdate reflects the changes to the blockchain resulting from the
// addition of a block.
type ApplyUpdate struct {
	Block types.Block
	State consensus.State // post-application
	Diff  consensus.BlockDiff
}

// A RevertUpdate reflects the changes to the blockchain resulting from the
// removal of a block.
type RevertUpdate struct {
	Block types.Block
	State consensus.State // post-reversion, i.e. pre-application
	Diff  consensus.BlockDiff
}

// A Subscriber processes updates to the blockchain. Implementations must not
// modify or retain the provided update object.
type Subscriber interface {
	// Implementations MUST not commit updates to persistent storage unless mayCommit is set.
	ProcessChainApplyUpdate(cau *ApplyUpdate, mayCommit bool) error
	ProcessChainRevertUpdate(cru *RevertUpdate) error
}

// A Store durably commits Manager-related data to storage. I/O errors must be
// handled internally, e.g. by panicking or calling os.Exit.
type Store interface {
	WithConsensus(func(consensus.Store))
	AddCheckpoint(c Checkpoint)
	Checkpoint(id types.BlockID) (Checkpoint, bool)
	BestIndex(height uint64) (types.ChainIndex, bool)
	ApplyDiff(s consensus.State, diff consensus.BlockDiff) (mayCommit bool)
	RevertDiff(s consensus.State, diff consensus.BlockDiff)
}

// A Manager tracks multiple blockchains and identifies the best valid
// chain.
type Manager struct {
	store       Store
	tipState    consensus.State
	subscribers []Subscriber
	lastCommit  time.Time

	mu sync.Mutex
}

// TipState returns the consensus state for the current tip.
func (m *Manager) TipState() consensus.State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tipState
}

// Tip returns the tip of the best known valid chain.
func (m *Manager) Tip() types.ChainIndex {
	return m.TipState().Index
}

// Block returns the block with the specified ID.
func (m *Manager) Block(id types.BlockID) (types.Block, bool) {
	c, ok := m.store.Checkpoint(id)
	return c.Block, ok
}

// History returns a set of block IDs that span the best chain, beginning with
// the 10 most-recent blocks, and subsequently spaced exponentionally farther
// apart until reaching the genesis block.
func (m *Manager) History() ([32]types.BlockID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	tipHeight := m.tipState.Index.Height
	histHeight := func(i int) uint64 {
		offset := uint64(i)
		if offset >= 10 {
			offset = 7 + 1<<(i-8) // strange, but it works
		}
		if offset > tipHeight {
			offset = tipHeight
		}
		return tipHeight - offset
	}
	var history [32]types.BlockID
	for i := range history {
		index, ok := m.store.BestIndex(histHeight(i))
		if !ok {
			return history, fmt.Errorf("missing best index at height %v", histHeight(i))
		}
		history[i] = index.ID
	}
	return history, nil
}

// BlocksForHistory fills the provided slice with consecutive blocks from the
// best chain, starting from the "attach point" -- the first ID in the history
// that is present in the best chain (or, if no match is found, genesis).
//
// The returned slice may have fewer than len(blocks) elements if the end of the
// best chain is reached.
func (m *Manager) BlocksForHistory(blocks []types.Block, history []types.BlockID) ([]types.Block, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var attachHeight uint64
	for _, id := range history {
		if c, ok := m.store.Checkpoint(id); !ok {
			continue
		} else if index, ok := m.store.BestIndex(c.State.Index.Height); ok && index == c.State.Index {
			attachHeight = c.State.Index.Height
			break
		}
	}
	for i := range blocks {
		if index, ok := m.store.BestIndex(attachHeight + uint64(i) + 1); !ok {
			return blocks[:i], nil
		} else if c, ok := m.store.Checkpoint(index.ID); !ok {
			return nil, fmt.Errorf("missing block %v", index)
		} else {
			blocks[i] = c.Block
		}
	}
	return blocks, nil
}

// AddBlocks adds a sequence of blocks to a tracked chain. If the blocks are
// valid, the chain may become the new best chain, triggering a reorg.
func (m *Manager) AddBlocks(blocks []types.Block) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(blocks) == 0 {
		return nil
	}

	cs := m.tipState
	for _, b := range blocks {
		if c, ok := m.store.Checkpoint(b.ID()); ok {
			// already have this block
			cs = c.State
			continue
		} else if b.ParentID != c.State.Index.ID {
			c, ok := m.store.Checkpoint(b.ParentID)
			if !ok {
				return fmt.Errorf("missing parent checkpoint for block %v", b.ID())
			}
			cs = c.State
		}
		if b.Timestamp.After(cs.MaxFutureTimestamp(time.Now())) {
			return ErrFutureBlock
		} else if err := consensus.ValidateOrphan(cs, b); err != nil {
			return fmt.Errorf("block %v is invalid: %w", types.ChainIndex{Height: cs.Index.Height + 1, ID: b.ID()}, err)
		}
		m.store.WithConsensus(func(cstore consensus.Store) {
			cs = consensus.ApplyState(cs, cstore, b)
		})
		m.store.AddCheckpoint(Checkpoint{b, cs, nil})
	}

	// if this chain is now the best chain, trigger a reorg
	//
	// TODO: SurpassThreshold?
	if cs.Depth.CmpWork(m.tipState.Depth) > 0 {
		if err := m.reorgTo(cs.Index); err != nil {
			return fmt.Errorf("reorg failed: %w", err)
		}
	}
	return nil
}

// revertTip reverts the current tip.
func (m *Manager) revertTip() error {
	c, ok := m.store.Checkpoint(m.tipState.Index.ID)
	if !ok {
		return fmt.Errorf("missing checkpoint for index %v", m.tipState.Index)
	}
	pc, ok := m.store.Checkpoint(c.Block.ParentID)
	if !ok {
		return fmt.Errorf("missing checkpoint for block %v", c.Block.ParentID)
	}
	m.store.RevertDiff(pc.State, *c.Diff)

	update := RevertUpdate{c.Block, pc.State, *c.Diff}
	for _, s := range m.subscribers {
		if err := s.ProcessChainRevertUpdate(&update); err != nil {
			return fmt.Errorf("subscriber %T: %w", s, err)
		}
	}

	m.tipState = pc.State
	return nil
}

// applyTip adds a block to the current tip.
func (m *Manager) applyTip(index types.ChainIndex) error {
	c, ok := m.store.Checkpoint(index.ID)
	if !ok {
		return fmt.Errorf("missing checkpoint for index %v", index)
	} else if c.Block.ParentID != m.tipState.Index.ID {
		panic("applyTip called with non-attaching block")
	}
	if c.Diff == nil {
		var err error
		m.store.WithConsensus(func(cstore consensus.Store) {
			if err = consensus.ValidateBlock(m.tipState, cstore, c.Block); err != nil {
				err = fmt.Errorf("block %v is invalid: %w", index, err)
				return
			}
			diff := consensus.ApplyDiff(m.tipState, cstore, c.Block)
			c.Diff = &diff
		})
		if err != nil {
			return err
		}
		m.store.AddCheckpoint(c)
	}
	mayCommit := m.store.ApplyDiff(c.State, *c.Diff)

	update := ApplyUpdate{c.Block, c.State, *c.Diff}
	for _, s := range m.subscribers {
		if err := s.ProcessChainApplyUpdate(&update, mayCommit); err != nil {
			return fmt.Errorf("subscriber %T: %w", s, err)
		}
	}

	m.tipState = c.State
	return nil
}

func (m *Manager) reorgPath(a, b types.ChainIndex) (revert, apply []types.ChainIndex, err error) {
	// helper function for "rewinding" to the parent index
	rewind := func(index *types.ChainIndex) (ok bool) {
		// if we're on the best chain, we can be a bit more efficient
		if bi, _ := m.store.BestIndex(index.Height); bi.ID == index.ID {
			*index, ok = m.store.BestIndex(index.Height - 1)
		} else {
			var c Checkpoint
			c, ok = m.store.Checkpoint(index.ID)
			*index = types.ChainIndex{Height: index.Height - 1, ID: c.Block.ParentID}
		}
		return ok
	}

	// rewind a or b until their heights match
	for a.Height > b.Height {
		revert = append(revert, a)
		if !rewind(&a) {
			return
		}
	}
	for b.Height > a.Height {
		apply = append(apply, b)
		if !rewind(&b) {
			return
		}
	}

	// now rewind both until we reach a common ancestor
	for a != b {
		revert = append(revert, a)
		apply = append(apply, b)
		if !rewind(&a) || !rewind(&b) {
			return
		}
	}

	// reverse the apply path
	for i := 0; i < len(apply)/2; i++ {
		j := len(apply) - i - 1
		apply[i], apply[j] = apply[j], apply[i]
	}
	return
}

func (m *Manager) reorgTo(index types.ChainIndex) error {
	revert, apply, err := m.reorgPath(m.tipState.Index, index)
	if err != nil {
		return err
	}
	for range revert {
		if err := m.revertTip(); err != nil {
			return fmt.Errorf("couldn't revert block %v: %w", m.tipState.Index, err)
		}
	}
	for _, index := range apply {
		if err := m.applyTip(index); err != nil {
			return fmt.Errorf("couldn't apply block %v: %w", index, err)
		}
	}
	return nil
}

// AddSubscriber subscribes s to m, ensuring that it will receive updates when
// the best chain changes. If tip does not match the Manager's current tip, s is
// updated accordingly.
func (m *Manager) AddSubscriber(s Subscriber, tip types.ChainIndex) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// reorg s to the current tip, if necessary
	revert, apply, err := m.reorgPath(tip, m.tipState.Index)
	if err != nil {
		return fmt.Errorf("couldn't determine reorg path from %v to %v: %w", tip, m.tipState.Index, err)
	}
	for _, index := range revert {
		c, ok := m.store.Checkpoint(index.ID)
		if !ok {
			return fmt.Errorf("missing revert checkpoint %v", index)
		} else if c.Diff == nil {
			panic("missing diff for reverted block")
		}
		pc, ok := m.store.Checkpoint(c.Block.ParentID)
		if !ok {
			return fmt.Errorf("missing revert parent checkpoint %v", c.Block.ParentID)
		}

		if err := s.ProcessChainRevertUpdate(&RevertUpdate{c.Block, pc.State, *c.Diff}); err != nil {
			return fmt.Errorf("couldn't process revert update: %w", err)
		}
	}
	for _, index := range apply {
		c, ok := m.store.Checkpoint(index.ID)
		if !ok {
			return fmt.Errorf("missing apply checkpoint %v", index)
		} else if c.Diff == nil {
			panic("missing diff for applied block")
		}
		// TODO: commit every minute for large len(apply)?
		shouldCommit := index == m.tipState.Index
		if err := s.ProcessChainApplyUpdate(&ApplyUpdate{c.Block, c.State, *c.Diff}, shouldCommit); err != nil {
			return fmt.Errorf("couldn't process apply update: %w", err)
		}
	}
	m.subscribers = append(m.subscribers, s)
	return nil
}

// NewManager returns a Manager initialized with the provided Store and State.
func NewManager(store Store, cs consensus.State) *Manager {
	return &Manager{
		store:      store,
		tipState:   cs,
		lastCommit: time.Now(),
	}
}
