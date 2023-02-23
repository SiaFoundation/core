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

// A Store durably commits Manager-related data to storage.
type Store interface {
	WithConsensus(func(consensus.Store) error) error
	AddCheckpoint(c Checkpoint) error
	Checkpoint(id types.BlockID) (Checkpoint, error)
	BestIndex(height uint64) (types.ChainIndex, error)
	ApplyDiff(s consensus.State, diff consensus.BlockDiff) (mayCommit bool, err error)
	RevertDiff(s consensus.State, diff consensus.BlockDiff) error
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
func (m *Manager) Block(id types.BlockID) (types.Block, error) {
	c, err := m.store.Checkpoint(id)
	return c.Block, err
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
		index, err := m.store.BestIndex(histHeight(i))
		if err != nil {
			return history, fmt.Errorf("couldn't get best index at %v: %w", histHeight(i), err)
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
		c, err := m.store.Checkpoint(id)
		if err != nil {
			continue
		}
		if index, err := m.store.BestIndex(c.State.Index.Height); err == nil && index == c.State.Index {
			attachHeight = c.State.Index.Height
			break
		}
	}
	for i := range blocks {
		if index, err := m.store.BestIndex(attachHeight + uint64(i) + 1); err != nil {
			return blocks[:i], nil
		} else if c, err := m.store.Checkpoint(index.ID); err != nil {
			return nil, fmt.Errorf("couldn't retrieve block %v: %w", index, err)
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
		if c, err := m.store.Checkpoint(b.ID()); err == nil {
			// already have this block
			cs = c.State
			continue
		} else if b.ParentID != c.State.Index.ID {
			c, err := m.store.Checkpoint(b.ParentID)
			if err != nil {
				return fmt.Errorf("couldn't get parent checkpoint for block %v: %w", b.ID(), err)
			}
			cs = c.State
		}
		if b.Timestamp.After(cs.MaxFutureTimestamp(time.Now())) {
			return ErrFutureBlock
		} else if err := consensus.ValidateOrphan(cs, b); err != nil {
			return fmt.Errorf("block %v is invalid: %w", types.ChainIndex{Height: cs.Index.Height + 1, ID: b.ID()}, err)
		}
		err := m.store.WithConsensus(func(cstore consensus.Store) error {
			cs = consensus.ApplyState(cs, cstore, b)
			return nil
		})
		if err != nil {
			return fmt.Errorf("couldn't apply block %v: %w", b.ID(), err)
		} else if err := m.store.AddCheckpoint(Checkpoint{b, cs, nil}); err != nil {
			return fmt.Errorf("couldn't store block %v: %w", cs.Index, err)
		}
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
	c, err := m.store.Checkpoint(m.tipState.Index.ID)
	if err != nil {
		return fmt.Errorf("couldn't get checkpoint for index %v: %w", m.tipState.Index, err)
	}
	pc, err := m.store.Checkpoint(c.Block.ParentID)
	if err != nil {
		return fmt.Errorf("couldn't get checkpoint for block %v: %w", c.Block.ParentID, err)
	}
	update := RevertUpdate{c.Block, pc.State, *c.Diff}

	if err := m.store.RevertDiff(pc.State, *c.Diff); err != nil {
		return fmt.Errorf("couldn't revert store tip: %w", err)
	}
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
	c, err := m.store.Checkpoint(index.ID)
	if err != nil {
		return fmt.Errorf("couldn't get checkpoint for index %v: %w", index, err)
	} else if c.Block.ParentID != m.tipState.Index.ID {
		panic("applyTip called with non-attaching block")
	}
	if c.Diff == nil {
		err := m.store.WithConsensus(func(cstore consensus.Store) error {
			if err := consensus.ValidateBlock(m.tipState, cstore, c.Block); err != nil {
				return fmt.Errorf("block %v is invalid: %w", index, err)
			}
			c.Diff = new(consensus.BlockDiff)
			*c.Diff = consensus.ApplyDiff(m.tipState, cstore, c.Block)
			return nil
		})
		if err != nil {
			return err
		}
		if err := m.store.AddCheckpoint(c); err != nil {
			return fmt.Errorf("couldn't store diff for checkpoint %v: %w", index, err)
		}
	}
	update := ApplyUpdate{c.Block, c.State, *c.Diff}

	// commit at most once per minute
	mayCommit, err := m.store.ApplyDiff(c.State, *c.Diff)
	if err != nil {
		return fmt.Errorf("couldn't apply diff to store: %w", err)
	}
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
	rewind := func(index *types.ChainIndex) bool {
		// if we're on the best chain, we can be a bit more efficient
		if bi, _ := m.store.BestIndex(index.Height); bi.ID == index.ID {
			*index, err = m.store.BestIndex(index.Height - 1)
		} else {
			var c Checkpoint
			c, err = m.store.Checkpoint(index.ID)
			*index = types.ChainIndex{Height: index.Height - 1, ID: c.Block.ParentID}
		}
		return err == nil
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
		c, err := m.store.Checkpoint(index.ID)
		if err != nil {
			return fmt.Errorf("couldn't get revert checkpoint %v: %w", index, err)
		} else if c.Diff == nil {
			panic("missing diff for reverted block")
		}
		pc, err := m.store.Checkpoint(c.Block.ParentID)
		if err != nil {
			return fmt.Errorf("couldn't get revert parent checkpoint %v: %w", c.Block.ParentID, err)
		}

		if err := s.ProcessChainRevertUpdate(&RevertUpdate{c.Block, pc.State, *c.Diff}); err != nil {
			return fmt.Errorf("couldn't process revert update: %w", err)
		}
	}
	for _, index := range apply {
		c, err := m.store.Checkpoint(index.ID)
		if err != nil {
			return fmt.Errorf("couldn't get apply checkpoint %v: %w", index, err)
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
