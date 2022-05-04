package chain

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

var (
	// ErrFutureBlock is returned when a block's timestamp is too far in the future.
	ErrFutureBlock = errors.New("block's timestamp is too far in the future")

	// ErrKnownBlock is returned when a block has already been processed.
	ErrKnownBlock = errors.New("block already known")

	// ErrUnknownIndex is returned when an index references a block that we do
	// not have.
	ErrUnknownIndex = errors.New("unknown index")

	// ErrPruned is returned for blocks that are valid, but have been pruned.
	ErrPruned = errors.New("block has been pruned")
)

// An ApplyUpdate reflects the changes to the blockchain resulting from the
// addition of a block.
type ApplyUpdate struct {
	consensus.ApplyUpdate
	Block types.Block
}

// A RevertUpdate reflects the changes to the blockchain resulting from the
// removal of a block.
type RevertUpdate struct {
	consensus.RevertUpdate
	Block types.Block
}

// A Subscriber processes updates to the blockchain. Implementations must not
// modify or retain the provided update object.
type Subscriber interface {
	// Implementations MUST not commit updates to persistent storage unless mayCommit is set.
	ProcessChainApplyUpdate(cau *ApplyUpdate, mayCommit bool) error
	ProcessChainRevertUpdate(cru *RevertUpdate) error
}

// A ManagerStore durably commits Manager-related data to storage.
type ManagerStore interface {
	AddCheckpoint(c consensus.Checkpoint) error
	Checkpoint(index types.ChainIndex) (consensus.Checkpoint, error)
	Header(index types.ChainIndex) (types.BlockHeader, error)

	ExtendBest(index types.ChainIndex) error
	RewindBest() error
	BestIndex(height uint64) (types.ChainIndex, error)

	Flush() error
	Close() error
}

// A Manager tracks multiple blockchains and identifies the best valid
// chain.
type Manager struct {
	store       ManagerStore
	cs          consensus.State
	chains      []*consensus.ScratchChain
	subscribers []Subscriber
	lastFlush   time.Time

	mu sync.Mutex
}

// TipState returns the consensus state for the current tip.
func (m *Manager) TipState() consensus.State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cs
}

// Tip returns the tip of the best known valid chain.
func (m *Manager) Tip() types.ChainIndex {
	return m.TipState().Index
}

// Block returns the block at the specified index.
func (m *Manager) Block(index types.ChainIndex) (types.Block, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.store.Checkpoint(index)
	return c.Block, err
}

// State returns the consensus state for the specified index.
func (m *Manager) State(index types.ChainIndex) (consensus.State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.store.Checkpoint(index)
	return c.State, err
}

// History returns a set of chain indices that span the entire chain, beginning
// with the last 10, and subsequently spaced exponentionally farther apart until
// reaching the genesis block.
func (m *Manager) History() ([]types.ChainIndex, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// determine base of store
	//
	// TODO: store should probably just expose this
	baseHeight := uint64(sort.Search(int(m.cs.Index.Height), func(height int) bool {
		_, err := m.store.BestIndex(uint64(height))
		return err == nil
	}))

	histHeight := func(i int) uint64 {
		offset := uint64(i)
		if offset >= 10 {
			offset = 7 + 1<<(i-8) // strange, but it works
		}
		if offset > m.cs.Index.Height-baseHeight {
			offset = m.cs.Index.Height - baseHeight
		}
		return m.cs.Index.Height - offset
	}
	var history []types.ChainIndex
	for {
		index, err := m.store.BestIndex(histHeight(len(history)))
		if err != nil {
			return nil, fmt.Errorf("failed to get best index at %v: %w", histHeight(len(history)), err)
		}
		history = append(history, index)
		if index.Height == baseHeight {
			break
		}
	}
	return history, nil
}

// HeadersForHistory fills the provided slice with consecutive headers from the
// best chain, starting from the "attach point" -- the first ChainIndex in the
// history that is present in the best chain (or, if no match is found,
// genesis).
//
// The returned slice may have fewer than len(headers) elements if the end of
// the best chain is reached.
func (m *Manager) HeadersForHistory(headers []types.BlockHeader, history []types.ChainIndex) ([]types.BlockHeader, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var attachHeight uint64
	for _, h := range history {
		if index, err := m.store.BestIndex(h.Height); err != nil && !errors.Is(err, ErrUnknownIndex) && !errors.Is(err, ErrPruned) {
			return nil, fmt.Errorf("couldn't retrieve header at height %v: %w", h.Height, err)
		} else if index == h {
			attachHeight = h.Height
			break
		}
	}
	for i := range headers {
		if index, err := m.store.BestIndex(attachHeight + uint64(i) + 1); err != nil {
			return headers[:i], nil
		} else if headers[i], err = m.store.Header(index); err != nil {
			return nil, fmt.Errorf("couldn't retrieve header %v: %w", index, err)
		}
	}
	return headers, nil
}

// AddHeaders incorporates a chain of headers, using some or all of them to
// extend a ScratchChain (or create a new one). If the incorporation of these
// headers causes a ScratchChain to become the new (unvalidated) best chain,
// that chain is returned; otherwise, AddHeaders returns nil.
func (m *Manager) AddHeaders(headers []types.BlockHeader) (*consensus.ScratchChain, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(headers) == 0 {
		return nil, nil
	}
	// if the last header is in any known chain, we can ignore the entire set --
	// we've already seen them
	headerTip := headers[len(headers)-1]
	if m.cs.Index == headerTip.Index() {
		return nil, nil
	} else if _, err := m.store.Header(headerTip.Index()); err == nil {
		return nil, nil
	}
	for _, sc := range m.chains {
		if sc.Contains(headerTip.Index()) {
			if sc.TotalWork().Cmp(m.cs.TotalWork) > 0 {
				return sc, nil
			}
			return nil, nil
		}
	}

	// attempt to locate the chain that these headers attach to
	var chain *consensus.ScratchChain
	for _, sc := range m.chains {
		if headerTip.Height <= sc.Tip().Height || headerTip.Height > sc.Tip().Height+uint64(len(headers)) {
			continue
		}
		attachHeight := len(headers) - int(headerTip.Height-sc.Tip().Height)
		if sc.Tip() == headers[attachHeight].ParentIndex() {
			chain = sc
			headers = headers[attachHeight:]
			break
		}
	}

	// no existing chain; attempt to create a new one
	if chain == nil {
		// locate attach point
		//
		// TODO: linear scan is horribly inefficient here
		// TODO: add a special case for attaching to the current tip
		if _, err := m.store.Header(headers[0].ParentIndex()); err != nil {
			return nil, fmt.Errorf("orphaned header chain %v: %w", headers[0].ParentIndex(), err)
		}
		for {
			h := headers[0]
			if _, err := m.store.Header(h.Index()); errors.Is(err, ErrUnknownIndex) {
				break
			} else if err != nil {
				return nil, fmt.Errorf("could not read header: %w", err)
			}
			headers = headers[1:]
			if len(headers) == 0 {
				// NOTE: this should be unreachable because of the tip check at
				// the top of this function, but we might as well handle it
				// safely to prevent an OOB panic
				return nil, nil
			}
		}
		base, err := m.store.Header(headers[0].ParentIndex())
		if err != nil {
			return nil, fmt.Errorf("could not load base of new chain %v: %w", headers[0].ParentIndex(), err)
		}
		c, err := m.store.Checkpoint(base.Index())
		if err != nil {
			return nil, fmt.Errorf("could not load checkpoint %v: %w", base.Index(), err)
		}
		chain = consensus.NewScratchChain(c.State)
		m.chains = append(m.chains, chain)
	}

	// validate the headers
	for _, h := range headers {
		if err := chain.AppendHeader(h); err != nil {
			// TODO: it's possible that the chain prior to this header is still
			// the best; in that case, we should still reorg to it. But should
			// the error be returned as well?
			return nil, fmt.Errorf("header %v was invalid: %w", h.Index(), err)
		}
	}

	if chain.TotalWork().Cmp(m.cs.TotalWork) > 0 {
		return chain, nil
	}
	return nil, nil
}

// AddBlocks adds a sequence of blocks to a known ScratchChain. If the blocks
// are valid, the ScratchChain may become the new best chain, triggering a
// reorg.
func (m *Manager) AddBlocks(blocks []types.Block) (*consensus.ScratchChain, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(blocks) == 0 {
		return nil, nil
	}
	index := blocks[0].Index()
	var chain *consensus.ScratchChain
	for _, sc := range m.chains {
		if !sc.FullyValidated() && sc.ValidTip().Height >= (index.Height-1) && sc.Contains(index) {
			chain = sc
			break
		}
	}
	if chain == nil {
		return nil, fmt.Errorf("index %v does not attach to any known chain: %w", index, ErrUnknownIndex)
	}

	// the chain may already contain some of the supplied blocks; ignore
	// the ones we already have
	have := chain.ValidTip().Height - (index.Height - 1)
	blocks = blocks[have:]

	for _, b := range blocks {
		c, err := chain.ApplyBlock(b)
		if err != nil {
			return nil, fmt.Errorf("invalid block %v: %w", b.Index(), err)
		} else if err := m.store.AddCheckpoint(c); err != nil {
			return nil, fmt.Errorf("couldn't store block: %w", err)
		} else if c.State.TotalWork.Cmp(m.cs.TotalWork) <= 0 {
			// keep validating blocks until this becomes the best chain
			continue
		}

		// this is now the best chain; if we haven't reorged to it yet, do so
		if m.cs.Index != c.Block.Header.ParentIndex() {
			if err := m.reorgTo(chain); err != nil {
				return nil, fmt.Errorf("reorg failed: %w", err)
			}
			continue
		}
		// otherwise, apply directly to tip
		if err := m.applyTip(c.State.Index); err != nil {
			return nil, err
		}
	}

	if chain.FullyValidated() {
		m.discardChain(chain)
	}

	return chain, nil
}

// AddTipBlock adds a single block to the current tip, triggering a reorg.
func (m *Manager) AddTipBlock(b types.Block) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// check whether the block attaches to our tip
	if b.Header.ParentID != m.cs.Index.ID {
		// if we've already processed this block, ignore it
		if m.cs.Index == b.Index() {
			return ErrKnownBlock
		}
		for _, sc := range m.chains {
			if sc.Contains(b.Index()) && sc.ValidTip().Height >= b.Header.Height {
				return ErrKnownBlock
			}
		}
		if _, err := m.store.Header(b.Index()); err == nil {
			return ErrKnownBlock
		} else if err != ErrUnknownIndex {
			return fmt.Errorf("could not load header %v: %w", b.Index(), err)
		}
		// TODO: check if we have the block's parent, and if so, whether adding
		// this block would make it the best chain
		return fmt.Errorf("missing parent for %v: %w", b.Index(), ErrUnknownIndex)
	}

	// validate and store
	if b.Header.Timestamp.After(m.cs.MaxFutureTimestamp(time.Now())) {
		return ErrFutureBlock
	} else if err := m.cs.ValidateBlock(b); err != nil {
		return fmt.Errorf("invalid block: %w", err)
	}
	sau := consensus.ApplyBlock(m.cs, b)
	if err := m.store.AddCheckpoint(consensus.Checkpoint{Block: b, State: sau.State}); err != nil {
		return fmt.Errorf("failed to add checkpoint: %w", err)
	} else if err := m.store.ExtendBest(b.Index()); err != nil {
		return fmt.Errorf("couldn't update tip: %w", err)
	}
	m.cs = sau.State

	mayCommit := false
	if time.Since(m.lastFlush) > time.Minute {
		if err := m.store.Flush(); err != nil {
			return fmt.Errorf("couldn't flush store: %w", err)
		}
		m.lastFlush = time.Now()
		mayCommit = true
	}

	// update subscribers
	update := ApplyUpdate{sau, b}
	for _, s := range m.subscribers {
		if err := s.ProcessChainApplyUpdate(&update, mayCommit); err != nil {
			return fmt.Errorf("subscriber %T: %w", s, err)
		}
	}
	return nil
}

// revertTip reverts the current tip.
func (m *Manager) revertTip() error {
	c, err := m.store.Checkpoint(m.cs.Index)
	if err != nil {
		return fmt.Errorf("failed to get checkpoint for index %v: %w", m.cs.Index, err)
	}
	b := c.Block
	c, err = m.store.Checkpoint(b.Header.ParentIndex())
	if err != nil {
		return fmt.Errorf("failed to get checkpoint for parent %v: %w", b.Header.ParentIndex(), err)
	}
	cs := c.State

	sru := consensus.RevertBlock(cs, b)
	update := RevertUpdate{sru, b}
	for _, s := range m.subscribers {
		if err := s.ProcessChainRevertUpdate(&update); err != nil {
			return fmt.Errorf("subscriber %T: %w", s, err)
		}
	}
	if err := m.store.RewindBest(); err != nil {
		return fmt.Errorf("unable to rewind: %w", err)
	}

	m.cs = cs
	return nil
}

// applyTip adds a block to the current tip.
func (m *Manager) applyTip(index types.ChainIndex) error {
	c, err := m.store.Checkpoint(index)
	if err != nil {
		return fmt.Errorf("couldn't retrieve entry: %w", err)
	} else if c.Block.Header.ParentIndex() != m.cs.Index {
		panic("applyTip called with non-attaching block")
	}
	if err := m.store.ExtendBest(c.State.Index); err != nil {
		return fmt.Errorf("couldn't update tip: %w", err)
	}

	// flush at most once per minute; if we haven't flushed, tell the subscriber
	// that it must not commit chain data to disk
	mayCommit := false
	if time.Since(m.lastFlush) > time.Minute {
		if err := m.store.Flush(); err != nil {
			return fmt.Errorf("couldn't flush store: %w", err)
		}
		m.lastFlush = time.Now()
		mayCommit = true
	}

	sau := consensus.ApplyBlock(m.cs, c.Block)
	update := ApplyUpdate{sau, c.Block}
	for _, s := range m.subscribers {
		if err := s.ProcessChainApplyUpdate(&update, mayCommit); err != nil {
			return fmt.Errorf("subscriber %T: %w", s, err)
		}
	}

	m.cs = sau.State
	return nil
}

func (m *Manager) reorgTo(sc *consensus.ScratchChain) error {
	// starting at sc.Base(), follow parent chain until we connect to the
	// current best chain
	var rebase []types.ChainIndex
	base, err := m.store.Header(sc.Base())
	if err != nil {
		return fmt.Errorf("could not load base of new chain %v: %w", sc.Base(), err)
	}
	for {
		if index, err := m.store.BestIndex(base.Height); err != nil && !errors.Is(err, ErrUnknownIndex) {
			return fmt.Errorf("unable to get index for %v: %w", base.Height, err)
		} else if index == base.Index() {
			break
		}
		rebase = append(rebase, base.Index())
		base, err = m.store.Header(base.ParentIndex())
		if err != nil {
			return fmt.Errorf("could not rebase new chain to %v: %w", base.ParentIndex(), err)
		}
	}

	// revert to branch point
	for m.cs.Index != base.Index() {
		if err := m.revertTip(); err != nil {
			return fmt.Errorf("couldn't revert block %v: %w", m.cs.Index, err)
		}
	}

	// apply to scratch chain tip
	for m.cs.Index != sc.ValidTip() {
		var next types.ChainIndex
		if len(rebase) > 0 {
			rebase, next = rebase[:len(rebase)-1], rebase[len(rebase)-1]
		} else {
			next = sc.Index(m.cs.Index.Height + 1)
		}
		if err := m.applyTip(next); err != nil {
			return fmt.Errorf("couldn't apply block %v: %w", next, err)
		}
	}

	return nil
}

func (m *Manager) discardChain(sc *consensus.ScratchChain) {
	for i := range m.chains {
		if m.chains[i] == sc {
			m.chains = append(m.chains[:i], m.chains[i+1:]...)
			break
		}
	}
}

func (m *Manager) reorgPath(a, b types.ChainIndex) (revert, apply []types.ChainIndex, err error) {
	// TODO: In the common case, a and b will rejoin the best chain fairly
	// quickly. Once both are on the best chain, we can determine their common
	// ancestor directly, and read the path elements via BestIndex, which is
	// (presumably) much faster than "parent-chasing" via Header.

	// helper function for "rewinding" to the parent index
	rewind := func(index *types.ChainIndex) bool {
		h, hErr := m.store.Header(*index)
		if hErr != nil {
			err = fmt.Errorf("failed to get header %v: %w", a, hErr)
			return false
		}
		*index = h.ParentIndex()
		return true
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
	return revert, apply, nil
}

// AddSubscriber subscribes s to m, ensuring that it will receive updates when
// the best chain changes. If tip does not match the Manager's current tip, s is
// updated accordingly.
func (m *Manager) AddSubscriber(s Subscriber, tip types.ChainIndex) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// reorg s to the current tip, if necessary
	revert, apply, err := m.reorgPath(tip, m.cs.Index)
	if err != nil {
		return fmt.Errorf("failed to establish reorg path from %v to %v: %w", tip, m.cs.Index, err)
	}
	for _, index := range revert {
		c, err := m.store.Checkpoint(index)
		if err != nil {
			return fmt.Errorf("failed to get revert checkpoint %v: %w", index, err)
		}
		b := c.Block
		c, err = m.store.Checkpoint(b.Header.ParentIndex())
		if err != nil {
			return fmt.Errorf("failed to get revert parent checkpoint %v: %w", b.Header.ParentIndex(), err)
		}
		sru := consensus.RevertBlock(c.State, b)
		if err := s.ProcessChainRevertUpdate(&RevertUpdate{sru, b}); err != nil {
			return fmt.Errorf("failed to process revert update: %w", err)
		}
	}
	for _, index := range apply {
		c, err := m.store.Checkpoint(index)
		if err != nil {
			return fmt.Errorf("failed to get apply checkpoint %v: %w", index, err)
		}
		b := c.Block
		c, err = m.store.Checkpoint(b.Header.ParentIndex())
		if err != nil {
			return fmt.Errorf("failed to get apply parent checkpoint %v: %w", b.Header.ParentIndex(), err)
		}
		sau := consensus.ApplyBlock(c.State, b)
		shouldCommit := index == m.cs.Index
		if err := s.ProcessChainApplyUpdate(&ApplyUpdate{sau, b}, shouldCommit); err != nil {
			return fmt.Errorf("failed to process apply update: %w", err)
		}
	}
	m.subscribers = append(m.subscribers, s)
	return nil
}

// UpdateElementProof updates the Merkle proof of the provided StateElement,
// which must be valid as of index a, so that it is valid as of index b. An
// error is returned if the Manager cannot establish a path from a to b, or if
// the StateElement does not exist at index b.
func (m *Manager) UpdateElementProof(e *types.StateElement, a, b types.ChainIndex) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	revert, apply, err := m.reorgPath(a, b)
	if err != nil {
		return fmt.Errorf("failed to establish reorg path from %v to %v: %w", a, b, err)
	}
	for _, index := range revert {
		c, err := m.store.Checkpoint(index)
		if err != nil {
			return fmt.Errorf("failed to get revert checkpoint %v: %w", index, err)
		}
		b := c.Block
		c, err = m.store.Checkpoint(b.Header.ParentIndex())
		if err != nil {
			return fmt.Errorf("failed to get revert parent checkpoint %v: %w", b.Header.ParentIndex(), err)
		}
		sru := consensus.RevertBlock(c.State, b)
		if e.LeafIndex >= sru.State.Elements.NumLeaves {
			return fmt.Errorf("element %v does not exist at destination index", e.ID)
		}
		sru.UpdateElementProof(e)
	}
	for _, index := range apply {
		c, err := m.store.Checkpoint(index)
		if err != nil {
			return fmt.Errorf("failed to get apply checkpoint %v: %w", index, err)
		}
		b := c.Block
		c, err = m.store.Checkpoint(b.Header.ParentIndex())
		if err != nil {
			return fmt.Errorf("failed to get apply parent checkpoint %v: %w", b.Header.ParentIndex(), err)
		}
		sau := consensus.ApplyBlock(c.State, b)
		sau.UpdateElementProof(e)
	}
	return nil
}

// Close flushes and closes the underlying store.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.store.Flush(); err != nil {
		m.store.Close()
		return fmt.Errorf("error flushing store: %w", err)
	}
	return m.store.Close()
}

// NewManager returns a Manager initialized with the provided Store and State.
func NewManager(store ManagerStore, cs consensus.State) *Manager {
	return &Manager{
		store:     store,
		cs:        cs,
		lastFlush: time.Now(),
	}
}
