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
	vc          consensus.ValidationContext
	chains      []*consensus.ScratchChain
	subscribers []Subscriber
	lastFlush   time.Time

	mu sync.Mutex
}

// Tip returns the tip of the best known valid chain.
func (m *Manager) Tip() types.ChainIndex {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.vc.Index
}

// Block returns the block at the specified index.
func (m *Manager) Block(index types.ChainIndex) (types.Block, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.store.Checkpoint(index)
	return c.Block, err
}

// ValidationContext returns the ValidationContext for the specified
// index.
func (m *Manager) ValidationContext(index types.ChainIndex) (consensus.ValidationContext, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.store.Checkpoint(index)
	return c.Context, err
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
	baseHeight := uint64(sort.Search(int(m.vc.Index.Height), func(height int) bool {
		_, err := m.store.BestIndex(uint64(height))
		return err == nil
	}))

	histHeight := func(i int) uint64 {
		offset := uint64(i)
		if offset >= 10 {
			offset = 7 + 1<<(i-8) // strange, but it works
		}
		if offset > m.vc.Index.Height-baseHeight {
			offset = m.vc.Index.Height - baseHeight
		}
		return m.vc.Index.Height - offset
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
	if m.vc.Index == headerTip.Index() {
		return nil, nil
	} else if _, err := m.store.Header(headerTip.Index()); err == nil {
		return nil, nil
	}
	for _, sc := range m.chains {
		if sc.Contains(headerTip.Index()) {
			if sc.TotalWork().Cmp(m.vc.TotalWork) > 0 {
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
		chain = consensus.NewScratchChain(c.Context)
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

	if chain.TotalWork().Cmp(m.vc.TotalWork) > 0 {
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
			return nil, fmt.Errorf("invalid block %v: %w", chain.UnvalidatedBase(), err)
		} else if err := m.store.AddCheckpoint(c); err != nil {
			return nil, fmt.Errorf("couldn't store block: %w", err)
		} else if c.Context.TotalWork.Cmp(m.vc.TotalWork) <= 0 {
			// keep validating blocks until this becomes the best chain
			continue
		}

		// this is now the best chain; if we haven't reorged to it yet, do so
		if m.vc.Index != c.Block.Header.ParentIndex() {
			if err := m.reorgTo(chain); err != nil {
				return nil, fmt.Errorf("reorg failed: %w", err)
			}
			continue
		}
		// otherwise, apply directly to tip
		if err := m.applyTip(c.Context.Index); err != nil {
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
	if b.Header.ParentID != m.vc.Index.ID {
		// if we've already processed this block, ignore it
		if m.vc.Index == b.Index() {
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
	if err := m.vc.ValidateBlock(b); err != nil {
		return fmt.Errorf("invalid block: %w", err)
	}
	sau := consensus.ApplyBlock(m.vc, b)
	if err := m.store.AddCheckpoint(consensus.Checkpoint{Block: b, Context: sau.Context}); err != nil {
		return fmt.Errorf("failed to add checkpoint: %w", err)
	} else if err := m.store.ExtendBest(b.Index()); err != nil {
		return fmt.Errorf("couldn't update tip: %w", err)
	}
	m.vc = sau.Context

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
	c, err := m.store.Checkpoint(m.vc.Index)
	if err != nil {
		return fmt.Errorf("failed to get checkpoint for index %v: %w", m.vc.Index, err)
	}
	b := c.Block
	c, err = m.store.Checkpoint(b.Header.ParentIndex())
	if err != nil {
		return fmt.Errorf("failed to get checkpoint for parent %v: %w", b.Header.ParentIndex(), err)
	}
	vc := c.Context

	sru := consensus.RevertBlock(vc, b)
	update := RevertUpdate{sru, b}
	for _, s := range m.subscribers {
		if err := s.ProcessChainRevertUpdate(&update); err != nil {
			return fmt.Errorf("subscriber %T: %w", s, err)
		}
	}
	if err := m.store.RewindBest(); err != nil {
		return fmt.Errorf("unable to rewind: %w", err)
	}

	m.vc = vc
	return nil
}

// applyTip adds a block to the current tip.
func (m *Manager) applyTip(index types.ChainIndex) error {
	c, err := m.store.Checkpoint(index)
	if err != nil {
		return fmt.Errorf("couldn't retrieve entry: %w", err)
	} else if c.Block.Header.ParentIndex() != m.vc.Index {
		panic("applyTip called with non-attaching block")
	}
	if err := m.store.ExtendBest(c.Context.Index); err != nil {
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

	sau := consensus.ApplyBlock(m.vc, c.Block)
	update := ApplyUpdate{sau, c.Block}
	for _, s := range m.subscribers {
		if err := s.ProcessChainApplyUpdate(&update, mayCommit); err != nil {
			return fmt.Errorf("subscriber %T: %w", s, err)
		}
	}

	m.vc = sau.Context
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
	for m.vc.Index != base.Index() {
		if err := m.revertTip(); err != nil {
			return fmt.Errorf("couldn't revert block %v: %w", m.vc.Index, err)
		}
	}

	// apply to scratch chain tip
	for m.vc.Index != sc.ValidTip() {
		var next types.ChainIndex
		if len(rebase) > 0 {
			rebase, next = rebase[:len(rebase)-1], rebase[len(rebase)-1]
		} else {
			next = sc.Index(m.vc.Index.Height + 1)
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

// AddSubscriber subscribes s to m, ensuring that it will receive updates when
// the best chain changes. If tip does not match the Manager's current tip, s is
// updated accordingly.
func (m *Manager) AddSubscriber(s Subscriber, tip types.ChainIndex) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.vc.Index != tip {
		// starting at tip, follow parent chain until we connect to the
		// current best chain
		h, err := m.store.Header(tip)
		if err != nil {
			return fmt.Errorf("failed to get header %v: %w", tip, err)
		}
		for {
			if index, err := m.store.BestIndex(h.Height); err != nil && !errors.Is(err, ErrUnknownIndex) {
				return fmt.Errorf("failed to get index at %v: %w", h.Height, err)
			} else if index == h.Index() {
				break
			}

			// construct and send update
			c, err := m.store.Checkpoint(h.Index())
			if err != nil {
				return fmt.Errorf("failed to get revert checkpoint %v: %w", h.Index(), err)
			}
			b := c.Block
			c, err = m.store.Checkpoint(h.ParentIndex())
			if err != nil {
				return fmt.Errorf("failed to get revert parent checkpoint %v: %w", h.ParentIndex(), err)
			}
			sru := consensus.RevertBlock(c.Context, b)
			if err := s.ProcessChainRevertUpdate(&RevertUpdate{sru, b}); err != nil {
				return fmt.Errorf("failed to process revert update: %w", err)
			}

			// load parent
			h, err = m.store.Header(h.ParentIndex())
			if err != nil {
				return fmt.Errorf("failed to get header %v: %w", h.ParentIndex(), err)
			}
		}

		// apply to m.Tip
		c, err := m.store.Checkpoint(h.Index())
		if err != nil {
			return fmt.Errorf("failed to get current checkpoint %v: %w", h.Index(), err)
		}
		vc := c.Context
		for vc.Index != m.vc.Index {
			index, err := m.store.BestIndex(vc.Index.Height + 1)
			if err != nil {
				return fmt.Errorf("failed to get apply index %v: %w", vc.Index.Height+1, err)
			}
			c, err := m.store.Checkpoint(index)
			if err != nil {
				return fmt.Errorf("failed to get apply checkpoint %v: %w", index, err)
			}
			sau := consensus.ApplyBlock(vc, c.Block)
			shouldCommit := index == m.vc.Index
			if err := s.ProcessChainApplyUpdate(&ApplyUpdate{sau, c.Block}, shouldCommit); err != nil {
				return fmt.Errorf("failed to process apply update: %w", err)
			}
			vc = sau.Context
		}
	}
	m.subscribers = append(m.subscribers, s)
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

// NewManager returns a Manager initialized with the provided Store and context.
func NewManager(store ManagerStore, vc consensus.ValidationContext) *Manager {
	return &Manager{
		store:     store,
		vc:        vc,
		lastFlush: time.Now(),
	}
}
