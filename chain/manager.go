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
)

// An ApplyUpdate reflects the changes to the blockchain resulting from the
// addition of a block.
type ApplyUpdate struct {
	consensus.ApplyUpdate

	Block types.Block
	State consensus.State // post-application
}

// A RevertUpdate reflects the changes to the blockchain resulting from the
// removal of a block.
type RevertUpdate struct {
	consensus.RevertUpdate

	Block types.Block
	State consensus.State // post-reversion, i.e. pre-application
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
	BestIndex(height uint64) (types.ChainIndex, bool)
	SupplementTipTransaction(txn types.Transaction) consensus.V1TransactionSupplement
	SupplementTipBlock(b types.Block) consensus.V1BlockSupplement

	Block(id types.BlockID) (types.Block, *consensus.V1BlockSupplement, bool)
	AddBlock(b types.Block, bs *consensus.V1BlockSupplement)
	State(id types.BlockID) (consensus.State, bool)
	AddState(cs consensus.State)
	AncestorTimestamp(id types.BlockID) (time.Time, bool)

	// Except when mustCommit is set, ApplyBlock and RevertBlock are free to
	// commit whenever they see fit.
	ApplyBlock(s consensus.State, cau consensus.ApplyUpdate, mustCommit bool) (committed bool)
	RevertBlock(s consensus.State, cru consensus.RevertUpdate)
}

// blockAndParent returns the block with the specified ID, along with its parent
// state.
func blockAndParent(s Store, id types.BlockID) (types.Block, *consensus.V1BlockSupplement, consensus.State, bool) {
	b, bs, ok := s.Block(id)
	cs, ok2 := s.State(b.ParentID)
	return b, bs, cs, ok && ok2
}

// blockAndChild returns the block with the specified ID, along with its child
// state.
func blockAndChild(s Store, id types.BlockID) (types.Block, *consensus.V1BlockSupplement, consensus.State, bool) {
	b, bs, ok := s.Block(id)
	cs, ok2 := s.State(id)
	return b, bs, cs, ok && ok2
}

// A Manager tracks multiple blockchains and identifies the best valid
// chain.
type Manager struct {
	store         Store
	tipState      consensus.State
	subscribers   []Subscriber
	lastCommit    time.Time
	invalidBlocks map[types.BlockID]error

	txpool struct {
		txns           []types.Transaction
		v2txns         []types.V2Transaction
		indices        map[types.TransactionID]int
		invalidTxnSets map[types.Hash256]error
		ms             *consensus.MidState
		weight         uint64
		medianFee      *types.Currency
		parentMap      map[types.Hash256]int
		lastReverted   []types.Transaction
		lastRevertedV2 []types.V2Transaction
	}

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
	m.mu.Lock()
	defer m.mu.Unlock()
	b, _, ok := m.store.Block(id)
	return b, ok
}

// State returns the state with the specified ID.
func (m *Manager) State(id types.BlockID) (consensus.State, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.store.State(id)
}

// BestIndex returns the index of the block at the specified height within the
// best chain.
func (m *Manager) BestIndex(height uint64) (types.ChainIndex, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.store.BestIndex(height)
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

// BlocksForHistory returns up to max consecutive blocks from the best chain,
// starting from the "attach point" -- the first ID in the history that is
// present in the best chain (or, if no match is found, genesis). It also
// returns the number of blocks between the end of the returned slice and the
// current tip.
func (m *Manager) BlocksForHistory(history []types.BlockID, max uint64) ([]types.Block, uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var attachHeight uint64
	for _, id := range history {
		if cs, ok := m.store.State(id); !ok {
			continue
		} else if index, ok := m.store.BestIndex(cs.Index.Height); ok && index == cs.Index {
			attachHeight = cs.Index.Height
			break
		}
	}
	if max > m.tipState.Index.Height-attachHeight {
		max = m.tipState.Index.Height - attachHeight
	}
	blocks := make([]types.Block, max)
	for i := range blocks {
		index, _ := m.store.BestIndex(attachHeight + uint64(i) + 1)
		b, _, ok := m.store.Block(index.ID)
		if !ok {
			return nil, 0, fmt.Errorf("missing block %v", index)
		}
		blocks[i] = b
	}
	return blocks, m.tipState.Index.Height - (attachHeight + max), nil
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
		bid := b.ID()
		var ok bool
		if err := m.invalidBlocks[bid]; err != nil {
			return fmt.Errorf("block %v is invalid: %w", types.ChainIndex{Height: cs.Index.Height + 1, ID: bid}, err)
		} else if cs, ok = m.store.State(bid); ok {
			// already have this block
			continue
		} else if b.ParentID != cs.Index.ID {
			if cs, ok = m.store.State(b.ParentID); !ok {
				return fmt.Errorf("missing parent state for block %v", bid)
			}
		}
		if b.Timestamp.After(cs.MaxFutureTimestamp(time.Now())) {
			return ErrFutureBlock
		} else if err := consensus.ValidateOrphan(cs, b); err != nil {
			m.markBadBlock(bid, err)
			return fmt.Errorf("block %v is invalid: %w", types.ChainIndex{Height: cs.Index.Height + 1, ID: bid}, err)
		}
		ancestorTimestamp, ok := m.store.AncestorTimestamp(b.ParentID)
		if !ok {
			return fmt.Errorf("missing ancestor timestamp for block %v", b.ParentID)
		}
		cs = consensus.ApplyOrphan(cs, b, ancestorTimestamp)
		m.store.AddState(cs)
		m.store.AddBlock(b, nil)
	}

	// if this chain is now the best chain, trigger a reorg
	//
	// TODO: SurpassThreshold?
	if cs.Depth.CmpWork(m.tipState.Depth) > 0 {
		oldTip := m.tipState.Index
		if err := m.reorgTo(cs.Index); err != nil {
			if err := m.reorgTo(oldTip); err != nil {
				return fmt.Errorf("failed to revert failed reorg: %w", err)
			}
			return fmt.Errorf("reorg failed: %w", err)
		}
	}
	return nil
}

// markBadBlock marks a block as bad, so that we don't waste resources
// re-validating it if we see it again.
func (m *Manager) markBadBlock(bid types.BlockID, err error) {
	const maxInvalidBlocks = 1000
	if len(m.invalidBlocks) >= maxInvalidBlocks {
		// forget a random entry
		for bid := range m.invalidBlocks {
			delete(m.invalidBlocks, bid)
			break
		}
	}
	m.invalidBlocks[bid] = err
}

// revertTip reverts the current tip.
func (m *Manager) revertTip() error {
	b, bs, cs, ok := blockAndParent(m.store, m.tipState.Index.ID)
	if !ok {
		return fmt.Errorf("missing block at index %v", m.tipState.Index)
	}
	cru := consensus.RevertBlock(cs, b, *bs)
	m.store.RevertBlock(cs, cru)

	update := RevertUpdate{cru, b, cs}
	for _, s := range m.subscribers {
		if err := s.ProcessChainRevertUpdate(&update); err != nil {
			return fmt.Errorf("subscriber %T: %w", s, err)
		}
	}

	m.revertPoolUpdate(&update)
	m.tipState = cs
	return nil
}

// applyTip adds a block to the current tip.
func (m *Manager) applyTip(index types.ChainIndex) error {
	var cau consensus.ApplyUpdate
	b, bs, cs, ok := blockAndChild(m.store, index.ID)
	if !ok {
		return fmt.Errorf("missing block at index %v", index)
	} else if b.ParentID != m.tipState.Index.ID {
		panic("applyTip called with non-attaching block")
	} else if bs == nil {
		bs = new(consensus.V1BlockSupplement)
		*bs = m.store.SupplementTipBlock(b)
		if err := consensus.ValidateBlock(m.tipState, b, *bs); err != nil {
			m.markBadBlock(index.ID, err)
			return fmt.Errorf("block %v is invalid: %w", index, err)
		}
		ancestorTimestamp, ok := m.store.AncestorTimestamp(b.ParentID)
		if !ok {
			return fmt.Errorf("missing ancestor timestamp for block %v", b.ParentID)
		}
		cs, cau = consensus.ApplyBlock(m.tipState, b, *bs, ancestorTimestamp)
		m.store.AddState(cs)
		m.store.AddBlock(b, bs)
	} else {
		ancestorTimestamp, ok := m.store.AncestorTimestamp(b.ParentID)
		if !ok {
			return fmt.Errorf("missing ancestor timestamp for block %v", b.ParentID)
		}
		_, cau = consensus.ApplyBlock(m.tipState, b, *bs, ancestorTimestamp)
	}

	// force the store to commit if we're at the tip (or close to it), or at
	// least every 2 seconds; this ensures that the amount of uncommitted data
	// never grows too large
	forceCommit := time.Since(b.Timestamp) < cs.BlockInterval()*2 || time.Since(m.lastCommit) > 2*time.Second
	committed := m.store.ApplyBlock(cs, cau, forceCommit)
	if committed {
		m.lastCommit = time.Now()
	}

	update := &ApplyUpdate{cau, b, cs}
	for _, s := range m.subscribers {
		if err := s.ProcessChainApplyUpdate(update, committed); err != nil {
			return fmt.Errorf("subscriber %T: %w", s, err)
		}
	}

	m.applyPoolUpdate(update)
	m.tipState = cs
	return nil
}

func (m *Manager) reorgPath(a, b types.ChainIndex) (revert, apply []types.ChainIndex, err error) {
	// helper function for "rewinding" to the parent index
	rewind := func(index *types.ChainIndex) (ok bool) {
		// if we're on the best chain, we can be a bit more efficient
		if bi, _ := m.store.BestIndex(index.Height); bi.ID == index.ID {
			*index, ok = m.store.BestIndex(index.Height - 1)
		} else {
			var b types.Block
			b, _, ok = m.store.Block(index.ID)
			*index = types.ChainIndex{Height: index.Height - 1, ID: b.ParentID}
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

	// special case: if a is uninitialized, we're starting from genesis
	if a == (types.ChainIndex{}) {
		a, _ = m.store.BestIndex(0)
		apply = append(apply, a)
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

	// invalidate txpool caches
	m.txpool.ms = nil
	m.txpool.medianFee = nil
	m.txpool.parentMap = nil
	if len(revert) > 0 {
		b, _, _ := m.store.Block(revert[0].ID)
		m.txpool.lastReverted = b.Transactions
		m.txpool.lastRevertedV2 = b.V2Transactions()
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
		b, bs, cs, ok := blockAndParent(m.store, index.ID)
		if !ok {
			return fmt.Errorf("missing reverted block at index %v", index)
		} else if bs == nil {
			panic("missing supplement for reverted block")
		}
		cru := consensus.RevertBlock(cs, b, *bs)
		if err := s.ProcessChainRevertUpdate(&RevertUpdate{cru, b, cs}); err != nil {
			return fmt.Errorf("couldn't process revert update: %w", err)
		}
	}
	for _, index := range apply {
		b, bs, cs, ok := blockAndParent(m.store, index.ID)
		if !ok {
			return fmt.Errorf("missing applied block at index %v", index)
		} else if bs == nil {
			panic("missing supplement for applied block")
		}
		ancestorTimestamp, ok := m.store.AncestorTimestamp(b.ParentID)
		if !ok && index.Height != 0 {
			return fmt.Errorf("missing ancestor timestamp for block %v", b.ParentID)
		}
		cs, cau := consensus.ApplyBlock(cs, b, *bs, ancestorTimestamp)
		// TODO: commit every minute for large len(apply)?
		shouldCommit := index == m.tipState.Index
		if err := s.ProcessChainApplyUpdate(&ApplyUpdate{cau, b, cs}, shouldCommit); err != nil {
			return fmt.Errorf("couldn't process apply update: %w", err)
		}
	}
	m.subscribers = append(m.subscribers, s)
	return nil
}

// RemoveSubscriber unsubscribes s from m.
func (m *Manager) RemoveSubscriber(s Subscriber) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.subscribers {
		if m.subscribers[i] == s {
			m.subscribers = append(m.subscribers[:i], m.subscribers[i+1:]...)
			return
		}
	}
}

func (m *Manager) revalidatePool() {
	txpoolMaxWeight := m.tipState.MaxBlockWeight() * 10
	if m.txpool.ms != nil && m.txpool.weight < txpoolMaxWeight {
		return
	}
	// if the pool is full, remove low-fee transactions until we are below 75%
	//
	// NOTE: ideally we would consider the total fees of each *set* of dependent
	// transactions, but that's expensive; this approach should work fine in
	// practice.
	if m.txpool.weight >= txpoolMaxWeight {
		// sort txns fee without modifying the actual pool slice
		type feeTxn struct {
			index  int
			fees   types.Currency
			weight uint64
			v2     bool
		}
		txnFees := make([]feeTxn, 0, len(m.txpool.txns)+len(m.txpool.v2txns))
		for i, txn := range m.txpool.txns {
			txnFees = append(txnFees, feeTxn{
				index:  i,
				fees:   txn.TotalFees(),
				weight: m.tipState.TransactionWeight(txn),
			})
		}
		for i, txn := range m.txpool.v2txns {
			txnFees = append(txnFees, feeTxn{
				index:  i,
				fees:   txn.MinerFee,
				weight: m.tipState.V2TransactionWeight(txn),
				v2:     true,
			})
		}
		sort.Slice(txnFees, func(i, j int) bool {
			return txnFees[i].fees.Div64(txnFees[i].weight).Cmp(txnFees[j].fees.Div64(txnFees[j].weight)) < 0
		})
		for m.txpool.weight >= (txpoolMaxWeight*3)/4 && len(txnFees) > 0 {
			m.txpool.weight -= txnFees[0].weight
			txnFees = txnFees[1:]
		}
		sort.Slice(txnFees, func(i, j int) bool {
			return txnFees[i].index < txnFees[j].index
		})
		rem := m.txpool.txns[:0]
		for _, ft := range txnFees {
			rem = append(rem, m.txpool.txns[ft.index])
		}
		m.txpool.txns = rem
	}

	// remove and re-add all transactions
	for txid := range m.txpool.indices {
		delete(m.txpool.indices, txid)
	}
	m.txpool.ms = consensus.NewMidState(m.tipState)
	txns := append(m.txpool.txns, m.txpool.lastReverted...)
	m.txpool.txns = m.txpool.txns[:0]
	m.txpool.weight = 0
	for _, txn := range txns {
		ts := m.store.SupplementTipTransaction(txn)
		if consensus.ValidateTransaction(m.txpool.ms, txn, ts) == nil {
			m.txpool.ms.ApplyTransaction(txn, ts)
			m.txpool.indices[txn.ID()] = len(m.txpool.txns)
			m.txpool.txns = append(m.txpool.txns, txn)
			m.txpool.weight += m.tipState.TransactionWeight(txn)
		}
	}
	v2txns := append(m.txpool.v2txns, m.txpool.lastRevertedV2...)
	m.txpool.v2txns = m.txpool.v2txns[:0]
	for _, txn := range v2txns {
		if consensus.ValidateV2Transaction(m.txpool.ms, txn) == nil {
			m.txpool.ms.ApplyV2Transaction(txn)
			m.txpool.indices[txn.ID()] = len(m.txpool.v2txns)
			m.txpool.v2txns = append(m.txpool.v2txns, txn)
			m.txpool.weight += m.tipState.V2TransactionWeight(txn)
		}
	}
}

func (m *Manager) computeMedianFee() types.Currency {
	if m.txpool.medianFee != nil {
		return *m.txpool.medianFee
	}

	calculateBlockMedianFee := func(cs consensus.State, b types.Block) types.Currency {
		type weightedFee struct {
			weight uint64
			fee    types.Currency
		}
		var fees []weightedFee
		for _, txn := range b.Transactions {
			fees = append(fees, weightedFee{cs.TransactionWeight(txn), txn.TotalFees()})
		}
		for _, txn := range b.V2Transactions() {
			fees = append(fees, weightedFee{cs.V2TransactionWeight(txn), txn.MinerFee})
		}
		// account for the remaining space in the block, for which no fees were paid
		remaining := cs.MaxBlockWeight()
		for _, wf := range fees {
			remaining -= wf.weight
		}
		fees = append(fees, weightedFee{remaining, types.ZeroCurrency})
		sort.Slice(fees, func(i, j int) bool { return fees[i].fee.Cmp(fees[j].fee) < 0 })
		var progress uint64
		var i int
		for i = range fees {
			// use the 75th percentile
			if progress += fees[i].weight; progress > cs.MaxBlockWeight()/4 {
				break
			}
		}
		return fees[i].fee
	}
	prevFees := make([]types.Currency, 0, 10)
	for i := uint64(0); i < 10; i++ {
		index, ok1 := m.store.BestIndex(m.tipState.Index.Height - i)
		b, _, cs, ok2 := blockAndParent(m.store, index.ID)
		if ok1 && ok2 {
			prevFees = append(prevFees, calculateBlockMedianFee(cs, b))
		}
	}
	sort.Slice(prevFees, func(i, j int) bool { return prevFees[i].Cmp(prevFees[j]) < 0 })
	if len(prevFees) == 0 {
		return types.ZeroCurrency
	}
	m.txpool.medianFee = &prevFees[len(prevFees)/2]
	return *m.txpool.medianFee
}

func (m *Manager) computeParentMap() map[types.Hash256]int {
	if m.txpool.parentMap != nil {
		return m.txpool.parentMap
	}
	m.txpool.parentMap = make(map[types.Hash256]int)
	for index, txn := range m.txpool.txns {
		for i := range txn.SiacoinOutputs {
			m.txpool.parentMap[types.Hash256(txn.SiacoinOutputID(i))] = index
		}
		for i := range txn.SiafundInputs {
			m.txpool.parentMap[types.Hash256(txn.SiafundClaimOutputID(i))] = index
		}
		for i := range txn.SiafundOutputs {
			m.txpool.parentMap[types.Hash256(txn.SiafundOutputID(i))] = index
		}
		for i := range txn.FileContracts {
			m.txpool.parentMap[types.Hash256(txn.FileContractID(i))] = index
		}
	}
	return m.txpool.parentMap
}

func updateTxnProofs(txn *types.V2Transaction, updateElementProof func(*types.StateElement), numLeaves uint64) (valid bool) {
	valid = true
	updateProof := func(e *types.StateElement) {
		valid = valid && e.LeafIndex < numLeaves
		if !valid || e.LeafIndex == types.EphemeralLeafIndex {
			return
		}
		updateElementProof(e)
	}
	for i := range txn.SiacoinInputs {
		updateProof(&txn.SiacoinInputs[i].Parent.StateElement)
	}
	for i := range txn.SiafundInputs {
		updateProof(&txn.SiafundInputs[i].Parent.StateElement)
	}
	for i := range txn.FileContractRevisions {
		updateProof(&txn.FileContractRevisions[i].Parent.StateElement)
	}
	for i := range txn.FileContractResolutions {
		updateProof(&txn.FileContractResolutions[i].Parent.StateElement)
		if sp, ok := txn.FileContractResolutions[i].Resolution.(*types.V2StorageProof); ok {
			updateProof(&sp.ProofIndex.StateElement)
		}
	}
	return
}

func (m *Manager) revertPoolUpdate(cru *RevertUpdate) {
	// restore ephemeral elements, if necessary
	var uncreated map[types.Hash256]bool
	replaceEphemeral := func(e *types.StateElement) {
		if e.LeafIndex != types.EphemeralLeafIndex {
			return
		} else if uncreated == nil {
			uncreated = make(map[types.Hash256]bool)
			cru.ForEachSiacoinElement(func(sce types.SiacoinElement, spent bool) {
				if !spent {
					uncreated[sce.ID] = true
				}
			})
			cru.ForEachSiafundElement(func(sfe types.SiafundElement, spent bool) {
				if !spent {
					uncreated[sfe.ID] = true
				}
			})
			cru.ForEachFileContractElement(func(fce types.FileContractElement, rev *types.FileContractElement, resolved, valid bool) {
				if !resolved {
					uncreated[fce.ID] = true
				}
			})
			cru.ForEachV2FileContractElement(func(fce types.V2FileContractElement, rev *types.V2FileContractElement, res types.V2FileContractResolutionType) {
				if res != nil {
					uncreated[fce.ID] = true
				}
			})
		}
		if uncreated[e.ID] {
			*e = types.StateElement{ID: e.ID, LeafIndex: types.EphemeralLeafIndex}
		}
	}
	for _, txn := range m.txpool.v2txns {
		for i := range txn.SiacoinInputs {
			replaceEphemeral(&txn.SiacoinInputs[i].Parent.StateElement)
		}
		for i := range txn.SiafundInputs {
			replaceEphemeral(&txn.SiafundInputs[i].Parent.StateElement)
		}
		for i := range txn.FileContractRevisions {
			replaceEphemeral(&txn.FileContractRevisions[i].Parent.StateElement)
		}
		for i := range txn.FileContractResolutions {
			replaceEphemeral(&txn.FileContractResolutions[i].Parent.StateElement)
		}
	}

	rem := m.txpool.v2txns[:0]
	for _, txn := range m.txpool.v2txns {
		if updateTxnProofs(&txn, cru.UpdateElementProof, cru.State.Elements.NumLeaves) {
			rem = append(rem, txn)
		}
	}
	m.txpool.v2txns = rem
}

func (m *Manager) applyPoolUpdate(cau *ApplyUpdate) {
	// replace ephemeral elements, if necessary
	var newElements map[types.Hash256]types.StateElement
	replaceEphemeral := func(e *types.StateElement) {
		if e.LeafIndex != types.EphemeralLeafIndex {
			return
		} else if newElements == nil {
			newElements = make(map[types.Hash256]types.StateElement)
			cau.ForEachSiacoinElement(func(sce types.SiacoinElement, spent bool) {
				if !spent {
					newElements[sce.ID] = sce.StateElement
				}
			})
			cau.ForEachSiafundElement(func(sfe types.SiafundElement, spent bool) {
				if !spent {
					newElements[sfe.ID] = sfe.StateElement
				}
			})
			cau.ForEachFileContractElement(func(fce types.FileContractElement, rev *types.FileContractElement, resolved, valid bool) {
				if !resolved {
					newElements[fce.ID] = fce.StateElement
				}
			})
			cau.ForEachV2FileContractElement(func(fce types.V2FileContractElement, rev *types.V2FileContractElement, res types.V2FileContractResolutionType) {
				if res != nil {
					newElements[fce.ID] = fce.StateElement
				}
			})
		}
		*e = newElements[e.ID]
	}
	for _, txn := range m.txpool.v2txns {
		for i := range txn.SiacoinInputs {
			replaceEphemeral(&txn.SiacoinInputs[i].Parent.StateElement)
		}
		for i := range txn.SiafundInputs {
			replaceEphemeral(&txn.SiafundInputs[i].Parent.StateElement)
		}
		for i := range txn.FileContractRevisions {
			replaceEphemeral(&txn.FileContractRevisions[i].Parent.StateElement)
		}
		for i := range txn.FileContractResolutions {
			replaceEphemeral(&txn.FileContractResolutions[i].Parent.StateElement)
		}
	}

	rem := m.txpool.v2txns[:0]
	for _, txn := range m.txpool.v2txns {
		if updateTxnProofs(&txn, cau.UpdateElementProof, cau.State.Elements.NumLeaves) {
			rem = append(rem, txn)
		}
	}
	m.txpool.v2txns = rem
}

// PoolTransaction returns the transaction with the specified ID, if it is
// currently in the pool.
func (m *Manager) PoolTransaction(id types.TransactionID) (types.Transaction, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revalidatePool()
	i, ok := m.txpool.indices[id]
	if !ok {
		return types.Transaction{}, false
	}
	return m.txpool.txns[i], ok
}

// PoolTransactions returns the transactions currently in the txpool. Any prefix
// of the returned slice constitutes a valid transaction set.
func (m *Manager) PoolTransactions() []types.Transaction {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revalidatePool()
	return append([]types.Transaction(nil), m.txpool.txns...)
}

// V2PoolTransaction returns the v2 transaction with the specified ID, if it is
// currently in the pool.
func (m *Manager) V2PoolTransaction(id types.TransactionID) (types.V2Transaction, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revalidatePool()
	i, ok := m.txpool.indices[id]
	if !ok {
		return types.V2Transaction{}, false
	}
	return m.txpool.v2txns[i], ok
}

// V2PoolTransactions returns the v2 transactions currently in the txpool. Any
// prefix of the returned slice constitutes a valid transaction set.
func (m *Manager) V2PoolTransactions() []types.V2Transaction {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revalidatePool()
	return append([]types.V2Transaction(nil), m.txpool.v2txns...)
}

// TransactionsForPartialBlock returns the transactions in the txpool with the
// specified hashes.
func (m *Manager) TransactionsForPartialBlock(missing []types.Hash256) (txns []types.Transaction, v2txns []types.V2Transaction) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revalidatePool()
	want := make(map[types.Hash256]bool)
	for _, h := range missing {
		want[h] = true
	}
	// TODO: might want to cache these
	for _, txn := range m.txpool.txns {
		if h := txn.FullHash(); want[h] {
			txns = append(txns, txn)
			if delete(want, h); len(want) == 0 {
				return
			}
		}
	}
	for _, txn := range m.txpool.v2txns {
		if h := txn.FullHash(); want[h] {
			v2txns = append(v2txns, txn)
			if delete(want, h); len(want) == 0 {
				return
			}
		}
	}
	return
}

// RecommendedFee returns the recommended fee (per weight unit) to ensure a high
// probability of inclusion in the next block.
func (m *Manager) RecommendedFee() types.Currency {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revalidatePool()

	medianFee := m.computeMedianFee()

	// calculate a fee relative to the total txpool weight
	//
	// NOTE: empirically, the average txn weight is ~1000
	estPoolWeight := m.txpool.weight + uint64(10e3)
	// the target weight of the pool is 3e6, with an average fee of 1 SC / 1e3;
	// compute targetFee * (estPoolWeight / targetWeight)^3
	//
	// NOTE: alternating the multiplications and divisions is crucial here to
	// prevent immediate values from overflowing
	const targetWeight = 3e6
	weightFee := types.Siacoins(1).Div64(1000).
		Mul64(estPoolWeight).Div64(targetWeight).Mul64(estPoolWeight).
		Div64(targetWeight).Mul64(estPoolWeight).Div64(targetWeight)

	// finally, an absolute minimum fee: 1 SC / 100 KB
	minFee := types.Siacoins(1).Div64(100e3)

	// use the largest of all calculated fees
	fee := medianFee
	if fee.Cmp(weightFee) < 0 {
		fee = weightFee
	}
	if fee.Cmp(minFee) < 0 {
		fee = minFee
	}
	return fee
}

// UnconfirmedParents returns the transactions in the txpool that are referenced
// by txn.
func (m *Manager) UnconfirmedParents(txn types.Transaction) []types.Transaction {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revalidatePool()

	parentMap := m.computeParentMap()
	var parents []types.Transaction
	seen := make(map[int]bool)
	check := func(id types.Hash256) {
		if index, ok := parentMap[id]; ok && !seen[index] {
			seen[index] = true
			parents = append(parents, m.txpool.txns[index])
		}
	}
	addParents := func(txn types.Transaction) {
		for _, sci := range txn.SiacoinInputs {
			check(types.Hash256(sci.ParentID))
		}
		for _, sfi := range txn.SiafundInputs {
			check(types.Hash256(sfi.ParentID))
		}
		for _, fcr := range txn.FileContractRevisions {
			check(types.Hash256(fcr.ParentID))
		}
		for _, sp := range txn.StorageProofs {
			check(types.Hash256(sp.ParentID))
		}
	}

	// check txn, then keep checking parents until done
	addParents(txn)
	for {
		n := len(parents)
		for _, txn := range parents {
			addParents(txn)
		}
		if len(parents) == n {
			break
		}
	}
	// reverse so that parents always come before children
	for i := 0; i < len(parents)/2; i++ {
		j := len(parents) - 1 - i
		parents[i], parents[j] = parents[j], parents[i]
	}
	return parents
}

func (m *Manager) checkDupTxnSet(txns []types.Transaction, v2txns []types.V2Transaction) (types.Hash256, bool) {
	allInPool := true
	checkPool := func(txid types.TransactionID) {
		if allInPool {
			if _, ok := m.txpool.indices[txid]; !ok {
				allInPool = false
			}
		}
	}
	h := types.NewHasher()
	for i, txn := range txns {
		txid := txn.ID()
		checkPool(txid)
		h.E.WriteUint64(uint64(i))
		txid.EncodeTo(h.E)
	}
	for i, txn := range v2txns {
		txid := txn.ID()
		checkPool(txid)
		h.E.WriteUint64(uint64(i))
		txid.EncodeTo(h.E)
	}
	setID := h.Sum()
	_, invalid := m.txpool.invalidTxnSets[setID]
	return setID, allInPool || invalid
}

func (m *Manager) markBadTxnSet(setID types.Hash256, err error) error {
	const maxInvalidTxnSets = 1000
	if len(m.txpool.invalidTxnSets) >= maxInvalidTxnSets {
		// forget a random entry
		for id := range m.txpool.invalidTxnSets {
			delete(m.txpool.invalidTxnSets, id)
			break
		}
	}
	m.txpool.invalidTxnSets[setID] = err
	return err
}

// AddPoolTransactions validates a transaction set and adds it to the txpool. If
// any transaction references an element (SiacoinOutput, SiafundOutput, or
// FileContract) not present in the blockchain, that element must be created by
// a previous transaction in the set.
//
// If any transaction in the set is invalid, the entire set is rejected and none
// of the transactions are added to the pool. If all of the transactions are
// already known to the pool, AddPoolTransactions returns true.
func (m *Manager) AddPoolTransactions(txns []types.Transaction) (known bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revalidatePool()

	setID, known := m.checkDupTxnSet(txns, nil)
	if known {
		return true, m.txpool.invalidTxnSets[setID]
	}

	// validate as a standalone set
	ms := consensus.NewMidState(m.tipState)
	for _, txn := range txns {
		ts := m.store.SupplementTipTransaction(txn)
		if err := consensus.ValidateTransaction(ms, txn, ts); err != nil {
			return false, m.markBadTxnSet(setID, fmt.Errorf("transaction %v is invalid: %w", txn.ID(), err))
		}
		ms.ApplyTransaction(txn, ts)
	}

	for _, txn := range txns {
		txid := txn.ID()
		if _, ok := m.txpool.indices[txid]; ok {
			continue // skip transactions already in pool
		}
		m.txpool.ms.ApplyTransaction(txn, m.store.SupplementTipTransaction(txn))
		m.txpool.indices[txid] = len(m.txpool.txns)
		m.txpool.txns = append(m.txpool.txns, txn)
		m.txpool.weight += m.tipState.TransactionWeight(txn)
	}

	// invalidate caches
	m.txpool.medianFee = nil
	m.txpool.parentMap = nil
	return
}

// AddV2PoolTransactions validates a transaction set and adds it to the txpool.
// If any transaction references an element (SiacoinOutput, SiafundOutput, or
// FileContract) not present in the blockchain, that element must be created by
// a previous transaction in the set.
//
// If any transaction in the set is invalid, the entire set is rejected and none
// of the transactions are added to the pool. If all of the transactions are
// already known to the pool, AddV2PoolTransactions returns true.
//
// Since v2 transactions include Merkle proofs, AddV2PoolTransactions takes an
// index specifying the accumulator state for which those proofs are assumed to
// be valid. If that index differs from the Manager's current tip, the Merkle
// proofs will be updated accordingly. The original transactions are not
// modified.
func (m *Manager) AddV2PoolTransactions(basis types.ChainIndex, txns []types.V2Transaction) (known bool, _ error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revalidatePool()

	setID, known := m.checkDupTxnSet(nil, txns)
	if known {
		return true, m.txpool.invalidTxnSets[setID]
	}

	if basis != m.tipState.Index {
		// bring txns up-to-date, preserving the originals
		txns = append([]types.V2Transaction(nil), txns...)
		for i := range txns {
			txns[i] = txns[i].DeepCopy()
		}
		revert, apply, err := m.reorgPath(basis, m.tipState.Index)
		if err != nil {
			return false, fmt.Errorf("couldn't determine reorg path from %v to %v: %w", basis, m.tipState.Index, err)
		} else if len(revert)+len(apply) > 144 {
			return false, fmt.Errorf("reorg path from %v to %v is too long (-%v +%v)", basis, m.tipState.Index, len(revert), len(apply))
		}
		for _, index := range revert {
			b, _, cs, ok := blockAndParent(m.store, index.ID)
			if !ok {
				return false, fmt.Errorf("missing reverted block at index %v", index)
			} else if b.V2 == nil {
				return false, m.markBadTxnSet(setID, fmt.Errorf("reorg path from %v to %v contains a non-v2 block (%v)", basis, m.tipState.Index, index))
			}
			// NOTE: since we are post-hardfork, we don't need a v1 supplement
			cru := consensus.RevertBlock(cs, b, consensus.V1BlockSupplement{})
			for i := range txns {
				if !updateTxnProofs(&txns[i], cru.UpdateElementProof, cs.Elements.NumLeaves) {
					return false, m.markBadTxnSet(setID, fmt.Errorf("transaction %v references element that does not exist in our chain", txns[i].ID()))
				}
			}
		}
		for _, index := range apply {
			b, _, cs, ok := blockAndParent(m.store, index.ID)
			if !ok {
				return false, fmt.Errorf("missing applied block at index %v", index)
			} else if b.V2 == nil {
				return false, m.markBadTxnSet(setID, fmt.Errorf("reorg path from %v to %v contains a non-v2 block (%v)", basis, m.tipState.Index, index))
			}
			// NOTE: since we are post-hardfork, we don't need a v1 supplement or ancestorTimestamp
			cs, cau := consensus.ApplyBlock(cs, b, consensus.V1BlockSupplement{}, time.Time{})
			for i := range txns {
				// NOTE: all elements guaranteed to exist from here on, so no
				// need to check this return value
				updateTxnProofs(&txns[i], cau.UpdateElementProof, cs.Elements.NumLeaves)
			}
		}
	}

	// validate as a standalone set
	ms := consensus.NewMidState(m.tipState)
	for _, txn := range txns {
		if err := consensus.ValidateV2Transaction(ms, txn); err != nil {
			return false, m.markBadTxnSet(setID, fmt.Errorf("transaction %v is invalid: %w", txn.ID(), err))
		}
		ms.ApplyV2Transaction(txn)
	}

	for _, txn := range txns {
		txid := txn.ID()
		if _, ok := m.txpool.indices[txid]; ok {
			continue // skip transactions already in pool
		}
		m.txpool.ms.ApplyV2Transaction(txn)
		m.txpool.indices[txid] = len(m.txpool.v2txns)
		m.txpool.v2txns = append(m.txpool.v2txns, txn)
		m.txpool.weight += m.tipState.V2TransactionWeight(txn)
	}

	// invalidate caches
	m.txpool.medianFee = nil
	m.txpool.parentMap = nil
	return
}

// NewManager returns a Manager initialized with the provided Store and State.
func NewManager(store Store, cs consensus.State) *Manager {
	m := &Manager{
		store:         store,
		tipState:      cs,
		lastCommit:    time.Now(),
		invalidBlocks: make(map[types.BlockID]error),
	}
	m.txpool.indices = make(map[types.TransactionID]int)
	m.txpool.invalidTxnSets = make(map[types.Hash256]error)
	return m
}
