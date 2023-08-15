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

// A Checkpoint pairs a block with its resulting chain state.
type Checkpoint struct {
	Block      types.Block
	State      consensus.State
	Supplement *consensus.V1BlockSupplement
}

// EncodeTo implements types.EncoderTo.
func (c Checkpoint) EncodeTo(e *types.Encoder) {
	e.WriteUint8(2) // block (and supplement) version
	types.V2Block(c.Block).EncodeTo(e)
	e.WriteUint8(1) // state version
	c.State.EncodeTo(e)
	e.WriteBool(c.Supplement != nil)
	if c.Supplement != nil {
		c.Supplement.EncodeTo(e)
	}
}

// DecodeFrom implements types.DecoderFrom.
func (c *Checkpoint) DecodeFrom(d *types.Decoder) {
	v := d.ReadUint8()
	if v != 2 {
		d.SetErr(fmt.Errorf("incompatible block version (%d)", v))
	}
	(*types.V2Block)(&c.Block).DecodeFrom(d)
	if v := d.ReadUint8(); v != 1 {
		d.SetErr(fmt.Errorf("incompatible state version (%d)", v))
	}
	c.State.DecodeFrom(d)
	if d.ReadBool() {
		c.Supplement = new(consensus.V1BlockSupplement)
		c.Supplement.DecodeFrom(d)
	}
}

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

	AddCheckpoint(c Checkpoint)
	Checkpoint(id types.BlockID) (Checkpoint, bool)

	// Except when mustCommit is set, ApplyBlock and RevertBlock are free to
	// commit whenever they see fit.
	ApplyBlock(s consensus.State, cau consensus.ApplyUpdate, mustCommit bool) (committed bool)
	RevertBlock(s consensus.State, cru consensus.RevertUpdate)
}

// ancestorTimestamp returns the timestamp of the n'th ancestor of id.
func ancestorTimestamp(s Store, id types.BlockID, n uint64) time.Time {
	c, _ := s.Checkpoint(id)
	for i := uint64(1); i < n; i++ {
		// if we're on the best path, we can jump to the n'th block directly
		if index, _ := s.BestIndex(c.State.Index.Height); index.ID == id {
			height := c.State.Index.Height - (n - i)
			if c.State.Index.Height < (n - i) {
				height = 0
			}
			ancestorIndex, _ := s.BestIndex(height)
			c, _ = s.Checkpoint(ancestorIndex.ID)
			break
		}
		c, _ = s.Checkpoint(c.Block.ParentID)
	}
	return c.Block.Timestamp
}

// A Manager tracks multiple blockchains and identifies the best valid
// chain.
type Manager struct {
	store       Store
	tipState    consensus.State
	subscribers []Subscriber
	lastCommit  time.Time

	txpool struct {
		txns           []types.Transaction
		v2txns         []types.V2Transaction
		indices        map[types.TransactionID]int
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
	c, ok := m.store.Checkpoint(id)
	return c.Block, ok
}

// BestIndex returns the index of the block at the specified height within the
// best chain.
func (m *Manager) BestIndex(height uint64) (types.ChainIndex, bool) {
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
		cs = consensus.ApplyOrphan(cs, b, ancestorTimestamp(m.store, b.ParentID, cs.AncestorDepth()))
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
	cru := consensus.RevertBlock(pc.State, c.Block, *c.Supplement)
	m.store.RevertBlock(pc.State, cru)

	update := RevertUpdate{cru, c.Block, pc.State}
	for _, s := range m.subscribers {
		if err := s.ProcessChainRevertUpdate(&update); err != nil {
			return fmt.Errorf("subscriber %T: %w", s, err)
		}
	}

	m.revertPoolUpdate(cru)
	m.tipState = pc.State
	return nil
}

// applyTip adds a block to the current tip.
func (m *Manager) applyTip(index types.ChainIndex) error {
	var cau consensus.ApplyUpdate
	c, ok := m.store.Checkpoint(index.ID)
	if !ok {
		return fmt.Errorf("missing checkpoint for index %v", index)
	} else if c.Block.ParentID != m.tipState.Index.ID {
		panic("applyTip called with non-attaching block")
	} else if c.Supplement == nil {
		bs := m.store.SupplementTipBlock(c.Block)
		if err := consensus.ValidateBlock(m.tipState, c.Block, bs); err != nil {
			return fmt.Errorf("block %v is invalid: %w", index, err)
		}
		c.Supplement = &bs
		targetTimestamp := ancestorTimestamp(m.store, c.Block.ParentID, m.tipState.AncestorDepth())
		c.State, cau = consensus.ApplyBlock(m.tipState, c.Block, bs, targetTimestamp)
		m.store.AddCheckpoint(c)
	} else {
		targetTimestamp := ancestorTimestamp(m.store, c.Block.ParentID, m.tipState.AncestorDepth())
		_, cau = consensus.ApplyBlock(m.tipState, c.Block, *c.Supplement, targetTimestamp)
	}

	// force the store to commit if we're at the tip (or close to it), or at
	// least every 2 seconds; this ensures that the amount of uncommitted data
	// never grows too large
	forceCommit := time.Since(c.Block.Timestamp) < c.State.BlockInterval()*2 || time.Since(m.lastCommit) > 2*time.Second
	committed := m.store.ApplyBlock(c.State, cau, forceCommit)
	if committed {
		m.lastCommit = time.Now()
	}

	update := &ApplyUpdate{cau, c.Block, c.State}
	for _, s := range m.subscribers {
		if err := s.ProcessChainApplyUpdate(update, committed); err != nil {
			return fmt.Errorf("subscriber %T: %w", s, err)
		}
	}

	m.applyPoolUpdate(cau)
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
		c, _ := m.store.Checkpoint(revert[0].ID)
		m.txpool.lastReverted = c.Block.Transactions
		if c.Block.V2 != nil {
			m.txpool.lastRevertedV2 = c.Block.V2.Transactions
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
		} else if c.Supplement == nil {
			panic("missing supplement for reverted block")
		}
		pc, ok := m.store.Checkpoint(c.Block.ParentID)
		if !ok {
			return fmt.Errorf("missing revert parent checkpoint %v", c.Block.ParentID)
		}
		cru := consensus.RevertBlock(pc.State, c.Block, *c.Supplement)
		if err := s.ProcessChainRevertUpdate(&RevertUpdate{cru, c.Block, pc.State}); err != nil {
			return fmt.Errorf("couldn't process revert update: %w", err)
		}
	}
	for _, index := range apply {
		c, ok := m.store.Checkpoint(index.ID)
		if !ok {
			return fmt.Errorf("missing apply checkpoint %v", index)
		} else if c.Supplement == nil {
			panic("missing supplement for applied block")
		}
		pc, ok := m.store.Checkpoint(c.Block.ParentID)
		if !ok {
			return fmt.Errorf("missing apply parent checkpoint %v", c.Block.ParentID)
		}
		_, cau := consensus.ApplyBlock(pc.State, c.Block, *c.Supplement, ancestorTimestamp(m.store, c.Block.ParentID, pc.State.AncestorDepth()))
		// TODO: commit every minute for large len(apply)?
		shouldCommit := index == m.tipState.Index
		if err := s.ProcessChainApplyUpdate(&ApplyUpdate{cau, c.Block, c.State}, shouldCommit); err != nil {
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
		for m.txpool.weight >= (txpoolMaxWeight*3)/4 {
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
		if b.V2 != nil {
			for _, txn := range b.V2.Transactions {
				fees = append(fees, weightedFee{cs.V2TransactionWeight(txn), txn.MinerFee})
			}
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
		c, ok2 := m.store.Checkpoint(index.ID)
		pc, ok3 := m.store.Checkpoint(c.Block.ParentID)
		if !ok3 && m.tipState.Index.Height == 0 {
			// bit of a hack to make the genesis block work
			pc.State = c.State.Network.GenesisState()
			ok3 = true
		}
		if ok1 && ok2 && ok3 {
			prevFees = append(prevFees, calculateBlockMedianFee(pc.State, c.Block))
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

func (m *Manager) applyPoolUpdate(cau consensus.ApplyUpdate) {
	// replace ephemeral elements, if necessary
	var newElements map[types.Hash256]types.StateElement
	replaceEphemeral := func(e *types.StateElement) {
		if e.LeafIndex != types.EphemeralLeafIndex {
			return
		} else if newElements == nil {
			newElements := make(map[types.Hash256]types.StateElement)
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
			cau.ForEachFileContractElement(func(fce types.FileContractElement, rev *types.FileContractElement, spent bool) {
				if !spent {
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

	// update proofs
	for _, txn := range m.txpool.v2txns {
		for i := range txn.SiacoinInputs {
			cau.UpdateElementProof(&txn.SiacoinInputs[i].Parent.StateElement)
		}
		for i := range txn.SiafundInputs {
			cau.UpdateElementProof(&txn.SiafundInputs[i].Parent.StateElement)
		}
		for i := range txn.FileContractRevisions {
			cau.UpdateElementProof(&txn.FileContractRevisions[i].Parent.StateElement)
		}
		for i := range txn.FileContractResolutions {
			cau.UpdateElementProof(&txn.FileContractResolutions[i].Parent.StateElement)
			if sp, ok := txn.FileContractResolutions[i].Resolution.(types.V2StorageProof); ok {
				cau.UpdateElementProof(&sp.ProofStart.StateElement)
				txn.FileContractResolutions[i].Resolution = sp
			}
		}
	}
}

func (m *Manager) revertPoolUpdate(cru consensus.RevertUpdate) {
	// restore ephemeral elements, if necessary
	var uncreated map[types.Hash256]bool
	replaceEphemeral := func(e *types.StateElement) {
		if e.LeafIndex != types.EphemeralLeafIndex {
			return
		} else if uncreated == nil {
			uncreated := make(map[types.Hash256]types.StateElement)
			cru.ForEachSiacoinElement(func(sce types.SiacoinElement, spent bool) {
				if !spent {
					uncreated[sce.ID] = sce.StateElement
				}
			})
			cru.ForEachSiafundElement(func(sfe types.SiafundElement, spent bool) {
				if !spent {
					uncreated[sfe.ID] = sfe.StateElement
				}
			})
			cru.ForEachFileContractElement(func(fce types.FileContractElement, rev *types.FileContractElement, spent bool) {
				if !spent {
					uncreated[fce.ID] = fce.StateElement
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

	// update proofs
	for _, txn := range m.txpool.v2txns {
		for i := range txn.SiacoinInputs {
			cru.UpdateElementProof(&txn.SiacoinInputs[i].Parent.StateElement)
		}
		for i := range txn.SiafundInputs {
			cru.UpdateElementProof(&txn.SiafundInputs[i].Parent.StateElement)
		}
		for i := range txn.FileContractRevisions {
			cru.UpdateElementProof(&txn.FileContractRevisions[i].Parent.StateElement)
		}
		for i := range txn.FileContractResolutions {
			cru.UpdateElementProof(&txn.FileContractResolutions[i].Parent.StateElement)
			if sp, ok := txn.FileContractResolutions[i].Resolution.(types.V2StorageProof); ok {
				cru.UpdateElementProof(&sp.ProofStart.StateElement)
				txn.FileContractResolutions[i].Resolution = sp
			}
		}
	}
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

	// finally, an absolute minumum fee: 1 SC / 100 KB
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

// AddPoolTransactions validates a transaction set and adds it to the txpool. If
// any transaction references an element (SiacoinOutput, SiafundOutput, or
// FileContract) not present in the blockchain, that element must be created by
// a previous transaction in the set.
//
// If any transaction in the set is invalid, the entire set is rejected and none
// of the transactions are added to the pool.
func (m *Manager) AddPoolTransactions(txns []types.Transaction) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revalidatePool()

	// validate as a standalone set
	ms := consensus.NewMidState(m.tipState)
	for _, txn := range txns {
		ts := m.store.SupplementTipTransaction(txn)
		if err := consensus.ValidateTransaction(ms, txn, ts); err != nil {
			return fmt.Errorf("transaction %v is invalid: %v", txn.ID(), err)
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
	return nil
}

// AddV2PoolTransactions validates a transaction set and adds it to the txpool.
// If any transaction references an element (SiacoinOutput, SiafundOutput, or
// FileContract) not present in the blockchain, that element must be created by
// a previous transaction in the set.
//
// If any transaction in the set is invalid, the entire set is rejected and none
// of the transactions are added to the pool.
func (m *Manager) AddV2PoolTransactions(txns []types.V2Transaction) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revalidatePool()

	// validate as a standalone set
	ms := consensus.NewMidState(m.tipState)
	for _, txn := range txns {
		if err := consensus.ValidateV2Transaction(ms, txn); err != nil {
			return fmt.Errorf("transaction %v is invalid: %v", txn.ID(), err)
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
	return nil
}

// NewManager returns a Manager initialized with the provided Store and State.
func NewManager(store Store, cs consensus.State) *Manager {
	m := &Manager{
		store:      store,
		tipState:   cs,
		lastCommit: time.Now(),
	}
	m.txpool.indices = make(map[types.TransactionID]int)
	return m
}
