package chain

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

// A DB is a generic key-value database.
type DB interface {
	View(func(DBTx) error) error
	Update(func(DBTx) error) error
}

// A DBTx is a transaction executed on a key-value database.
type DBTx interface {
	Bucket(name []byte) DBBucket
	CreateBucket(name []byte) (DBBucket, error)
}

// A DBBucket is a set of key-value pairs.
type DBBucket interface {
	Get(key []byte) []byte
	Put(key, value []byte) error
	Delete(key []byte) error
}

// MemDB implements DB with an in-memory map.
type MemDB struct {
	buckets map[string]map[string][]byte
}

func (db *MemDB) tx(writeable bool) *memTx {
	tx := &memTx{
		puts:      make(map[string]map[string][]byte),
		dels:      make(map[string]map[string]struct{}),
		writeable: writeable,
		db:        db,
	}
	for name := range db.buckets {
		tx.puts[name] = make(map[string][]byte)
		tx.dels[name] = make(map[string]struct{})
	}
	return tx
}

func (db *MemDB) commit(tx *memTx) error {
	for bucket, puts := range tx.puts {
		if db.buckets[bucket] == nil {
			db.buckets[bucket] = make(map[string][]byte)
		}
		for key, val := range puts {
			db.buckets[bucket][key] = val
		}
	}
	for bucket, dels := range tx.dels {
		if db.buckets[bucket] == nil {
			db.buckets[bucket] = make(map[string][]byte)
		}
		for key := range dels {
			delete(db.buckets[bucket], key)
		}
	}
	return nil
}

// View implements DB.
func (db *MemDB) View(fn func(DBTx) error) error {
	return fn(db.tx(false))
}

// Update implements DB.
func (db *MemDB) Update(fn func(DBTx) error) error {
	tx := db.tx(true)
	if err := fn(tx); err != nil {
		return err
	}
	return db.commit(tx)
}

type memTx struct {
	puts      map[string]map[string][]byte
	dels      map[string]map[string]struct{}
	writeable bool
	db        *MemDB
}

func (tx *memTx) get(bucket string, key []byte) []byte {
	if val, ok := tx.puts[bucket][string(key)]; ok {
		return val
	} else if _, ok := tx.dels[bucket][string(key)]; ok {
		return nil
	}
	return tx.db.buckets[bucket][string(key)]
}

func (tx *memTx) put(bucket string, key, value []byte) error {
	if !tx.writeable {
		panic("cannot Put within a read-only transaction")
	}
	if tx.puts[bucket] == nil {
		if tx.db.buckets[bucket] == nil {
			return errors.New("bucket does not exist")
		}
		tx.puts[bucket] = make(map[string][]byte)
	}
	tx.puts[bucket][string(key)] = value
	delete(tx.dels[bucket], string(key))
	return nil
}

func (tx *memTx) delete(bucket string, key []byte) error {
	if !tx.writeable {
		panic("cannot Delete within a read-only transaction")
	}
	if tx.dels[bucket] == nil {
		if tx.db.buckets[bucket] == nil {
			return errors.New("bucket does not exist")
		}
		tx.dels[bucket] = make(map[string]struct{})
	}
	tx.dels[bucket][string(key)] = struct{}{}
	delete(tx.puts[bucket], string(key))
	return nil
}

func (tx *memTx) Bucket(name []byte) DBBucket {
	return memBucket{string(name), tx}
}

func (tx *memTx) CreateBucket(name []byte) (DBBucket, error) {
	if tx.db.buckets[string(name)] != nil {
		return nil, errors.New("bucket already exists")
	}
	tx.puts[string(name)] = make(map[string][]byte)
	tx.dels[string(name)] = make(map[string]struct{})
	return tx.Bucket(name), nil
}

type memBucket struct {
	name string
	tx   *memTx
}

func (b memBucket) Get(key []byte) []byte       { return b.tx.get(b.name, key) }
func (b memBucket) Put(key, value []byte) error { return b.tx.put(b.name, key, value) }
func (b memBucket) Delete(key []byte) error     { return b.tx.delete(b.name, key) }

// NewMemDB returns an in-memory DB for use with DBStore.
func NewMemDB() *MemDB {
	return &MemDB{
		buckets: make(map[string]map[string][]byte),
	}
}

var (
	bMainChain      = []byte("MainChain")
	bCheckpoints    = []byte("Checkpoints")
	bFileContracts  = []byte("FileContracts")
	bSiacoinOutputs = []byte("SiacoinOutputs")
	bSiafundOutputs = []byte("SiafundOutputs")

	keyFoundationOutputs = []byte("FoundationOutputs")
	keyHeight            = []byte("Height")
)

// DBStore implements Store using a key-value database.
type DBStore struct {
	db      DB
	network *consensus.Network
}

func (db DBStore) view(fn func(tx *dbTx)) error {
	return db.db.View(func(tx DBTx) error {
		dtx := &dbTx{tx: tx, n: db.network}
		fn(dtx)
		return dtx.err
	})
}

func (db DBStore) update(fn func(tx *dbTx)) error {
	return db.db.Update(func(tx DBTx) error {
		dtx := &dbTx{tx: tx, n: db.network}
		fn(dtx)
		return dtx.err
	})
}

// ApplyDiff implements Store.
func (db DBStore) ApplyDiff(s consensus.State, diff consensus.BlockDiff) (mayCommit bool, err error) {
	// NOTE: for now, we always return true; later, we should explore buffering
	// writes in a MemDB until some flush threshold is reached.
	return true, db.update(func(tx *dbTx) {
		tx.applyState(s)
		tx.applyDiff(s, diff)
	})
}

// RevertDiff implements Store.
func (db DBStore) RevertDiff(s consensus.State, diff consensus.BlockDiff) error {
	return db.update(func(tx *dbTx) {
		tx.revertDiff(s, diff)
		tx.revertState(s)
	})
}

// WithConsensus implements Store.
func (db DBStore) WithConsensus(fn func(consensus.Store) error) error {
	return db.view(func(tx *dbTx) { tx.setErr(fn(tx)) })
}

// AddCheckpoint implements Store.
func (db DBStore) AddCheckpoint(c Checkpoint) error {
	return db.update(func(tx *dbTx) { tx.putCheckpoint(c) })
}

// Checkpoint implements Store.
func (db DBStore) Checkpoint(id types.BlockID) (c Checkpoint, err error) {
	err = db.view(func(tx *dbTx) {
		var ok bool
		c, ok = tx.getCheckpoint(id)
		if !ok && tx.err == nil {
			tx.err = fmt.Errorf("no checkpoint for block %v", id)
		}
	})
	return
}

// BestIndex implements Store.
func (db DBStore) BestIndex(height uint64) (index types.ChainIndex, err error) {
	err = db.view(func(tx *dbTx) {
		var ok bool
		index, ok = tx.BestIndex(height)
		if !ok && tx.err == nil {
			tx.err = fmt.Errorf("no index at height %v", height)
		}
	})
	return
}

// NewDBStore creates a new DBStore using the provided database. The current
// checkpoint is also returned.
func NewDBStore(db DB, n *consensus.Network, genesisBlock types.Block) (*DBStore, Checkpoint, error) {
	dbs := &DBStore{db: db, network: n}
	err := dbs.update(func(tx *dbTx) {
		if _, ok := tx.getCheckpoint(genesisBlock.ID()); ok {
			return // already initialized
		}
		for _, bucket := range [][]byte{
			bMainChain,
			bCheckpoints,
			bFileContracts,
			bSiacoinOutputs,
			bSiafundOutputs,
		} {
			if tx.err == nil {
				_, tx.err = tx.tx.CreateBucket(bucket)
			}
		}

		// add genesis checkpoint and effects
		genesisState := n.GenesisState()
		cs := consensus.ApplyState(genesisState, tx, genesisBlock)
		diff := consensus.ApplyDiff(genesisState, tx, genesisBlock)
		tx.putCheckpoint(Checkpoint{genesisBlock, cs, &diff})
		tx.applyState(cs)
		tx.applyDiff(cs, diff)
	})
	if err != nil {
		return nil, Checkpoint{}, err
	}

	var c Checkpoint
	err = dbs.view(func(tx *dbTx) {
		index, _ := tx.BestIndex(tx.getHeight())
		c, _ = tx.getCheckpoint(index.ID)
	})
	return dbs, c, err
}

// wrappers with sticky errors and helper methods

type dbBucket struct {
	b  DBBucket
	tx *dbTx
}

func (b *dbBucket) getRaw(key []byte) []byte {
	if b == nil || b.tx.err != nil {
		return nil
	}
	return b.b.Get(key)
}

func (b *dbBucket) get(key []byte, v types.DecoderFrom) bool {
	val := b.getRaw(key)
	if val == nil || b.tx.err != nil {
		return false
	}
	d := types.NewBufDecoder(val)
	v.DecodeFrom(d)
	if d.Err() != nil {
		b.tx.setErr(fmt.Errorf("error decoding %T: %w", v, d.Err()))
		return false
	}
	return true
}

func (b *dbBucket) putRaw(key, value []byte) {
	if b == nil || b.tx.err != nil {
		return
	}
	b.tx.setErr(b.b.Put(key, value))
}

func (b *dbBucket) put(key []byte, v types.EncoderTo) {
	var buf bytes.Buffer
	e := types.NewEncoder(&buf)
	v.EncodeTo(e)
	e.Flush()
	b.putRaw(key, buf.Bytes())
}

func (b *dbBucket) delete(key []byte) {
	if b == nil || b.tx.err != nil {
		return
	}
	b.tx.setErr(b.b.Delete(key))
}

type dbTx struct {
	tx  DBTx
	n   *consensus.Network // for getCheckpoint
	err error
}

func (tx *dbTx) setErr(err error) {
	if tx.err == nil {
		tx.err = err
	}
}

func (tx *dbTx) bucket(name []byte) *dbBucket {
	if tx.err != nil {
		return nil
	}
	b := tx.tx.Bucket(name)
	if b == nil {
		return nil
	}
	return &dbBucket{b, tx}
}

func (tx *dbTx) encHeight(height uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], height)
	return buf[:]
}

func (tx *dbTx) BestIndex(height uint64) (index types.ChainIndex, ok bool) {
	index.Height = height
	ok = tx.bucket(bMainChain).get(tx.encHeight(height), &index.ID)
	return
}

func (tx *dbTx) putBestIndex(index types.ChainIndex) {
	tx.bucket(bMainChain).put(tx.encHeight(index.Height), &index.ID)
}

func (tx *dbTx) deleteBestIndex(height uint64) {
	tx.bucket(bMainChain).delete(tx.encHeight(height))
}

func (tx *dbTx) getHeight() (height uint64) {
	if val := tx.bucket(bMainChain).getRaw(keyHeight); len(val) == 8 {
		height = binary.BigEndian.Uint64(val)
	}
	return
}

func (tx *dbTx) putHeight(height uint64) {
	tx.bucket(bMainChain).putRaw(keyHeight, tx.encHeight(height))
}

func (tx *dbTx) getCheckpoint(id types.BlockID) (c Checkpoint, ok bool) {
	ok = tx.bucket(bCheckpoints).get(id[:], &c)
	c.State.Network = tx.n
	return
}

func (tx *dbTx) putCheckpoint(c Checkpoint) {
	tx.bucket(bCheckpoints).put(c.State.Index.ID[:], c)
}

func (tx *dbTx) deleteCheckpoint(id types.BlockID) {
	tx.bucket(bCheckpoints).delete(id[:])
}

func (tx *dbTx) AncestorTimestamp(id types.BlockID, n uint64) time.Time {
	c, _ := tx.getCheckpoint(id)
	for i := uint64(1); i < n; i++ {
		// if we're on the best path, we can jump to the n'th block directly
		if index, _ := tx.BestIndex(c.State.Index.Height); index.ID == id {
			ancestorIndex, _ := tx.BestIndex(c.State.Index.Height - (n - i))
			c, _ = tx.getCheckpoint(ancestorIndex.ID)
			break
		}
		c, _ = tx.getCheckpoint(c.Block.ParentID)
	}
	return c.Block.Timestamp
}

func (tx *dbTx) SiacoinOutput(id types.SiacoinOutputID) (sco types.SiacoinOutput, ok bool) {
	ok = tx.bucket(bSiacoinOutputs).get(id[:], &sco)
	return
}

func (tx *dbTx) putSiacoinOutput(id types.SiacoinOutputID, sco types.SiacoinOutput) {
	tx.bucket(bSiacoinOutputs).put(id[:], sco)
}

func (tx *dbTx) deleteSiacoinOutput(id types.SiacoinOutputID) {
	tx.bucket(bSiacoinOutputs).delete(id[:])
}

func (tx *dbTx) FileContract(id types.FileContractID) (fc types.FileContract, ok bool) {
	ok = tx.bucket(bFileContracts).get(id[:], &fc)
	return
}

func (tx *dbTx) MissedFileContracts(height uint64) (fcids []types.FileContractID) {
	ids := tx.bucket(bFileContracts).getRaw(tx.encHeight(height))
	for i := 0; i < len(ids); i += 32 {
		fcids = append(fcids, *(*types.FileContractID)(ids[i:]))
	}
	return
}

func (tx *dbTx) putFileContract(id types.FileContractID, fc types.FileContract) {
	b := tx.bucket(bFileContracts)
	b.put(id[:], fc)

	key := tx.encHeight(fc.WindowEnd)
	b.putRaw(key, append(b.getRaw(key), id[:]...))
}

func (tx *dbTx) reviseFileContract(id types.FileContractID, fc types.FileContract) {
	b := tx.bucket(bFileContracts)
	b.put(id[:], fc)
}

func (tx *dbTx) deleteFileContracts(fcds []consensus.FileContractDiff) {
	byHeight := make(map[uint64][]types.FileContractID)
	b := tx.bucket(bFileContracts)
	for _, fcd := range fcds {
		var fc types.FileContract
		if !b.get(fcd.ID[:], &fc) {
			tx.setErr(fmt.Errorf("missing file contract %v", fcd.ID))
		}
		b.delete(fcd.ID[:])
		byHeight[fc.WindowEnd] = append(byHeight[fc.WindowEnd], fcd.ID)
	}

	for height, ids := range byHeight {
		toDelete := make(map[types.FileContractID]struct{})
		for _, id := range ids {
			toDelete[id] = struct{}{}
		}
		key := tx.encHeight(height)
		val := append([]byte(nil), b.getRaw(key)...)
		for i := 0; i < len(val); i += 32 {
			id := *(*types.FileContractID)(val[i:])
			if _, ok := toDelete[id]; ok {
				copy(val[i:], val[len(val)-32:])
				val = val[:len(val)-32]
				i -= 32
				delete(toDelete, id)
			}
		}
		b.putRaw(key, val)
		if len(toDelete) != 0 {
			tx.setErr(errors.New("missing expired file contract(s)"))
		}
	}
}

type claimSFO struct {
	Output     types.SiafundOutput
	ClaimStart types.Currency
}

func (sfo claimSFO) EncodeTo(e *types.Encoder) {
	sfo.Output.EncodeTo(e)
	sfo.ClaimStart.EncodeTo(e)
}

func (sfo *claimSFO) DecodeFrom(d *types.Decoder) {
	sfo.Output.DecodeFrom(d)
	sfo.ClaimStart.DecodeFrom(d)
}

func (tx *dbTx) SiafundOutput(id types.SiafundOutputID) (sfo types.SiafundOutput, claimStart types.Currency, ok bool) {
	var csfo claimSFO
	ok = tx.bucket(bSiafundOutputs).get(id[:], &csfo)
	return csfo.Output, csfo.ClaimStart, ok
}

func (tx *dbTx) putSiafundOutput(id types.SiafundOutputID, sfo types.SiafundOutput, claimStart types.Currency) {
	tx.bucket(bSiafundOutputs).put(id[:], claimSFO{Output: sfo, ClaimStart: claimStart})
}

func (tx *dbTx) deleteSiafundOutput(id types.SiafundOutputID) {
	tx.bucket(bSiafundOutputs).delete(id[:])
}

func (tx *dbTx) MaturedSiacoinOutputs(height uint64) (dscods []consensus.DelayedSiacoinOutputDiff) {
	dscos := tx.bucket(bSiacoinOutputs).getRaw(tx.encHeight(height))
	d := types.NewBufDecoder(dscos)
	for {
		var dscod consensus.DelayedSiacoinOutputDiff
		dscod.DecodeFrom(d)
		if d.Err() != nil {
			break
		}
		dscods = append(dscods, dscod)
	}
	if !errors.Is(d.Err(), io.EOF) {
		tx.setErr(d.Err())
	}
	return
}

func (tx *dbTx) putDelayedSiacoinOutputs(dscods []consensus.DelayedSiacoinOutputDiff) {
	if len(dscods) == 0 {
		return
	}
	maturityHeight := dscods[0].MaturityHeight
	b := tx.bucket(bSiacoinOutputs)
	key := tx.encHeight(maturityHeight)
	var buf bytes.Buffer
	e := types.NewEncoder(&buf)
	for _, dscod := range dscods {
		if dscod.MaturityHeight != maturityHeight {
			tx.setErr(errors.New("mismatched maturity heights"))
			return
		}
		dscod.EncodeTo(e)
	}
	e.Flush()
	b.putRaw(key, append(b.getRaw(key), buf.Bytes()[:]...))
}

func (tx *dbTx) deleteDelayedSiacoinOutputs(dscods []consensus.DelayedSiacoinOutputDiff) {
	if len(dscods) == 0 {
		return
	}
	maturityHeight := dscods[0].MaturityHeight
	toDelete := make(map[types.SiacoinOutputID]struct{})
	for _, dscod := range dscods {
		if dscod.MaturityHeight != maturityHeight {
			tx.setErr(errors.New("mismatched maturity heights"))
			return
		}
		toDelete[dscod.ID] = struct{}{}
	}
	var buf bytes.Buffer
	e := types.NewEncoder(&buf)
	for _, mdscod := range tx.MaturedSiacoinOutputs(maturityHeight) {
		if _, ok := toDelete[mdscod.ID]; !ok {
			mdscod.EncodeTo(e)
		}
		delete(toDelete, mdscod.ID)
	}
	if len(toDelete) != 0 {
		tx.setErr(errors.New("missing delayed siacoin output(s)"))
		return
	}
	e.Flush()
	tx.bucket(bSiacoinOutputs).putRaw(tx.encHeight(maturityHeight), buf.Bytes())
}

func (tx *dbTx) putFoundationOutput(id types.SiacoinOutputID) {
	b := tx.bucket(bSiacoinOutputs)
	b.putRaw(keyFoundationOutputs, append(b.getRaw(keyFoundationOutputs), id[:]...))
}

func (tx *dbTx) deleteFoundationOutput(id types.SiacoinOutputID) {
	b := tx.bucket(bSiacoinOutputs)
	ids := append([]byte(nil), b.getRaw(keyFoundationOutputs)...)
	for i := 0; i < len(ids); i += 32 {
		if *(*types.SiacoinOutputID)(ids[i:]) == id {
			copy(ids[i:], ids[len(ids)-32:])
			b.putRaw(keyFoundationOutputs, ids[:len(ids)-32])
			return
		}
	}
	tx.setErr(fmt.Errorf("missing Foundation output %v", id))
}

func (tx *dbTx) moveFoundationOutputs(addr types.Address) {
	ids := tx.bucket(bSiacoinOutputs).getRaw(keyFoundationOutputs)
	for i := 0; i < len(ids); i += 32 {
		id := *(*types.SiacoinOutputID)(ids[i:])
		if sco, ok := tx.SiacoinOutput(id); ok {
			if sco.Address == addr {
				return // address unchanged; no migration necessary
			}
			sco.Address = addr
			tx.putSiacoinOutput(id, sco)
		}
	}
}

func (tx *dbTx) applyState(next consensus.State) {
	tx.moveFoundationOutputs(next.FoundationPrimaryAddress)
	tx.putBestIndex(next.Index)
	tx.putHeight(next.Index.Height)
}

func (tx *dbTx) revertState(prev consensus.State) {
	tx.moveFoundationOutputs(prev.FoundationPrimaryAddress)
	tx.deleteBestIndex(prev.Index.Height + 1)
	tx.putHeight(prev.Index.Height)
}

func (tx *dbTx) applyDiff(s consensus.State, diff consensus.BlockDiff) {
	for _, td := range diff.Transactions {
		for _, scod := range td.CreatedSiacoinOutputs {
			tx.putSiacoinOutput(scod.ID, scod.Output)
		}
		tx.putDelayedSiacoinOutputs(td.ImmatureSiacoinOutputs)
		for _, sfod := range td.CreatedSiafundOutputs {
			tx.putSiafundOutput(sfod.ID, sfod.Output, sfod.ClaimStart)
		}
		for _, fcd := range td.CreatedFileContracts {
			tx.putFileContract(fcd.ID, fcd.Contract)
		}
		for _, scod := range td.SpentSiacoinOutputs {
			tx.deleteSiacoinOutput(scod.ID)
		}
		for _, sfod := range td.SpentSiafundOutputs {
			tx.deleteSiafundOutput(sfod.ID)
		}
		for _, fcrd := range td.RevisedFileContracts {
			tx.reviseFileContract(fcrd.ID, fcrd.NewContract)
		}
		tx.deleteFileContracts(td.ValidFileContracts)
	}
	tx.putDelayedSiacoinOutputs(diff.ImmatureSiacoinOutputs)
	tx.deleteDelayedSiacoinOutputs(diff.MaturedSiacoinOutputs)
	for _, scod := range diff.MaturedSiacoinOutputs {
		tx.putSiacoinOutput(scod.ID, scod.Output)
	}
	tx.deleteFileContracts(diff.MissedFileContracts)
	if diff.FoundationSubsidy != nil {
		tx.putDelayedSiacoinOutputs([]consensus.DelayedSiacoinOutputDiff{*diff.FoundationSubsidy})
		tx.putFoundationOutput(diff.FoundationSubsidy.ID)
	}
}

func (tx *dbTx) revertDiff(s consensus.State, diff consensus.BlockDiff) {
	if diff.FoundationSubsidy != nil {
		tx.deleteFoundationOutput(diff.FoundationSubsidy.ID)
		tx.deleteDelayedSiacoinOutputs([]consensus.DelayedSiacoinOutputDiff{*diff.FoundationSubsidy})
	}
	for _, fcd := range diff.MissedFileContracts {
		tx.putFileContract(fcd.ID, fcd.Contract)
	}
	for _, scod := range diff.MaturedSiacoinOutputs {
		tx.deleteSiacoinOutput(scod.ID)
	}
	tx.putDelayedSiacoinOutputs(diff.MaturedSiacoinOutputs)
	tx.deleteDelayedSiacoinOutputs(diff.ImmatureSiacoinOutputs)
	for i := len(diff.Transactions) - 1; i >= 0; i-- {
		td := diff.Transactions[i]
		for _, fcd := range td.ValidFileContracts {
			tx.putFileContract(fcd.ID, fcd.Contract)
		}
		for _, fcrd := range td.RevisedFileContracts {
			tx.reviseFileContract(fcrd.ID, fcrd.OldContract)
		}
		for _, sfod := range td.SpentSiafundOutputs {
			tx.putSiafundOutput(sfod.ID, sfod.Output, sfod.ClaimStart)
		}
		for _, scod := range td.SpentSiacoinOutputs {
			tx.putSiacoinOutput(scod.ID, scod.Output)
		}
		tx.deleteFileContracts(td.CreatedFileContracts)
		for _, sfod := range td.CreatedSiafundOutputs {
			tx.deleteSiafundOutput(sfod.ID)
		}
		tx.deleteDelayedSiacoinOutputs(td.ImmatureSiacoinOutputs)
		for _, scod := range td.CreatedSiacoinOutputs {
			tx.deleteSiacoinOutput(scod.ID)
		}
	}
}
