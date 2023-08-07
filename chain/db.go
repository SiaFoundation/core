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
	Bucket(name []byte) DBBucket
	CreateBucket(name []byte) (DBBucket, error)
	Flush() error
	Cancel()
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
	puts    map[string]map[string][]byte
	dels    map[string]map[string]struct{}
}

// Flush implements DB.
func (db *MemDB) Flush() error {
	for bucket, puts := range db.puts {
		if db.buckets[bucket] == nil {
			db.buckets[bucket] = make(map[string][]byte)
		}
		for key, val := range puts {
			db.buckets[bucket][key] = val
		}
		delete(db.puts, bucket)
	}
	for bucket, dels := range db.dels {
		if db.buckets[bucket] == nil {
			db.buckets[bucket] = make(map[string][]byte)
		}
		for key := range dels {
			delete(db.buckets[bucket], key)
		}
		delete(db.dels, bucket)
	}
	return nil
}

// Cancel implements DB.
func (db *MemDB) Cancel() {
	for k := range db.puts {
		delete(db.puts, k)
	}
	for k := range db.dels {
		delete(db.dels, k)
	}
}

func (db *MemDB) get(bucket string, key []byte) []byte {
	if val, ok := db.puts[bucket][string(key)]; ok {
		return val
	} else if _, ok := db.dels[bucket][string(key)]; ok {
		return nil
	}
	return db.buckets[bucket][string(key)]
}

func (db *MemDB) put(bucket string, key, value []byte) error {
	if db.puts[bucket] == nil {
		if db.buckets[bucket] == nil {
			return errors.New("bucket does not exist")
		}
		db.puts[bucket] = make(map[string][]byte)
	}
	db.puts[bucket][string(key)] = value
	delete(db.dels[bucket], string(key))
	return nil
}

func (db *MemDB) delete(bucket string, key []byte) error {
	if db.dels[bucket] == nil {
		if db.buckets[bucket] == nil {
			return errors.New("bucket does not exist")
		}
		db.dels[bucket] = make(map[string]struct{})
	}
	db.dels[bucket][string(key)] = struct{}{}
	delete(db.puts[bucket], string(key))
	return nil
}

// Bucket implements DB.
func (db *MemDB) Bucket(name []byte) DBBucket {
	if db.buckets[string(name)] == nil && db.puts[string(name)] == nil && db.dels[string(name)] == nil {
		return nil
	}
	return memBucket{string(name), db}
}

// CreateBucket implements DB.
func (db *MemDB) CreateBucket(name []byte) (DBBucket, error) {
	if db.buckets[string(name)] != nil {
		return nil, errors.New("bucket already exists")
	}
	db.puts[string(name)] = make(map[string][]byte)
	db.dels[string(name)] = make(map[string]struct{})
	return db.Bucket(name), nil
}

type memBucket struct {
	name string
	db   *MemDB
}

func (b memBucket) Get(key []byte) []byte       { return b.db.get(b.name, key) }
func (b memBucket) Put(key, value []byte) error { return b.db.put(b.name, key, value) }
func (b memBucket) Delete(key []byte) error     { return b.db.delete(b.name, key) }

// NewMemDB returns an in-memory DB for use with DBStore.
func NewMemDB() *MemDB {
	return &MemDB{
		buckets: make(map[string]map[string][]byte),
		puts:    make(map[string]map[string][]byte),
		dels:    make(map[string]map[string]struct{}),
	}
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

// dbBucket is a helper type for implementing Store.
type dbBucket struct {
	b  DBBucket
	db *DBStore
}

func (b *dbBucket) getRaw(key []byte) []byte {
	if b.b == nil {
		return nil
	}
	return b.b.Get(key)
}

func (b *dbBucket) get(key []byte, v types.DecoderFrom) bool {
	val := b.getRaw(key)
	if val == nil {
		return false
	}
	d := types.NewBufDecoder(val)
	v.DecodeFrom(d)
	if d.Err() != nil {
		check(fmt.Errorf("error decoding %T: %w", v, d.Err()))
		return false
	}
	return true
}

func (b *dbBucket) putRaw(key, value []byte) {
	check(b.b.Put(key, value))
	b.db.unflushed += len(value)
}

func (b *dbBucket) put(key []byte, v types.EncoderTo) {
	var buf bytes.Buffer
	b.db.enc.Reset(&buf)
	v.EncodeTo(&b.db.enc)
	b.db.enc.Flush()
	b.putRaw(key, buf.Bytes())
}

func (b *dbBucket) delete(key []byte) {
	check(b.b.Delete(key))
}

var (
	bVersion        = []byte("Version")
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
	db DB
	n  *consensus.Network // for getCheckpoint

	unflushed int
	lastFlush time.Time

	enc types.Encoder
}

func (db *DBStore) bucket(name []byte) *dbBucket {
	return &dbBucket{db.db.Bucket(name), db}
}

func (db *DBStore) encHeight(height uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], height)
	return buf[:]
}

func (db *DBStore) putBestIndex(index types.ChainIndex) {
	db.bucket(bMainChain).put(db.encHeight(index.Height), &index.ID)
}

func (db *DBStore) deleteBestIndex(height uint64) {
	db.bucket(bMainChain).delete(db.encHeight(height))
}

func (db *DBStore) getHeight() (height uint64) {
	if val := db.bucket(bMainChain).getRaw(keyHeight); len(val) == 8 {
		height = binary.BigEndian.Uint64(val)
	}
	return
}

func (db *DBStore) putHeight(height uint64) {
	db.bucket(bMainChain).putRaw(keyHeight, db.encHeight(height))
}

func (db *DBStore) putCheckpoint(c Checkpoint) {
	db.bucket(bCheckpoints).put(c.State.Index.ID[:], c)
}

func (db *DBStore) putSiacoinOutput(id types.SiacoinOutputID, sco types.SiacoinOutput) {
	db.bucket(bSiacoinOutputs).put(id[:], sco)
}

func (db *DBStore) deleteSiacoinOutput(id types.SiacoinOutputID) {
	db.bucket(bSiacoinOutputs).delete(id[:])
}

func (db *DBStore) putFileContract(id types.FileContractID, fc types.FileContract) {
	b := db.bucket(bFileContracts)
	b.put(id[:], fc)

	key := db.encHeight(fc.WindowEnd)
	b.putRaw(key, append(b.getRaw(key), id[:]...))
}

func (db *DBStore) reviseFileContract(id types.FileContractID, fc types.FileContract) {
	db.bucket(bFileContracts).put(id[:], fc)
}

func (db *DBStore) deleteFileContracts(fcds []consensus.FileContractDiff) {
	byHeight := make(map[uint64][]types.FileContractID)
	b := db.bucket(bFileContracts)
	for _, fcd := range fcds {
		var fc types.FileContract
		if !b.get(fcd.ID[:], &fc) {
			check(fmt.Errorf("missing file contract %v", fcd.ID))
		}
		b.delete(fcd.ID[:])
		byHeight[fc.WindowEnd] = append(byHeight[fc.WindowEnd], fcd.ID)
	}

	for height, ids := range byHeight {
		toDelete := make(map[types.FileContractID]struct{})
		for _, id := range ids {
			toDelete[id] = struct{}{}
		}
		key := db.encHeight(height)
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
			check(errors.New("missing expired file contract(s)"))
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

func (db *DBStore) putSiafundOutput(id types.SiafundOutputID, sfo types.SiafundOutput, claimStart types.Currency) {
	db.bucket(bSiafundOutputs).put(id[:], claimSFO{Output: sfo, ClaimStart: claimStart})
}

func (db *DBStore) deleteSiafundOutput(id types.SiafundOutputID) {
	db.bucket(bSiafundOutputs).delete(id[:])
}

func (db *DBStore) putDelayedSiacoinOutputs(dscods []consensus.DelayedSiacoinOutputDiff) {
	if len(dscods) == 0 {
		return
	}
	maturityHeight := dscods[0].MaturityHeight
	b := db.bucket(bSiacoinOutputs)
	key := db.encHeight(maturityHeight)
	var buf bytes.Buffer
	b.db.enc.Reset(&buf)
	for _, dscod := range dscods {
		if dscod.MaturityHeight != maturityHeight {
			check(errors.New("mismatched maturity heights"))
			return
		}
		dscod.EncodeTo(&b.db.enc)
	}
	b.db.enc.Flush()
	b.putRaw(key, append(b.getRaw(key), buf.Bytes()[:]...))
}

func (db *DBStore) deleteDelayedSiacoinOutputs(dscods []consensus.DelayedSiacoinOutputDiff) {
	if len(dscods) == 0 {
		return
	}
	maturityHeight := dscods[0].MaturityHeight
	toDelete := make(map[types.SiacoinOutputID]struct{})
	for _, dscod := range dscods {
		if dscod.MaturityHeight != maturityHeight {
			check(errors.New("mismatched maturity heights"))
			return
		}
		toDelete[dscod.ID] = struct{}{}
	}
	var buf bytes.Buffer
	db.enc.Reset(&buf)
	for _, mdscod := range db.MaturedSiacoinOutputs(maturityHeight) {
		if _, ok := toDelete[mdscod.ID]; !ok {
			mdscod.EncodeTo(&db.enc)
		}
		delete(toDelete, mdscod.ID)
	}
	if len(toDelete) != 0 {
		check(errors.New("missing delayed siacoin output(s)"))
		return
	}
	db.enc.Flush()
	db.bucket(bSiacoinOutputs).putRaw(db.encHeight(maturityHeight), buf.Bytes())
}

func (db *DBStore) putFoundationOutput(id types.SiacoinOutputID) {
	b := db.bucket(bSiacoinOutputs)
	b.putRaw(keyFoundationOutputs, append(b.getRaw(keyFoundationOutputs), id[:]...))
}

func (db *DBStore) deleteFoundationOutput(id types.SiacoinOutputID) {
	b := db.bucket(bSiacoinOutputs)
	ids := append([]byte(nil), b.getRaw(keyFoundationOutputs)...)
	for i := 0; i < len(ids); i += 32 {
		if *(*types.SiacoinOutputID)(ids[i:]) == id {
			copy(ids[i:], ids[len(ids)-32:])
			b.putRaw(keyFoundationOutputs, ids[:len(ids)-32])
			return
		}
	}
	check(fmt.Errorf("missing Foundation output %v", id))
}

func (db *DBStore) moveFoundationOutputs(addr types.Address) {
	ids := db.bucket(bSiacoinOutputs).getRaw(keyFoundationOutputs)
	for i := 0; i < len(ids); i += 32 {
		id := *(*types.SiacoinOutputID)(ids[i:])
		if sco, ok := db.SiacoinOutput(id); ok {
			if sco.Address == addr {
				return // address unchanged; no migration necessary
			}
			sco.Address = addr
			db.putSiacoinOutput(id, sco)
		}
	}
}

func (db *DBStore) applyState(next consensus.State) {
	db.moveFoundationOutputs(next.FoundationPrimaryAddress)
	db.putBestIndex(next.Index)
	db.putHeight(next.Index.Height)
}

func (db *DBStore) revertState(prev consensus.State) {
	db.moveFoundationOutputs(prev.FoundationPrimaryAddress)
	db.deleteBestIndex(prev.Index.Height + 1)
	db.putHeight(prev.Index.Height)
}

func (db *DBStore) applyDiff(s consensus.State, diff consensus.BlockDiff) {
	for _, td := range diff.Transactions {
		for _, scod := range td.CreatedSiacoinOutputs {
			db.putSiacoinOutput(scod.ID, scod.Output)
		}
		db.putDelayedSiacoinOutputs(td.ImmatureSiacoinOutputs)
		for _, sfod := range td.CreatedSiafundOutputs {
			db.putSiafundOutput(sfod.ID, sfod.Output, sfod.ClaimStart)
		}
		for _, fcd := range td.CreatedFileContracts {
			db.putFileContract(fcd.ID, fcd.Contract)
		}
		for _, scod := range td.SpentSiacoinOutputs {
			db.deleteSiacoinOutput(scod.ID)
		}
		for _, sfod := range td.SpentSiafundOutputs {
			db.deleteSiafundOutput(sfod.ID)
		}
		for _, fcrd := range td.RevisedFileContracts {
			db.reviseFileContract(fcrd.ID, fcrd.NewContract)
		}
		db.deleteFileContracts(td.ValidFileContracts)
	}
	db.putDelayedSiacoinOutputs(diff.ImmatureSiacoinOutputs)
	for _, dscod := range diff.ImmatureSiacoinOutputs {
		if dscod.Source == consensus.OutputSourceFoundation {
			db.putFoundationOutput(dscod.ID)
		}
	}
	db.deleteDelayedSiacoinOutputs(diff.MaturedSiacoinOutputs)
	for _, scod := range diff.MaturedSiacoinOutputs {
		db.putSiacoinOutput(scod.ID, scod.Output)
	}
	db.deleteFileContracts(diff.MissedFileContracts)
}

func (db *DBStore) revertDiff(s consensus.State, diff consensus.BlockDiff) {
	for _, fcd := range diff.MissedFileContracts {
		db.putFileContract(fcd.ID, fcd.Contract)
	}
	for _, scod := range diff.MaturedSiacoinOutputs {
		db.deleteSiacoinOutput(scod.ID)
	}
	db.putDelayedSiacoinOutputs(diff.MaturedSiacoinOutputs)
	for _, dscod := range diff.ImmatureSiacoinOutputs {
		if dscod.Source == consensus.OutputSourceFoundation {
			db.deleteFoundationOutput(dscod.ID)
		}
	}
	db.deleteDelayedSiacoinOutputs(diff.ImmatureSiacoinOutputs)
	for i := len(diff.Transactions) - 1; i >= 0; i-- {
		td := diff.Transactions[i]
		for _, fcd := range td.ValidFileContracts {
			db.putFileContract(fcd.ID, fcd.Contract)
		}
		for _, fcrd := range td.RevisedFileContracts {
			db.reviseFileContract(fcrd.ID, fcrd.OldContract)
		}
		for _, sfod := range td.SpentSiafundOutputs {
			db.putSiafundOutput(sfod.ID, sfod.Output, sfod.ClaimStart)
		}
		for _, scod := range td.SpentSiacoinOutputs {
			db.putSiacoinOutput(scod.ID, scod.Output)
		}
		db.deleteFileContracts(td.CreatedFileContracts)
		for _, sfod := range td.CreatedSiafundOutputs {
			db.deleteSiafundOutput(sfod.ID)
		}
		db.deleteDelayedSiacoinOutputs(td.ImmatureSiacoinOutputs)
		for _, scod := range td.CreatedSiacoinOutputs {
			db.deleteSiacoinOutput(scod.ID)
		}
	}
}

// BestIndex implements consensus.Store.
func (db *DBStore) BestIndex(height uint64) (index types.ChainIndex, ok bool) {
	index.Height = height
	ok = db.bucket(bMainChain).get(db.encHeight(height), &index.ID)
	return
}

// AncestorTimestamp implements consensus.Store.
func (db *DBStore) AncestorTimestamp(id types.BlockID, n uint64) time.Time {
	c, _ := db.Checkpoint(id)
	for i := uint64(1); i < n; i++ {
		// if we're on the best path, we can jump to the n'th block directly
		if index, _ := db.BestIndex(c.State.Index.Height); index.ID == id {
			ancestorIndex, _ := db.BestIndex(c.State.Index.Height - (n - i))
			c, _ = db.Checkpoint(ancestorIndex.ID)
			break
		}
		c, _ = db.Checkpoint(c.Block.ParentID)
	}
	return c.Block.Timestamp
}

// SiacoinOutput implements consensus.Store.
func (db *DBStore) SiacoinOutput(id types.SiacoinOutputID) (sco types.SiacoinOutput, ok bool) {
	ok = db.bucket(bSiacoinOutputs).get(id[:], &sco)
	return
}

// FileContract implements consensus.Store.
func (db *DBStore) FileContract(id types.FileContractID) (fc types.FileContract, ok bool) {
	ok = db.bucket(bFileContracts).get(id[:], &fc)
	return
}

// MissedFileContracts implements consensus.Store.
func (db *DBStore) MissedFileContracts(height uint64) (fcids []types.FileContractID) {
	ids := db.bucket(bFileContracts).getRaw(db.encHeight(height))
	for i := 0; i < len(ids); i += 32 {
		fcids = append(fcids, *(*types.FileContractID)(ids[i:]))
	}
	return
}

// SiafundOutput implements consensus.Store.
func (db *DBStore) SiafundOutput(id types.SiafundOutputID) (sfo types.SiafundOutput, claimStart types.Currency, ok bool) {
	var csfo claimSFO
	ok = db.bucket(bSiafundOutputs).get(id[:], &csfo)
	return csfo.Output, csfo.ClaimStart, ok
}

// MaturedSiacoinOutputs implements consensus.Store.
func (db *DBStore) MaturedSiacoinOutputs(height uint64) (dscods []consensus.DelayedSiacoinOutputDiff) {
	dscos := db.bucket(bSiacoinOutputs).getRaw(db.encHeight(height))
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
		check(d.Err())
	}
	return
}

// AddCheckpoint implements Store.
func (db *DBStore) AddCheckpoint(c Checkpoint) {
	db.bucket(bCheckpoints).put(c.State.Index.ID[:], c)
}

// Checkpoint implements Store.
func (db *DBStore) Checkpoint(id types.BlockID) (c Checkpoint, ok bool) {
	ok = db.bucket(bCheckpoints).get(id[:], &c)
	c.State.Network = db.n
	return
}

func (db *DBStore) shouldFlush() bool {
	// NOTE: these values were chosen empirically and should constitute a
	// sensible default; if necessary, we can make them configurable
	const flushSizeThreshold = 2e6
	const flushDurationThreshold = 100 * time.Millisecond
	return db.unflushed >= flushSizeThreshold || time.Since(db.lastFlush) >= flushDurationThreshold
}

func (db *DBStore) flush() {
	if err := db.db.Flush(); err != nil {
		panic(err)
	}
	db.unflushed = 0
	db.lastFlush = time.Now()
}

// ApplyDiff implements Store.
func (db *DBStore) ApplyDiff(s consensus.State, diff consensus.BlockDiff, mustCommit bool) (committed bool) {
	db.applyState(s)
	db.applyDiff(s, diff)
	committed = mustCommit || db.shouldFlush()
	if committed {
		db.flush()
	}
	return
}

// RevertDiff implements Store.
func (db *DBStore) RevertDiff(s consensus.State, diff consensus.BlockDiff) {
	db.revertDiff(s, diff)
	db.revertState(s)
	if db.shouldFlush() {
		db.flush()
	}
}

// Close flushes any uncommitted data to the underlying DB.
func (db *DBStore) Close() error {
	return db.db.Flush()
}

// NewDBStore creates a new DBStore using the provided database. The current
// checkpoint is also returned.
func NewDBStore(db DB, n *consensus.Network, genesisBlock types.Block) (_ *DBStore, _ Checkpoint, err error) {
	// during initialization, we should return an error instead of panicking
	defer func() {
		if r := recover(); r != nil {
			db.Cancel()
			err = fmt.Errorf("panic during database initialization: %v", r)
		}
	}()

	// don't accidentally overwrite a siad database
	if db.Bucket([]byte("ChangeLog")) != nil {
		return nil, Checkpoint{}, errors.New("detected siad database, refusing to proceed")
	}

	dbs := &DBStore{
		db: db,
		n:  n,
	}

	// if the db is empty, initialize it; otherwise, check that the genesis
	// block is correct
	if dbGenesis, ok := dbs.BestIndex(0); !ok {
		for _, bucket := range [][]byte{
			bVersion,
			bMainChain,
			bCheckpoints,
			bFileContracts,
			bSiacoinOutputs,
			bSiafundOutputs,
		} {
			if _, err := db.CreateBucket(bucket); err != nil {
				panic(err)
			}
		}
		dbs.bucket(bVersion).putRaw(bVersion, []byte{1})

		// store genesis checkpoint and apply its effects
		genesisState := n.GenesisState()
		cs := consensus.ApplyState(genesisState, dbs, genesisBlock)
		diff := consensus.ApplyDiff(genesisState, dbs, genesisBlock)
		dbs.putCheckpoint(Checkpoint{genesisBlock, cs, &diff})
		dbs.applyState(cs)
		dbs.applyDiff(cs, diff)
		dbs.flush()
	} else if dbGenesis.ID != genesisBlock.ID() {
		// try to detect network so we can provide a more helpful error message
		_, mainnetGenesis := Mainnet()
		_, zenGenesis := TestnetZen()
		if genesisBlock.ID() == mainnetGenesis.ID() && dbGenesis.ID == zenGenesis.ID() {
			return nil, Checkpoint{}, errors.New("cannot use Zen testnet database on mainnet")
		} else if genesisBlock.ID() == zenGenesis.ID() && dbGenesis.ID == mainnetGenesis.ID() {
			return nil, Checkpoint{}, errors.New("cannot use mainnet database on Zen testnet")
		} else {
			return nil, Checkpoint{}, errors.New("database previously initialized with different genesis block")
		}
	}

	// load current checkpoint
	index, _ := dbs.BestIndex(dbs.getHeight())
	c, _ := dbs.Checkpoint(index.ID)
	return dbs, c, err
}
