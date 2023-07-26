package chain

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
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
	bVersion              = []byte("Version")
	bMainChain            = []byte("MainChain")
	bCheckpoints          = []byte("Checkpoints")
	bFileContractElements = []byte("FileContracts")
	bSiacoinElements      = []byte("SiacoinElements")
	bSiafundElements      = []byte("SiafundElements")
	bTree                 = []byte("Tree")

	keyHeight = []byte("Height")
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

func (db *DBStore) encLeaf(index uint64, height int) []byte {
	// For a given leaf index and height, we want to compute a key corresponding
	// to the tree node at the given height within the leaf's proof path. For
	// example, if height is 3, then we should return the same key for indices
	// 0, 1, 2, and 3 (since all of these leaves share a parent at that height),
	// and a different key for indices 4, 5, 6, and 7.
	//
	// This is easily achieved by masking the least significant height bits of
	// index and prepending the height (to avoid collisions with lower levels).
	// We can assume that the total number of elements is less than 2^32 (and
	// thus the height will be less than 2^8), so the resulting key is 5 bytes.
	//
	// Can we do better? Yes -- we can fit it in 4 bytes, if we assume that the
	// total number of elements is less than 2^31. This gives us 2^31 values for
	// storing leaves, and 2^31 values for storing all the other nodes. We
	// distinguish them by setting the top bit. Going up a level, we see that at
	// most 2^30 values are needed, leaving 2^30 for the remaining levels; we
	// distinguish these by setting the penultimate bit. Each time we ascend a
	// level, we have one fewer bit to work with; but since each level requires
	// half as many nodes as the previous, it balances out and we always have
	// enough space.
	return binary.BigEndian.AppendUint32(nil, bits.RotateLeft32(uint32(index)|((1<<height)-1), -height))
}

func (db *DBStore) putElementProof(leafIndex uint64, proof []types.Hash256) {
	for i, p := range proof {
		db.bucket(bTree).put(db.encLeaf(leafIndex, i), p)
	}
}

func (db *DBStore) getElementProof(leafIndex uint64) (proof []types.Hash256) {
	var p types.Hash256
	for db.bucket(bTree).get(db.encLeaf(leafIndex, len(proof)), &p) {
		proof = append(proof, p)
	}
	return
}

func (db *DBStore) putSiacoinElement(sce types.SiacoinElement) {
	db.putElementProof(sce.LeafIndex, sce.MerkleProof)
	sce.MerkleProof = nil
	db.bucket(bSiacoinElements).put(sce.ID[:], sce)
}

func (db *DBStore) deleteSiacoinElement(id types.SiacoinOutputID) {
	db.bucket(bSiacoinElements).delete(id[:])
}

func (db *DBStore) putFileContract(fce types.FileContractElement) {
	b := db.bucket(bFileContractElements)
	db.putElementProof(fce.LeafIndex, fce.MerkleProof)
	fce.MerkleProof = nil
	b.put(fce.ID[:], fce)

	key := db.encHeight(fce.WindowEnd)
	b.putRaw(key, append(b.getRaw(key), fce.ID[:]...))
}

func (db *DBStore) deleteFileContract(id types.FileContractID, windowEnd uint64) {
	b := db.bucket(bFileContractElements)
	b.delete(id[:])

	key := db.encHeight(windowEnd)
	val := append([]byte(nil), b.getRaw(key)...)
	for i := 0; i < len(val); i += 32 {
		if *(*types.FileContractID)(val[i:]) == id {
			copy(val[i:], val[len(val)-32:])
			val = val[:len(val)-32]
			i -= 32
			b.putRaw(key, val)
			return
		}
	}
	panic("missing file contract expiration")
}

func (db *DBStore) putSiafundElement(sfe types.SiafundElement) {
	db.putElementProof(sfe.LeafIndex, sfe.MerkleProof)
	sfe.MerkleProof = nil
	db.bucket(bSiafundElements).put(sfe.ID[:], sfe)
}

func (db *DBStore) deleteSiafundElement(id types.SiafundOutputID) {
	db.bucket(bSiafundElements).delete(id[:])
}

func (db *DBStore) applyState(next consensus.State) {
	db.putBestIndex(next.Index)
	db.putHeight(next.Index.Height)
}

func (db *DBStore) revertState(prev consensus.State) {
	db.deleteBestIndex(prev.Index.Height + 1)
	db.putHeight(prev.Index.Height)
}

func (db *DBStore) applyDiff(diff consensus.BlockDiff) {
	for _, td := range diff.Transactions {
		for _, sce := range td.CreatedSiacoinElements {
			db.putSiacoinElement(sce)
		}
		for _, sfe := range td.CreatedSiafundElements {
			db.putSiafundElement(sfe)
		}
		for _, fce := range td.CreatedFileContracts {
			db.putFileContract(fce)
		}
		for _, sce := range td.SpentSiacoinElements {
			db.deleteSiacoinElement(types.SiacoinOutputID(sce.ID))
		}
		for _, sfe := range td.SpentSiafundElements {
			db.deleteSiafundElement(types.SiafundOutputID(sfe.ID))
		}
		for _, fcer := range td.RevisedFileContracts {
			db.deleteFileContract(types.FileContractID(fcer.Parent.ID), fcer.Parent.WindowEnd)
			db.putFileContract(fcer.RevisedElement())
		}
		for _, fce := range td.ValidFileContracts {
			db.deleteFileContract(types.FileContractID(fce.ID), fce.WindowEnd)
		}
	}

	for _, td := range diff.V2Transactions {
		for _, sce := range td.CreatedSiacoinElements {
			db.putSiacoinElement(sce)
		}
		for _, sfe := range td.CreatedSiafundElements {
			db.putSiafundElement(sfe)
		}
		for _, sce := range td.SpentSiacoinElements {
			db.deleteSiacoinElement(types.SiacoinOutputID(sce.ID))
		}
		for _, sfe := range td.SpentSiafundElements {
			db.deleteSiafundElement(types.SiafundOutputID(sfe.ID))
		}
	}

	for _, sce := range diff.CreatedSiacoinElements {
		db.putSiacoinElement(sce)
	}
	for _, fce := range diff.MissedFileContracts {
		db.deleteFileContract(types.FileContractID(fce.ID), fce.WindowEnd)
	}
}

func (db *DBStore) revertDiff(diff consensus.BlockDiff) {
	for _, fce := range diff.MissedFileContracts {
		db.putFileContract(fce)
	}
	for _, sce := range diff.CreatedSiacoinElements {
		db.deleteSiacoinElement(types.SiacoinOutputID(sce.ID))
	}
	for i := len(diff.Transactions) - 1; i >= 0; i-- {
		td := diff.Transactions[i]
		for _, fce := range td.ValidFileContracts {
			db.putFileContract(fce)
		}
		for _, fcer := range td.RevisedFileContracts {
			db.deleteFileContract(types.FileContractID(fcer.Parent.ID), fcer.Revision.WindowEnd)
			db.putFileContract(fcer.Parent)
		}
		for _, sfe := range td.SpentSiafundElements {
			db.putSiafundElement(sfe)
		}
		for _, sce := range td.SpentSiacoinElements {
			db.putSiacoinElement(sce)
		}
		for _, fce := range td.CreatedFileContracts {
			db.deleteFileContract(types.FileContractID(fce.ID), fce.WindowEnd)
		}
		for _, sfe := range td.CreatedSiafundElements {
			db.deleteSiafundElement(types.SiafundOutputID(sfe.ID))
		}
		for _, sce := range td.CreatedSiacoinElements {
			db.deleteSiacoinElement(types.SiacoinOutputID(sce.ID))
		}
	}

	for i := len(diff.V2Transactions) - 1; i >= 0; i-- {
		td := diff.V2Transactions[i]
		for _, sfe := range td.SpentSiafundElements {
			db.putSiafundElement(sfe)
		}
		for _, sce := range td.SpentSiacoinElements {
			db.putSiacoinElement(sce)
		}
		for _, sfe := range td.CreatedSiafundElements {
			db.deleteSiafundElement(types.SiafundOutputID(sfe.ID))
		}
		for _, sce := range td.CreatedSiacoinElements {
			db.deleteSiacoinElement(types.SiacoinOutputID(sce.ID))
		}
	}

	// TODO: proofs!!!!
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

// SiacoinElement implements consensus.Store.
func (db *DBStore) SiacoinElement(id types.SiacoinOutputID) (sce types.SiacoinElement, ok bool) {
	ok = db.bucket(bSiacoinElements).get(id[:], &sce)
	sce.MerkleProof = db.getElementProof(sce.LeafIndex)
	return
}

// FileContractElement implements consensus.Store.
func (db *DBStore) FileContractElement(id types.FileContractID) (fce types.FileContractElement, ok bool) {
	ok = db.bucket(bFileContractElements).get(id[:], &fce)
	fce.MerkleProof = db.getElementProof(fce.LeafIndex)
	return
}

// MissedFileContracts implements consensus.Store.
func (db *DBStore) MissedFileContracts(height uint64) (fcids []types.FileContractID) {
	ids := db.bucket(bFileContractElements).getRaw(db.encHeight(height))
	for i := 0; i < len(ids); i += 32 {
		fcids = append(fcids, *(*types.FileContractID)(ids[i:]))
	}
	return
}

// SiafundOutput implements consensus.Store.
func (db *DBStore) SiafundElement(id types.SiafundOutputID) (sfe types.SiafundElement, ok bool) {
	ok = db.bucket(bSiafundElements).get(id[:], &sfe)
	sfe.MerkleProof = db.getElementProof(sfe.LeafIndex)
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
	db.applyDiff(diff)
	committed = mustCommit || db.shouldFlush()
	if committed {
		db.flush()
	}
	return
}

// RevertDiff implements Store.
func (db *DBStore) RevertDiff(s consensus.State, diff consensus.BlockDiff) {
	db.revertDiff(diff)
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
			bFileContractElements,
			bSiacoinElements,
			bSiafundElements,
			bTree,
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
		dbs.applyDiff(diff)
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
