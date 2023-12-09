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

type supplementedBlock struct {
	Block      types.Block
	Supplement *consensus.V1BlockSupplement
}

func (sb supplementedBlock) EncodeTo(e *types.Encoder) {
	e.WriteUint8(2)
	(types.V2Block)(sb.Block).EncodeTo(e)
	e.WriteBool(sb.Supplement != nil)
	if sb.Supplement != nil {
		sb.Supplement.EncodeTo(e)
	}
}

func (sb *supplementedBlock) DecodeFrom(d *types.Decoder) {
	if v := d.ReadUint8(); v != 2 {
		d.SetErr(fmt.Errorf("incompatible version (%d)", v))
	}
	(*types.V2Block)(&sb.Block).DecodeFrom(d)
	if d.ReadBool() {
		sb.Supplement = new(consensus.V1BlockSupplement)
		sb.Supplement.DecodeFrom(d)
	}
}

type versionedState struct {
	State consensus.State
}

func (vs versionedState) EncodeTo(e *types.Encoder) {
	e.WriteUint8(2)
	vs.State.EncodeTo(e)
}

func (vs *versionedState) DecodeFrom(d *types.Decoder) {
	if v := d.ReadUint8(); v != 2 {
		d.SetErr(fmt.Errorf("incompatible version (%d)", v))
	}
	vs.State.DecodeFrom(d)
}

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
	bStates               = []byte("States")
	bBlocks               = []byte("Blocks")
	bFileContractElements = []byte("FileContracts")
	bSiacoinElements      = []byte("SiacoinElements")
	bSiafundElements      = []byte("SiafundElements")
	bTree                 = []byte("Tree")

	keyHeight = []byte("Height")
)

// DBStore implements Store using a key-value database.
type DBStore struct {
	db  DB
	n   *consensus.Network // for getState
	enc types.Encoder

	unflushed int
	lastFlush time.Time
}

func (db *DBStore) bucket(name []byte) *dbBucket {
	return &dbBucket{db.db.Bucket(name), db}
}

func (db *DBStore) encHeight(height uint64) []byte {
	var buf [8]byte
	return binary.BigEndian.AppendUint64(buf[:0], height)
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

func (db *DBStore) getState(id types.BlockID) (consensus.State, bool) {
	var vs versionedState
	ok := db.bucket(bStates).get(id[:], &vs)
	vs.State.Network = db.n
	return vs.State, ok
}

func (db *DBStore) putState(cs consensus.State) {
	db.bucket(bStates).put(cs.Index.ID[:], versionedState{cs})
}

func (db *DBStore) getBlock(id types.BlockID) (b types.Block, bs *consensus.V1BlockSupplement, _ bool) {
	var sb supplementedBlock
	ok := db.bucket(bBlocks).get(id[:], &sb)
	return sb.Block, sb.Supplement, ok
}

func (db *DBStore) putBlock(b types.Block, bs *consensus.V1BlockSupplement) {
	id := b.ID()
	db.bucket(bBlocks).put(id[:], supplementedBlock{b, bs})
}

func (db *DBStore) treeKey(row, col uint64) []byte {
	// If we assume that the total number of elements is less than 2^32, we can
	// pack row and col into one uint32 key. We do this by setting the top 'row'
	// bits of 'col' to 1. Since each successive row has half as many columns,
	// we never have to worry about clobbering any bits of 'col'.
	var buf [4]byte
	return binary.BigEndian.AppendUint32(buf[:0], uint32(((1<<row)-1)<<(32-row)|col))
}

func (db *DBStore) getElementProof(leafIndex, numLeaves uint64) (proof []types.Hash256) {
	// The size of the proof is the mergeHeight of leafIndex and numLeaves-1. To
	// see why, imagine a tree large enough to contain both leafIndex and
	// numLeaves-1 within the same subtree; the height at which the paths to
	// those leaves diverge must be the size of the subtree containing leafIndex
	// in the actual tree.
	proof = make([]types.Hash256, bits.Len64(leafIndex^(numLeaves-1))-1)
	for i := range proof {
		row, col := uint64(i), (leafIndex>>i)^1
		if !db.bucket(bTree).get(db.treeKey(row, col), &proof[i]) {
			panic(fmt.Sprintf("missing proof element %v for leaf %v", i, leafIndex))
		}
	}
	return
}

func (db *DBStore) getSiacoinElement(id types.SiacoinOutputID, numLeaves uint64) (sce types.SiacoinElement, ok bool) {
	ok = db.bucket(bSiacoinElements).get(id[:], &sce)
	sce.MerkleProof = db.getElementProof(sce.LeafIndex, numLeaves)
	return
}

func (db *DBStore) putSiacoinElement(sce types.SiacoinElement) {
	sce.MerkleProof = nil
	db.bucket(bSiacoinElements).put(sce.ID[:], sce)
}

func (db *DBStore) deleteSiacoinElement(id types.SiacoinOutputID) {
	db.bucket(bSiacoinElements).delete(id[:])
}

func (db *DBStore) getSiafundElement(id types.SiafundOutputID, numLeaves uint64) (sfe types.SiafundElement, ok bool) {
	ok = db.bucket(bSiafundElements).get(id[:], &sfe)
	sfe.MerkleProof = db.getElementProof(sfe.LeafIndex, numLeaves)
	return
}

func (db *DBStore) putSiafundElement(sfe types.SiafundElement) {
	sfe.MerkleProof = nil
	db.bucket(bSiafundElements).put(sfe.ID[:], sfe)
}

func (db *DBStore) deleteSiafundElement(id types.SiafundOutputID) {
	db.bucket(bSiafundElements).delete(id[:])
}

func (db *DBStore) getFileContractElement(id types.FileContractID, numLeaves uint64) (fce types.FileContractElement, ok bool) {
	ok = db.bucket(bFileContractElements).get(id[:], &fce)
	fce.MerkleProof = db.getElementProof(fce.LeafIndex, numLeaves)
	return
}

func (db *DBStore) putFileContractElement(fce types.FileContractElement) {
	fce.MerkleProof = nil
	db.bucket(bFileContractElements).put(fce.ID[:], fce)
}

func (db *DBStore) deleteFileContractElement(id types.FileContractID) {
	db.bucket(bFileContractElements).delete(id[:])
}

func (db *DBStore) putFileContractExpiration(id types.FileContractID, windowEnd uint64) {
	b := db.bucket(bFileContractElements)
	key := db.encHeight(windowEnd)
	b.putRaw(key, append(b.getRaw(key), id[:]...))
}

func (db *DBStore) deleteFileContractExpiration(id types.FileContractID, windowEnd uint64) {
	b := db.bucket(bFileContractElements)
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

func (db *DBStore) applyState(next consensus.State) {
	db.putBestIndex(next.Index)
	db.putHeight(next.Index.Height)
}

func (db *DBStore) revertState(prev consensus.State) {
	db.deleteBestIndex(prev.Index.Height + 1)
	db.putHeight(prev.Index.Height)
}

func (db *DBStore) applyElements(cau consensus.ApplyUpdate) {
	cau.ForEachTreeNode(func(row, col uint64, h types.Hash256) {
		db.bucket(bTree).put(db.treeKey(row, col), h)
	})

	cau.ForEachSiacoinElement(func(sce types.SiacoinElement, spent bool) {
		if sce.LeafIndex == types.EphemeralLeafIndex {
			return
		} else if spent {
			db.deleteSiacoinElement(types.SiacoinOutputID(sce.ID))
		} else {
			db.putSiacoinElement(sce)
		}
	})
	cau.ForEachSiafundElement(func(sfe types.SiafundElement, spent bool) {
		if sfe.LeafIndex == types.EphemeralLeafIndex {
			return
		} else if spent {
			db.deleteSiafundElement(types.SiafundOutputID(sfe.ID))
		} else {
			db.putSiafundElement(sfe)
		}
	})
	cau.ForEachFileContractElement(func(fce types.FileContractElement, rev *types.FileContractElement, resolved, valid bool) {
		if resolved {
			db.deleteFileContractElement(types.FileContractID(fce.ID))
			db.deleteFileContractExpiration(types.FileContractID(fce.ID), fce.FileContract.WindowEnd)
		} else if rev != nil {
			db.putFileContractElement(*rev)
			if rev.FileContract.WindowEnd != fce.FileContract.WindowEnd {
				db.deleteFileContractExpiration(types.FileContractID(fce.ID), fce.FileContract.WindowEnd)
				db.putFileContractExpiration(types.FileContractID(fce.ID), rev.FileContract.WindowEnd)
			}
		} else {
			db.putFileContractElement(fce)
			db.putFileContractExpiration(types.FileContractID(fce.ID), fce.FileContract.WindowEnd)
		}
	})
}

func (db *DBStore) revertElements(cru consensus.RevertUpdate) {
	cru.ForEachFileContractElement(func(fce types.FileContractElement, rev *types.FileContractElement, resolved, valid bool) {
		if resolved {
			// contract no longer resolved; restore it
			db.putFileContractElement(fce)
			db.putFileContractExpiration(types.FileContractID(fce.ID), fce.FileContract.WindowEnd)
		} else if rev != nil {
			// contract no longer revised; restore prior revision
			db.putFileContractElement(fce)
			if rev.FileContract.WindowEnd != fce.FileContract.WindowEnd {
				db.deleteFileContractExpiration(types.FileContractID(fce.ID), fce.FileContract.WindowEnd)
				db.putFileContractExpiration(types.FileContractID(fce.ID), rev.FileContract.WindowEnd)
			}
		} else {
			// contract no longer exists; delete it
			db.deleteFileContractElement(types.FileContractID(fce.ID))
			db.deleteFileContractExpiration(types.FileContractID(fce.ID), fce.FileContract.WindowEnd)
		}
	})
	cru.ForEachSiafundElement(func(sfe types.SiafundElement, spent bool) {
		if sfe.LeafIndex == types.EphemeralLeafIndex {
			return
		} else if spent {
			// output no longer spent; restore it
			db.putSiafundElement(sfe)
		} else {
			// output no longer exists; delete it
			db.deleteSiafundElement(types.SiafundOutputID(sfe.ID))
		}
	})
	cru.ForEachSiacoinElement(func(sce types.SiacoinElement, spent bool) {
		if sce.LeafIndex == types.EphemeralLeafIndex {
			return
		} else if spent {
			// output no longer spent; restore it
			db.putSiacoinElement(sce)
		} else {
			// output no longer exists; delete it
			db.deleteSiacoinElement(types.SiacoinOutputID(sce.ID))
		}
	})

	cru.ForEachTreeNode(func(row, col uint64, h types.Hash256) {
		db.bucket(bTree).put(db.treeKey(row, col), h)
	})

	// NOTE: Although the element tree has shrunk, we do not need to explicitly
	// delete any nodes; getElementProof always stops at the correct height for
	// the given tree size, so the no-longer-valid nodes are simply never
	// accessed. (They will continue to occupy storage, but this storage will
	// inevitably be overwritten by future nodes, so there is little reason to
	// reclaim it immediately.)
}

// BestIndex implements Store.
func (db *DBStore) BestIndex(height uint64) (index types.ChainIndex, ok bool) {
	index.Height = height
	ok = db.bucket(bMainChain).get(db.encHeight(height), &index.ID)
	return
}

// SupplementTipTransaction implements Store.
func (db *DBStore) SupplementTipTransaction(txn types.Transaction) (ts consensus.V1TransactionSupplement) {
	// get tip state, for proof-trimming
	index, _ := db.BestIndex(db.getHeight())
	cs, _ := db.State(index.ID)
	numLeaves := cs.Elements.NumLeaves

	for _, sci := range txn.SiacoinInputs {
		if sce, ok := db.getSiacoinElement(sci.ParentID, numLeaves); ok {
			ts.SiacoinInputs = append(ts.SiacoinInputs, sce)
		}
	}
	for _, sfi := range txn.SiafundInputs {
		if sfe, ok := db.getSiafundElement(sfi.ParentID, numLeaves); ok {
			ts.SiafundInputs = append(ts.SiafundInputs, sfe)
		}
	}
	for _, fcr := range txn.FileContractRevisions {
		if fce, ok := db.getFileContractElement(fcr.ParentID, numLeaves); ok {
			ts.RevisedFileContracts = append(ts.RevisedFileContracts, fce)
		}
	}
	for _, sp := range txn.StorageProofs {
		if fce, ok := db.getFileContractElement(sp.ParentID, numLeaves); ok {
			if windowIndex, ok := db.BestIndex(fce.FileContract.WindowStart - 1); ok {
				ts.ValidFileContracts = append(ts.ValidFileContracts, fce)
				ts.StorageProofBlockIDs = append(ts.StorageProofBlockIDs, windowIndex.ID)
			}
		}
	}
	return
}

// SupplementTipBlock implements Store.
func (db *DBStore) SupplementTipBlock(b types.Block) (bs consensus.V1BlockSupplement) {
	// get tip state, for proof-trimming
	index, _ := db.BestIndex(db.getHeight())
	cs, _ := db.State(index.ID)
	numLeaves := cs.Elements.NumLeaves

	bs = consensus.V1BlockSupplement{
		Transactions: make([]consensus.V1TransactionSupplement, len(b.Transactions)),
	}
	for i, txn := range b.Transactions {
		bs.Transactions[i] = db.SupplementTipTransaction(txn)
	}
	ids := db.bucket(bFileContractElements).getRaw(db.encHeight(db.getHeight() + 1))
	for i := 0; i < len(ids); i += 32 {
		fce, ok := db.getFileContractElement(*(*types.FileContractID)(ids[i:]), numLeaves)
		if !ok {
			panic("missing FileContractElement")
		}
		bs.ExpiringFileContracts = append(bs.ExpiringFileContracts, fce)
	}
	return bs
}

// State implements Store.
func (db *DBStore) State(id types.BlockID) (consensus.State, bool) {
	return db.getState(id)
}

// AddState implements Store.
func (db *DBStore) AddState(cs consensus.State) {
	db.putState(cs)
}

// Block implements Store.
func (db *DBStore) Block(id types.BlockID) (types.Block, *consensus.V1BlockSupplement, bool) {
	return db.getBlock(id)
}

// AddBlock implements Store.
func (db *DBStore) AddBlock(b types.Block, bs *consensus.V1BlockSupplement) {
	db.putBlock(b, bs)
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

// ApplyBlock implements Store.
func (db *DBStore) ApplyBlock(s consensus.State, cau consensus.ApplyUpdate, mustCommit bool) (committed bool) {
	db.applyState(s)
	db.applyElements(cau)
	committed = mustCommit || db.shouldFlush()
	if committed {
		db.flush()
	}
	return
}

// RevertBlock implements Store.
func (db *DBStore) RevertBlock(s consensus.State, cru consensus.RevertUpdate) {
	db.revertElements(cru)
	db.revertState(s)
	if db.shouldFlush() {
		db.flush()
	}
}

// Close flushes any uncommitted data to the underlying DB.
func (db *DBStore) Close() error {
	return db.db.Flush()
}

// NewDBStore creates a new DBStore using the provided database. The tip state
// is also returned.
func NewDBStore(db DB, n *consensus.Network, genesisBlock types.Block) (_ *DBStore, _ consensus.State, err error) {
	// during initialization, we should return an error instead of panicking
	defer func() {
		if r := recover(); r != nil {
			db.Cancel()
			err = fmt.Errorf("panic during database initialization: %v", r)
		}
	}()

	// don't accidentally overwrite a siad database
	if db.Bucket([]byte("ChangeLog")) != nil {
		return nil, consensus.State{}, errors.New("detected siad database, refusing to proceed")
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
			bStates,
			bBlocks,
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

		// store genesis state and apply genesis block to it
		genesisState := n.GenesisState()
		dbs.putState(genesisState)
		bs := consensus.V1BlockSupplement{Transactions: make([]consensus.V1TransactionSupplement, len(genesisBlock.Transactions))}
		cs, cau := consensus.ApplyBlock(genesisState, genesisBlock, bs, time.Time{})
		dbs.putBlock(genesisBlock, &bs)
		dbs.putState(cs)
		dbs.ApplyBlock(cs, cau, true)
	} else if dbGenesis.ID != genesisBlock.ID() {
		// try to detect network so we can provide a more helpful error message
		_, mainnetGenesis := Mainnet()
		_, zenGenesis := TestnetZen()
		if genesisBlock.ID() == mainnetGenesis.ID() && dbGenesis.ID == zenGenesis.ID() {
			return nil, consensus.State{}, errors.New("cannot use Zen testnet database on mainnet")
		} else if genesisBlock.ID() == zenGenesis.ID() && dbGenesis.ID == mainnetGenesis.ID() {
			return nil, consensus.State{}, errors.New("cannot use mainnet database on Zen testnet")
		} else {
			return nil, consensus.State{}, errors.New("database previously initialized with different genesis block")
		}
	}

	// load tip state
	index, _ := dbs.BestIndex(dbs.getHeight())
	cs, _ := dbs.State(index.ID)
	return dbs, cs, err
}
