package chainutil

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"go.sia.tech/core/chain"
	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

// EphemeralStore implements chain.ManagerStore in memory.
type EphemeralStore struct {
	entries map[types.ChainIndex]consensus.Checkpoint
	best    []types.ChainIndex
}

// AddCheckpoint implements chain.ManagerStore.
func (es *EphemeralStore) AddCheckpoint(c consensus.Checkpoint) error {
	es.entries[c.Context.Index] = c
	return nil
}

// Checkpoint implements chain.ManagerStore.
func (es *EphemeralStore) Checkpoint(index types.ChainIndex) (consensus.Checkpoint, error) {
	e, ok := es.entries[index]
	if !ok {
		return consensus.Checkpoint{}, chain.ErrUnknownIndex
	}
	return e, nil
}

// Header implements chain.ManagerStore.
func (es *EphemeralStore) Header(index types.ChainIndex) (types.BlockHeader, error) {
	c, err := es.Checkpoint(index)
	return c.Block.Header, err
}

// ExtendBest implements chain.ManagerStore.
func (es *EphemeralStore) ExtendBest(index types.ChainIndex) error {
	if _, ok := es.entries[index]; !ok {
		panic("no entry for index")
	}
	es.best = append(es.best, index)
	return nil
}

// RewindBest implements chain.ManagerStore.
func (es *EphemeralStore) RewindBest() error {
	es.best = es.best[:len(es.best)-1]
	return nil
}

// BestIndex implements chain.ManagerStore.
func (es *EphemeralStore) BestIndex(height uint64) (types.ChainIndex, error) {
	baseHeight, tipHeight := es.best[0].Height, es.best[len(es.best)-1].Height
	if !(baseHeight <= height && height <= tipHeight) {
		return types.ChainIndex{}, chain.ErrUnknownIndex
	}
	return es.best[height-baseHeight], nil
}

// Flush implements chain.ManagerStore.
func (es *EphemeralStore) Flush() error { return nil }

// NewEphemeralStore returns an in-memory chain.ManagerStore.
func NewEphemeralStore(c consensus.Checkpoint) *EphemeralStore {
	return &EphemeralStore{
		entries: map[types.ChainIndex]consensus.Checkpoint{c.Context.Index: c},
		best:    []types.ChainIndex{c.Context.Index},
	}
}

type metadata struct {
	indexSize int64
	entrySize int64
	tip       types.ChainIndex
}

// FlatStore implements chain.ManagerStore with persistent files.
type FlatStore struct {
	indexFile *os.File
	entryFile *os.File
	bestFile  *os.File

	meta     metadata
	metapath string

	base    types.ChainIndex
	offsets map[types.ChainIndex]int64
}

// AddCheckpoint implements chain.ManagerStore.
func (fs *FlatStore) AddCheckpoint(c consensus.Checkpoint) error {
	offset, err := fs.entryFile.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	if err := writeCheckpoint(fs.entryFile, c); err != nil {
		return err
	} else if err := writeIndex(fs.indexFile, c.Context.Index, offset); err != nil {
		return err
	}
	stat, err := fs.entryFile.Stat()
	if err != nil {
		return err
	}
	fs.offsets[c.Context.Index] = offset
	fs.meta.entrySize = stat.Size()
	fs.meta.indexSize += indexSize
	return nil
}

// Checkpoint implements chain.ManagerStore.
func (fs *FlatStore) Checkpoint(index types.ChainIndex) (c consensus.Checkpoint, err error) {
	if offset, ok := fs.offsets[index]; !ok {
		return consensus.Checkpoint{}, chain.ErrUnknownIndex
	} else if _, err := fs.entryFile.Seek(offset, io.SeekStart); err != nil {
		return consensus.Checkpoint{}, err
	}
	err = readCheckpoint(fs.entryFile, &c)
	return
}

// Header implements chain.ManagerStore.
func (fs *FlatStore) Header(index types.ChainIndex) (types.BlockHeader, error) {
	b := make([]byte, 8+32+8+8+32+32)
	if offset, ok := fs.offsets[index]; !ok {
		return types.BlockHeader{}, chain.ErrUnknownIndex
	} else if _, err := fs.entryFile.ReadAt(b, offset); err != nil {
		return types.BlockHeader{}, err
	}
	buf := bytes.NewBuffer(b)
	readUint64 := func() uint64 {
		return binary.LittleEndian.Uint64(buf.Next(8))
	}

	var h types.BlockHeader
	h.Height = readUint64()
	buf.Read(h.ParentID[:])
	buf.Read(h.Nonce[:])
	h.Timestamp = time.Unix(int64(readUint64()), 0)
	buf.Read(h.MinerAddress[:])
	buf.Read(h.Commitment[:])

	return h, nil
}

// ExtendBest implements chain.ManagerStore.
func (fs *FlatStore) ExtendBest(index types.ChainIndex) error {
	if err := writeBest(fs.bestFile, index); err != nil {
		return err
	}
	fs.meta.tip = index
	return nil
}

// RewindBest implements chain.ManagerStore.
func (fs *FlatStore) RewindBest() error {
	index, err := fs.BestIndex(fs.meta.tip.Height - 1)
	if err != nil {
		return err
	} else if off, err := fs.bestFile.Seek(-bestSize, io.SeekEnd); err != nil {
		return err
	} else if err := fs.bestFile.Truncate(off); err != nil {
		return err
	}
	fs.meta.tip = index
	return nil
}

// BestIndex implements chain.ManagerStore.
func (fs *FlatStore) BestIndex(height uint64) (index types.ChainIndex, err error) {
	if height < fs.base.Height {
		return types.ChainIndex{}, chain.ErrPruned
	}
	offset := int64(height-fs.base.Height) * bestSize
	buf := make([]byte, bestSize)
	if _, err = fs.bestFile.ReadAt(buf, offset); err == io.EOF {
		err = chain.ErrUnknownIndex
	}
	index.Height = readUint64(buf[:8])
	copy(index.ID[:], buf[8:40])
	return
}

// Flush implements chain.ManagerStore.
func (fs *FlatStore) Flush() error {
	// TODO: also sync parent directory?
	if err := fs.indexFile.Sync(); err != nil {
		return err
	} else if err := fs.entryFile.Sync(); err != nil {
		return err
	} else if err := fs.bestFile.Sync(); err != nil {
		return err
	}

	// atomically update metafile
	f, err := os.OpenFile(fs.metapath+"_tmp", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0660)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := writeMeta(f, fs.meta); err != nil {
		return err
	} else if f.Sync(); err != nil {
		return err
	} else if f.Close(); err != nil {
		return err
	} else if err := os.Rename(fs.metapath+"_tmp", fs.metapath); err != nil {
		return err
	}

	return nil
}

func (fs *FlatStore) recoverBest(tip types.ChainIndex) error {
	// if the store is empty, wipe the bestFile too
	if len(fs.offsets) == 0 {
		if err := fs.bestFile.Truncate(0); err != nil {
			return err
		}
		return nil
	}

	// truncate to multiple of bestSize
	if stat, err := fs.bestFile.Stat(); err != nil {
		return err
	} else if n := stat.Size() / bestSize; n%bestSize != 0 {
		if err := fs.bestFile.Truncate(n * bestSize); err != nil {
			return err
		}
	}

	// initialize base
	base, err := readBest(fs.bestFile)
	if err != nil {
		return err
	}
	fs.base = base

	// recover best chain by reading parents of tip, stopping when the index is
	// also in bestFile
	index := tip
	var path []types.ChainIndex
	for {
		if bestIndex, err := fs.BestIndex(index.Height); !errors.Is(err, chain.ErrUnknownIndex) {
			return err
		} else if bestIndex == index {
			break
		}
		path = append(path, index)
		h, err := fs.Header(index)
		if err != nil {
			return err
		}
		index = h.ParentIndex()
	}
	// truncate and extend
	if err := fs.bestFile.Truncate(int64(index.Height-base.Height) * bestSize); err != nil {
		return err
	}
	for i := len(path) - 1; i >= 0; i-- {
		if err := fs.ExtendBest(path[i]); err != nil {
			return err
		}
	}

	return nil
}

func (fs *FlatStore) Close() error {
	errs := []error{
		fs.Flush(),
		fs.indexFile.Close(),
		fs.entryFile.Close(),
		fs.bestFile.Close(),
	}
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// NewFlatStore returns a FlatStore that stores data in the specified dir.
func NewFlatStore(dir string, c consensus.Checkpoint) (*FlatStore, consensus.Checkpoint, error) {
	indexFile, err := os.OpenFile(filepath.Join(dir, "index.dat"), os.O_CREATE|os.O_RDWR, 0o660)
	if err != nil {
		return nil, consensus.Checkpoint{}, err
	}
	entryFile, err := os.OpenFile(filepath.Join(dir, "entry.dat"), os.O_CREATE|os.O_RDWR, 0o660)
	if err != nil {
		return nil, consensus.Checkpoint{}, err
	}
	bestFile, err := os.OpenFile(filepath.Join(dir, "best.dat"), os.O_CREATE|os.O_RDWR, 0o660)
	if err != nil {
		return nil, consensus.Checkpoint{}, err
	}

	// trim indexFile and entryFile according to metadata
	metapath := filepath.Join(dir, "meta.dat")
	meta, err := readMetaFile(metapath)
	if os.IsNotExist(err) {
		// initial metadata
		meta = metadata{tip: c.Context.Index}
	} else if err != nil {
		return nil, consensus.Checkpoint{}, err
	} else if err := indexFile.Truncate(meta.indexSize); err != nil {
		return nil, consensus.Checkpoint{}, err
	} else if err := entryFile.Truncate(meta.entrySize); err != nil {
		return nil, consensus.Checkpoint{}, err
	}

	// read index entries into map
	offsets := make(map[types.ChainIndex]int64)
	for {
		index, offset, err := readIndex(indexFile)
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, consensus.Checkpoint{}, err
		}
		offsets[index] = offset
	}

	fs := &FlatStore{
		indexFile: indexFile,
		entryFile: entryFile,
		bestFile:  bestFile,

		meta:     meta,
		metapath: metapath,

		base:    c.Context.Index,
		offsets: offsets,
	}

	// recover bestFile, if necessary
	if err := fs.recoverBest(meta.tip); err != nil {
		return nil, consensus.Checkpoint{}, err
	}
	if _, err := fs.bestFile.Seek(0, io.SeekEnd); err != nil {
		return nil, consensus.Checkpoint{}, err
	}

	// if store is empty, write base entry
	if len(fs.offsets) == 0 {
		if err := fs.AddCheckpoint(c); err != nil {
			return nil, consensus.Checkpoint{}, err
		} else if err := fs.ExtendBest(c.Context.Index); err != nil {
			return nil, consensus.Checkpoint{}, err
		}
		return fs, c, nil
	}

	c, err = fs.Checkpoint(meta.tip)
	if err != nil {
		return nil, consensus.Checkpoint{}, err
	}
	return fs, c, nil
}

const bestSize = 40
const indexSize = 48
const metaSize = 56

func writeUint64(buf []byte, u uint64) { binary.LittleEndian.PutUint64(buf, u) }
func readUint64(buf []byte) uint64     { return binary.LittleEndian.Uint64(buf) }

func writeMeta(w io.Writer, meta metadata) error {
	buf := make([]byte, metaSize)
	writeUint64(buf[0:], uint64(meta.indexSize))
	writeUint64(buf[8:], uint64(meta.entrySize))
	writeUint64(buf[16:], meta.tip.Height)
	copy(buf[24:], meta.tip.ID[:])
	_, err := w.Write(buf)
	return err
}

func readMeta(r io.Reader) (meta metadata, err error) {
	buf := make([]byte, metaSize)
	if _, err = io.ReadFull(r, buf); err != nil {
		return
	}
	meta.indexSize = int64(binary.LittleEndian.Uint64(buf[0:]))
	meta.entrySize = int64(binary.LittleEndian.Uint64(buf[8:]))
	meta.tip.Height = binary.LittleEndian.Uint64(buf[16:])
	copy(meta.tip.ID[:], buf[24:])
	return
}

func readMetaFile(path string) (meta metadata, err error) {
	f, err := os.Open(path)
	if err != nil {
		return metadata{}, err
	}
	defer f.Close()
	return readMeta(f)
}

func writeBest(w io.Writer, index types.ChainIndex) error {
	buf := make([]byte, bestSize)
	writeUint64(buf[:8], index.Height)
	copy(buf[8:40], index.ID[:])
	_, err := w.Write(buf)
	return err
}

func readBest(r io.Reader) (index types.ChainIndex, err error) {
	buf := make([]byte, bestSize)
	if _, err = io.ReadFull(r, buf); err != nil {
		return
	}
	index.Height = readUint64(buf[:8])
	copy(index.ID[:], buf[8:40])
	return
}

func writeIndex(w io.Writer, index types.ChainIndex, offset int64) error {
	buf := make([]byte, indexSize)
	writeUint64(buf[:8], index.Height)
	copy(buf[8:40], index.ID[:])
	writeUint64(buf[40:48], uint64(offset))
	_, err := w.Write(buf)
	return err
}

func readIndex(r io.Reader) (index types.ChainIndex, offset int64, err error) {
	buf := make([]byte, indexSize)
	if _, err = io.ReadFull(r, buf); err != nil {
		return
	}
	index.Height = readUint64(buf[:8])
	copy(index.ID[:], buf[8:40])
	offset = int64(readUint64(buf[40:48]))
	return
}

func writeCheckpoint(w io.Writer, c consensus.Checkpoint) error {
	// encoding helpers
	var buf bytes.Buffer
	write := func(p []byte) { buf.Write(p) }
	writeHash := func(h [32]byte) { buf.Write(h[:]) }
	writeUint64 := func(u uint64) {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, u)
		buf.Write(b)
	}
	writeInt := func(i int) { writeUint64(uint64(i)) }
	writeTime := func(t time.Time) { writeUint64(uint64(t.Unix())) }
	writeCurrency := func(c types.Currency) {
		writeUint64(c.Lo)
		writeUint64(c.Hi)
	}
	writeOutputID := func(id types.OutputID) {
		writeHash(id.TransactionID)
		writeUint64(id.Index)
	}

	// write header
	h := c.Block.Header
	writeUint64(h.Height)
	writeHash(h.ParentID)
	write(h.Nonce[:])
	writeTime(h.Timestamp)
	writeHash(h.MinerAddress)
	writeHash(h.Commitment)

	// write txns
	writeInt(len(c.Block.Transactions))
	for _, txn := range c.Block.Transactions {
		writeInt(len(txn.SiacoinInputs))
		for j := range txn.SiacoinInputs {
			in := &txn.SiacoinInputs[j]
			writeOutputID(in.Parent.ID)
			writeUint64(in.Parent.ID.Index)
			writeCurrency(in.Parent.Value)
			writeHash(in.Parent.Address)
			writeUint64(in.Parent.Timelock)
			writeInt(len(in.Parent.MerkleProof))
			writeUint64(in.Parent.LeafIndex)
			writeHash(in.PublicKey)
			write(in.Signature[:])
		}
		writeInt(len(txn.SiacoinOutputs))
		for j := range txn.SiacoinOutputs {
			out := &txn.SiacoinOutputs[j]
			writeCurrency(out.Value)
			writeHash(out.Address)
		}
		writeCurrency(txn.MinerFee)
	}

	// write multiproof
	proof := consensus.ComputeMultiproof(c.Block.Transactions)
	for _, p := range proof {
		writeHash(p)
	}

	// write context
	vc := c.Context
	writeUint64(vc.Index.Height)
	writeHash(vc.Index.ID)
	writeUint64(vc.State.NumLeaves)
	for i := range vc.State.Trees {
		if vc.State.HasTreeAtHeight(i) {
			writeHash(vc.State.Trees[i])
		}
	}
	writeUint64(vc.History.NumLeaves)
	for i := range vc.History.Trees {
		if vc.History.HasTreeAtHeight(i) {
			writeHash(vc.History.Trees[i])
		}
	}
	writeHash(vc.TotalWork.NumHashes)
	writeHash(vc.Difficulty.NumHashes)
	writeTime(vc.LastAdjust)
	for i := range vc.PrevTimestamps {
		writeTime(vc.PrevTimestamps[i])
	}

	_, err := w.Write(buf.Bytes())
	return err
}

func readCheckpoint(r io.Reader, c *consensus.Checkpoint) error {
	// decoding helpers + sticky error
	buf := make([]byte, 8)
	var err error
	read := func(p []byte) {
		if err == nil {
			_, err = io.ReadFull(r, p)
		}
	}
	readHash := func() (h [32]byte) {
		read(h[:])
		return
	}
	readUint64 := func() uint64 {
		read(buf[:8])
		if err != nil {
			// returning 0 means we won't allocate any more slice memory after
			// we encounter an error
			return 0
		}
		return binary.LittleEndian.Uint64(buf[:8])
	}
	readTime := func() time.Time { return time.Unix(int64(readUint64()), 0) }
	readCurrency := func() (c types.Currency) {
		return types.NewCurrency(readUint64(), readUint64())
	}
	readOutputID := func() types.OutputID {
		return types.OutputID{
			TransactionID: readHash(),
			Index:         readUint64(),
		}
	}

	// read header
	h := &c.Block.Header
	h.Height = readUint64()
	h.ParentID = readHash()
	read(h.Nonce[:])
	h.Timestamp = readTime()
	h.MinerAddress = readHash()
	h.Commitment = readHash()

	// read txns
	c.Block.Transactions = make([]types.Transaction, readUint64())
	for i := range c.Block.Transactions {
		txn := &c.Block.Transactions[i]
		txn.SiacoinInputs = make([]types.SiacoinInput, readUint64())
		for j := range txn.SiacoinInputs {
			in := &txn.SiacoinInputs[j]
			in.Parent.ID = readOutputID()
			in.Parent.ID.Index = readUint64()
			in.Parent.Value = readCurrency()
			in.Parent.Address = readHash()
			in.Parent.Timelock = readUint64()
			in.Parent.MerkleProof = make([]types.Hash256, readUint64())
			in.Parent.LeafIndex = readUint64()
			in.PublicKey = readHash()
			read(in.Signature[:])
		}
		txn.SiacoinOutputs = make([]types.Beneficiary, readUint64())
		for j := range txn.SiacoinOutputs {
			out := &txn.SiacoinOutputs[j]
			out.Value = readCurrency()
			out.Address = readHash()
		}
		txn.MinerFee = readCurrency()
	}

	// read multiproof
	proofLen := consensus.MultiproofSize(c.Block.Transactions)
	proof := make([]types.Hash256, proofLen)
	for i := range proof {
		proof[i] = readHash()
	}
	consensus.ExpandMultiproof(c.Block.Transactions, proof)

	// read context
	vc := &c.Context
	vc.Index.Height = readUint64()
	vc.Index.ID = readHash()
	vc.State.NumLeaves = readUint64()
	for i := range vc.State.Trees {
		if vc.State.HasTreeAtHeight(i) {
			vc.State.Trees[i] = readHash()
		}
	}
	vc.History.NumLeaves = readUint64()
	for i := range vc.History.Trees {
		if vc.History.HasTreeAtHeight(i) {
			vc.History.Trees[i] = readHash()
		}
	}
	vc.TotalWork.NumHashes = readHash()
	vc.Difficulty.NumHashes = readHash()
	vc.LastAdjust = readTime()
	for i := range vc.PrevTimestamps {
		vc.PrevTimestamps[i] = readTime()
	}

	return err
}
