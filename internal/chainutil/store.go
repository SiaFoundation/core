package chainutil

import (
	"bufio"
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
	err = readCheckpoint(bufio.NewReader(fs.entryFile), &c)
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
	d := types.NewBufDecoder(b)

	var h types.BlockHeader
	h.Height = d.ReadUint64()
	h.ParentID = types.BlockID(d.ReadHash())
	d.Read(h.Nonce[:])
	h.Timestamp = time.Unix(int64(d.ReadUint64()), 0)
	h.MinerAddress = d.ReadAddress()
	h.Commitment = d.ReadHash()

	return h, d.Err()
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
		return
	}

	d := types.NewBufDecoder(buf)
	index = d.ReadChainIndex()
	return index, d.Err()
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
		return fs.bestFile.Truncate(0)
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

// Close closes the store.
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

const (
	bestSize  = 40
	indexSize = 48
	metaSize  = 56
)

func bufferedDecoder(r io.Reader, size int) (*types.Decoder, error) {
	buf := make([]byte, size)
	_, err := io.ReadFull(r, buf)
	return types.NewBufDecoder(buf), err
}

func writeMeta(w io.Writer, meta metadata) error {
	e := types.NewEncoder(w)
	e.WriteUint64(uint64(meta.indexSize))
	e.WriteUint64(uint64(meta.entrySize))
	e.WriteChainIndex(meta.tip)
	return e.Flush()
}

func readMeta(r io.Reader) (meta metadata, err error) {
	d, err := bufferedDecoder(r, metaSize)
	meta.indexSize = int64(d.ReadUint64())
	meta.entrySize = int64(d.ReadUint64())
	meta.tip = d.ReadChainIndex()
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
	e := types.NewEncoder(w)
	e.WriteChainIndex(index)
	return e.Flush()
}

func readBest(r io.Reader) (index types.ChainIndex, err error) {
	d, err := bufferedDecoder(r, bestSize)
	index = d.ReadChainIndex()
	return
}

func writeIndex(w io.Writer, index types.ChainIndex, offset int64) error {
	e := types.NewEncoder(w)
	e.WriteChainIndex(index)
	e.WriteUint64(uint64(offset))
	return e.Flush()
}

func readIndex(r io.Reader) (index types.ChainIndex, offset int64, err error) {
	d, err := bufferedDecoder(r, indexSize)
	index = d.ReadChainIndex()
	offset = int64(d.ReadUint64())
	return
}

func writeCheckpoint(w io.Writer, c consensus.Checkpoint) error {
	e := types.NewEncoder(w)

	// write header
	h := c.Block.Header
	e.WriteUint64(h.Height)
	e.WriteHash(types.Hash256(h.ParentID))
	e.Write(h.Nonce[:])
	e.WriteTime(h.Timestamp)
	e.WriteAddress(h.MinerAddress)
	e.WriteHash(h.Commitment)

	// write txns
	e.WritePrefix(len(c.Block.Transactions))
	for _, txn := range c.Block.Transactions {
		e.WriteTransaction(txn)
	}

	// write multiproof
	proof := consensus.ComputeMultiproof(c.Block.Transactions)
	for _, p := range proof {
		e.WriteHash(p)
	}

	// write context
	vc := &c.Context
	e.WriteChainIndex(vc.Index)
	e.WriteUint64(vc.State.NumLeaves)
	for i := range vc.State.Trees {
		if vc.State.HasTreeAtHeight(i) {
			e.WriteHash(vc.State.Trees[i])
		}
	}
	e.WriteUint64(vc.History.NumLeaves)
	for i := range vc.History.Trees {
		if vc.History.HasTreeAtHeight(i) {
			e.WriteHash(vc.History.Trees[i])
		}
	}
	for i := range vc.PrevTimestamps {
		e.WriteTime(vc.PrevTimestamps[i])
	}
	e.WriteWork(vc.TotalWork)
	e.WriteWork(vc.Difficulty)
	e.WriteWork(vc.OakWork)
	e.WriteUint64(uint64(vc.OakTime))
	e.WriteTime(vc.GenesisTimestamp)
	e.WriteCurrency(vc.SiafundPool)
	e.WriteAddress(vc.FoundationAddress)

	return e.Flush()
}

func readCheckpoint(r io.Reader, c *consensus.Checkpoint) error {
	d := types.NewDecoder(io.LimitedReader{
		R: r,
		N: 100e6, // a checkpoint should never be anywhere near this large
	})

	// read header
	h := &c.Block.Header
	h.Height = d.ReadUint64()
	h.ParentID = types.BlockID(d.ReadHash())
	d.Read(h.Nonce[:])
	h.Timestamp = d.ReadTime()
	h.MinerAddress = d.ReadAddress()
	h.Commitment = d.ReadHash()

	// read txns
	c.Block.Transactions = make([]types.Transaction, d.ReadUint64())
	for i := range c.Block.Transactions {
		c.Block.Transactions[i] = d.ReadTransaction()
	}

	// read multiproof
	proofLen := consensus.MultiproofSize(c.Block.Transactions)
	proof := make([]types.Hash256, proofLen)
	for i := range proof {
		proof[i] = d.ReadHash()
	}
	consensus.ExpandMultiproof(c.Block.Transactions, proof)

	// read context
	vc := &c.Context
	vc.Index = d.ReadChainIndex()
	vc.State.NumLeaves = d.ReadUint64()
	for i := range vc.State.Trees {
		if vc.State.HasTreeAtHeight(i) {
			vc.State.Trees[i] = d.ReadHash()
		}
	}
	vc.History.NumLeaves = d.ReadUint64()
	for i := range vc.History.Trees {
		if vc.History.HasTreeAtHeight(i) {
			vc.History.Trees[i] = d.ReadHash()
		}
	}
	for i := range vc.PrevTimestamps {
		vc.PrevTimestamps[i] = d.ReadTime()
	}
	vc.TotalWork = d.ReadWork()
	vc.Difficulty = d.ReadWork()
	vc.OakWork = d.ReadWork()
	vc.OakTime = time.Duration(d.ReadUint64())
	vc.GenesisTimestamp = d.ReadTime()
	vc.SiafundPool = d.ReadCurrency()
	vc.FoundationAddress = d.ReadAddress()

	return d.Err()
}
