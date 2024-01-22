package gateway

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/types"
)

func withV1Encoder(w io.Writer, fn func(*types.Encoder)) error {
	var buf bytes.Buffer
	e := types.NewEncoder(&buf)
	e.WritePrefix(0) // placeholder
	fn(e)
	e.Flush()
	b := buf.Bytes()
	binary.LittleEndian.PutUint64(b, uint64(buf.Len()-8))
	_, err := w.Write(b)
	return err
}

func withV1Decoder(r io.Reader, maxLen int, fn func(*types.Decoder)) error {
	d := types.NewDecoder(io.LimitedReader{R: r, N: int64(8 + maxLen)})
	d.ReadPrefix() // ignored
	fn(d)
	return d.Err()
}

func withV2Encoder(w io.Writer, fn func(*types.Encoder)) error {
	e := types.NewEncoder(w)
	fn(e)
	return e.Flush()
}

func withV2Decoder(r io.Reader, maxLen int, fn func(*types.Decoder)) error {
	d := types.NewDecoder(io.LimitedReader{R: r, N: int64(maxLen)})
	fn(d)
	return d.Err()
}

func (h *Header) encodeTo(e *types.Encoder) {
	h.GenesisID.EncodeTo(e)
	e.Write(h.UniqueID[:])
	e.WriteString(h.NetAddress)
}

func (h *Header) decodeFrom(d *types.Decoder) {
	h.GenesisID.DecodeFrom(d)
	d.Read(h.UniqueID[:])
	h.NetAddress = d.ReadString()
}

func (h *BlockHeader) encodeTo(e *types.Encoder) {
	h.ParentID.EncodeTo(e)
	e.WriteUint64(h.Nonce)
	e.WriteTime(h.Timestamp)
	h.MerkleRoot.EncodeTo(e)
}

func (h *BlockHeader) decodeFrom(d *types.Decoder) {
	h.ParentID.DecodeFrom(d)
	h.Nonce = d.ReadUint64()
	h.Timestamp = d.ReadTime()
	h.MerkleRoot.DecodeFrom(d)
}

func (h *V2BlockHeader) encodeTo(e *types.Encoder) {
	h.Parent.EncodeTo(e)
	e.WriteUint64(h.Nonce)
	e.WriteTime(h.Timestamp)
	h.TransactionsRoot.EncodeTo(e)
	h.MinerAddress.EncodeTo(e)
}

func (h *V2BlockHeader) decodeFrom(d *types.Decoder) {
	h.Parent.DecodeFrom(d)
	h.Nonce = d.ReadUint64()
	h.Timestamp = d.ReadTime()
	h.TransactionsRoot.DecodeFrom(d)
	h.MinerAddress.DecodeFrom(d)
}

func (ob *V2BlockOutline) encodeTo(e *types.Encoder) {
	e.WriteUint64(ob.Height)
	ob.ParentID.EncodeTo(e)
	e.WriteUint64(ob.Nonce)
	e.WriteTime(ob.Timestamp)
	ob.MinerAddress.EncodeTo(e)

	var txns []types.Transaction
	var v2txns []types.V2Transaction
	var hashes []types.Hash256
	var kinds []uint8
	for _, ot := range ob.Transactions {
		switch {
		case ot.Transaction != nil:
			txns = append(txns, *ot.Transaction)
			kinds = append(kinds, 0)
		case ot.V2Transaction != nil:
			v2txns = append(v2txns, *ot.V2Transaction)
			kinds = append(kinds, 1)
		default:
			hashes = append(hashes, ot.Hash)
			kinds = append(kinds, 2)
		}
	}
	e.WritePrefix(len(txns))
	for i := range txns {
		txns[i].EncodeTo(e)
	}
	types.V2TransactionsMultiproof(v2txns).EncodeTo(e)
	e.WritePrefix(len(hashes))
	for i := range hashes {
		hashes[i].EncodeTo(e)
	}
	for i := range kinds {
		e.WriteUint8(kinds[i])
	}
}

func (ob *V2BlockOutline) decodeFrom(d *types.Decoder) {
	ob.Height = d.ReadUint64()
	ob.ParentID.DecodeFrom(d)
	ob.Nonce = d.ReadUint64()
	ob.Timestamp = d.ReadTime()
	ob.MinerAddress.DecodeFrom(d)

	txns := make([]types.Transaction, d.ReadPrefix())
	for i := range txns {
		txns[i].DecodeFrom(d)
	}
	var v2txns types.V2TransactionsMultiproof
	v2txns.DecodeFrom(d)
	hashes := make([]types.Hash256, d.ReadPrefix())
	for i := range hashes {
		hashes[i].DecodeFrom(d)
	}
	kinds := make([]uint8, len(txns)+len(v2txns)+len(hashes))
	var counts [3]int
	for i := range kinds {
		kinds[i] = d.ReadUint8()
		if kinds[i] > 2 {
			d.SetErr(fmt.Errorf("invalid outline transaction type (%d)", kinds[i]))
			return
		}
		counts[kinds[i]]++
	}
	if counts[0] != len(txns) || counts[1] != len(v2txns) || counts[2] != len(hashes) {
		d.SetErr(fmt.Errorf("outline kinds (%v %v %v) do not match received kinds (%v %v %v)", counts[0], counts[1], counts[2], len(txns), len(v2txns), len(hashes)))
		return
	} else if d.Err() != nil {
		return // FullHash chokes on invalid input
	}
	ob.Transactions = make([]OutlineTransaction, len(kinds))
	for i := range ob.Transactions {
		ot := &ob.Transactions[i]
		switch kinds[i] {
		case 0:
			ot.Transaction, txns = &txns[0], txns[1:]
			ot.Hash = ot.Transaction.FullHash()
		case 1:
			ot.V2Transaction, v2txns = &v2txns[0], v2txns[1:]
			ot.Hash = ot.V2Transaction.FullHash()
		case 2:
			ot.Hash, hashes = hashes[0], hashes[1:]
		}
	}
}

// An Object can be sent or received via RPC.
type Object interface {
	encodeRequest(e *types.Encoder)
	decodeRequest(d *types.Decoder)
	maxRequestLen() int
	encodeResponse(e *types.Encoder)
	decodeResponse(d *types.Decoder)
	maxResponseLen() int
}

type emptyRequest struct{}

func (emptyRequest) encodeRequest(*types.Encoder) {}
func (emptyRequest) decodeRequest(*types.Decoder) {}
func (emptyRequest) maxRequestLen() int           { return 0 }

type emptyResponse struct{}

func (emptyResponse) encodeResponse(*types.Encoder) {}
func (emptyResponse) decodeResponse(*types.Decoder) {}
func (emptyResponse) maxResponseLen() int           { return 0 }

// RPCShareNodes requests a list of potential peers.
type RPCShareNodes struct {
	emptyRequest
	Peers []string
}

func (r *RPCShareNodes) encodeResponse(e *types.Encoder) {
	e.WritePrefix(len(r.Peers))
	for i := range r.Peers {
		e.WriteString(r.Peers[i])
	}
}
func (r *RPCShareNodes) decodeResponse(d *types.Decoder) {
	r.Peers = make([]string, d.ReadPrefix())
	for i := range r.Peers {
		r.Peers[i] = d.ReadString()
	}
}
func (r *RPCShareNodes) maxResponseLen() int { return 100 * 128 }

// RPCDiscoverIP requests the caller's externally-visible IP address.
type RPCDiscoverIP struct {
	emptyRequest
	IP string
}

func (r *RPCDiscoverIP) encodeResponse(e *types.Encoder) { e.WriteString(r.IP) }
func (r *RPCDiscoverIP) decodeResponse(d *types.Decoder) { r.IP = d.ReadString() }
func (r *RPCDiscoverIP) maxResponseLen() int             { return 128 }

// RPCSendBlocks requests a set of blocks.
type RPCSendBlocks struct {
	History [32]types.BlockID
	Blocks  []types.Block
}

func (r *RPCSendBlocks) encodeRequest(e *types.Encoder) {
	for i := range r.History {
		r.History[i].EncodeTo(e)
	}
}
func (r *RPCSendBlocks) decodeRequest(d *types.Decoder) {
	for i := range r.History {
		r.History[i].DecodeFrom(d)
	}
}
func (r *RPCSendBlocks) maxRequestLen() int { return 32 * 32 }

func (r *RPCSendBlocks) encodeResponse(e *types.Encoder) {
	e.WritePrefix(len(r.Blocks))
	for i := range r.Blocks {
		types.V1Block(r.Blocks[i]).EncodeTo(e)
	}
}
func (r *RPCSendBlocks) decodeResponse(d *types.Decoder) {
	r.Blocks = make([]types.Block, d.ReadPrefix())
	for i := range r.Blocks {
		(*types.V1Block)(&r.Blocks[i]).DecodeFrom(d)
	}
}
func (r *RPCSendBlocks) maxResponseLen() int { return 10 * 5e6 }

// RPCSendBlocksMoreAvailable indicates whether more blocks are available.
type RPCSendBlocksMoreAvailable struct {
	emptyRequest
	MoreAvailable bool
}

func (r *RPCSendBlocksMoreAvailable) encodeResponse(e *types.Encoder) {
	e.WriteBool(r.MoreAvailable)
}
func (r *RPCSendBlocksMoreAvailable) decodeResponse(d *types.Decoder) {
	r.MoreAvailable = d.ReadBool()
}
func (r *RPCSendBlocksMoreAvailable) maxResponseLen() int { return 1 }

// RPCSendBlk requests a single block.
type RPCSendBlk struct {
	ID    types.BlockID
	Block types.Block
}

func (r *RPCSendBlk) encodeRequest(e *types.Encoder)  { r.ID.EncodeTo(e) }
func (r *RPCSendBlk) decodeRequest(d *types.Decoder)  { r.ID.DecodeFrom(d) }
func (r *RPCSendBlk) maxRequestLen() int              { return 32 }
func (r *RPCSendBlk) encodeResponse(e *types.Encoder) { (types.V1Block)(r.Block).EncodeTo(e) }
func (r *RPCSendBlk) decodeResponse(d *types.Decoder) { (*types.V1Block)(&r.Block).DecodeFrom(d) }
func (r *RPCSendBlk) maxResponseLen() int             { return 5e6 }

// RPCRelayHeader relays a header.
type RPCRelayHeader struct {
	Header BlockHeader
	emptyResponse
}

func (r *RPCRelayHeader) encodeRequest(e *types.Encoder) { r.Header.encodeTo(e) }
func (r *RPCRelayHeader) decodeRequest(d *types.Decoder) { r.Header.decodeFrom(d) }
func (r *RPCRelayHeader) maxRequestLen() int             { return 32 + 8 + 8 + 32 }

// RPCRelayTransactionSet relays a transaction set.
type RPCRelayTransactionSet struct {
	Transactions []types.Transaction
	emptyResponse
}

func (r *RPCRelayTransactionSet) encodeRequest(e *types.Encoder) {
	e.WritePrefix(len(r.Transactions))
	for i := range r.Transactions {
		r.Transactions[i].EncodeTo(e)
	}
}
func (r *RPCRelayTransactionSet) decodeRequest(d *types.Decoder) {
	r.Transactions = make([]types.Transaction, d.ReadPrefix())
	for i := range r.Transactions {
		r.Transactions[i].DecodeFrom(d)
	}
}
func (r *RPCRelayTransactionSet) maxRequestLen() int { return 5e6 }

// RPCSendV2Blocks requests a set of blocks.
type RPCSendV2Blocks struct {
	History   []types.BlockID
	Max       uint64
	Blocks    []types.Block
	Remaining uint64
}

func (r *RPCSendV2Blocks) encodeRequest(e *types.Encoder) {
	e.WritePrefix(len(r.History))
	for i := range r.History {
		r.History[i].EncodeTo(e)
	}
	e.WriteUint64(r.Max)
}
func (r *RPCSendV2Blocks) decodeRequest(d *types.Decoder) {
	r.History = make([]types.BlockID, d.ReadPrefix())
	for i := range r.History {
		r.History[i].DecodeFrom(d)
	}
	r.Max = d.ReadUint64()
}
func (r *RPCSendV2Blocks) maxRequestLen() int { return 8 + 32*32 + 8 }

func (r *RPCSendV2Blocks) encodeResponse(e *types.Encoder) {
	e.WritePrefix(len(r.Blocks))
	for i := range r.Blocks {
		types.V2Block(r.Blocks[i]).EncodeTo(e)
	}
	e.WriteUint64(r.Remaining)
}
func (r *RPCSendV2Blocks) decodeResponse(d *types.Decoder) {
	r.Blocks = make([]types.Block, d.ReadPrefix())
	for i := range r.Blocks {
		(*types.V2Block)(&r.Blocks[i]).DecodeFrom(d)
	}
	r.Remaining = d.ReadUint64()
}
func (r *RPCSendV2Blocks) maxResponseLen() int { return int(r.Max) * 5e6 }

// RPCSendTransactions requests a subset of a block's transactions.
type RPCSendTransactions struct {
	Index  types.ChainIndex
	Hashes []types.Hash256

	Transactions   []types.Transaction
	V2Transactions []types.V2Transaction
}

func (r *RPCSendTransactions) encodeRequest(e *types.Encoder) {
	r.Index.EncodeTo(e)
	e.WritePrefix(len(r.Hashes))
	for i := range r.Hashes {
		r.Hashes[i].EncodeTo(e)
	}
}
func (r *RPCSendTransactions) decodeRequest(d *types.Decoder) {
	r.Index.DecodeFrom(d)
	r.Hashes = make([]types.Hash256, d.ReadPrefix())
	for i := range r.Hashes {
		r.Hashes[i].DecodeFrom(d)
	}
}
func (r *RPCSendTransactions) maxRequestLen() int { return 8 + 32 + 8 + 100*32 }

func (r *RPCSendTransactions) encodeResponse(e *types.Encoder) {
	e.WritePrefix(len(r.Transactions))
	for i := range r.Transactions {
		r.Transactions[i].EncodeTo(e)
	}
	e.WritePrefix(len(r.V2Transactions))
	for i := range r.V2Transactions {
		r.V2Transactions[i].EncodeTo(e)
	}
}
func (r *RPCSendTransactions) decodeResponse(d *types.Decoder) {
	r.Transactions = make([]types.Transaction, d.ReadPrefix())
	for i := range r.Transactions {
		r.Transactions[i].DecodeFrom(d)
	}
	r.V2Transactions = make([]types.V2Transaction, d.ReadPrefix())
	for i := range r.V2Transactions {
		r.V2Transactions[i].DecodeFrom(d)
	}
}
func (r *RPCSendTransactions) maxResponseLen() int { return 5e6 }

// RPCSendCheckpoint requests a checkpoint.
type RPCSendCheckpoint struct {
	Index types.ChainIndex

	Block types.Block
	State consensus.State
}

func (r *RPCSendCheckpoint) encodeRequest(e *types.Encoder) { r.Index.EncodeTo(e) }
func (r *RPCSendCheckpoint) decodeRequest(d *types.Decoder) { r.Index.DecodeFrom(d) }
func (r *RPCSendCheckpoint) maxRequestLen() int             { return 8 + 32 }

func (r *RPCSendCheckpoint) encodeResponse(e *types.Encoder) {
	(types.V2Block)(r.Block).EncodeTo(e)
	r.State.EncodeTo(e)
}
func (r *RPCSendCheckpoint) decodeResponse(d *types.Decoder) {
	(*types.V2Block)(&r.Block).DecodeFrom(d)
	r.State.DecodeFrom(d)
}
func (r *RPCSendCheckpoint) maxResponseLen() int { return 5e6 + 4e3 }

// RPCRelayV2Header relays a v2 block header.
type RPCRelayV2Header struct {
	Header V2BlockHeader
	emptyResponse
}

func (r *RPCRelayV2Header) encodeRequest(e *types.Encoder) { r.Header.encodeTo(e) }
func (r *RPCRelayV2Header) decodeRequest(d *types.Decoder) { r.Header.decodeFrom(d) }
func (r *RPCRelayV2Header) maxRequestLen() int             { return 8 + 32 + 8 + 8 + 32 + 32 }

// RPCRelayV2BlockOutline relays a v2 block outline.
type RPCRelayV2BlockOutline struct {
	Block V2BlockOutline
	emptyResponse
}

func (r *RPCRelayV2BlockOutline) encodeRequest(e *types.Encoder) { r.Block.encodeTo(e) }
func (r *RPCRelayV2BlockOutline) decodeRequest(d *types.Decoder) { r.Block.decodeFrom(d) }
func (r *RPCRelayV2BlockOutline) maxRequestLen() int             { return 5e6 }

// RPCRelayV2TransactionSet relays a v2 transaction set.
type RPCRelayV2TransactionSet struct {
	Index        types.ChainIndex
	Transactions []types.V2Transaction
	emptyResponse
}

func (r *RPCRelayV2TransactionSet) encodeRequest(e *types.Encoder) {
	r.Index.EncodeTo(e)
	e.WritePrefix(len(r.Transactions))
	for i := range r.Transactions {
		r.Transactions[i].EncodeTo(e)
	}
}
func (r *RPCRelayV2TransactionSet) decodeRequest(d *types.Decoder) {
	r.Index.DecodeFrom(d)
	r.Transactions = make([]types.V2Transaction, d.ReadPrefix())
	for i := range r.Transactions {
		r.Transactions[i].DecodeFrom(d)
	}
}
func (r *RPCRelayV2TransactionSet) maxRequestLen() int { return 5e6 }

type v1RPCID types.Specifier

func (id *v1RPCID) encodeTo(e *types.Encoder) { e.Write(id[:8]) }
func (id *v1RPCID) decodeFrom(d *types.Decoder) {
	var shortID [8]byte
	d.Read(shortID[:])
	switch string(shortID[:]) {
	case "ShareNod":
		*id = v1RPCID(idShareNodes)
	case "Discover":
		*id = v1RPCID(idDiscoverIP)
	case "SendBloc":
		*id = v1RPCID(idSendBlocks)
	case "SendBlk\x00":
		*id = v1RPCID(idSendBlk)
	case "RelayHea":
		*id = v1RPCID(idRelayHeader)
	case "RelayTra":
		*id = v1RPCID(idRelayTransactionSet)
	default:
		copy(id[:], shortID[:])
	}
}

var (
	// v1
	idShareNodes          = types.NewSpecifier("ShareNodes")
	idDiscoverIP          = types.NewSpecifier("DiscoverIP")
	idSendBlocks          = types.NewSpecifier("SendBlocks")
	idSendBlk             = types.NewSpecifier("SendBlk")
	idRelayHeader         = types.NewSpecifier("RelayHeader")
	idRelayTransactionSet = types.NewSpecifier("RelayTransactionSet")
	// v2
	idSendV2Blocks          = types.NewSpecifier("SendV2Blocks")
	idSendTransactions      = types.NewSpecifier("SendTransactions")
	idSendCheckpoint        = types.NewSpecifier("SendCheckpoint")
	idRelayV2Header         = types.NewSpecifier("RelayV2Header")
	idRelayV2BlockOutline   = types.NewSpecifier("RelayV2BlockOutline")
	idRelayV2TransactionSet = types.NewSpecifier("RelayV2TransactionSet")
)

func idForObject(o Object) types.Specifier {
	switch o.(type) {
	case *RPCShareNodes:
		return idShareNodes
	case *RPCDiscoverIP:
		return idDiscoverIP
	case *RPCSendBlocks:
		return idSendBlocks
	case *RPCSendBlk:
		return idSendBlk
	case *RPCRelayHeader:
		return idRelayHeader
	case *RPCRelayTransactionSet:
		return idRelayTransactionSet
	case *RPCSendV2Blocks:
		return idSendV2Blocks
	case *RPCSendTransactions:
		return idSendTransactions
	case *RPCSendCheckpoint:
		return idSendCheckpoint
	case *RPCRelayV2Header:
		return idRelayV2Header
	case *RPCRelayV2BlockOutline:
		return idRelayV2BlockOutline
	case *RPCRelayV2TransactionSet:
		return idRelayV2TransactionSet
	default:
		panic(fmt.Sprintf("unhandled object type %T", o))
	}
}

// ObjectForID returns the object type corresponding to the given RPC ID.
func ObjectForID(id types.Specifier) Object {
	switch id {
	case idShareNodes:
		return new(RPCShareNodes)
	case idDiscoverIP:
		return new(RPCDiscoverIP)
	case idSendBlocks:
		return new(RPCSendBlocks)
	case idSendBlk:
		return new(RPCSendBlk)
	case idRelayHeader:
		return new(RPCRelayHeader)
	case idRelayTransactionSet:
		return new(RPCRelayTransactionSet)
	case idSendV2Blocks:
		return new(RPCSendV2Blocks)
	case idSendTransactions:
		return new(RPCSendTransactions)
	case idRelayV2Header:
		return new(RPCRelayV2Header)
	case idRelayV2BlockOutline:
		return new(RPCRelayV2BlockOutline)
	case idRelayV2TransactionSet:
		return new(RPCRelayV2TransactionSet)
	default:
		return nil
	}
}
