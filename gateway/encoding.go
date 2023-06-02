package gateway

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"go.sia.tech/core/types"
)

func withEncoder(w io.Writer, fn func(*types.Encoder)) error {
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

func withDecoder(r io.Reader, maxLen int, fn func(*types.Decoder)) error {
	d := types.NewDecoder(io.LimitedReader{R: r, N: int64(8 + maxLen)})
	d.ReadPrefix() // ignored
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
	e.WriteUint64(h.Height)
	h.ParentID.EncodeTo(e)
	e.WriteUint64(h.Nonce)
	e.WriteTime(h.Timestamp)
	h.MinerAddress.EncodeTo(e)
	h.Commitment.EncodeTo(e)
}

func (h *V2BlockHeader) decodeFrom(d *types.Decoder) {
	h.Height = d.ReadUint64()
	h.ParentID.DecodeFrom(d)
	h.Nonce = d.ReadUint64()
	h.Timestamp = d.ReadTime()
	h.MinerAddress.DecodeFrom(d)
	h.Commitment.DecodeFrom(d)
}

type object interface {
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
	History       [32]types.BlockID
	Blocks        []types.Block
	MoreAvailable bool
	emptyResponse // SendBlocks is special
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

func (r *RPCSendBlocks) encodeBlocksResponse(e *types.Encoder) {
	e.WritePrefix(len(r.Blocks))
	for i := range r.Blocks {
		types.V1Block(r.Blocks[i]).EncodeTo(e)
	}
}
func (r *RPCSendBlocks) decodeBlocksResponse(d *types.Decoder) {
	r.Blocks = make([]types.Block, d.ReadPrefix())
	for i := range r.Blocks {
		(*types.V1Block)(&r.Blocks[i]).DecodeFrom(d)
	}
}
func (r *RPCSendBlocks) maxBlocksResponseLen() int { return 10 * 5e6 }
func (r *RPCSendBlocks) encodeMoreAvailableResponse(e *types.Encoder) {
	e.WriteBool(r.MoreAvailable)
}
func (r *RPCSendBlocks) decodeMoreAvailableResponse(d *types.Decoder) {
	r.MoreAvailable = d.ReadBool()
}
func (r *RPCSendBlocks) maxMoreAvailableResponseLen() int { return 1 }

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

// RPCRelayV2Header relays a v2 header.
type RPCRelayV2Header struct {
	Header V2BlockHeader
	emptyResponse
}

func (r *RPCRelayV2Header) encodeRequest(e *types.Encoder) { r.Header.encodeTo(e) }
func (r *RPCRelayV2Header) decodeRequest(d *types.Decoder) { r.Header.decodeFrom(d) }
func (r *RPCRelayV2Header) maxRequestLen() int             { return 32 + 8 + 8 + 32 }

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

// RPCRelayV2TransactionSet relays a v2 transaction set.
type RPCRelayV2TransactionSet struct {
	Transactions []types.V2Transaction
	emptyResponse
}

func (r *RPCRelayV2TransactionSet) encodeRequest(e *types.Encoder) {
	e.WritePrefix(len(r.Transactions))
	for i := range r.Transactions {
		r.Transactions[i].EncodeTo(e)
	}
}
func (r *RPCRelayV2TransactionSet) decodeRequest(d *types.Decoder) {
	r.Transactions = make([]types.V2Transaction, d.ReadPrefix())
	for i := range r.Transactions {
		r.Transactions[i].DecodeFrom(d)
	}
}
func (r *RPCRelayV2TransactionSet) maxRequestLen() int { return 5e6 }

type rpcID types.Specifier

func (id *rpcID) encodeTo(e *types.Encoder)   { e.Write(id[:8]) }
func (id *rpcID) decodeFrom(d *types.Decoder) { d.Read(id[:8]) }

func newID(str string) (id rpcID) {
	copy(id[:8], str)
	return
}

var (
	idShareNodes          = newID("ShareNodes")
	idDiscoverIP          = newID("DiscoverIP")
	idSendBlocks          = newID("SendBlocks")
	idSendBlk             = newID("SendBlk")
	idRelayHeader         = newID("RelayHeader")
	idRelayTransactionSet = newID("RelayTransactionSet")
)

func idForObject(o object) rpcID {
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
	default:
		panic(fmt.Sprintf("unhandled object type %T", o))
	}
}

func objectForID(id rpcID) object {
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
	default:
		return nil
	}
}
