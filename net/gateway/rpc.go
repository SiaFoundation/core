package gateway

import (
	"fmt"

	"go.sia.tech/core/consensus"
	"go.sia.tech/core/merkle"
	"go.sia.tech/core/net/rpc"
	"go.sia.tech/core/types"
)

const defaultMaxLen = 10e3
const largeMaxLen = 1e6

// MaxRPCPeersLen is the maximum number of peers that RPCPeers can return.
const MaxRPCPeersLen = 100

// RPC IDs
var (
	RPCPeersID      = rpc.NewSpecifier("Peers")
	RPCHeadersID    = rpc.NewSpecifier("Headers")
	RPCBlocksID     = rpc.NewSpecifier("Blocks")
	RPCCheckpointID = rpc.NewSpecifier("Checkpoint")
	RPCRelayBlockID = rpc.NewSpecifier("RelayBlock")
	RPCRelayTxnID   = rpc.NewSpecifier("RelayTxn")
)

// RPC request/response objects
type (
	// RPCPeersRequest contains the request parameters for the Peers RPC.
	RPCPeersRequest struct{}

	// RPCHeadersRequest contains the request parameters for the Headers RPC.
	RPCHeadersRequest struct {
		History []types.ChainIndex
	}

	// RPCHeadersResponse contains the response data for the Headers RPC.
	RPCHeadersResponse struct {
		Headers []types.BlockHeader
	}

	// RPCBlocksRequest contains the request parameters for the Blocks RPC.
	RPCBlocksRequest struct {
		Blocks []types.ChainIndex
	}

	// RPCBlocksResponse contains the response data for the Blocks RPC.
	RPCBlocksResponse struct {
		Blocks []types.Block
	}

	// RPCCheckpointRequest contains the request parameters for the Checkpoint RPC.
	RPCCheckpointRequest struct {
		Index types.ChainIndex
	}

	// RPCCheckpointResponse contains the response data for the Checkpoint RPC.
	RPCCheckpointResponse struct {
		// NOTE: we don't use a consensus.Checkpoint, because a Checkpoint.State
		// is the *child* state for the block, not its parent state.
		Block       types.Block
		ParentState consensus.State
	}

	// RPCRelayBlockRequest contains the request parameters for the RelayBlock RPC.
	RPCRelayBlockRequest struct {
		Block types.Block
	}

	// RPCRelayTxnRequest contains the request parameters for the RelayTxn RPC.
	RPCRelayTxnRequest struct {
		Transaction types.Transaction
		DependsOn   []types.Transaction
	}
)

// IsRelayRPC returns true for request objects that should be relayed.
func IsRelayRPC(msg rpc.Object) bool {
	switch msg.(type) {
	case *RPCHeadersRequest,
		*RPCPeersRequest,
		*RPCBlocksRequest,
		*RPCCheckpointRequest:
		return false
	case *RPCRelayBlockRequest,
		*RPCRelayTxnRequest:
		return true
	default:
		panic(fmt.Sprintf("unhandled type %T", msg))
	}
}

// rpc.Object implementations

// EncodeTo implements rpc.Object.
func (RPCPeersRequest) EncodeTo(e *types.Encoder) {}

// DecodeFrom implements rpc.Object.
func (RPCPeersRequest) DecodeFrom(d *types.Decoder) {}

// MaxLen implements rpc.Object.
func (RPCPeersRequest) MaxLen() int { return 0 }

// EncodeTo implements rpc.Object.
func (r *RPCHeadersRequest) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.History))
	for i := range r.History {
		r.History[i].EncodeTo(e)
	}
}

// DecodeFrom implements rpc.Object.
func (r *RPCHeadersRequest) DecodeFrom(d *types.Decoder) {
	r.History = make([]types.ChainIndex, d.ReadPrefix())
	for i := range r.History {
		r.History[i].DecodeFrom(d)
	}
}

// MaxLen implements rpc.Object.
func (RPCHeadersRequest) MaxLen() int { return defaultMaxLen }

// EncodeTo implements rpc.Object.
func (r *RPCHeadersResponse) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.Headers))
	for i := range r.Headers {
		r.Headers[i].EncodeTo(e)
	}
}

// DecodeFrom implements rpc.Object.
func (r *RPCHeadersResponse) DecodeFrom(d *types.Decoder) {
	r.Headers = make([]types.BlockHeader, d.ReadPrefix())
	for i := range r.Headers {
		r.Headers[i].DecodeFrom(d)
	}
}

// MaxLen implements rpc.Object.
func (RPCHeadersResponse) MaxLen() int { return largeMaxLen }

// RPCPeersResponse contains the response data for the Peers RPC.
type RPCPeersResponse []string

// EncodeTo implements rpc.Object.
func (r *RPCPeersResponse) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(*r))
	for i := range *r {
		e.WriteString((*r)[i])
	}
}

// DecodeFrom implements rpc.Object.
func (r *RPCPeersResponse) DecodeFrom(d *types.Decoder) {
	*r = make([]string, d.ReadPrefix())
	for i := range *r {
		(*r)[i] = d.ReadString()
	}
}

// MaxLen implements rpc.Object.
func (RPCPeersResponse) MaxLen() int {
	const maxDomainLen = 256 // See https://www.freesoft.org/CIE/RFC/1035/9.htm
	return 8 + MaxRPCPeersLen*maxDomainLen
}

// EncodeTo implements rpc.Object.
func (r *RPCBlocksRequest) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.Blocks))
	for i := range r.Blocks {
		r.Blocks[i].EncodeTo(e)
	}
}

// DecodeFrom implements rpc.Object.
func (r *RPCBlocksRequest) DecodeFrom(d *types.Decoder) {
	r.Blocks = make([]types.ChainIndex, d.ReadPrefix())
	for i := range r.Blocks {
		r.Blocks[i].DecodeFrom(d)
	}
}

// MaxLen implements rpc.Object.
func (RPCBlocksRequest) MaxLen() int { return defaultMaxLen }

// EncodeTo implements rpc.Object.
func (r *RPCBlocksResponse) EncodeTo(e *types.Encoder) {
	e.WritePrefix(len(r.Blocks))
	for i := range r.Blocks {
		merkle.CompressedBlock(r.Blocks[i]).EncodeTo(e)
	}
}

// DecodeFrom implements rpc.Object.
func (r *RPCBlocksResponse) DecodeFrom(d *types.Decoder) {
	r.Blocks = make([]types.Block, d.ReadPrefix())
	for i := range r.Blocks {
		(*merkle.CompressedBlock)(&r.Blocks[i]).DecodeFrom(d)
	}
}

// MaxLen implements rpc.Object.
func (RPCBlocksResponse) MaxLen() int {
	return 100e6 // arbitrary
}

// EncodeTo implements rpc.Object.
func (r *RPCCheckpointRequest) EncodeTo(e *types.Encoder) {
	r.Index.EncodeTo(e)
}

// DecodeFrom implements rpc.Object.
func (r *RPCCheckpointRequest) DecodeFrom(d *types.Decoder) {
	r.Index.DecodeFrom(d)
}

// MaxLen implements rpc.Object.
func (RPCCheckpointRequest) MaxLen() int { return 40 }

// EncodeTo implements rpc.Object.
func (r *RPCCheckpointResponse) EncodeTo(e *types.Encoder) {
	merkle.CompressedBlock(r.Block).EncodeTo(e)
	r.ParentState.EncodeTo(e)
}

// DecodeFrom implements rpc.Object.
func (r *RPCCheckpointResponse) DecodeFrom(d *types.Decoder) {
	(*merkle.CompressedBlock)(&r.Block).DecodeFrom(d)
	r.ParentState.DecodeFrom(d)
}

// MaxLen implements rpc.Object.
func (RPCCheckpointResponse) MaxLen() int { return largeMaxLen }

// EncodeTo implements rpc.Object.
func (r *RPCRelayBlockRequest) EncodeTo(e *types.Encoder) {
	merkle.CompressedBlock(r.Block).EncodeTo(e)
}

// DecodeFrom implements rpc.Object.
func (r *RPCRelayBlockRequest) DecodeFrom(d *types.Decoder) {
	(*merkle.CompressedBlock)(&r.Block).DecodeFrom(d)
}

// MaxLen implements rpc.Object.
func (RPCRelayBlockRequest) MaxLen() int { return defaultMaxLen }

// EncodeTo implements rpc.Object.
func (r *RPCRelayTxnRequest) EncodeTo(e *types.Encoder) {
	r.Transaction.EncodeTo(e)
	e.WritePrefix(len(r.DependsOn))
	for i := range r.DependsOn {
		r.DependsOn[i].EncodeTo(e)
	}
}

// DecodeFrom implements rpc.Object.
func (r *RPCRelayTxnRequest) DecodeFrom(d *types.Decoder) {
	r.Transaction.DecodeFrom(d)
	r.DependsOn = make([]types.Transaction, d.ReadPrefix())
	for i := range r.DependsOn {
		r.DependsOn[i].DecodeFrom(d)
	}
}

// MaxLen implements rpc.Object.
func (RPCRelayTxnRequest) MaxLen() int { return defaultMaxLen }
