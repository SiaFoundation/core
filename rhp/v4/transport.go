package rhp

import (
	"fmt"
	"io"
	"net"

	"go.sia.tech/core/types"
)

// Error codes.
const (
	ErrorCodeTransport = iota
)

// An RPCError pairs a human-readable error description with a status code.
type RPCError struct {
	Code        uint8
	Description string
}

// Error implements error.
func (e *RPCError) Error() string {
	return fmt.Sprintf("%v %v", e.Code, e.Description)
}

// ErrorCode returns the code of err. If err is not an RPCError, ErrorCode
// returns ErrorCodeTransport.
func ErrorCode(err error) uint8 {
	if rpcErr, ok := err.(*RPCError); ok {
		return rpcErr.Code
	}
	return ErrorCodeTransport
}

func withEncoder(s net.Conn, fn func(*types.Encoder)) error {
	e := types.NewEncoder(s)
	fn(e)
	return e.Flush()
}

func withDecoder(s net.Conn, maxLen int, fn func(*types.Decoder)) error {
	d := types.NewDecoder(io.LimitedReader{R: s, N: int64(maxLen)})
	fn(d)
	return d.Err()
}

// WriteID writes a request's ID to the stream.
func WriteID(s net.Conn, r Request) error {
	return withEncoder(s, r.id().EncodeTo)
}

// ReadID reads an RPC ID from the stream.
func ReadID(s net.Conn) (id types.Specifier, err error) {
	err = withDecoder(s, 16, id.DecodeFrom)
	return
}

// WriteRequest writes a request to the stream.
func WriteRequest(s net.Conn, r Request) error {
	return withEncoder(s, r.encodeTo)
}

// ReadRequest reads a request from the stream.
func ReadRequest(s net.Conn, r Object) error {
	return withDecoder(s, r.maxLen(), r.decodeFrom)
}

// WriteResponse writes a response to the stream. Note that RPCError implements
// Object, and may be used as a response to any RPC.
func WriteResponse(s net.Conn, r Object) error {
	return withEncoder(s, func(e *types.Encoder) {
		_, isErr := r.(*RPCError)
		e.WriteBool(isErr)
		r.encodeTo(e)
	})
}

// ReadResponse reads a response from the stream into r.
func ReadResponse(s net.Conn, r Object) error {
	return withDecoder(s, (*RPCError)(nil).maxLen()+r.maxLen(), func(d *types.Decoder) {
		if d.ReadBool() {
			r := new(RPCError)
			r.decodeFrom(d)
			d.SetErr(r)
			return
		}
		r.decodeFrom(d)
	})
}
