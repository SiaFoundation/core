package rhp

import (
	"errors"
	"fmt"
	"io"

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
	if re := new(RPCError); errors.As(err, &re) {
		return re.Code
	}
	return ErrorCodeTransport
}

func withEncoder(w io.Writer, fn func(*types.Encoder)) error {
	e := types.NewEncoder(w)
	fn(e)
	return e.Flush()
}

func withDecoder(r io.Reader, maxLen int, fn func(*types.Decoder)) error {
	d := types.NewDecoder(io.LimitedReader{R: r, N: int64(maxLen)})
	fn(d)
	return d.Err()
}

// WriteID writes a request's ID to the stream.
func WriteID(w io.Writer, r Request) error {
	return withEncoder(w, r.ID().EncodeTo)
}

// ReadID reads an RPC ID from the stream.
func ReadID(r io.Reader) (id types.Specifier, err error) {
	err = withDecoder(r, 16, id.DecodeFrom)
	return
}

// WriteRequest writes a request to the stream.
func WriteRequest(w io.Writer, r Request) error {
	return withEncoder(w, r.encodeTo)
}

// ReadRequest reads a request from the stream.
func ReadRequest(r io.Reader, o Object) error {
	return withDecoder(r, o.maxLen(), o.decodeFrom)
}

// WriteResponse writes a response to the stream. Note that RPCError implements
// Object, and may be used as a response to any RPC.
func WriteResponse(w io.Writer, o Object) error {
	return withEncoder(w, func(e *types.Encoder) {
		_, isErr := o.(*RPCError)
		e.WriteBool(isErr)
		o.encodeTo(e)
	})
}

// ReadResponse reads a response from the stream into r.
func ReadResponse(r io.Reader, o Object) error {
	return withDecoder(r, (*RPCError)(nil).maxLen()+o.maxLen(), func(d *types.Decoder) {
		if d.ReadBool() {
			r := new(RPCError)
			r.decodeFrom(d)
			d.SetErr(r)
			return
		}
		o.decodeFrom(d)
	})
}
