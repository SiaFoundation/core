package rhp

import (
	"io"

	"go.sia.tech/core/types"
)

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

// ReadID reads an RPC header from the stream.
func ReadID(r io.Reader) (id RPCSpecifier, err error) {
	err = withDecoder(r, 16, (*types.Specifier)(&id).DecodeFrom)
	return
}

// WriteRequest writes a request to the stream.
func WriteRequest(w io.Writer, id RPCSpecifier, o Object) error {
	return withEncoder(w, func(e *types.Encoder) {
		types.Specifier(id).EncodeTo(e)
		if o == nil {
			return
		}
		o.encodeTo(e)
	})
}

// ReadRequest reads a request from the stream.
func ReadRequest(r io.Reader, o Object) error {
	return withDecoder(r, o.maxLen(), func(d *types.Decoder) {
		o.decodeFrom(d)
	})
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
