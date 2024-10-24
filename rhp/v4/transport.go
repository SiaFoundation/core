package rhp

import (
	"bytes"
	"fmt"
	"io"
	"log"

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

// ReadID reads an RPC ID from the stream.
func ReadID(r io.Reader) (id types.Specifier, err error) {
	err = withDecoder(r, 16, id.DecodeFrom)
	if err == nil {
		log.Println("read request id")
	}
	return
}

// WriteRequest writes a request to the stream.
func WriteRequest(w io.Writer, id types.Specifier, o Object) error {
	return withEncoder(w, func(e *types.Encoder) {
		id.EncodeTo(e)
		fmt.Println("wrote request id")
		if o == nil {
			return
		}
		fmt.Printf("writing request %T\n", o)
		o.encodeTo(e)
	})
}

// ReadRequest reads a request from the stream.
func ReadRequest(r io.Reader, o Object) error {
	return withDecoder(r, o.maxLen(), func(d *types.Decoder) {
		o.decodeFrom(d)
		fmt.Printf("read request %T\n", o)
	})
}

// WriteResponse writes a response to the stream. Note that RPCError implements
// Object, and may be used as a response to any RPC.
func WriteResponse(w io.Writer, o Object) error {
	buf := bytes.NewBuffer(nil)
	w = io.MultiWriter(w, buf)
	err := withEncoder(w, func(e *types.Encoder) {
		_, isErr := o.(*RPCError)
		e.WriteBool(isErr)
		o.encodeTo(e)
		fmt.Printf("wrote response %T\n", o)
	})
	fmt.Printf("write response %T: %v\n", o, buf.Bytes())
	return err
}

// ReadResponse reads a response from the stream into r.
func ReadResponse(r io.Reader, o Object) error {
	buf := bytes.NewBuffer(nil)
	r = io.TeeReader(r, buf)
	err := withDecoder(r, (*RPCError)(nil).maxLen()+o.maxLen(), func(d *types.Decoder) {
		if d.ReadBool() {
			r := new(RPCError)
			r.decodeFrom(d)
			d.SetErr(r)
			fmt.Printf("read response error\n")
			return
		}
		o.decodeFrom(d)
		fmt.Printf("read response %T\n", o)
	})
	fmt.Printf("read response %T: %v\n", o, buf.Bytes())
	return err
}
