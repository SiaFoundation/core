package rpc

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"

	"go.sia.tech/core/types"
)

// An Object can be sent and received via RPC.
type Object interface {
	types.EncoderTo
	types.DecoderFrom
	MaxLen() int
}

// A Specifier is a generic identification tag.
type Specifier [16]byte

// EncodeTo implements Object.
func (s *Specifier) EncodeTo(e *types.Encoder) { e.Write(s[:]) }

// DecodeFrom implements Object.
func (s *Specifier) DecodeFrom(d *types.Decoder) { d.Read(s[:]) }

// MaxLen implements Object.
func (s *Specifier) MaxLen() int { return 16 }

// String implements fmt.Stringer.
func (s Specifier) String() string { return string(bytes.Trim(s[:], "\x00")) }

// NewSpecifier constructs a Specifier from the provided string, which must not
// be longer than 16 bytes.
func NewSpecifier(str string) Specifier {
	if len(str) > 16 {
		panic("specifier is too long")
	}
	var s Specifier
	copy(s[:], str)
	return s
}

// An Error may be sent instead of a response object to any RPC.
type Error struct {
	Type        Specifier
	Data        []byte // structure depends on Type
	Description string // human-readable error string
}

// EncodeTo implements types.EncoderTo.
func (err *Error) EncodeTo(e *types.Encoder) {
	err.Type.EncodeTo(e)
	e.WriteBytes(err.Data)
	e.WriteString(err.Description)
}

// DecodeFrom implements types.DecoderFrom.
func (err *Error) DecodeFrom(d *types.Decoder) {
	err.Type.DecodeFrom(d)
	err.Data = d.ReadBytes()
	err.Description = d.ReadString()
}

// MaxLen implements Object.
func (err *Error) MaxLen() int {
	return 1024 // arbitrary
}

// Error implements the error interface.
func (err *Error) Error() string {
	return err.Description
}

// Is reports whether this error matches target.
func (err *Error) Is(target error) bool {
	return strings.Contains(err.Description, target.Error())
}

// rpcResponse is a helper type for encoding and decoding RPC responses.
type rpcResponse struct {
	err *Error
	obj Object
}

func (resp *rpcResponse) EncodeTo(e *types.Encoder) {
	e.WriteBool(resp.err != nil)
	if resp.err != nil {
		resp.err.EncodeTo(e)
	} else {
		resp.obj.EncodeTo(e)
	}
}

func (resp *rpcResponse) DecodeFrom(d *types.Decoder) {
	if isErr := d.ReadBool(); isErr {
		resp.err = new(Error)
		resp.err.DecodeFrom(d)
	} else {
		resp.obj.DecodeFrom(d)
	}
}

func (resp *rpcResponse) MaxLen() int {
	return 1 + resp.err.MaxLen() + resp.obj.MaxLen()
}

// WriteObject writes obj to conn.
func WriteObject(conn net.Conn, obj Object) error {
	e := types.NewEncoder(conn)
	obj.EncodeTo(e)
	return e.Flush()
}

// ReadObject reads obj from conn.
func ReadObject(conn net.Conn, obj Object) error {
	d := types.NewDecoder(io.LimitedReader{R: conn, N: int64(obj.MaxLen())})
	obj.DecodeFrom(d)
	return d.Err()
}

// WriteRequest sends an RPC request, comprising an RPC ID and an optional
// request object.
func WriteRequest(conn net.Conn, id Specifier, req Object) error {
	if err := WriteObject(conn, &id); err != nil {
		return fmt.Errorf("couldn't write request ID: %w", err)
	}
	if req != nil {
		if err := WriteObject(conn, req); err != nil {
			return fmt.Errorf("couldn't write request object: %w", err)
		}
	}
	return nil
}

// ReadID reads an RPC request ID.
func ReadID(conn net.Conn) (id Specifier, err error) {
	err = ReadObject(conn, &id)
	return
}

// ReadRequest reads an RPC request.
func ReadRequest(conn net.Conn, req Object) error {
	return ReadObject(conn, req)
}

// WriteResponse writes an RPC response object or an error. Either resp or err must
// be nil. If err is an *rpc.Error, it is sent directly; otherwise, a generic
// rpc.Error is created from err's Error string.
func WriteResponse(conn net.Conn, resp Object, err error) error {
	re, ok := err.(*Error)
	if err != nil && !ok {
		re = &Error{Description: err.Error()}
	}
	return WriteObject(conn, &rpcResponse{obj: resp, err: re})
}

// ReadResponse reads an RPC response. If the response is an error, it is
// returned directly.
func ReadResponse(conn net.Conn, resp Object) error {
	rr := rpcResponse{obj: resp}
	if err := ReadObject(conn, &rr); err != nil {
		return fmt.Errorf("failed to read message: %w", err)
	} else if rr.err != nil {
		return fmt.Errorf("response error: %w", rr.err)
	}
	return nil
}
