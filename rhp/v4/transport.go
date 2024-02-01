package rhp

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"net"
	"time"

	"go.sia.tech/core/types"
	"go.sia.tech/mux"
)

// Error codes.
const (
	ErrorCodeInvalid = iota
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
// returns ErrorCodeInvalid.
func ErrorCode(err error) uint8 {
	if rpcErr, ok := err.(*RPCError); ok {
		return rpcErr.Code
	}
	return ErrorCodeInvalid
}

// A Stream provides a multiplexed stream for the RHPv4 protocol.
type Stream struct {
	mux *mux.Stream
}

func (s *Stream) withEncoder(fn func(*types.Encoder)) error {
	e := types.NewEncoder(s.mux)
	fn(e)
	return e.Flush()
}

func (s *Stream) withDecoder(maxLen int, fn func(*types.Decoder)) error {
	d := types.NewDecoder(io.LimitedReader{R: s.mux, N: int64(maxLen)})
	fn(d)
	return d.Err()
}

// WriteID writes the RPC ID of r to the stream.
func (s *Stream) WriteID(r RPC) error {
	return s.withEncoder(r.id().EncodeTo)
}

// ReadID reads an RPC ID from the stream.
func (s *Stream) ReadID() (id types.Specifier, err error) {
	err = s.withDecoder(16, id.DecodeFrom)
	return
}

// WriteRequest writes a request to the stream.
func (s *Stream) WriteRequest(r Object) error {
	return s.withEncoder(r.encodeTo)
}

// ReadRequest reads a request from the stream.
func (s *Stream) ReadRequest(r Object) error {
	return s.withDecoder(r.maxLen(), r.decodeFrom)
}

// WriteResponse writes a response to the stream. Note that RPCError implements
// Object, and may be used as a response to any RPC.
func (s *Stream) WriteResponse(r Object) error {
	return s.withEncoder(func(e *types.Encoder) {
		_, isErr := r.(*RPCError)
		e.WriteBool(isErr)
		r.encodeTo(e)
	})
}

// ReadResponse reads a response from the stream into r.
func (s *Stream) ReadResponse(r Object) error {
	return s.withDecoder((*RPCError)(nil).maxLen()+r.maxLen(), func(d *types.Decoder) {
		if d.ReadBool() {
			r := new(RPCError)
			r.decodeFrom(d)
			d.SetErr(r)
			return
		}
		r.decodeFrom(d)
	})
}

// SetDeadline implements net.Conn.
func (s *Stream) SetDeadline(t time.Time) error {
	return s.mux.SetDeadline(t)
}

// Close closes the stream.
func (s *Stream) Close() error {
	return s.mux.Close()
}

// Transport provides a multiplexing transport for the RHPv4 protocol.
type Transport struct {
	mux *mux.Mux
}

// DialStream opens a new multiplexed stream.
func (t *Transport) DialStream() (*Stream, error) {
	return &Stream{mux: t.mux.DialStream()}, nil
}

// AcceptStream accepts an incoming multiplexed stream.
func (t *Transport) AcceptStream() (*Stream, error) {
	s, err := t.mux.AcceptStream()
	return &Stream{mux: s}, err
}

// Close closes the underlying connection.
func (t *Transport) Close() error {
	return t.mux.Close()
}

// Dial establishes a new RHPv4 session over the supplied connection.
func Dial(conn net.Conn, hostKey types.PublicKey) (*Transport, error) {
	m, err := mux.Dial(conn, hostKey[:])
	return &Transport{mux: m}, err
}

// Accept accepts a new RHPv4 session over the supplied connection.
func Accept(conn net.Conn, hostKey types.PrivateKey) (*Transport, error) {
	m, err := mux.Accept(conn, ed25519.PrivateKey(hostKey))
	return &Transport{mux: m}, err
}
