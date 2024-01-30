package rhp

import (
	"crypto/ed25519"
	"errors"
	"io"
	"net"
	"time"

	"go.sia.tech/core/types"
	"go.sia.tech/mux"
)

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
	id := idForRPC(r)
	return s.withEncoder(id.EncodeTo)
}

// ReadID reads an RPC ID from the stream.
func (s *Stream) ReadID() (id types.Specifier, err error) {
	err = s.withDecoder(16, id.DecodeFrom)
	return
}

// WriteRequest writes the request fields of r to the stream.
func (s *Stream) WriteRequest(r RPC) error {
	return s.withEncoder(r.encodeRequest)
}

// ReadRequest reads a request from the stream into r.
func (s *Stream) ReadRequest(r RPC) error {
	return s.withDecoder(r.maxRequestLen(), r.decodeRequest)
}

// WriteResponse writes the response fields of r to the stream.
func (s *Stream) WriteResponse(r RPC) error {
	return s.withEncoder(func(e *types.Encoder) {
		e.WriteBool(false)
		r.encodeResponse(e)
	})
}

// WriteResponseErr writes err to the stream.
func (s *Stream) WriteResponseErr(err error) error {
	return s.withEncoder(func(e *types.Encoder) {
		e.WriteBool(true)
		e.WriteString(err.Error())
	})
}

// ReadResponse reads a response from the stream into r.
func (s *Stream) ReadResponse(r RPC) error {
	return s.withDecoder(1+256+r.maxResponseLen(), func(d *types.Decoder) {
		if d.ReadBool() {
			d.SetErr(errors.New(d.ReadString()))
			return
		}
		r.decodeResponse(d)
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
