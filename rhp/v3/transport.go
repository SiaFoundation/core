package rhp

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"go.sia.tech/core/types"
	"go.sia.tech/mux"
	"lukechampine.com/frand"
)

// An RPCError may be sent instead of a response object to any RPC.
type RPCError struct {
	Type        types.Specifier
	Data        []byte // structure depends on Type
	Description string // human-readable error string
}

// Error implements the error interface.
func (e *RPCError) Error() string {
	return e.Description
}

// Is reports whether this error matches target.
func (e *RPCError) Is(target error) bool {
	return strings.Contains(e.Description, target.Error())
}

func wrapErr(err *error, fnName string) {
	if *err != nil {
		*err = fmt.Errorf("%s: %w", fnName, *err)
	}
}

// helper type for encoding and decoding RPC response messages, which can
// represent either valid data or an error.
type rpcResponse struct {
	err  *RPCError
	data ProtocolObject
}

// A ProtocolObject can be transferred using the RHPv3 protocol.
type ProtocolObject interface {
	types.EncoderTo
	types.DecoderFrom
}

const minMessageSize = 1024

// A Stream is a duplex connection over which RPCs can be sent and received.
type Stream struct {
	s *mux.Stream
}

func (s *Stream) readObject(resp ProtocolObject, maxLen uint64) error {
	d := types.NewDecoder(io.LimitedReader{R: s.s, N: int64(maxLen)})
	if l := d.ReadPrefix(); uint64(l) > maxLen {
		return fmt.Errorf("message too long: %v > %v", l, maxLen)
	}
	rr := rpcResponse{nil, resp}
	rr.DecodeFrom(d)
	if d.Err() != nil {
		return d.Err()
	} else if rr.err != nil {
		return rr.err
	}
	return nil
}

func (s *Stream) writeObject(resp *rpcResponse) error {
	var buf bytes.Buffer
	e := types.NewEncoder(&buf)
	e.WritePrefix(0) // placeholder
	resp.EncodeTo(e)
	e.Flush()
	b := buf.Bytes()
	binary.LittleEndian.PutUint64(b[:8], uint64(len(b)-8))
	_, err := s.s.Write(b)
	return err
}

// WriteResponse writes an RPC response object.
func (s *Stream) WriteResponse(resp ProtocolObject) (err error) {
	defer wrapErr(&err, "WriteResponse")
	return s.writeObject(&rpcResponse{nil, resp})
}

// WriteResponseErr writes an error. If err is an *RPCError, it is sent
// directly; otherwise, a generic RPCError is created from err's Error string.
func (s *Stream) WriteResponseErr(resp error) (err error) {
	defer wrapErr(&err, "WriteResponseErr")
	re, ok := resp.(*RPCError)
	if resp != nil && !ok {
		re = &RPCError{Description: resp.Error()}
	}
	return s.writeObject(&rpcResponse{re, nil})
}

// WriteRequest sends an encrypted RPC request, comprising an RPC ID and a
// request object.
func (s *Stream) WriteRequest(rpcID types.Specifier, req ProtocolObject) error {
	// write subscription and read response
	e := types.NewEncoder(s.s)
	e.WritePrefix(8 + len("host"))
	e.WriteString("host")
	if err := e.Flush(); err != nil {
		return err
	}
	d := types.NewDecoder(io.LimitedReader{R: s.s, N: minMessageSize})
	d.ReadPrefix()
	if errStr := d.ReadString(); errStr != "" {
		return errors.New(errStr)
	} else if d.Err() != nil {
		return d.Err()
	}

	// write ID and request object
	if err := s.writeObject(&rpcResponse{nil, &rpcID}); err != nil {
		return fmt.Errorf("WriteRequestID: %w", err)
	}
	if req != nil {
		if err := s.writeObject(&rpcResponse{nil, req}); err != nil {
			return fmt.Errorf("WriteRequest: %w", err)
		}
	}
	return nil
}

// ReadID reads an RPC request ID.
func (s *Stream) ReadID() (rpcID types.Specifier, err error) {
	defer wrapErr(&err, "ReadID")

	// read subscription and write response
	d := types.NewDecoder(io.LimitedReader{R: s.s, N: minMessageSize})
	d.ReadPrefix()
	sub := d.ReadString()
	if d.Err() != nil {
		return types.Specifier{}, d.Err()
	}
	errStr := ""
	if sub != "host" {
		errStr = "bad subscription"
	}
	e := types.NewEncoder(s.s)
	e.WritePrefix(8)
	e.WriteString(errStr)
	if err := e.Flush(); err != nil {
		return types.Specifier{}, err
	} else if errStr != "" {
		return types.Specifier{}, errors.New(errStr)
	}

	err = s.readObject(&rpcID, minMessageSize)
	return
}

// ReadRequest reads an RPC request using the new loop protocol.
func (s *Stream) ReadRequest(req ProtocolObject, maxLen uint64) (err error) {
	defer wrapErr(&err, "ReadRequest")
	return s.readObject(req, maxLen)
}

// ReadResponse reads an RPC response. If the response is an error, it is
// returned directly.
func (s *Stream) ReadResponse(resp ProtocolObject, maxLen uint64) (err error) {
	defer wrapErr(&err, "ReadResponse")
	return s.readObject(resp, maxLen)
}

// Call is a helper method that writes a request and then reads a response.
func (s *Stream) Call(rpcID types.Specifier, req, resp ProtocolObject) error {
	if err := s.WriteRequest(rpcID, req); err != nil {
		return err
	}
	// use a maxlen large enough for all RPCs except Read, Write, and
	// SectorRoots (which don't use Call anyway)
	err := s.ReadResponse(resp, 4096)
	if errors.As(err, new(*RPCError)) {
		return fmt.Errorf("host rejected %v request: %w", rpcID, err)
	} else if err != nil {
		return fmt.Errorf("couldn't read %v response: %w", rpcID, err)
	}
	return nil
}

// SetDeadline sets the read and write deadlines associated with the Stream.
func (s *Stream) SetDeadline(t time.Time) error {
	return s.s.SetDeadline(t)
}

// Close closes the Stream.
func (s *Stream) Close() error {
	return s.s.Close()
}

// A Transport facilitates the exchange of RPCs via the renter-host protocol,
// version 3.
type Transport struct {
	mux *mux.Mux
}

// DialStream opens a new stream with the host.
func (t *Transport) DialStream() *Stream {
	s := t.mux.DialStream()
	return &Stream{s: s}
}

// AcceptStream accepts a new stream from the renter.
func (t *Transport) AcceptStream() (*Stream, error) {
	s, err := t.mux.AcceptStream()
	return &Stream{s: s}, err
}

// Close closes the protocol connection.
func (t *Transport) Close() error {
	return t.mux.Close()
}

// NewRenterTransport establishes a new RHPv3 session over the supplied connection.
func NewRenterTransport(conn net.Conn, hostKey types.PublicKey) (*Transport, error) {
	m, err := mux.Dial(conn, hostKey[:])
	if err != nil {
		return nil, err
	}

	// perform seed handshake
	s := m.DialStream()
	defer s.Close()
	buf := make([]byte, 8+8)
	binary.LittleEndian.PutUint64(buf[:8], 8)
	frand.Read(buf[8:])
	if _, err := s.Write(buf); err != nil {
		return nil, err
	} else if _, err := io.ReadFull(s, buf); err != nil {
		return nil, err
	}

	return &Transport{
		mux: m,
	}, nil
}

// NewHostTransport establishes a new RHPv3 session over the supplied connection.
func NewHostTransport(conn net.Conn, hostKey types.PrivateKey) (*Transport, error) {
	m, err := mux.Accept(conn, ed25519.PrivateKey(hostKey))
	if err != nil {
		return nil, err
	}

	// perform seed handshake
	s := m.DialStream()
	defer s.Close()
	buf := make([]byte, 8+8)
	if _, err := io.ReadFull(s, buf); err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint64(buf[:8], 8)
	frand.Read(buf[8:])
	if _, err := s.Write(buf); err != nil {
		return nil, err
	}

	return &Transport{
		mux: m,
	}, nil
}
