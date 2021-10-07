// Package rhp implements the Sia renter-host protocol.
package rhp

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"lukechampine.com/frand"
	"net"
	"sync"

	"go.sia.tech/core/types"
	"golang.org/x/crypto/blake2b"
)

// SectorSize is the size of one sector in bytes.
const SectorSize = 1 << 22 // 4 MiB

// ErrRenterClosed is returned by (*Session).ReadID when the renter sends the
// session termination signal.
var ErrRenterClosed = errors.New("renter has terminated session")

func wrapErr(err *error, fnName string) {
	if *err != nil {
		*err = fmt.Errorf("%s: %w", fnName, *err)
	}
}

// A Session is an ongoing exchange of RPCs via the renter-host protocol.
type Session struct {
	conn      io.ReadWriteCloser
	challenge [16]byte
	isRenter  bool

	mu     sync.Mutex
	err    error // set when Session is prematurely closed
	closed bool
}

func (s *Session) setErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil && s.err == nil {
		if ne, ok := err.(net.Error); !ok || !ne.Temporary() {
			s.conn.Close()
			s.err = err
		}
	}
}

// PrematureCloseErr returns the error that resulted in the Session being closed
// prematurely.
func (s *Session) PrematureCloseErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// IsClosed returns whether the Session is closed. Check PrematureCloseErr to
// determine whether the Session was closed gracefully.
func (s *Session) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed || s.err != nil
}

// SetChallenge sets the current session challenge.
func (s *Session) SetChallenge(challenge [16]byte) {
	s.challenge = challenge
}

func hashChallenge(challenge [16]byte) [32]byte {
	c := make([]byte, 32)
	copy(c[:16], "challenge")
	copy(c[16:], challenge[:])
	return blake2b.Sum256(c)
}

// SignChallenge signs the current session challenge.
func (s *Session) SignChallenge(priv ed25519.PrivateKey) (sig types.Signature) {
	h := hashChallenge(s.challenge)
	copy(sig[:], ed25519.Sign(priv, h[:]))
	return
}

// VerifyChallenge verifies a signature of the current session challenge.
func (s *Session) VerifyChallenge(sig types.Signature, pub ed25519.PublicKey) bool {
	h := hashChallenge(s.challenge)
	return ed25519.Verify(pub, h[:], sig[:])
}

// Write implements io.Writer.
func (s *Session) Write(p []byte) (int, error) { return s.conn.Write(p) }

// Read implements io.Reader.
func (s *Session) Read(p []byte) (int, error) { return s.conn.Read(p) }

func (s *Session) writeMessage(obj ProtocolObject) error {
	if err := s.PrematureCloseErr(); err != nil {
		return err
	}
	e := types.NewEncoder(s.conn)
	obj.encodeTo(e)
	err := e.Flush()
	s.setErr(err)
	return err
}

func (s *Session) readMessage(obj ProtocolObject, maxLen uint64) error {
	if err := s.PrematureCloseErr(); err != nil {
		return err
	}
	d := types.NewDecoder(io.LimitedReader{R: s.conn, N: int64(maxLen)})
	obj.decodeFrom(d)
	s.setErr(d.Err())
	return d.Err()
}

// WriteRequest sends an RPC request, comprising an RPC ID and a request object.
func (s *Session) WriteRequest(rpcID Specifier, req ProtocolObject) error {
	if err := s.writeMessage(&rpcID); err != nil {
		return fmt.Errorf("WriteRequestID: %w", err)
	}
	if req != nil {
		if err := s.writeMessage(req); err != nil {
			return fmt.Errorf("WriteRequest: %w", err)
		}
	}
	return nil
}

// ReadID reads an RPC request ID. If the renter sends the session termination
// signal, ReadID returns ErrRenterClosed.
func (s *Session) ReadID() (rpcID Specifier, err error) {
	defer wrapErr(&err, "ReadID")
	err = s.readMessage(&rpcID, 16)
	if rpcID == loopExit {
		err = ErrRenterClosed
	}
	return
}

// ReadRequest reads an RPC request using the new loop protocol.
func (s *Session) ReadRequest(req ProtocolObject, maxLen uint64) (err error) {
	defer wrapErr(&err, "ReadRequest")
	return s.readMessage(req, maxLen)
}

// WriteResponse writes an RPC response object or error. Either resp or err must
// be nil. If err is an *RPCError, it is sent directly; otherwise, a generic
// RPCError is created from err's Error string.
func (s *Session) WriteResponse(resp ProtocolObject, err error) (e error) {
	defer wrapErr(&e, "WriteResponse")
	re, ok := err.(*RPCError)
	if err != nil && !ok {
		re = &RPCError{Description: err.Error()}
	}
	return s.writeMessage(&rpcResponse{re, resp})
}

// ReadResponse reads an RPC response. If the response is an error, it is
// returned directly.
func (s *Session) ReadResponse(resp ProtocolObject, maxLen uint64) (err error) {
	defer wrapErr(&err, "ReadResponse")
	rr := rpcResponse{nil, resp}
	if err := s.readMessage(&rr, maxLen); err != nil {
		return err
	} else if rr.err != nil {
		return rr.err
	}
	return nil
}

// Close gracefully terminates the RPC loop and closes the connection.
func (s *Session) Close() (err error) {
	defer wrapErr(&err, "Close")
	if s.IsClosed() {
		return nil
	}
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	if s.isRenter {
		s.writeMessage(&loopExit)
	}
	return s.conn.Close()
}

// NewHostSession conducts the hosts's half of the renter-host protocol
// handshake, returning a Session that can be used to handle RPC requests.
func NewHostSession(conn io.ReadWriteCloser) (_ *Session, err error) {
	defer wrapErr(&err, "NewHostSession")
	s := &Session{
		conn:     conn,
		isRenter: false,
	}
	frand.Read(s.challenge[:])
	// hack: cast challenge to Specifier to make it a ProtocolObject
	if err := s.writeMessage((*Specifier)(&s.challenge)); err != nil {
		return nil, fmt.Errorf("couldn't write challenge: %w", err)
	}
	return s, nil
}

// NewRenterSession conducts the renter's half of the renter-host protocol
// handshake, returning a Session that can be used to make RPC requests.
func NewRenterSession(conn io.ReadWriteCloser) (_ *Session, err error) {
	defer wrapErr(&err, "NewRenterSession")
	s := &Session{
		conn:     conn,
		isRenter: true,
	}
	// hack: cast challenge to Specifier to make it a ProtocolObject
	if err := s.readMessage((*Specifier)(&s.challenge), 16); err != nil {
		return nil, fmt.Errorf("couldn't read host's challenge: %w", err)
	}
	return s, nil
}
