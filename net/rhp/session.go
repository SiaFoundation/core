// Package rhp implements the Sia renter-host protocol.
package rhp

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"go.sia.tech/core/types"
	"golang.org/x/crypto/blake2b"
	"lukechampine.com/frand"
)

// SectorSize is the size of one sector in bytes.
const SectorSize = 1 << 22 // 4 MiB

// ErrRenterClosed is returned by (*Session).ReadID when the renter sends the
// session termination signal.
var ErrRenterClosed = errors.New("renter has terminated session")

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

// SetChallenge sets the current session challenge. Challenges allow the host to
// verify that a renter controls the contract signing key before allowing them
// to lock the contract.
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
	return types.SignHash(priv, hashChallenge(s.challenge))
}

// VerifyChallenge verifies a signature of the current session challenge.
func (s *Session) VerifyChallenge(sig types.Signature, pub types.PublicKey) bool {
	return pub.VerifyHash(hashChallenge(s.challenge), sig)
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
	err = s.readMessage(&rpcID, 16)
	if rpcID == loopExit {
		err = ErrRenterClosed
	} else if err != nil {
		err = fmt.Errorf("ReadID: %w", err)
	}
	return
}

// ReadRequest reads an RPC request using the new loop protocol.
func (s *Session) ReadRequest(req ProtocolObject, maxLen uint64) error {
	if err := s.readMessage(req, maxLen); err != nil {
		return fmt.Errorf("ReadRequest: %w", err)
	}
	return nil
}

// WriteResponse writes an RPC response object or error. Either resp or err must
// be nil. If err is an *RPCError, it is sent directly; otherwise, a generic
// RPCError is created from err's Error string.
func (s *Session) WriteResponse(resp ProtocolObject, err error) error {
	re, ok := err.(*RPCError)
	if err != nil && !ok {
		re = &RPCError{Description: err.Error()}
	}

	if err := s.writeMessage(&rpcResponse{re, resp}); err != nil {
		return fmt.Errorf("WriteResponse: %w", err)
	}
	return nil
}

// ReadResponse reads an RPC response. If the response is an error, it is
// returned directly.
func (s *Session) ReadResponse(resp ProtocolObject, maxLen uint64) error {
	rr := rpcResponse{nil, resp}
	if err := s.readMessage(&rr, maxLen); err != nil {
		return fmt.Errorf("failed to read message: %w", err)
	} else if rr.err != nil {
		return fmt.Errorf("response error: %w", rr.err)
	}
	return nil
}

// Close gracefully terminates the RPC loop and closes the connection.
func (s *Session) Close() error {
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
func NewHostSession(conn io.ReadWriteCloser) (*Session, error) {
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
func NewRenterSession(conn io.ReadWriteCloser) (*Session, error) {
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
