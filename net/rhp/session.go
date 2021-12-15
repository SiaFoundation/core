// Package rhp implements the Sia renter-host protocol.
package rhp

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"

	"go.sia.tech/core/net/mux"
	"go.sia.tech/core/types"
	"golang.org/x/crypto/blake2b"
	"lukechampine.com/frand"
)

const protocolVersion = 1

// ErrRenterClosed is returned by (*Session).ReadID when the renter sends the
// session termination signal.
var ErrRenterClosed = errors.New("renter has terminated session")

func hashChallenge(challenge [16]byte) [32]byte {
	c := make([]byte, 32)
	copy(c[:16], "challenge")
	copy(c[16:], challenge[:])
	return blake2b.Sum256(c)
}

// A Session is an ongoing exchange of RPCs via the renter-host protocol.
type Session struct {
	*mux.Mux
	challenge [16]byte
}

// SetChallenge sets the current session challenge. Challenges allow the host to
// verify that a renter controls the contract signing key before allowing them
// to lock the contract.
func (s *Session) SetChallenge(challenge [16]byte) {
	s.challenge = challenge
}

// SignChallenge signs the current session challenge.
func (s *Session) SignChallenge(priv types.PrivateKey) (sig types.Signature) {
	return priv.SignHash(hashChallenge(s.challenge))
}

// VerifyChallenge verifies a signature of the current session challenge.
func (s *Session) VerifyChallenge(sig types.Signature, pub types.PublicKey) bool {
	return pub.VerifyHash(hashChallenge(s.challenge), sig)
}

// AcceptSession conducts the host's half of the renter-host protocol handshake,
// returning a Session that can be used to handle RPC requests.
func AcceptSession(conn net.Conn, priv types.PrivateKey) (_ *Session, err error) {
	m, err := mux.Accept(conn, ed25519.PrivateKey(priv))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			m.Close()
		}
	}()
	// exchange versions and write initial challenge
	s, err := m.AcceptStream()
	if err != nil {
		return nil, err
	}
	defer s.Close()
	var buf [1]byte
	if _, err := s.Read(buf[:]); err != nil {
		return nil, fmt.Errorf("could not read peer version: %w", err)
	} else if _, err := s.Write([]byte{protocolVersion}); err != nil {
		return nil, fmt.Errorf("could not write our version: %w", err)
	} else if version := buf[0]; version != protocolVersion {
		return nil, fmt.Errorf("incompatible versions (ours = %v, theirs = %v)", protocolVersion, version)
	}
	challenge := frand.Entropy128()
	if _, err := s.Write(challenge[:]); err != nil {
		return nil, fmt.Errorf("couldn't write challenge: %w", err)
	}
	return &Session{
		Mux:       m,
		challenge: challenge,
	}, nil
}

// DialSession conducts the renter's half of the renter-host protocol handshake,
// returning a Session that can be used to make RPC requests.
func DialSession(conn net.Conn, pub types.PublicKey) (_ *Session, err error) {
	m, err := mux.Dial(conn, pub[:])
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			m.Close()
		}
	}()
	// exchange versions and read host's initial challenge
	s, err := m.DialStream()
	if err != nil {
		return nil, err
	}
	defer s.Close()
	var buf [1]byte
	if _, err := s.Write([]byte{protocolVersion}); err != nil {
		return nil, fmt.Errorf("could not write our version: %w", err)
	} else if _, err := s.Read(buf[:]); err != nil {
		return nil, fmt.Errorf("could not read peer version: %w", err)
	} else if version := buf[0]; version != protocolVersion {
		return nil, fmt.Errorf("incompatible versions (ours = %v, theirs = %v)", protocolVersion, version)
	}
	var challenge [16]byte
	if _, err := io.ReadFull(s, challenge[:]); err != nil {
		return nil, fmt.Errorf("couldn't read host challenge: %w", err)
	} else if challenge == ([16]byte{}) {
		return nil, errors.New("host rejected our version")
	}
	return &Session{
		Mux:       m,
		challenge: challenge,
	}, nil
}
