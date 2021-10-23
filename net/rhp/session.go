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

const (
	// SectorSize is the size of one sector in bytes.
	SectorSize = 1 << 22 // 4 MiB

	protocolVersion = 1
)

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
func (s *Session) SignChallenge(priv ed25519.PrivateKey) (sig types.Signature) {
	return types.SignHash(priv, hashChallenge(s.challenge))
}

// VerifyChallenge verifies a signature of the current session challenge.
func (s *Session) VerifyChallenge(sig types.Signature, pub types.PublicKey) bool {
	return pub.VerifyHash(hashChallenge(s.challenge), sig)
}

// AcceptSession conducts the host's half of the renter-host protocol handshake,
// returning a Session that can be used to handle RPC requests.
func AcceptSession(conn net.Conn, priv ed25519.PrivateKey) (_ *Session, err error) {
	m, err := mux.Accept(conn, priv)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			m.Close()
		}
	}()
	// read renter's version and write initial challenge
	s, err := m.AcceptStream()
	if err != nil {
		return nil, err
	}
	defer s.Close()
	var buf [1]byte
	if _, err := s.Read(buf[:]); err != nil {
		return nil, err
	} else if version := buf[0]; version != protocolVersion {
		// incompatible version; send empty challenge to signal rejection
		var challenge [16]byte
		s.Write(challenge[:])
		return nil, fmt.Errorf("renter sent incompatible version (%d)", version)
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
func DialSession(conn net.Conn, pub ed25519.PublicKey) (_ *Session, err error) {
	m, err := mux.Dial(conn, pub)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			m.Close()
		}
	}()
	// write our version and read host's initial challenge
	s, err := m.DialStream()
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if _, err := s.Write([]byte{protocolVersion}); err != nil {
		return nil, fmt.Errorf("couldn't write our version: %w", err)
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
