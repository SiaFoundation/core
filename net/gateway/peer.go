package gateway

import (
	"errors"
	"fmt"
	"net"

	"go.sia.tech/core/net/mux"
	"go.sia.tech/core/net/rpc"
	"go.sia.tech/core/types"
	"lukechampine.com/frand"
)

const protocolVersion = 1

var errRejectedVersion = errors.New("peer rejected our version")

// A UniqueID is a randomly-generated nonce that helps prevent self-connections
// and double-connections.
type UniqueID [8]byte

// GenerateUniqueID returns a random UniqueID.
func GenerateUniqueID() (id UniqueID) {
	frand.Read(id[:])
	return
}

type rpcHeader struct {
	GenesisID types.BlockID
	UniqueID  [8]byte
}

func validateHeader(ours, theirs rpcHeader) error {
	if theirs.GenesisID != ours.GenesisID {
		return errors.New("peer has different genesis block")
	} else if theirs.UniqueID == ours.UniqueID {
		return errors.New("peer has same unique ID as us")
	}
	return nil
}

func (h *rpcHeader) EncodeTo(e *types.Encoder) {
	h.GenesisID.EncodeTo(e)
	e.Write(h.UniqueID[:])
}

func (h *rpcHeader) DecodeFrom(d *types.Decoder) {
	h.GenesisID.DecodeFrom(d)
	d.Read(h.UniqueID[:])
}

func (h *rpcHeader) MaxLen() int {
	return 1024 // arbitrary
}

// A Session is an ongoing exchange of RPCs via the gateway protocol.
type Session struct {
	*mux.Mux
	RemoteAddr string
	RemoteID   UniqueID
}

// DialSession initiates the gateway handshake with a peer, establishing a
// Session.
func DialSession(conn net.Conn, genesisID types.BlockID, uid UniqueID) (_ *Session, err error) {
	m, err := mux.DialAnonymous(conn)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			m.Close()
		}
	}()
	s, err := m.DialStream()
	if err != nil {
		return nil, err
	}
	defer s.Close()

	// exchange versions
	var buf [1]byte
	if _, err := s.Write([]byte{protocolVersion}); err != nil {
		return nil, fmt.Errorf("could not write our version: %w", err)
	} else if _, err := s.Read(buf[:]); err != nil {
		return nil, fmt.Errorf("could not read peer version: %w", err)
	} else if version := buf[0]; version != protocolVersion {
		return nil, fmt.Errorf("incompatible versions (ours = %v, theirs = %v)", protocolVersion, version)
	}

	// exchange headers
	ourHeader := rpcHeader{genesisID, uid}
	var peerHeader rpcHeader
	if err := rpc.WriteObject(s, &ourHeader); err != nil {
		return nil, fmt.Errorf("could not write our header: %w", err)
	} else if err := rpc.ReadObject(s, &peerHeader); err != nil {
		return nil, fmt.Errorf("could not read peer's header: %w", err)
	} else if err := validateHeader(ourHeader, peerHeader); err != nil {
		return nil, fmt.Errorf("unacceptable header: %w", err)
	}

	return &Session{
		Mux:        m,
		RemoteAddr: conn.RemoteAddr().String(),
		RemoteID:   peerHeader.UniqueID,
	}, nil
}

// AcceptSession reciprocates the gateway handshake with a peer, establishing a
// Session.
func AcceptSession(conn net.Conn, genesisID types.BlockID, uid UniqueID) (_ *Session, err error) {
	m, err := mux.AcceptAnonymous(conn)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			m.Close()
		}
	}()
	s, err := m.AcceptStream()
	if err != nil {
		return nil, err
	}
	defer s.Close()

	// exchange versions
	var buf [1]byte
	if _, err := s.Read(buf[:]); err != nil {
		return nil, fmt.Errorf("could not read peer version: %w", err)
	} else if _, err := s.Write([]byte{protocolVersion}); err != nil {
		return nil, fmt.Errorf("could not write our version: %w", err)
	} else if version := buf[0]; version != protocolVersion {
		return nil, fmt.Errorf("incompatible versions (ours = %v, theirs = %v)", protocolVersion, version)
	}

	// exchange headers
	ourHeader := rpcHeader{genesisID, uid}
	var peerHeader rpcHeader
	if err := rpc.ReadObject(s, &peerHeader); err != nil {
		return nil, fmt.Errorf("could not read peer's header: %w", err)
	} else if err := rpc.WriteObject(s, &ourHeader); err != nil {
		return nil, fmt.Errorf("could not write our header: %w", err)
	} else if err := validateHeader(ourHeader, peerHeader); err != nil {
		return nil, fmt.Errorf("unacceptable header: %w", err)
	}

	return &Session{
		Mux:        m,
		RemoteAddr: conn.RemoteAddr().String(),
		RemoteID:   peerHeader.UniqueID,
	}, nil
}
