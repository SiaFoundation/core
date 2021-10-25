package gateway

import (
	"errors"
	"fmt"
	"net"

	"go.sia.tech/core/net/mux"
	"go.sia.tech/core/net/rpc"
	"go.sia.tech/core/types"
)

const (
	protocolVersion = 1
)

var (
	errRejectedVersion = errors.New("peer rejected our version")
)

// A Header contains metadata that is exchanged when connecting to a peer.
type Header struct {
	GenesisID  types.BlockID
	UniqueID   [8]byte
	NetAddress string
}

func validateHeader(ours, theirs Header) error {
	if theirs.GenesisID != ours.GenesisID {
		return errors.New("peer has different genesis block")
	} else if theirs.UniqueID == ours.UniqueID {
		return errors.New("peer has same unique ID as us")
	} else if _, _, err := net.SplitHostPort(theirs.NetAddress); err != nil {
		return fmt.Errorf("invalid remote address: %w", err)
	}
	return nil
}

type rpcHeader Header

func (h *rpcHeader) EncodeTo(e *types.Encoder) {
	h.GenesisID.EncodeTo(e)
	e.Write(h.UniqueID[:])
	e.WriteString(h.NetAddress)
}

func (h *rpcHeader) DecodeFrom(d *types.Decoder) {
	h.GenesisID.DecodeFrom(d)
	d.Read(h.UniqueID[:])
	h.NetAddress = d.ReadString()
}

func (h *rpcHeader) MaxLen() int {
	return 1024 // arbitrary
}

// A Session is an ongoing exchange of RPCs via the gateway protocol.
type Session struct {
	*mux.Mux
	Peer Header
}

// DialSession initiates the gateway handshake with a peer, establishing a
// Session.
func DialSession(conn net.Conn, header Header) (_ *Session, err error) {
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
	var peerHeader Header
	if err := rpc.WriteObject(s, (*rpcHeader)(&header)); err != nil {
		return nil, fmt.Errorf("could not write our header: %w", err)
	} else if err := rpc.ReadObject(s, (*rpcHeader)(&peerHeader)); err != nil {
		return nil, fmt.Errorf("could not read peer's header: %w", err)
	} else if err := validateHeader(header, peerHeader); err != nil {
		return nil, fmt.Errorf("unacceptable header: %w", err)
	}

	return &Session{
		Mux:  m,
		Peer: peerHeader,
	}, nil
}

// AcceptSession reciprocates the gateway handshake with a peer, establishing a
// Session.
func AcceptSession(conn net.Conn, header Header) (_ *Session, err error) {
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
	var peerHeader Header
	if err := rpc.ReadObject(s, (*rpcHeader)(&peerHeader)); err != nil {
		return nil, fmt.Errorf("could not read peer's header: %w", err)
	} else if err := rpc.WriteObject(s, (*rpcHeader)(&header)); err != nil {
		return nil, fmt.Errorf("could not write our header: %w", err)
	} else if err := validateHeader(header, peerHeader); err != nil {
		return nil, fmt.Errorf("unacceptable header: %w", err)
	}

	return &Session{
		Mux:  m,
		Peer: peerHeader,
	}, nil
}
