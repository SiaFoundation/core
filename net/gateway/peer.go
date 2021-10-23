package gateway

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"

	"go.sia.tech/core/net/mux"
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

func (h *Header) encodeTo(e *types.Encoder) {
	h.GenesisID.EncodeTo(e)
	e.Write(h.UniqueID[:])
	e.WriteString(h.NetAddress)
}

func (h *Header) decodeFrom(d *types.Decoder) {
	h.GenesisID.DecodeFrom(d)
	d.Read(h.UniqueID[:])
	h.NetAddress = d.ReadString()
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

// NOTE: unlike e.g. the RHP, we don't care about verifying the identity of who
// we connect to, so we use a hard-coded keypair for the mux handshake
var zeroPrivkey = ed25519.NewKeyFromSeed(make([]byte, 32))
var zeroPubkey = zeroPrivkey.Public().(ed25519.PublicKey)

// A Session is an ongoing exchange of RPCs via the gateway protocol.
type Session struct {
	*mux.Mux
	Peer Header
}

// DialSession initiates the gateway handshake with a peer, establishing a
// Session.
func DialSession(conn net.Conn, header Header) (_ *Session, err error) {
	m, err := mux.Dial(conn, zeroPubkey)
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
	e := types.NewEncoder(s)
	d := types.NewDecoder(io.LimitedReader{R: s, N: 1 + maxHeaderSize})

	// exchange versions
	e.WriteUint8(protocolVersion)
	if err := e.Flush(); err != nil {
		return nil, fmt.Errorf("could not write our version: %w", err)
	}
	remoteVersion := d.ReadUint8()
	if err := d.Err(); err != nil {
		return nil, err
	} else if remoteVersion == 0 {
		return nil, errRejectedVersion
	}

	// exchange headers
	header.encodeTo(e)
	if err := e.Flush(); err != nil {
		return nil, fmt.Errorf("could not write our header: %w", err)
	}
	var peerHeader Header
	peerHeader.decodeFrom(d)
	if err := d.Err(); err != nil {
		return nil, fmt.Errorf("could not read peer's header: %w", err)
	}

	return &Session{
		Mux:  m,
		Peer: peerHeader,
	}, nil
}

// AcceptSession reciprocates the gateway handshake with a peer, establishing a
// Session.
func AcceptSession(conn net.Conn, header Header) (_ *Session, err error) {
	m, err := mux.Accept(conn, zeroPrivkey)
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
	e := types.NewEncoder(s)
	d := types.NewDecoder(io.LimitedReader{R: s, N: 1 + maxHeaderSize})

	// exchange versions
	remoteVersion := d.ReadUint8()
	if err := d.Err(); err != nil {
		return nil, err
	} else if remoteVersion != protocolVersion {
		e.WriteUint8(0)
		e.Flush()
		return nil, errors.New("incompatible version")
	}
	e.WriteUint8(protocolVersion)
	if err := e.Flush(); err != nil {
		return nil, fmt.Errorf("could not write our version: %w", err)
	}

	// exchange headers
	var peerHeader Header
	peerHeader.decodeFrom(d)
	if err := d.Err(); err != nil {
		return nil, fmt.Errorf("could not read peer's header: %w", err)
	}
	header.encodeTo(e)
	if err := e.Flush(); err != nil {
		return nil, fmt.Errorf("could not write our header: %w", err)
	}
	if err := validateHeader(header, peerHeader); err != nil {
		return nil, fmt.Errorf("unacceptable header: %w", err)
	}

	return &Session{
		Mux:  m,
		Peer: peerHeader,
	}, nil
}
