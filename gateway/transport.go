package gateway

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"go.sia.tech/core/internal/smux"
	"go.sia.tech/core/types"
	"go.sia.tech/mux"
	"lukechampine.com/frand"
)

// A UniqueID is a randomly-generated nonce that helps prevent self-connections
// and double-connections.
type UniqueID [8]byte

// GenerateUniqueID returns a random UniqueID.
func GenerateUniqueID() (id UniqueID) {
	frand.Read(id[:])
	return
}

// A Header contains various peer metadata which is exchanged during the gateway
// handshake.
type Header struct {
	GenesisID  types.BlockID
	UniqueID   UniqueID
	NetAddress string
}

func validateHeader(ours, theirs Header) error {
	if theirs.GenesisID != ours.GenesisID {
		return errors.New("peer has different genesis block")
	} else if theirs.UniqueID == ours.UniqueID {
		return errors.New("peer has same unique ID as us")
	}
	return nil
}

func writeHeader(conn net.Conn, ourHeader Header) error {
	var accept string
	if err := withV1Encoder(conn, ourHeader.encodeTo); err != nil {
		return fmt.Errorf("could not write our header: %w", err)
	} else if err := withV1Decoder(conn, 128, func(d *types.Decoder) { accept = d.ReadString() }); err != nil {
		return fmt.Errorf("could not read peer header acceptance: %w", err)
	} else if accept != "accept" {
		return fmt.Errorf("peer rejected our header: %v", accept)
	}
	return nil
}

func readHeader(conn net.Conn, ourHeader Header, dialAddr *string, uniqueID *UniqueID) error {
	var peerHeader Header
	if err := withV1Decoder(conn, 32+8+128, peerHeader.decodeFrom); err != nil {
		return fmt.Errorf("could not read peer's header: %w", err)
	} else if err := validateHeader(ourHeader, peerHeader); err != nil {
		withV1Encoder(conn, func(e *types.Encoder) { e.WriteString(err.Error()) })
		return fmt.Errorf("unacceptable header: %w", err)
	} else if err := withV1Encoder(conn, func(e *types.Encoder) { e.WriteString("accept") }); err != nil {
		return fmt.Errorf("could not write accept: %w", err)
	} else if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err != nil {
		return fmt.Errorf("invalid remote addr (%q): %w", conn.RemoteAddr(), err)
	} else if _, port, err := net.SplitHostPort(peerHeader.NetAddress); err != nil {
		return fmt.Errorf("peer provided invalid net address (%q): %w", peerHeader.NetAddress, err)
	} else {
		*dialAddr = net.JoinHostPort(host, port)
		*uniqueID = peerHeader.UniqueID
	}
	return nil
}

// A Transport provides a multiplexing transport for the Sia gateway protocol.
type Transport struct {
	UniqueID UniqueID
	Version  string
	Addr     string
	smux     *smux.Session // for v1
	mux      *mux.Mux      // for v2
}

// DialStream opens a new multiplexed stream.
func (t *Transport) DialStream() (*Stream, error) {
	if t.smux != nil {
		s, err := t.smux.OpenStream()
		return &Stream{smux: s}, err
	}
	return &Stream{mux: t.mux.DialStream()}, nil
}

// AcceptStream accepts an incoming multiplexed stream.
func (t *Transport) AcceptStream() (*Stream, error) {
	if t.smux != nil {
		s, err := t.smux.AcceptStream()
		return &Stream{smux: s}, err
	}
	s, err := t.mux.AcceptStream()
	return &Stream{mux: s}, err
}

// SupportsV2 returns true if the transport supports v2 RPCs.
func (t *Transport) SupportsV2() bool { return t.mux != nil }

// Close closes the underlying connection.
func (t *Transport) Close() error {
	if t.smux != nil {
		return t.smux.Close()
	}
	return t.mux.Close()
}

// A Stream provides a multiplexed stream for the Sia gateway protocol.
type Stream struct {
	smux *smux.Stream // for v1
	mux  *mux.Stream  // for v2
}

func (s *Stream) withEncoder(fn func(*types.Encoder)) error {
	if s.smux != nil {
		return withV1Encoder(s.smux, fn)
	}
	return withV2Encoder(s.mux, fn)
}

func (s *Stream) withDecoder(maxLen int, fn func(*types.Decoder)) error {
	if s.smux != nil {
		return withV1Decoder(s.smux, maxLen, fn)
	}
	return withV2Decoder(s.mux, maxLen, fn)
}

// WriteID writes the RPC ID of r to the stream.
func (s *Stream) WriteID(r Object) error {
	id := idForObject(r)
	if s.smux != nil {
		return s.withEncoder((*v1RPCID)(&id).encodeTo)
	}
	return s.withEncoder(id.EncodeTo)
}

// ReadID reads an RPC ID from the stream.
func (s *Stream) ReadID() (id types.Specifier, err error) {
	if s.smux != nil {
		err = s.withDecoder(8, (*v1RPCID)(&id).decodeFrom)
	} else {
		err = s.withDecoder(16, id.DecodeFrom)
	}
	return
}

// WriteRequest writes the request field of r to the stream.
func (s *Stream) WriteRequest(r Object) error {
	return s.withEncoder(r.encodeRequest)
}

// ReadRequest reads a request from the stream into r.
func (s *Stream) ReadRequest(r Object) error {
	if r.maxRequestLen() == 0 {
		return nil
	}
	return s.withDecoder(r.maxRequestLen(), r.decodeRequest)
}

// WriteResponse writes the response field of r to the stream.
func (s *Stream) WriteResponse(r Object) error {
	return s.withEncoder(r.encodeResponse)
}

// ReadResponse reads a response from the stream into r.
func (s *Stream) ReadResponse(r Object) error {
	if r.maxResponseLen() == 0 {
		return nil
	}
	return s.withDecoder(r.maxResponseLen(), r.decodeResponse)
}

// SetDeadline implements net.Conn.
func (s *Stream) SetDeadline(t time.Time) error {
	if s.smux != nil {
		return s.smux.SetDeadline(t)
	}
	return s.mux.SetDeadline(t)
}

// Close closes the stream.
func (s *Stream) Close() error {
	if s.smux != nil {
		return s.smux.Close()
	}
	return s.mux.Close()
}

// Dial initiates the gateway handshake with a peer.
func Dial(conn net.Conn, ourHeader Header) (*Transport, error) {
	p := &Transport{}

	// exchange versions
	const ourVersion = "2.0.0"
	if err := withV1Encoder(conn, func(e *types.Encoder) { e.WriteString(ourVersion) }); err != nil {
		return nil, fmt.Errorf("could not write our version: %w", err)
	} else if err := withV1Decoder(conn, 128, func(d *types.Decoder) { p.Version = d.ReadString() }); err != nil {
		return nil, fmt.Errorf("could not read peer version: %w", err)
	}
	// exchange headers
	if err := writeHeader(conn, ourHeader); err != nil {
		return nil, fmt.Errorf("could not write our header: %w", err)
	} else if err := readHeader(conn, ourHeader, &p.Addr, &p.UniqueID); err != nil {
		return nil, fmt.Errorf("could not read peer's header: %w", err)
	}
	// establish mux
	var err error
	if strings.HasPrefix(p.Version, "1.") {
		p.smux, err = smux.Client(conn, nil)
	} else {
		p.mux, err = mux.DialAnonymous(conn)
	}
	return p, err
}

// Accept reciprocates the gateway handshake with a peer.
func Accept(conn net.Conn, ourHeader Header) (*Transport, error) {
	p := &Transport{}

	// exchange versions
	const ourVersion = "2.0.0"
	if err := withV1Decoder(conn, 128, func(d *types.Decoder) { p.Version = d.ReadString() }); err != nil {
		return nil, fmt.Errorf("could not read peer version: %w", err)
	} else if err := withV1Encoder(conn, func(e *types.Encoder) { e.WriteString(ourVersion) }); err != nil {
		return nil, fmt.Errorf("could not write our version: %w", err)
	}
	// exchange headers
	if err := readHeader(conn, ourHeader, &p.Addr, &p.UniqueID); err != nil {
		return nil, fmt.Errorf("could not read peer's header: %w", err)
	} else if err := writeHeader(conn, ourHeader); err != nil {
		return nil, fmt.Errorf("could not write our header: %w", err)
	}
	// establish mux
	var err error
	if strings.HasPrefix(p.Version, "1.") {
		p.smux, err = smux.Server(conn, nil)
	} else {
		p.mux, err = mux.AcceptAnonymous(conn)
	}
	return p, err
}
