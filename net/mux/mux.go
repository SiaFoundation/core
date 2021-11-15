package mux

import (
	"bytes"
	"crypto/cipher"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// Errors relating to stream or mux shutdown.
var (
	ErrClosedConn       = errors.New("underlying connection was closed")
	ErrClosedStream     = errors.New("stream was gracefully closed")
	ErrPeerClosedStream = errors.New("peer closed stream gracefully")
	ErrPeerClosedConn   = errors.New("peer closed underlying connection")
)

// A Mux multiplexes multiple duplex Streams onto a single net.Conn.
type Mux struct {
	conn     net.Conn
	aead     cipher.AEAD
	settings connSettings

	// all subsequent fields are guarded by mu
	mu      sync.Mutex
	cond    sync.Cond
	streams map[uint32]*Stream
	nextID  uint32
	err     error // sticky and fatal
	write   struct {
		header   frameHeader
		payload  []byte
		timedOut bool
		cond     sync.Cond // separate cond for waking a single bufferFrame
	}
}

// setErr sets the Mux error and wakes up all Mux-related goroutines. If m.err
// is already set, setErr is a no-op.
func (m *Mux) setErr(err error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}

	// try to detect when the peer closed the connection
	if isConnCloseError(err) {
		err = ErrPeerClosedConn
	}

	// set sticky error, close conn, and wake everyone up
	m.err = err
	for _, s := range m.streams {
		s.cond.L.Lock()
		s.err = err
		s.cond.Broadcast()
		s.cond.L.Unlock()
	}
	m.conn.Close()
	m.cond.Broadcast()
	m.write.cond.Broadcast()
	return err
}

// bufferFrame blocks until it can store its frame in the m.write struct. It
// returns early with an error if m.err is set or if the deadline expires.
func (m *Mux) bufferFrame(h frameHeader, payload []byte, deadline time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !deadline.IsZero() {
		if !time.Now().Before(deadline) {
			return os.ErrDeadlineExceeded
		}
		timer := time.AfterFunc(time.Until(deadline), m.write.cond.Broadcast) // nice
		defer timer.Stop()
	}
	// wait for current frame to be consumed
	for m.write.header.id != 0 && m.err == nil && (deadline.IsZero() || time.Now().Before(deadline)) {
		m.write.cond.Wait()
	}
	if m.err != nil {
		return m.err
	} else if !deadline.IsZero() && !time.Now().Before(deadline) {
		return os.ErrDeadlineExceeded
	}
	// queue our frame and wake the writeLoop
	//
	// NOTE: it is not necessary to wait for the writeLoop to flush our frame. A
	// successful write() syscall doesn't mean that the peer actually received
	// the data, just that the packets are sitting in a kernel buffer somewhere.
	m.write.header = h
	m.write.payload = append(m.write.payload[:0], payload...)
	m.cond.Broadcast()
	return nil
}

// writeLoop handles the actual Writes to the Mux's net.Conn. It waits for a
// bufferFrame call to fill the m.write buffer, then Writes the frame and wakes
// up the next bufferFrame call (if any). It also handles keepalives.
func (m *Mux) writeLoop() {
	// wake cond whenever a keepalive is due
	//
	// NOTE: we send a keepalive when 75% of the MaxTimeout has elapsed
	keepaliveInterval := m.settings.MaxTimeout - m.settings.MaxTimeout/4
	nextKeepalive := time.Now().Add(keepaliveInterval)
	timer := time.AfterFunc(keepaliveInterval, m.cond.Broadcast)
	defer timer.Stop()

	writeBuf := make([]byte, m.settings.maxFrameSize())
	for {
		// wait for a frame
		m.mu.Lock()
		for m.write.header.id == 0 && m.err == nil && time.Now().Before(nextKeepalive) {
			m.cond.Wait()
		}
		if m.err != nil {
			m.mu.Unlock()
			return
		}
		// if we have a normal frame, use that; otherwise, send a keepalive
		//
		// NOTE: even if we were woken by the keepalive timer, there might be a
		// normal frame ready to send, in which case we don't need a keepalive
		h, payload := m.write.header, m.write.payload
		if h.id == 0 {
			h, payload = frameHeader{id: idKeepalive}, nil
		}
		frame := encryptFrame(writeBuf, h, payload, m.settings.RequestedPacketSize, m.aead)
		m.mu.Unlock()

		// reset keepalive timer
		timer.Stop()
		timer.Reset(keepaliveInterval)
		nextKeepalive = time.Now().Add(keepaliveInterval)

		// write the frame
		if _, err := m.conn.Write(frame); err != nil {
			m.setErr(err)
			return
		}

		// clear the payload and wake at most one bufferFrame call
		m.mu.Lock()
		m.write.header = frameHeader{}
		m.write.payload = m.write.payload[:0]
		m.write.cond.Signal()
		m.mu.Unlock()
	}
}

// readLoop handles the actual Reads from the Mux's net.Conn. It waits for a
// frame to arrive, then routes it to the appropriate Stream, creating a new
// Stream if none exists. It then waits for the frame to be fully consumed by
// the Stream before attempting to Read again.
func (m *Mux) readLoop() {
	var curStream *Stream // saves a lock acquisition + map lookup in the common case
	buf := make([]byte, m.settings.maxFrameSize())
	for {
		h, payload, err := readEncryptedFrame(m.conn, buf, m.settings.RequestedPacketSize, m.aead)
		if err != nil {
			m.setErr(err)
			return
		}
		switch h.id {
		case idErrorBadInit, idEstablishEncryption, idUpdateSettings:
			// peer is behaving weirdly; after initialization, we shouldn't
			// receive any of these IDs
			m.setErr(errors.New("peer sent invalid frame ID"))
			return
		case idKeepalive:
			continue // no action required
		default:
			// look for matching Stream
			if curStream == nil || h.id != curStream.id {
				m.mu.Lock()
				if s := m.streams[h.id]; s != nil {
					curStream = s
				} else {
					if h.flags&flagFirst == 0 {
						// we don't recognize the frame's ID, but it's not the
						// first frame of a new stream either; we must have
						// already closed the stream this frame belongs to, so
						// ignore it
						m.mu.Unlock()
						continue
					}
					// create a new stream
					curStream = &Stream{
						m:           m,
						id:          h.id,
						needAccept:  true,
						cond:        sync.Cond{L: new(sync.Mutex)},
						established: true,
					}
					m.streams[h.id] = curStream
					m.cond.Broadcast() // wake (*Mux).AcceptStream
				}
				m.mu.Unlock()
			}
			curStream.consumeFrame(h, payload)
		}
	}
}

// Close closes the underlying net.Conn.
func (m *Mux) Close() error {
	// if there's a buffered Write, wait for it to be sent
	m.mu.Lock()
	for m.write.header.id != 0 && m.err == nil {
		m.write.cond.Wait()
	}
	m.mu.Unlock()
	err := m.setErr(ErrClosedConn)
	if err == ErrClosedConn || err == ErrPeerClosedConn {
		err = nil
	}
	return err
}

// AcceptStream waits for and returns the next peer-initiated Stream.
func (m *Mux) AcceptStream() (*Stream, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for {
		if m.err != nil {
			return nil, m.err
		}
		for _, s := range m.streams {
			if s.needAccept {
				s.needAccept = false
				return s, nil
			}
		}
		m.cond.Wait()
	}
}

// DialStream creates a new Stream.
//
// Unlike e.g. net.Dial, this does not perform any I/O; the peer will not be
// aware of the new Stream until Write is called.
func (m *Mux) DialStream() (*Stream, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	s := &Stream{
		m:           m,
		id:          m.nextID,
		needAccept:  false,
		cond:        sync.Cond{L: new(sync.Mutex)},
		established: false,
	}
	m.nextID += 2
	m.streams[s.id] = s
	return s, nil
}

// newMux initializes a Mux and spawns its readLoop and writeLoop goroutines.
func newMux(conn net.Conn, aead cipher.AEAD, settings connSettings) *Mux {
	m := &Mux{
		conn:     conn,
		aead:     aead,
		settings: settings,
		streams:  make(map[uint32]*Stream),
		nextID:   1 << 8, // avoid collisions with reserved IDs
	}
	// both conds use the same mutex
	m.cond.L = &m.mu
	m.write.cond.L = &m.mu
	go m.readLoop()
	go m.writeLoop()
	return m
}

// Dial initiates a mux protocol handshake on the provided conn.
func Dial(conn net.Conn, theirKey ed25519.PublicKey) (*Mux, error) {
	if err := initiateVersionHandshake(conn); err != nil {
		return nil, fmt.Errorf("version handshake failed: %w", err)
	}
	aead, err := initiateEncryptionHandshake(conn, theirKey)
	if err != nil {
		return nil, fmt.Errorf("encryption handshake failed: %w", err)
	}
	settings, err := initiateSettingsHandshake(conn, defaultConnSettings, aead)
	if err != nil {
		return nil, fmt.Errorf("settings handshake failed: %w", err)
	}
	return newMux(conn, aead, settings), nil
}

// Accept reciprocates a mux protocol handshake on the provided conn.
func Accept(conn net.Conn, ourKey ed25519.PrivateKey) (*Mux, error) {
	if err := acceptVersionHandshake(conn); err != nil {
		return nil, fmt.Errorf("version handshake failed: %w", err)
	}
	aead, err := acceptEncryptionHandshake(conn, ourKey)
	if err != nil {
		return nil, fmt.Errorf("encryption handshake failed: %w", err)
	}
	settings, err := acceptSettingsHandshake(conn, defaultConnSettings, aead)
	if err != nil {
		return nil, fmt.Errorf("settings handshake failed: %w", err)
	}
	m := newMux(conn, aead, settings)
	m.nextID++ // avoid collisions with Dialing peer
	return m, nil
}

var anonPrivkey = ed25519.NewKeyFromSeed(make([]byte, 32))
var anonPubkey = anonPrivkey.Public().(ed25519.PublicKey)

// DialAnonymous initiates a mux protocol handshake to a party without a
// pre-established identity. The counterparty must reciprocate the handshake with
// AcceptAnonymous.
func DialAnonymous(conn net.Conn) (*Mux, error) { return Dial(conn, anonPubkey) }

// AcceptAnonymous reciprocates a mux protocol handshake without a
// pre-established identity. The counterparty must initiate the handshake with
// DialAnonymous.
func AcceptAnonymous(conn net.Conn) (*Mux, error) { return Accept(conn, anonPrivkey) }

// A Stream is a duplex connection multiplexed over a net.Conn. It implements
// the net.Conn interface.
type Stream struct {
	m          *Mux
	id         uint32
	needAccept bool // managed by Mux

	cond        sync.Cond // guards + synchronizes subsequent fields
	established bool      // has the first frame been sent?
	err         error
	readBuf     []byte
	rd, wd      time.Time // deadlines
}

// LocalAddr returns the underlying connection's LocalAddr.
func (s *Stream) LocalAddr() net.Addr { return s.m.conn.LocalAddr() }

// RemoteAddr returns the underlying connection's RemoteAddr.
func (s *Stream) RemoteAddr() net.Addr { return s.m.conn.RemoteAddr() }

// SetDeadline sets the read and write deadlines associated with the Stream. It
// is equivalent to calling both SetReadDeadline and SetWriteDeadline.
//
// This implementation does not entirely conform to the net.Conn interface:
// setting a new deadline does not affect pending Read or Write calls, only
// future calls.
func (s *Stream) SetDeadline(t time.Time) error {
	s.SetReadDeadline(t)
	s.SetWriteDeadline(t)
	return nil
}

// SetReadDeadline sets the read deadline associated with the Stream.
//
// This implementation does not entirely conform to the net.Conn interface:
// setting a new deadline does not affect pending Read calls, only future calls.
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	s.rd = t
	return nil
}

// SetWriteDeadline sets the write deadline associated with the Stream.
//
// This implementation does not entirely conform to the net.Conn interface:
// setting a new deadline does not affect pending Write calls, only future
// calls.
func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	s.wd = t
	return nil
}

// consumeFrame stores a frame in s.readBuf and waits for it to be consumed by
// (*Stream).Read calls.
func (s *Stream) consumeFrame(h frameHeader, payload []byte) {
	if h.flags&flagLast != 0 {
		// stream is closing; set s.err
		err := ErrPeerClosedStream
		if h.flags&flagError != 0 {
			err = errors.New(string(payload))
		}
		s.cond.L.Lock()
		s.err = err
		s.cond.Broadcast() // wake Read
		s.cond.L.Unlock()

		// delete stream from Mux
		s.m.mu.Lock()
		delete(s.m.streams, s.id)
		s.m.mu.Unlock()
		return
	}
	// set payload and wait for it to be consumed
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	s.readBuf = payload
	s.cond.Broadcast() // wake Read
	for len(s.readBuf) > 0 && s.err == nil {
		s.cond.Wait()
	}
}

// Read reads data from the Stream.
func (s *Stream) Read(p []byte) (int, error) {
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	if !s.established {
		// developer error: peer doesn't know this Stream exists yet
		panic("mux: Read called before Write on newly-Dialed Stream")
	}
	if !s.rd.IsZero() {
		if !time.Now().Before(s.rd) {
			return 0, os.ErrDeadlineExceeded
		}
		timer := time.AfterFunc(time.Until(s.rd), s.cond.Broadcast)
		defer timer.Stop()
	}
	for len(s.readBuf) == 0 && s.err == nil && (s.rd.IsZero() || time.Now().Before(s.rd)) {
		s.cond.Wait()
	}
	if s.err != nil {
		if s.err == ErrPeerClosedStream {
			return 0, io.EOF
		}
		return 0, s.err
	} else if !s.rd.IsZero() && !time.Now().Before(s.rd) {
		return 0, os.ErrDeadlineExceeded
	}
	n := copy(p, s.readBuf)
	s.readBuf = s.readBuf[n:]
	s.cond.Broadcast() // wake consumeFrame
	return n, nil
}

// Write writes data to the Stream.
func (s *Stream) Write(p []byte) (int, error) {
	buf := bytes.NewBuffer(p)
	for buf.Len() > 0 {
		// check for error
		s.cond.L.Lock()
		err := s.err
		var flags uint16
		if err == nil && !s.established {
			flags = flagFirst
			s.established = true
		}
		s.cond.L.Unlock()
		if err != nil {
			return len(p) - buf.Len(), err
		}
		// write next frame's worth of data
		payload := buf.Next(s.m.settings.maxPayloadSize())
		h := frameHeader{
			id:     s.id,
			length: uint32(len(payload)),
			flags:  flags,
		}
		if err := s.m.bufferFrame(h, payload, s.wd); err != nil {
			return len(p) - buf.Len(), err
		}
	}
	return len(p), nil
}

// Close closes the Stream. The underlying connection is not closed.
func (s *Stream) Close() error {
	// cancel outstanding Read/Write calls
	//
	// NOTE: Read calls will be interrupted immediately, but Write calls might
	// send another frame before observing the Close. This is ok: the peer will
	// discard any frames that arrive after the flagLast frame.
	s.cond.L.Lock()
	if s.err == ErrClosedStream {
		s.cond.L.Unlock()
		return nil
	}
	s.err = ErrClosedStream
	s.cond.Broadcast()
	s.cond.L.Unlock()

	h := frameHeader{
		id:    s.id,
		flags: flagLast,
	}
	err := s.m.bufferFrame(h, nil, s.wd)
	if err != nil && err != ErrPeerClosedStream {
		return err
	}

	// delete stream from Mux
	s.m.mu.Lock()
	delete(s.m.streams, s.id)
	s.m.mu.Unlock()
	return nil
}

var _ net.Conn = (*Stream)(nil)
