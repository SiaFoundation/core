// Package renterhost implements the handshake and transport for the Sia
// renter-host protocol.
package renterhost

import (
	"bytes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"sync"

	"github.com/aead/chacha20/chacha"
	"go.sia.tech/core/types"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/poly1305"
)

// SectorSize is the size of one sector in bytes.
const SectorSize = 1 << 22 // 4 MiB

// MinMessageSize is the minimum size of an RPC message. If an encoded message
// would be smaller than MinMessageSize, the sender MAY pad it with random data.
// This hinders traffic analysis by obscuring the true sizes of messages.
const MinMessageSize = 4096

// ErrRenterClosed is returned by (*Session).ReadID when the renter sends the
// session termination signal.
var ErrRenterClosed = errors.New("renter has terminated session")

func wrapErr(err *error, fnName string) {
	if *err != nil {
		*err = fmt.Errorf("%s: %w", fnName, *err)
	}
}

func generateX25519KeyPair() (xsk, xpk [32]byte) {
	// NOTE: The docstring for ScalarBaseMult recommends using X25519 instead,
	// but ScalarBaseMult's API fits our types better.
	rand.Read(xsk[:])
	curve25519.ScalarBaseMult(&xpk, &xsk)
	return
}

func deriveSharedSecret(xsk, xpk [32]byte) ([32]byte, error) {
	// NOTE: an error is only possible here if xpk is a "low-order point."
	// Basically, if the other party chooses one of these points as their public
	// key, then the resulting "secret" can be derived by anyone who observes
	// the handshake, effectively rendering the protocol unencrypted. This would
	// be a strange thing to do; the other party can decrypt the messages
	// anyway, so if they want to make the messages public, nothing can stop
	// them from doing so. Consequently, some people (notably djb himself) will
	// tell you not to bother checking for low-order points at all. Personally,
	// though, I think the situation is sufficiently lacking in legal clarity
	// that it's better to be safe than sorry.
	secret, err := curve25519.X25519(xsk[:], xpk[:])
	return blake2b.Sum256(secret), err
}

func signHash(priv ed25519.PrivateKey, hash types.Hash256) (sig types.Signature) {
	copy(sig[:], ed25519.Sign(priv, hash[:]))
	return
}

func verifyHash(pub ed25519.PublicKey, hash types.Hash256, sig types.Signature) bool {
	return ed25519.Verify(pub, hash[:], sig[:])
}

// A Session is an ongoing exchange of RPCs via the renter-host protocol.
type Session struct {
	conn      io.ReadWriteCloser
	aead      cipher.AEAD
	key       []byte // for RawResponse
	inbuf     bytes.Buffer
	outbuf    bytes.Buffer
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
func (s *Session) SignChallenge(priv ed25519.PrivateKey) types.Signature {
	return signHash(priv, hashChallenge(s.challenge))
}

// VerifyChallenge verifies a signature of the current session challenge.
func (s *Session) VerifyChallenge(sig types.Signature, pub ed25519.PublicKey) bool {
	return verifyHash(pub, hashChallenge(s.challenge), sig)
}

func (s *Session) writeMessage(obj ProtocolObject) error {
	if err := s.PrematureCloseErr(); err != nil {
		return err
	}
	// generate random nonce
	nonce := make([]byte, 256)[:s.aead.NonceSize()] // avoid heap alloc
	rand.Read(nonce)

	// write length, nonce, and object into buffer
	s.outbuf.Reset()
	s.outbuf.Grow(MinMessageSize)
	e := types.NewEncoder(&s.outbuf)
	e.WriteUint64(0) // will be overwritten once we know the actual length
	e.Write(nonce)
	obj.encodeTo(e)
	e.Flush()

	// pad short messages if necessary and fixup the length prefix
	msgSize := s.outbuf.Len() + s.aead.NonceSize() + s.aead.Overhead()
	if msgSize < MinMessageSize {
		msgSize = MinMessageSize
	}
	s.outbuf.Reset()
	e.WriteUint64(uint64(msgSize - 8))
	e.Flush()

	// encrypt the object in-place
	msg := s.outbuf.Bytes()[:msgSize]
	msgNonce := msg[8:][:len(nonce)]
	payload := msg[8+len(nonce) : msgSize-s.aead.Overhead()]
	s.aead.Seal(payload[:0], msgNonce, payload, nil)

	_, err := s.conn.Write(msg)
	s.setErr(err)
	return err
}

func (s *Session) readMessage(obj ProtocolObject, maxLen uint64) error {
	if err := s.PrematureCloseErr(); err != nil {
		return err
	}
	if maxLen < MinMessageSize {
		maxLen = MinMessageSize
	}
	// read length prefix
	d := types.NewDecoder(io.LimitedReader{R: s.conn, N: 8})
	msgSize := d.ReadUint64()
	if d.Err() != nil {
		s.setErr(d.Err())
		return d.Err()
	} else if msgSize > maxLen {
		return fmt.Errorf("message size (%v bytes) exceeds maxLen of %v bytes", msgSize, maxLen)
	} else if msgSize < uint64(s.aead.NonceSize()+s.aead.Overhead()) {
		return fmt.Errorf("message size (%v bytes) is too small (nonce + MAC is %v bytes)", msgSize, s.aead.NonceSize()+s.aead.Overhead())
	}

	// read encrypted object into buffer
	s.inbuf.Reset()
	if _, err := s.inbuf.ReadFrom(io.LimitReader(s.conn, int64(msgSize))); err != nil {
		s.setErr(err)
		return err
	}

	// decrypt in place and decode
	nonce := s.inbuf.Next(s.aead.NonceSize())
	paddedPayload := s.inbuf.Bytes()
	_, err := s.aead.Open(paddedPayload[:0], nonce, paddedPayload, nil)
	if err != nil {
		s.setErr(err) // not an I/O error, but still fatal
		return err
	}
	d = types.NewBufDecoder(s.inbuf.Bytes())
	obj.decodeFrom(d)
	return d.Err()
}

// WriteRequest sends an encrypted RPC request, comprising an RPC ID and a
// request object.
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
	err = s.readMessage(&rpcID, MinMessageSize)
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

// A ResponseReader contains an unencrypted, unauthenticated RPC response
// message.
type ResponseReader struct {
	msgR   io.Reader
	tagR   io.Reader
	mac    *poly1305.MAC
	clen   int
	setErr func(error)
}

// Read implements io.Reader.
func (rr *ResponseReader) Read(p []byte) (int, error) {
	n, err := rr.msgR.Read(p)
	if err != io.EOF {
		// EOF is expected, since this is a limited reader
		rr.setErr(err)
	}
	return n, err
}

// VerifyTag verifies the authentication tag appended to the message. VerifyTag
// must be called after Read returns io.EOF, and the message must be discarded
// if VerifyTag returns a non-nil error.
func (rr *ResponseReader) VerifyTag() error {
	// the caller may not have consumed the full message (e.g. if it was padded
	// to MinMessageSize), so make sure the whole thing is written to the MAC
	if _, err := io.Copy(ioutil.Discard, rr); err != nil {
		return err
	}

	var tag [poly1305.TagSize]byte
	if _, err := io.ReadFull(rr.tagR, tag[:]); err != nil {
		rr.setErr(err)
		return err
	}
	// MAC is padded to 16 bytes, and covers the length of AD (0 in this case)
	// and ciphertext
	tail := make([]byte, 0, 32)[:32-(rr.clen%16)]
	binary.LittleEndian.PutUint64(tail[len(tail)-8:], uint64(rr.clen))
	rr.mac.Write(tail)
	var ourTag [poly1305.TagSize]byte
	rr.mac.Sum(ourTag[:0])
	if subtle.ConstantTimeCompare(tag[:], ourTag[:]) != 1 {
		err := errors.New("chacha20poly1305: message authentication failed")
		rr.setErr(err) // not an I/O error, but still fatal
		return err
	}
	return nil
}

// RawResponse returns a stream containing the (unencrypted, unauthenticated)
// content of the next message. The Reader must be fully consumed by the caller,
// after which the caller should call VerifyTag to authenticate the message. If
// the response was an RPCError, it is authenticated and returned immediately.
func (s *Session) RawResponse(maxLen int) (*ResponseReader, error) {
	if maxLen < MinMessageSize {
		maxLen = MinMessageSize
	}

	// read msgSize and nonce
	buf := make([]byte, 8+s.aead.NonceSize())
	if _, err := io.ReadFull(s.conn, buf); err != nil {
		s.setErr(err)
		return nil, err
	}
	msgSize := int(binary.LittleEndian.Uint64(buf[:8]))
	nonce := buf[8:]
	if msgSize > maxLen {
		return nil, fmt.Errorf("message size (%v bytes) exceeds maxLen of %v bytes", msgSize, maxLen)
	} else if msgSize < s.aead.NonceSize()+s.aead.Overhead() {
		return nil, fmt.Errorf("message size (%v bytes) is too small (nonce + MAC is %v bytes)", msgSize, s.aead.NonceSize()+s.aead.Overhead())
	}
	msgSize -= s.aead.NonceSize() + s.aead.Overhead()

	// construct reader
	c, _ := chacha.NewCipher(nonce, s.key, 20)
	var polyKey [32]byte
	c.XORKeyStream(polyKey[:], polyKey[:])
	mac := poly1305.New(&polyKey)
	c.SetCounter(1)
	rr := &ResponseReader{
		msgR: cipher.StreamReader{
			R: io.TeeReader(io.LimitReader(s.conn, int64(msgSize)), mac),
			S: c,
		},
		tagR:   io.LimitReader(s.conn, poly1305.TagSize),
		mac:    mac,
		clen:   msgSize,
		setErr: s.setErr,
	}

	// check if response is an RPCError
	d := types.NewDecoder(io.LimitedReader{R: rr, N: int64(msgSize)})
	isErr := d.ReadBool()
	if d.Err() != nil {
		return nil, d.Err()
	} else if isErr {
		err := new(RPCError)
		err.decodeFrom(d)
		if d.Err() != nil {
			return nil, d.Err()
		} else if err := rr.VerifyTag(); err != nil {
			return nil, err
		}
		return nil, err
	}
	// not an error; pass rest of stream to caller
	return rr, nil
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

func hashKeys(k1, k2 [32]byte) types.Hash256 {
	return blake2b.Sum256(append(append(make([]byte, 0, len(k1)+len(k2)), k1[:]...), k2[:]...))
}

// NewHostSession conducts the hosts's half of the renter-host protocol
// handshake, returning a Session that can be used to handle RPC requests.
func NewHostSession(conn io.ReadWriteCloser, priv ed25519.PrivateKey) (_ *Session, err error) {
	defer wrapErr(&err, "NewHostSession")
	var req loopKeyExchangeRequest
	if err := req.readFrom(conn); err != nil {
		return nil, err
	}

	var supportsChaCha bool
	for _, c := range req.Ciphers {
		if c == cipherChaCha20Poly1305 {
			supportsChaCha = true
		}
	}
	if !supportsChaCha {
		(&loopKeyExchangeResponse{Cipher: cipherNoOverlap}).writeTo(conn)
		return nil, errors.New("no supported ciphers")
	}

	xsk, xpk := generateX25519KeyPair()
	resp := loopKeyExchangeResponse{
		Cipher:    cipherChaCha20Poly1305,
		PublicKey: xpk,
		Signature: signHash(priv, hashKeys(req.PublicKey, xpk)),
	}
	if err := resp.writeTo(conn); err != nil {
		return nil, err
	}

	cipherKey, err := deriveSharedSecret(xsk, req.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("renter sent invalid pubkey: %w", err)
	}
	aead, _ := chacha20poly1305.New(cipherKey[:]) // no error possible
	s := &Session{
		conn:     conn,
		aead:     aead,
		key:      cipherKey[:],
		isRenter: false,
	}
	rand.Read(s.challenge[:])
	// hack: cast challenge to Specifier to make it a ProtocolObject
	if err := s.writeMessage((*Specifier)(&s.challenge)); err != nil {
		return nil, fmt.Errorf("couldn't write challenge: %w", err)
	}
	return s, nil
}

// NewRenterSession conducts the renter's half of the renter-host protocol
// handshake, returning a Session that can be used to make RPC requests.
func NewRenterSession(conn io.ReadWriteCloser, pub ed25519.PublicKey) (_ *Session, err error) {
	defer wrapErr(&err, "NewRenterSession")

	xsk, xpk := generateX25519KeyPair()
	req := &loopKeyExchangeRequest{
		PublicKey: xpk,
		Ciphers:   []Specifier{cipherChaCha20Poly1305},
	}
	if err := req.writeTo(conn); err != nil {
		return nil, fmt.Errorf("couldn't write handshake: %w", err)
	}
	var resp loopKeyExchangeResponse
	if err := resp.readFrom(conn); err != nil {
		return nil, fmt.Errorf("couldn't read host's handshake: %w", err)
	}
	// validate the signature before doing anything else
	if !verifyHash(pub, hashKeys(req.PublicKey, resp.PublicKey), resp.Signature) {
		return nil, errors.New("host's handshake signature was invalid")
	}
	if resp.Cipher == cipherNoOverlap {
		return nil, errors.New("host does not support any of our proposed ciphers")
	} else if resp.Cipher != cipherChaCha20Poly1305 {
		return nil, errors.New("host selected unsupported cipher")
	}

	cipherKey, err := deriveSharedSecret(xsk, resp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("host sent invalid pubkey: %w", err)
	}
	aead, _ := chacha20poly1305.New(cipherKey[:]) // no error possible
	s := &Session{
		conn:     conn,
		aead:     aead,
		key:      cipherKey[:],
		isRenter: true,
	}
	// hack: cast challenge to Specifier to make it a ProtocolObject
	if err := s.readMessage((*Specifier)(&s.challenge), MinMessageSize); err != nil {
		return nil, fmt.Errorf("couldn't read host's challenge: %w", err)
	}
	return s, nil
}
