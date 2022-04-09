package mux

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"lukechampine.com/frand"
)

const (
	flagFirst = 1 << iota // first frame in stream
	flagLast              // stream is being closed gracefully
	flagError             // stream is being closed due to an error
)

const (
	idErrorBadInit = iota // should never be seen
	idKeepalive           // empty frame to keep connection open
)

const (
	chachaPoly1305NonceSize = 12
	chachaPoly1305TagSize   = 16
	chachaOverhead          = chachaPoly1305NonceSize + chachaPoly1305TagSize
)

type frameHeader struct {
	id     uint32
	length uint16
	flags  uint16
}

const frameHeaderSize = 4 + 2 + 2

func encodeFrameHeader(buf []byte, h frameHeader) {
	binary.LittleEndian.PutUint32(buf[0:], (h.id<<1)|1)
	binary.LittleEndian.PutUint16(buf[4:], h.length)
	binary.LittleEndian.PutUint16(buf[6:], h.flags)
}

func decodeFrameHeader(buf []byte) (h frameHeader) {
	h.id = binary.LittleEndian.Uint32(buf[0:]) >> 1
	h.length = binary.LittleEndian.Uint16(buf[4:])
	h.flags = binary.LittleEndian.Uint16(buf[6:])
	return
}

func generateX25519KeyPair() (xsk, xpk [32]byte) {
	frand.Read(xsk[:])
	curve25519.ScalarBaseMult(&xpk, &xsk)
	return
}

func deriveSharedAEAD(xsk, xpk [32]byte) (cipher.AEAD, error) {
	// NOTE: an error is only possible here if xpk is a "low-order point."
	// Basically, if the other party chooses one of these points as their public
	// key, then the resulting "secret" can be derived by anyone who observes
	// the handshake, effectively rendering the protocol unencrypted. This would
	// be a strange thing to do; the other party can decrypt the messages
	// anyway, so if they want to make the messages public, nothing can stop
	// them from doing so. Consequently, some people (notably djb himself) will
	// tell you not to bother checking for low-order points at all. But why
	// would we want to talk to a peer that's behaving weirdly?
	secret, err := curve25519.X25519(xsk[:], xpk[:])
	if err != nil {
		return nil, err
	}
	key := blake2b.Sum256(secret)
	return chacha20poly1305.New(key[:])
}

func encryptInPlace(buf []byte, aead cipher.AEAD) {
	nonce, plaintext := buf[:chachaPoly1305NonceSize], buf[chachaPoly1305NonceSize:len(buf)-chachaPoly1305TagSize]
	frand.Read(nonce)
	aead.Seal(plaintext[:0], nonce, plaintext, nil)
}

func decryptInPlace(buf []byte, aead cipher.AEAD) ([]byte, error) {
	nonce, ciphertext := buf[:chachaPoly1305NonceSize], buf[chachaPoly1305NonceSize:]
	return aead.Open(ciphertext[:0], nonce, ciphertext, nil)
}

func appendFrame(buf []byte, h frameHeader, payload []byte) []byte {
	frame := buf[len(buf):][:frameHeaderSize+len(payload)]
	encodeFrameHeader(frame[:frameHeaderSize], h)
	copy(frame[frameHeaderSize:], payload)
	return buf[:len(buf)+len(frame)]
}

type packetReader struct {
	r          io.Reader
	aead       cipher.AEAD
	packetSize int

	buf       []byte
	decrypted []byte
	partial   []byte
}

func (pr *packetReader) Read(p []byte) (int, error) {
	if len(pr.decrypted) == 0 {
		// read at least one packet
		pr.buf = append(pr.buf[:0], pr.partial...)
		n, err := io.ReadAtLeast(pr.r, pr.buf[len(pr.buf):cap(pr.buf)], pr.packetSize-len(pr.partial))
		if err != nil {
			return 0, err
		}
		pr.buf = pr.buf[:len(pr.buf)+n]

		// decrypt packets
		pr.decrypted = pr.buf[:0]
		numPackets := len(pr.buf) / pr.packetSize
		for i := 0; i < numPackets; i++ {
			packet := pr.buf[i*pr.packetSize:][:pr.packetSize]
			nonce, ciphertext := packet[:chachaPoly1305NonceSize], packet[chachaPoly1305NonceSize:]
			plaintext, err := pr.aead.Open(ciphertext[:0], nonce, ciphertext, nil)
			if err != nil {
				return 0, err
			}
			pr.decrypted = append(pr.decrypted, plaintext...)
		}
		pr.partial = pr.buf[numPackets*pr.packetSize:]
	}

	n := copy(p, pr.decrypted)
	pr.decrypted = pr.decrypted[n:]
	return n, nil
}

func (pr *packetReader) nextFrame(buf []byte) (frameHeader, []byte, error) {
	// skip padding
	for len(pr.decrypted) > 0 && pr.decrypted[0]&1 == 0 {
		pr.decrypted = pr.decrypted[1:]
	}

	if _, err := io.ReadFull(pr, buf[:frameHeaderSize]); err != nil {
		return frameHeader{}, nil, fmt.Errorf("could not read frame header: %w", err)
	}
	h := decodeFrameHeader(buf[:frameHeaderSize])
	if h.length > uint16(pr.packetSize-frameHeaderSize) {
		return frameHeader{}, nil, errors.New("peer sent too-large frame")
	} else if _, err := io.ReadFull(pr, buf[:h.length]); err != nil {
		return frameHeader{}, nil, fmt.Errorf("could not read frame payload: %w", err)
	}
	return h, buf[:h.length], nil
}

func encryptPackets(buf []byte, p []byte, packetSize int, aead cipher.AEAD) []byte {
	maxFrameSize := packetSize - chachaOverhead
	numPackets := len(p) / maxFrameSize
	for i := 0; i < numPackets; i++ {
		packet := buf[i*packetSize:][:packetSize]
		plaintext := p[i*maxFrameSize:][:maxFrameSize]
		nonce, ciphertext := packet[:chachaPoly1305NonceSize], packet[chachaPoly1305NonceSize:]
		frand.Read(nonce)
		aead.Seal(ciphertext[:0], nonce, plaintext, nil)
	}
	return buf[:numPackets*packetSize]
}
