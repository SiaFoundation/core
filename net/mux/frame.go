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
	length uint32
	flags  uint16
}

const frameHeaderSize = 10
const encryptedHeaderSize = frameHeaderSize + chachaOverhead

func encodeFrameHeader(buf []byte, h frameHeader) {
	binary.LittleEndian.PutUint32(buf[0:], h.id)
	binary.LittleEndian.PutUint32(buf[4:], h.length)
	binary.LittleEndian.PutUint16(buf[8:], h.flags)
}

func decodeFrameHeader(buf []byte) (h frameHeader) {
	h.id = binary.LittleEndian.Uint32(buf[0:])
	h.length = binary.LittleEndian.Uint32(buf[4:])
	h.flags = binary.LittleEndian.Uint16(buf[8:])
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

func encryptFrame(buf []byte, h frameHeader, payload []byte, packetSize int, aead cipher.AEAD) []byte {
	// pad frame to packet boundary
	numPackets := (encryptedHeaderSize + (len(payload) + chachaOverhead) + (packetSize - 1)) / packetSize
	frame := buf[:numPackets*packetSize]
	// encode + encrypt header
	encodeFrameHeader(frame[chachaPoly1305NonceSize:][:frameHeaderSize], h)
	encryptInPlace(frame[:encryptedHeaderSize], aead)
	// pad + encrypt payload
	copy(frame[encryptedHeaderSize+chachaPoly1305NonceSize:], payload)
	encryptInPlace(frame[encryptedHeaderSize:], aead)
	return frame
}

func decryptFrameHeader(buf []byte, aead cipher.AEAD) (frameHeader, error) {
	buf, err := decryptInPlace(buf, aead)
	if err != nil {
		return frameHeader{}, err
	}
	return decodeFrameHeader(buf), nil
}

func readEncryptedFrame(r io.Reader, buf []byte, packetSize int, aead cipher.AEAD) (frameHeader, []byte, error) {
	// read, decrypt, and decode header
	if _, err := io.ReadFull(r, buf[:encryptedHeaderSize]); err != nil {
		return frameHeader{}, nil, fmt.Errorf("could not read frame header: %w", err)
	}
	h, err := decryptFrameHeader(buf[:encryptedHeaderSize], aead)
	if err != nil {
		return frameHeader{}, nil, fmt.Errorf("could not decrypt header: %w", err)
	}
	numPackets := (encryptedHeaderSize + (int(h.length) + chachaOverhead) + (packetSize - 1)) / packetSize
	paddedSize := numPackets*packetSize - encryptedHeaderSize
	if h.length > uint32(len(buf)) || paddedSize > len(buf) {
		return frameHeader{}, nil, errors.New("peer sent too-large frame")
	}
	// read (padded) payload
	if _, err := io.ReadFull(r, buf[:paddedSize]); err != nil {
		return frameHeader{}, nil, fmt.Errorf("could not read frame payload: %w", err)
	}
	// decrypt payload
	payload, err := decryptInPlace(buf[:paddedSize], aead)
	if err != nil {
		return frameHeader{}, nil, fmt.Errorf("could not decrypt payload: %w", err)
	}
	return h, payload[:h.length], nil
}
