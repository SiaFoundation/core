package mux

import (
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"

	"lukechampine.com/frand"
)

const (
	cipherChaCha20Poly1305  = "Chacha20P1305\x00\x00\x00" // padded to 16 bytes
	chachaPoly1305NonceSize = 12
	chachaPoly1305TagSize   = 16
	chachaOverhead          = chachaPoly1305NonceSize + chachaPoly1305TagSize
)

func generateX25519KeyPair() (xsk, xpk [32]byte) {
	frand.Read(xsk[:])
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

func initiateEncryptionHandshake(conn net.Conn, theirKey ed25519.PublicKey) (cipher.AEAD, error) {
	xsk, xpk := generateX25519KeyPair()

	// write request
	buf := make([]byte, 112) // large enough to hold request + response
	frameBuf := buf[:frameHeaderSize+32+8+16]
	payload := frameBuf[frameHeaderSize:]
	encodeFrameHeader(frameBuf, frameHeader{
		id:     idEstablishEncryption,
		length: uint32(len(payload)),
	})
	copy(payload[:32], xpk[:])
	binary.LittleEndian.PutUint64(payload[32:], 1) // number of ciphers we're offering
	copy(payload[40:], cipherChaCha20Poly1305)
	if _, err := conn.Write(frameBuf); err != nil {
		return nil, fmt.Errorf("could not write establish encryption frame: %w", err)
	}

	// read response
	h, payload, err := readFrame(conn, buf)
	if err != nil {
		return nil, err
	} else if h.id != idEstablishEncryption {
		return nil, errors.New("invalid handshake ID")
	} else if h.length < 32+64+16 {
		return nil, errors.New("handshake payload is too short")
	} else if string(payload[32+64:]) != cipherChaCha20Poly1305 {
		return nil, errors.New("invalid cipher selected")
	}
	var rxpk [32]byte
	copy(rxpk[:], payload[:32])
	sig := payload[32:96]

	// verify signature
	sigHash := blake2b.Sum256(append(rxpk[:], xpk[:]...))
	if !ed25519.Verify(theirKey, sigHash[:], sig) {
		return nil, errors.New("invalid signature")
	}

	// derive encryption key
	cipherKey, err := deriveSharedSecret(xsk, rxpk)
	if err != nil {
		return nil, fmt.Errorf("failed to derive shared secret: %w", err)
	}
	cipher, err := chacha20poly1305.New(cipherKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	return cipher, nil
}

func acceptEncryptionHandshake(conn net.Conn, ourKey ed25519.PrivateKey) (cipher.AEAD, error) {
	xsk, xpk := generateX25519KeyPair()

	// read request
	buf := make([]byte, 1024) // large enough to hold many ciphers
	h, payload, err := readFrame(conn, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read handshake frame: %w", err)
	} else if h.id != idEstablishEncryption {
		return nil, errors.New("invalid handshake ID")
	} else if h.length < 8+32+16 {
		return nil, errors.New("handshake payload is too short")
	}

	// parse pubkey
	var rxpk [32]byte
	copy(rxpk[:], payload[:32])
	// select cipher
	numCiphers := binary.LittleEndian.Uint64(payload[32:])
	if uint64(h.length-40)/16 < numCiphers {
		return nil, errors.New("invalid cipher encoding")
	}
	var supportsChaCha bool
	for i := uint64(0); i < numCiphers; i++ {
		supportsChaCha = supportsChaCha || string(payload[40+16*i:][:16]) == cipherChaCha20Poly1305
	}
	if !supportsChaCha {
		return nil, errors.New("no cipher overlap")
	}

	// write response
	sigHash := blake2b.Sum256(append(xpk[:], rxpk[:]...))
	sig := ed25519.Sign(ourKey, sigHash[:])
	frameBuf := buf[:frameHeaderSize+32+64+16]
	payload = frameBuf[frameHeaderSize:]
	encodeFrameHeader(frameBuf, frameHeader{
		id:     idEstablishEncryption,
		length: uint32(len(payload)),
	})
	copy(payload[:32], xpk[:])
	copy(payload[32:96], sig)
	copy(payload[96:], cipherChaCha20Poly1305)
	if _, err := conn.Write(frameBuf); err != nil {
		return nil, fmt.Errorf("failed to write accept handshake frame: %w", err)
	}

	// derive encryption key
	cipherKey, err := deriveSharedSecret(xsk, rxpk)
	if err != nil {
		return nil, fmt.Errorf("failed to derive secret: %w", err)
	}
	cipher, err := chacha20poly1305.New(cipherKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	return cipher, nil
}
