package mux

import (
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/hdevalence/ed25519consensus"
	"golang.org/x/crypto/blake2b"
)

var ourVersion = []byte{2}

func initiateVersionHandshake(conn net.Conn) error {
	theirVersion := make([]byte, 1)
	if _, err := conn.Write(ourVersion); err != nil {
		return fmt.Errorf("could not write our version: %w", err)
	} else if _, err := io.ReadFull(conn, theirVersion); err != nil {
		return fmt.Errorf("could not read peer version: %w", err)
	} else if theirVersion[0] != ourVersion[0] {
		return errors.New("bad version")
	}
	return nil
}

func acceptVersionHandshake(conn net.Conn) error {
	theirVersion := make([]byte, 1)
	if _, err := io.ReadFull(conn, theirVersion); err != nil {
		return fmt.Errorf("could not read peer version: %w", err)
	} else if _, err := conn.Write(ourVersion); err != nil {
		return fmt.Errorf("could not write our version: %w", err)
	} else if theirVersion[0] != ourVersion[0] {
		return errors.New("bad version")
	}
	return nil
}

func initiateEncryptionHandshake(conn net.Conn, theirKey ed25519.PublicKey) (cipher.AEAD, error) {
	xsk, xpk := generateX25519KeyPair()

	buf := make([]byte, 32+64)
	if _, err := conn.Write(xpk[:]); err != nil {
		return nil, fmt.Errorf("could not write encryption handshake request: %w", err)
	} else if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("could not read encryption handshake response: %w", err)
	}
	var rxpk [32]byte
	copy(rxpk[:], buf[:32])
	sig := buf[32:96]

	// verify signature
	sigHash := blake2b.Sum256(append(rxpk[:], xpk[:]...))
	if !ed25519consensus.Verify(theirKey, sigHash[:], sig) {
		return nil, errors.New("invalid signature")
	}

	cipher, err := deriveSharedAEAD(xsk, rxpk)
	if err != nil {
		return nil, fmt.Errorf("failed to derive shared cipher: %w", err)
	}
	return cipher, nil
}

func acceptEncryptionHandshake(conn net.Conn, ourKey ed25519.PrivateKey) (cipher.AEAD, error) {
	xsk, xpk := generateX25519KeyPair()

	var rxpk [32]byte
	if _, err := io.ReadFull(conn, rxpk[:]); err != nil {
		return nil, fmt.Errorf("could not read encryption handshake request: %w", err)
	}
	sigHash := blake2b.Sum256(append(xpk[:], rxpk[:]...))
	sig := ed25519.Sign(ourKey, sigHash[:])
	if _, err := conn.Write(append(xpk[:], sig...)); err != nil {
		return nil, fmt.Errorf("could not write encryption handshake response: %w", err)
	}

	cipher, err := deriveSharedAEAD(xsk, rxpk)
	if err != nil {
		return nil, fmt.Errorf("failed to derive shared cipher: %w", err)
	}
	return cipher, nil
}

type connSettings struct {
	PacketSize int
	MaxTimeout time.Duration
}

func (cs connSettings) maxFrameSize() int {
	return cs.PacketSize - chachaOverhead
}

func (cs connSettings) maxPayloadSize() int {
	return cs.maxFrameSize() - frameHeaderSize
}

var defaultConnSettings = connSettings{
	PacketSize: 1440, // IPv6 MTU
	MaxTimeout: 20 * time.Minute,
}

const connSettingsSize = 4 + 4

func encodeConnSettings(buf []byte, cs connSettings) {
	binary.LittleEndian.PutUint32(buf[0:], uint32(cs.PacketSize))
	binary.LittleEndian.PutUint32(buf[4:], uint32(cs.MaxTimeout.Seconds()))
}

func decodeConnSettings(buf []byte) (cs connSettings) {
	cs.PacketSize = int(binary.LittleEndian.Uint32(buf[0:]))
	cs.MaxTimeout = time.Second * time.Duration(binary.LittleEndian.Uint32(buf[4:]))
	return
}

func mergeSettings(ours, theirs connSettings) (connSettings, error) {
	// use smaller value for all settings
	merged := ours
	if theirs.PacketSize < merged.PacketSize {
		merged.PacketSize = theirs.PacketSize
	}
	if theirs.MaxTimeout < merged.MaxTimeout {
		merged.MaxTimeout = theirs.MaxTimeout
	}
	// enforce minimums and maximums
	switch {
	case merged.PacketSize < 1220:
		return connSettings{}, fmt.Errorf("requested packet size (%v) is too small", merged.PacketSize)
	case merged.PacketSize > 32768:
		return connSettings{}, fmt.Errorf("requested packet size (%v) is too large", merged.PacketSize)
	case merged.MaxTimeout < 2*time.Minute:
		return connSettings{}, fmt.Errorf("maximum timeout (%v) is too short", merged.MaxTimeout)
	case merged.MaxTimeout > 2*time.Hour:
		return connSettings{}, fmt.Errorf("maximum timeout (%v) is too long", merged.MaxTimeout)
	}
	return merged, nil
}

func initiateSettingsHandshake(conn net.Conn, ours connSettings, aead cipher.AEAD) (connSettings, error) {
	// encode + encrypt + write request
	buf := make([]byte, connSettingsSize+chachaOverhead)
	encodeConnSettings(buf[chachaPoly1305NonceSize:], ours)
	encryptInPlace(buf, aead)
	if _, err := conn.Write(buf); err != nil {
		return connSettings{}, fmt.Errorf("could not write settings request: %w", err)
	}
	// read + decrypt + decode response
	if _, err := io.ReadFull(conn, buf); err != nil {
		return connSettings{}, fmt.Errorf("could not read settings response: %w", err)
	}
	plaintext, err := decryptInPlace(buf, aead)
	if err != nil {
		return connSettings{}, fmt.Errorf("could not decrypt settings response: %w", err)
	}
	theirs := decodeConnSettings(plaintext)
	return mergeSettings(ours, theirs)
}

func acceptSettingsHandshake(conn net.Conn, ours connSettings, aead cipher.AEAD) (connSettings, error) {
	// read + decrypt + decode request
	buf := make([]byte, connSettingsSize+chachaOverhead)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return connSettings{}, fmt.Errorf("could not read settings response: %w", err)
	}
	plaintext, err := decryptInPlace(buf, aead)
	if err != nil {
		return connSettings{}, fmt.Errorf("could not decrypt settings response: %w", err)
	}
	theirs := decodeConnSettings(plaintext)
	// encode + encrypt + write response
	encodeConnSettings(buf[chachaPoly1305NonceSize:], ours)
	encryptInPlace(buf, aead)
	if _, err := conn.Write(buf); err != nil {
		return connSettings{}, fmt.Errorf("could not write settings request: %w", err)
	}
	return mergeSettings(ours, theirs)
}
