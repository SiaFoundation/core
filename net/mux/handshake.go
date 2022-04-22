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
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"lukechampine.com/frand"
)

const ourVersion = 2

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

const ipv6MTU = 1440 // 1500-byte Ethernet frame - 40-byte IPv6 header - 20-byte TCP header

var defaultConnSettings = connSettings{
	PacketSize: ipv6MTU * 3, // chosen empirically via BenchmarkPackets
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

func initiateHandshake(conn net.Conn, theirKey ed25519.PublicKey, ourSettings connSettings) (cipher.AEAD, connSettings, error) {
	xsk, xpk := generateX25519KeyPair()

	// write version and pubkey
	buf := make([]byte, 1+32+64+connSettingsSize+chachaOverhead)
	buf[0] = ourVersion
	copy(buf[1:], xpk[:])
	if _, err := conn.Write(buf[:1+32]); err != nil {
		return nil, connSettings{}, fmt.Errorf("could not write handshake request: %w", err)
	}
	// read version, pubkey, signature, and settings
	if n, err := io.ReadAtLeast(conn, buf, 1); err != nil {
		return nil, connSettings{}, fmt.Errorf("could not read version: %w", err)
	} else if buf[0] != ourVersion {
		// respond with our version even if we're incompatible
		buf[0] = ourVersion
		conn.Write(buf[:1])
		return nil, connSettings{}, fmt.Errorf("incompatible version (%d)", buf[0])
	} else if _, err := io.ReadFull(conn, buf[n:]); err != nil {
		return nil, connSettings{}, fmt.Errorf("could not read handshake response: %w", err)
	}

	// verify signature
	var rxpk [32]byte
	copy(rxpk[:], buf[1:][:32])
	sig := buf[1+32:][:64]
	sigHash := blake2b.Sum256(append(xpk[:], rxpk[:]...))
	if !ed25519consensus.Verify(theirKey, sigHash[:], sig) {
		return nil, connSettings{}, errors.New("invalid signature")
	}

	// derive shared cipher
	aead, err := deriveSharedAEAD(xsk, rxpk)
	if err != nil {
		return nil, connSettings{}, fmt.Errorf("failed to derive shared cipher: %w", err)
	}

	// decrypt settings
	var mergedSettings connSettings
	if plaintext, err := decryptInPlace(buf[1+32+64:], aead); err != nil {
		return nil, connSettings{}, fmt.Errorf("could not decrypt settings response: %w", err)
	} else if mergedSettings, err = mergeSettings(ourSettings, decodeConnSettings(plaintext)); err != nil {
		return nil, connSettings{}, fmt.Errorf("peer sent unacceptable settings: %w", err)
	}

	// encrypt + write our settings
	encodeConnSettings(buf[chachaPoly1305NonceSize:], ourSettings)
	encryptInPlace(buf[:connSettingsSize+chachaOverhead], aead)
	if _, err := conn.Write(buf[:connSettingsSize+chachaOverhead]); err != nil {
		return nil, connSettings{}, fmt.Errorf("could not write settings: %w", err)
	}

	return aead, mergedSettings, nil
}

func acceptHandshake(conn net.Conn, ourKey ed25519.PrivateKey, ourSettings connSettings) (cipher.AEAD, connSettings, error) {
	xsk, xpk := generateX25519KeyPair()

	// read version and pubkey
	buf := make([]byte, 1+32+64+connSettingsSize+chachaOverhead)
	if n, err := io.ReadAtLeast(conn, buf[:1+32], 1); err != nil {
		return nil, connSettings{}, fmt.Errorf("could not read version: %w", err)
	} else if buf[0] != ourVersion {
		// respond with our version even if we're incompatible
		buf[0] = ourVersion
		conn.Write(buf[:1])
		return nil, connSettings{}, fmt.Errorf("incompatible version (%d)", buf[0])
	} else if _, err := io.ReadFull(conn, buf[n:1+32]); err != nil {
		return nil, connSettings{}, fmt.Errorf("could not read handshake request: %w", err)
	}

	// derive shared cipher
	var rxpk [32]byte
	copy(rxpk[:], buf[1:][:32])
	aead, err := deriveSharedAEAD(xsk, rxpk)
	if err != nil {
		return nil, connSettings{}, fmt.Errorf("failed to derive shared cipher: %w", err)
	}

	// write version, pubkey, signature, and settings
	sigHash := blake2b.Sum256(append(rxpk[:], xpk[:]...))
	sig := ed25519.Sign(ourKey, sigHash[:])
	buf[0] = ourVersion
	copy(buf[1:], xpk[:])
	copy(buf[1+32:], sig)
	encodeConnSettings(buf[1+32+64+chachaPoly1305NonceSize:], ourSettings)
	encryptInPlace(buf[1+32+64:], aead)
	if _, err := conn.Write(buf); err != nil {
		return nil, connSettings{}, fmt.Errorf("could not write handshake response: %w", err)
	}

	// read + decrypt settings
	var settings connSettings
	if _, err := io.ReadFull(conn, buf[:connSettingsSize+chachaOverhead]); err != nil {
		return nil, connSettings{}, fmt.Errorf("could not read settings response: %w", err)
	} else if plaintext, err := decryptInPlace(buf[:connSettingsSize+chachaOverhead], aead); err != nil {
		return nil, connSettings{}, fmt.Errorf("could not decrypt settings response: %w", err)
	} else if settings, err = mergeSettings(ourSettings, decodeConnSettings(plaintext)); err != nil {
		return nil, connSettings{}, fmt.Errorf("peer sent unacceptable settings: %w", err)
	}

	return aead, settings, nil
}
