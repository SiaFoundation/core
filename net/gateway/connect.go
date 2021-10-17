package gateway

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"go.sia.tech/core/net/mux"
	"go.sia.tech/core/types"
	"io"
	"net"
)

var (
	errRejectedVersion = errors.New("peer rejected our version")
)

const (
	currentVersion uint8 = 1
	minimumVersion uint8 = 1
	rejectResponse       = "reject"
	acceptResponse       = "accept"
	// listener / tcp connections not implemented yet
	dummyAddr = "127.0.0.1:1"
)

type SessionConfig struct {
	PublicKey  ed25519.PublicKey
	GenesisID  types.BlockID
	UniqueID   [8]byte
	NetAddress string
}

func Dial(conn net.Conn, config SessionConfig) (*Session, error) {
	var g Session

	// version handshake

	// Send our version.
	e := types.NewEncoder(conn)
	e.WriteUint8(currentVersion)
	if err := e.Flush(); err != nil {
		return nil, err
	}

	d := types.NewDecoder(io.LimitedReader{R: conn, N: 32})
	// See if they approved our version
	if d.ReadString() != acceptResponse {
		return nil, errRejectedVersion
	}

	// Read remote version.
	remoteVersion := d.ReadUint8()
	if err := d.Err(); err != nil {
		return nil, err
	}

	// Check that their version is acceptable.
	if err := acceptableVersion(remoteVersion); err != nil {
		e.WriteString(rejectResponse)
		if err := e.Flush(); err != nil {
			return nil, fmt.Errorf("failed to write reject: %v", err)
		}
		return nil, err
	}
	e.WriteString(acceptResponse)
	if err := e.Flush(); err != nil {
		return nil, fmt.Errorf("failed to write accept: %v", err)
	}

	// exchange session headers
	if err := exchangeOurHeader(conn, config); err != nil {
		return nil, err
	}
	// receive their header so we have their public key
	remoteHeader, err := exchangeRemoteHeader(conn, config)
	if err != nil {
		return nil, err
	}

	session, err := mux.Dial(conn, remoteHeader.PublicKey)
	if err != nil {
		return nil, err
	}
	g.mux = session

	return &g, nil
}

func Accept(conn net.Conn, config SessionConfig, privateKey ed25519.PrivateKey) (*Session, error) {
	var g Session

	// version handshake
	e := types.NewEncoder(conn)
	d := types.NewDecoder(io.LimitedReader{R: conn, N: 32})

	// Check that their version is acceptable.
	if err := acceptableVersion(d.ReadUint8()); err != nil {
		e.WriteString(rejectResponse)
		if err := e.Flush(); err != nil {
			return nil, fmt.Errorf("failed to write reject: %v", err)
		}
		return nil, err
	}
	e.WriteString(acceptResponse)
	if err := e.Flush(); err != nil {
		return nil, fmt.Errorf("failed to write accept: %v", err)
	}

	// Send our version.
	e.WriteUint8(currentVersion)
	if err := e.Flush(); err != nil {
		return nil, fmt.Errorf("failed to write version: %v", err)
	}

	// See if they approved our version
	if d.ReadString() != acceptResponse {
		return nil, errRejectedVersion
	}

	if err := d.Err(); err != nil {
		return nil, fmt.Errorf("decoder error: %v", err)
	}

	// exchange session headers
	if _, err := exchangeRemoteHeader(conn, config); err != nil {
		return nil, err
	}
	if err := exchangeOurHeader(conn, config); err != nil {
		return nil, err
	}

	session, err := mux.Accept(conn, privateKey)
	if err != nil {
		return nil, err
	}
	g.mux = session

	return &g, nil
}

func acceptableVersion(version uint8) error {
	// Check that their version is acceptable.
	if currentVersion < minimumVersion {
		return errors.New("version too old")
	}
	return nil
}

// acceptableSessionHeader returns an error if remoteHeader indicates a peer
// that should not be connected to.
func acceptableSessionHeader(ourHeader, remoteHeader SessionConfig, remoteAddr string) error {
	if remoteHeader.GenesisID != ourHeader.GenesisID {
		return errors.New("peer has different genesis ID")
	} else if remoteHeader.UniqueID == ourHeader.UniqueID {
		return errors.New("can't add our own address")
	} else if _, _, err := net.SplitHostPort(remoteHeader.NetAddress); err != nil {
		return fmt.Errorf("invalid remote address: %v", err)
	}
	return nil
}

// exchangeOurHeader writes ourHeader and reads the remote's error response.
func exchangeOurHeader(conn net.Conn, ourHeader SessionConfig) error {
	e := types.NewEncoder(conn)
	d := types.NewDecoder(io.LimitedReader{R: conn, N: 1024})

	// Send our header.
	e.Write(ourHeader.PublicKey)
	ourHeader.GenesisID.EncodeTo(e)
	e.Write(ourHeader.UniqueID[:])
	e.WriteString(string(ourHeader.NetAddress))
	if err := e.Flush(); err != nil {
		return fmt.Errorf("failed to write header: %v", err)
	}

	// Read remote response.
	response := d.ReadString()
	if err := d.Err(); err != nil {
		return fmt.Errorf("failed to read header acceptance: %v", err)
	} else if response != acceptResponse {
		return fmt.Errorf("peer rejected our header: %v", response)
	}

	return nil
}

// exchangeRemoteHeader reads the remote header and writes an error response.
func exchangeRemoteHeader(conn net.Conn, ourHeader SessionConfig) (SessionConfig, error) {
	e := types.NewEncoder(conn)
	d := types.NewDecoder(io.LimitedReader{R: conn, N: 1024})

	// Read remote header.
	var remoteHeader SessionConfig
	remoteHeader.PublicKey = make([]byte, ed25519.PublicKeySize)
	d.Read(remoteHeader.PublicKey)
	remoteHeader.GenesisID.DecodeFrom(d)
	d.Read(remoteHeader.UniqueID[:])
	remoteHeader.NetAddress = d.ReadString()
	if err := d.Err(); err != nil {
		return SessionConfig{}, fmt.Errorf("failed to read header: %v", err)
	}

	// Validate remote header and write acceptance or rejection.
	if err := acceptableSessionHeader(ourHeader, remoteHeader, string(ourHeader.NetAddress)); err != nil {
		e.WriteString(rejectResponse)
		if err := e.Flush(); err != nil {
			return SessionConfig{}, fmt.Errorf("failed to write header rejection: %v", err)
		}
		return SessionConfig{}, fmt.Errorf("peer's header was not acceptable: %v", err)
	}
	e.WriteString(acceptResponse)
	if err := e.Flush(); err != nil {
		return SessionConfig{}, fmt.Errorf("failed to write header acceptance: %v", err)
	}

	return remoteHeader, nil
}
