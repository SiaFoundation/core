package gateway

import (
	"crypto/ed25519"
	"errors"
	"go.sia.tech/core/net/mux"
	"go.sia.tech/core/net/rpc"
	"go.sia.tech/core/types"
	"io"
	"lukechampine.com/frand"
	"net"
	"testing"
	"time"
)

type objString string

func (s *objString) EncodeTo(e *types.Encoder)   { e.WriteString(string(*s)) }
func (s *objString) DecodeFrom(d *types.Decoder) { *s = objString(d.ReadString()) }

type pipeRWC struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (p pipeRWC) Read(b []byte) (int, error) {
	return p.r.Read(b)
}

func (p pipeRWC) Write(b []byte) (int, error) {
	return p.w.Write(b)
}

func (p pipeRWC) Close() error {
	p.r.Close()
	return p.w.Close()
}

// dummy functions to satisfy net.Conn interface
func (p pipeRWC) SetDeadline(time.Time) error {
	return nil
}

func (p pipeRWC) SetReadDeadline(time.Time) error {
	return nil
}

func (p pipeRWC) SetWriteDeadline(time.Time) error {
	return nil
}

func (p pipeRWC) RemoteAddr() (a net.Addr) {
	return
}

func (p pipeRWC) LocalAddr() (a net.Addr) {
	return
}

func newFakeConns() (net.Conn, net.Conn) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()
	return pipeRWC{r1, w2}, pipeRWC{r2, w1}
}

func TestGateway(t *testing.T) {
	var genesisBlock types.Block

	server, client := newFakeConns()
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- func() error {
			publicKey, privateKey, err := ed25519.GenerateKey(nil)
			if err != nil {
				return err
			}
			config := SessionConfig{
				PublicKey:  publicKey,
				GenesisID:  genesisBlock.ID(),
				NetAddress: dummyAddr,
			}
			copy(config.UniqueID[:], frand.Bytes(8))

			hs, err := Accept(client, config, privateKey)
			if err != nil {
				return err
			}
			defer hs.Close()
			for {
				id, err := hs.ReadID()
				if errors.Is(err, mux.ErrPeerClosedConn) {
					return nil
				} else if err != nil {
					return err
				}
				switch id {
				case rpc.NewSpecifier("Greet"):
					var name objString
					if err := hs.ReadRequest(&name, 4096); err != nil {
						return err
					}
					if name == "" {
						err = hs.WriteResponse(nil, errors.New("invalid name"))
					} else {
						resp := objString("Hello, " + name)
						err = hs.WriteResponse(&resp, nil)
					}
					if err != nil {
						return err
					}
				default:
					return errors.New("unknown specifier")
				}
			}
		}()
	}()

	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	config := SessionConfig{
		PublicKey:  publicKey,
		GenesisID:  genesisBlock.ID(),
		NetAddress: dummyAddr,
	}
	copy(config.UniqueID[:], frand.Bytes(8))

	rs, err := Dial(server, config)
	if err != nil {
		t.Fatal(err)
	}
	req := objString("Foo")
	var resp objString
	if err := rs.WriteRequest(rpc.NewSpecifier("Greet"), &req); err != nil {
		t.Fatal(err)
	} else if err := rs.ReadResponse(&resp, 4096); err != nil {
		t.Fatal(err)
	} else if resp != "Hello, Foo" {
		t.Fatal("unexpected response:", resp)
	}

	if err := rs.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}
