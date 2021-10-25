package gateway

import (
	"errors"
	"net"
	"testing"

	"go.sia.tech/core/net/rpc"
	"go.sia.tech/core/types"
)

type objString string

func (s *objString) EncodeTo(e *types.Encoder)   { e.WriteString(string(*s)) }
func (s *objString) DecodeFrom(d *types.Decoder) { *s = objString(d.ReadString()) }
func (s *objString) MaxLen() int                 { return 100 }

func TestHandshake(t *testing.T) {
	genesisID := (&types.Block{}).ID()
	rpcGreet := rpc.NewSpecifier("greet")

	// initialize peer
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	peerErr := make(chan error, 1)
	go func() {
		peerErr <- func() error {
			conn, err := l.Accept()
			if err != nil {
				return err
			}
			defer conn.Close()
			h := Header{
				GenesisID:  genesisID,
				UniqueID:   [8]byte{0},
				NetAddress: l.Addr().String(),
			}
			sess, err := AcceptSession(conn, h)
			if err != nil {
				return err
			}
			defer sess.Close()
			stream, err := sess.AcceptStream()
			if err != nil {
				return err
			}
			defer stream.Close()
			id, err := rpc.ReadID(stream)
			if err != nil {
				return err
			} else if id != rpcGreet {
				return errors.New("unexpected RPC ID")
			}
			var name objString
			if err := rpc.ReadRequest(stream, &name); err != nil {
				return err
			}
			greeting := "Hello, " + name
			if err := rpc.WriteResponse(stream, &greeting, nil); err != nil {
				return err
			}
			return nil
		}()
	}()

	// connect to peer
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	h := Header{
		GenesisID:  genesisID,
		UniqueID:   [8]byte{1},
		NetAddress: conn.LocalAddr().String(),
	}
	sess, err := DialSession(conn, h)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	stream, err := sess.DialStream()
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	name := objString("foo")
	var greeting objString
	if err := rpc.WriteRequest(stream, rpcGreet, &name); err != nil {
		t.Fatal(err)
	} else if err := rpc.ReadResponse(stream, &greeting); err != nil {
		t.Fatal(err)
	} else if greeting != "Hello, foo" {
		t.Fatal("unexpected greeting:", greeting)
	}
	if err := <-peerErr; err != nil {
		t.Fatal(err)
	}
}
