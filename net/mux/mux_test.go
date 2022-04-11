package mux

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"lukechampine.com/frand"
)

func TestMux(t *testing.T) {
	serverKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	serverCh := make(chan error, 1)
	go func() {
		serverCh <- func() error {
			conn, err := l.Accept()
			if err != nil {
				return err
			}
			m, err := Accept(conn, serverKey)
			if err != nil {
				return err
			}
			defer m.Close()
			s, err := m.AcceptStream()
			if err != nil {
				return err
			}
			defer s.Close()
			buf := make([]byte, 100)
			if n, err := s.Read(buf); err != nil {
				return err
			} else if _, err := fmt.Fprintf(s, "hello, %s!", buf[:n]); err != nil {
				return err
			}
			return s.Close()
		}()
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	m, err := Dial(conn, serverKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	s := m.DialStream()
	defer s.Close()
	buf := make([]byte, 100)
	if _, err := s.Write([]byte("world")); err != nil {
		t.Fatal(err)
	} else if n, err := io.ReadFull(s, buf[:13]); err != nil {
		t.Fatal(err)
	} else if string(buf[:n]) != "hello, world!" {
		t.Fatal("bad hello:", string(buf[:n]))
	}
	if err := s.Close(); err != nil && err != ErrPeerClosedConn {
		t.Fatal(err)
	}

	if err := <-serverCh; err != nil && err != ErrPeerClosedStream {
		t.Fatal(err)
	}

	// all streams should have been deleted
	time.Sleep(time.Millisecond * 100)
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.streams) != 0 {
		t.Error("streams not closed")
	}
}

func TestManyStreams(t *testing.T) {
	serverKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	serverCh := make(chan error, 1)
	go func() {
		serverCh <- func() error {
			conn, err := l.Accept()
			if err != nil {
				return err
			}
			m, err := Accept(conn, serverKey)
			if err != nil {
				return err
			}
			defer m.Close()
			for {
				s, err := m.AcceptStream()
				if err != nil {
					return err
				}
				// simple echo handler
				go func() {
					buf := make([]byte, 100)
					n, _ := s.Read(buf)
					s.Write(buf[:n])
					s.Close()
				}()
			}
		}()
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	m, err := Dial(conn, serverKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	// spawn 100 streams
	var wg sync.WaitGroup
	errChan := make(chan error, 100)
	for i := 0; i < cap(errChan); i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := m.DialStream()
			defer s.Close()
			msg := fmt.Sprintf("hello, %v!", i)
			buf := make([]byte, len(msg))
			if _, err := s.Write([]byte(msg)); err != nil {
				errChan <- err
			} else if _, err := io.ReadFull(s, buf); err != nil {
				errChan <- err
			} else if string(buf) != msg {
				errChan <- err
			} else if err := s.Close(); err != nil {
				errChan <- err
			}
		}(i)
	}
	wg.Wait()
	close(errChan)
	for err := range errChan {
		if err != nil {
			t.Fatal(err)
		}
	}

	if err := m.Close(); err != nil {
		t.Fatal(err)
	} else if err := <-serverCh; err != nil && err != ErrPeerClosedConn {
		t.Fatal(err)
	}

	// all streams should have been deleted
	time.Sleep(time.Millisecond * 100)
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.streams) != 0 {
		t.Error("streams not closed:", len(m.streams))
	}
}

func TestDeadline(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	serverKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	serverCh := make(chan error, 1)
	go func() {
		serverCh <- func() error {
			conn, err := l.Accept()
			if err != nil {
				return err
			}
			m, err := Accept(conn, serverKey)
			if err != nil {
				return err
			}
			defer m.Close()
			for {
				s, err := m.AcceptStream()
				if err != nil {
					return err
				}
				// wait 100ms before reading/writing
				buf := make([]byte, 100)
				time.Sleep(100 * time.Millisecond)
				if _, err := s.Read(buf); err != nil {
					return err
				}
				time.Sleep(100 * time.Millisecond)
				if _, err := s.Write([]byte("hello, world!")); err != nil {
					return err
				} else if err := s.Close(); err != nil {
					return err
				}
			}
		}()
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	m, err := Dial(conn, serverKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	// a Read deadline should not timeout a Write
	s := m.DialStream()
	buf := []byte("hello, world!")
	s.SetReadDeadline(time.Now().Add(time.Millisecond))
	time.Sleep(2 * time.Millisecond)
	_, err = s.Write(buf)
	s.SetReadDeadline(time.Time{})
	if err != nil {
		t.Fatal("SetReadDeadline caused Write to fail:", err)
	} else if _, err := io.ReadFull(s, buf); err != nil {
		t.Fatal(err)
	} else if string(buf) != "hello, world!" {
		t.Fatal("bad echo")
	} else if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		timeout bool
		fn      func(*Stream)
	}{
		{false, func(*Stream) {}}, // no deadline
		{false, func(s *Stream) {
			s.SetDeadline(time.Now().Add(time.Hour)) // plenty of time
		}},
		{true, func(s *Stream) {
			s.SetDeadline(time.Now().Add(time.Millisecond)) // too short
		}},
		{true, func(s *Stream) {
			s.SetDeadline(time.Now().Add(time.Millisecond))
			s.SetReadDeadline(time.Time{}) // Write should still fail
		}},
		{true, func(s *Stream) {
			s.SetDeadline(time.Now().Add(time.Millisecond))
			s.SetWriteDeadline(time.Time{}) // Read should still fail
		}},
		{false, func(s *Stream) {
			s.SetDeadline(time.Now())
			s.SetDeadline(time.Time{}) // should overwrite
		}},
		{false, func(s *Stream) {
			s.SetDeadline(time.Now().Add(time.Millisecond))
			s.SetWriteDeadline(time.Time{}) // overwrites Read
			s.SetReadDeadline(time.Time{})  // overwrites Write
		}},
	}
	for i, test := range tests {
		err := func() error {
			s := m.DialStream()
			defer s.Close()
			test.fn(s) // set deadlines

			// need to write a fairly large message; otherwise the packets just
			// get buffered and "succeed" instantly
			if _, err := s.Write(make([]byte, m.settings.PacketSize*2)); err != nil {
				return fmt.Errorf("foo: %w", err)
			} else if _, err := io.ReadFull(s, buf[:13]); err != nil {
				return err
			} else if string(buf) != "hello, world!" {
				return errors.New("bad echo")
			}
			return s.Close()
		}()
		if isTimeout := errors.Is(err, os.ErrDeadlineExceeded); test.timeout != isTimeout {
			t.Errorf("test %v: expected timeout=%v, got %v", i, test.timeout, err)
		}
	}

	if err := m.Close(); err != nil {
		t.Fatal(err)
	} else if err := <-serverCh; err != nil && err != ErrPeerClosedConn && err != ErrPeerClosedStream {
		t.Fatal(err)
	}
}

func TestContext(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	serverKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	serverCh := make(chan error, 1)
	go func() {
		serverCh <- func() error {
			conn, err := l.Accept()
			if err != nil {
				return err
			}
			m, err := Accept(conn, serverKey)
			if err != nil {
				return err
			}
			defer m.Close()
			for {
				s, err := m.AcceptStream()
				if err != nil {
					return err
				}
				// wait 250ms before reading
				time.Sleep(250 * time.Millisecond)
				var n uint64
				if err := binary.Read(s, binary.LittleEndian, &n); err != nil {
					return err
				}
				buf := make([]byte, n)
				if _, err := io.ReadFull(s, buf); err != nil {
					if errors.Is(err, io.ErrUnexpectedEOF) {
						return nil
					}
					return err
				}

				// wait 250ms before replying
				time.Sleep(250 * time.Millisecond)
				echo := make([]byte, len(buf)+8)
				binary.LittleEndian.PutUint64(echo, n)
				copy(echo[8:], buf)
				if _, err := s.Write(echo); err != nil {
					return err
				} else if err := s.Close(); err != nil {
					return err
				}
			}
		}()
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	m, err := Dial(conn, serverKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	tests := []struct {
		err     error
		context func() context.Context
	}{
		{nil, func() context.Context {
			ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
			t.Cleanup(cancel)
			return ctx
		}},
		{context.Canceled, func() context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		}},
		{context.Canceled, func() context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(time.Millisecond*5, cancel)
			return ctx
		}},
		{context.DeadlineExceeded, func() context.Context {
			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*5)
			t.Cleanup(cancel)
			return ctx
		}},
	}
	for i, test := range tests {
		err := func() error {
			s := m.DialStreamContext(test.context())
			defer s.Close()

			msg := make([]byte, m.settings.PacketSize+8)
			frand.Read(msg[8 : 128+8])
			binary.LittleEndian.PutUint64(msg, uint64(len(msg)-8))
			if _, err := s.Write(msg); err != nil {
				return fmt.Errorf("write: %w", err)
			}

			resp := make([]byte, len(msg))
			if _, err := io.ReadFull(s, resp); err != nil {
				return fmt.Errorf("read: %w", err)
			} else if !bytes.Equal(msg, resp) {
				return errors.New("bad echo")
			}
			return s.Close()
		}()
		if !errors.Is(err, test.err) {
			t.Fatalf("test %v: expected error %v, got %v", i, test.err, err)
		}
	}

	if err := m.Close(); err != nil {
		t.Fatal(err)
	} else if err := <-serverCh; err != nil && err != ErrPeerClosedConn && err != ErrPeerClosedStream {
		t.Fatal(err)
	}
}

type statsConn struct {
	r, w int32
	net.Conn
}

func (c *statsConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	atomic.AddInt32(&c.r, int32(n))
	return n, err
}

func (c *statsConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	atomic.AddInt32(&c.w, int32(n))
	return n, err
}

func TestCovertStream(t *testing.T) {
	serverKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	serverCh := make(chan error, 1)
	go func() {
		serverCh <- func() error {
			conn, err := l.Accept()
			if err != nil {
				return err
			}
			m, err := Accept(conn, serverKey)
			if err != nil {
				return err
			}
			defer m.Close()
			// accept covert stream
			cs, err := m.AcceptStream()
			if err != nil {
				return err
			}
			covertCh := make(chan error)
			go func() {
				defer cs.Close()
				buf := make([]byte, 100)
				if n, err := cs.Read(buf); err != nil {
					covertCh <- err
				} else if _, err := fmt.Fprintf(cs, "hello, %s!", buf[:n]); err != nil {
					covertCh <- err
				} else {
					covertCh <- cs.Close()
				}
			}()
			// accept regular stream
			s, err := m.AcceptStream()
			if err != nil {
				return err
			}
			defer s.Close()
			buf := make([]byte, 100)
			n, err := s.Read(buf)
			if err != nil {
				return err
			}
			// wait for covert stream to buffer before writing
			if err := <-covertCh; err != nil {
				return err
			}
			if _, err := fmt.Fprintf(s, "hello, %s!", buf[:n]); err != nil {
				return err
			} else if err := s.Close(); err != nil {
				return err
			}
			return m.Close()
		}()
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn = &statsConn{Conn: conn} // track raw number of bytes on wire

	m, err := Dial(conn, serverKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	covertCh := make(chan error, 1)
	bufChan := make(chan struct{})
	go func() {
		s := m.DialCovertStream()
		defer s.Close()
		buf := make([]byte, 100)
		if _, err := s.Write([]byte("covert")); err != nil {
			covertCh <- err
			return
		}
		bufChan <- struct{}{}
		if n, err := io.ReadFull(s, buf[:14]); err != nil {
			covertCh <- err
		} else if string(buf[:n]) != "hello, covert!" {
			covertCh <- fmt.Errorf("bad hello: %s %x", buf[:n], buf[:n])
		} else {
			covertCh <- s.Close()
		}
	}()

	// to generate padding for covert stream, send a regular packet
	s := m.DialStream()
	<-bufChan // wait for covert stream to buffer
	buf := make([]byte, 100)
	if _, err := s.Write([]byte("world")); err != nil {
		t.Log(<-serverCh)
		t.Fatal(err)
	} else if n, err := io.ReadFull(s, buf[:13]); err != nil {
		t.Log(<-serverCh)
		t.Fatal(err)
	} else if string(buf[:n]) != "hello, world!" {
		t.Fatalf("bad hello: %s", buf[:n])
	}

	if err := <-covertCh; err != nil && err != ErrPeerClosedConn {
		t.Fatal(err)
	} else if err := m.Close(); err != nil {
		t.Fatal(err)
	} else if err := <-serverCh; err != nil && err != ErrPeerClosedStream {
		t.Fatal(err)
	}
	// wait for read/write goroutines to exit
	time.Sleep(time.Second)

	// amount of data transferred should be the same as without covert stream
	expWritten := 1 + // version
		32 + // key exchange
		connSettingsSize + chachaOverhead + // settings
		m.settings.PacketSize // "world"

	expRead := 1 + // version
		32 + 64 + // key exchange
		connSettingsSize + chachaOverhead + // settings
		m.settings.PacketSize // "hello, world!"

	w := int(atomic.LoadInt32(&conn.(*statsConn).w))
	r := int(atomic.LoadInt32(&conn.(*statsConn).r))

	// NOTE: either peer may have sent the Close packet, or both; we don't care
	// either way
	if w > expWritten {
		expWritten += m.settings.PacketSize
	}
	if r > expRead {
		expRead += m.settings.PacketSize
	}
	if w != expWritten {
		t.Errorf("wrote %v bytes, expected %v", w, expWritten)
	}
	if r != expRead {
		t.Errorf("read %v bytes, expected %v", r, expRead)
	}
}

func BenchmarkMux(b *testing.B) {
	for _, numStreams := range []int{1, 2, 10, 100, 500, 1000} {
		b.Run(fmt.Sprint(numStreams), func(b *testing.B) {
			serverKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
			l, err := net.Listen("tcp", ":0")
			if err != nil {
				b.Fatal(err)
			}
			defer l.Close()
			serverCh := make(chan error, 1)
			go func() {
				serverCh <- func() error {
					conn, err := l.Accept()
					if err != nil {
						return err
					}
					m, err := Accept(conn, serverKey)
					if err != nil {
						return err
					}
					var wg sync.WaitGroup
					for i := 0; i < b.N*numStreams; i++ {
						s, err := m.AcceptStream()
						if err != nil {
							return err
						}
						wg.Add(1)
						go func() {
							defer wg.Done()
							io.Copy(io.Discard, s)
							s.Close()
						}()
					}
					wg.Wait()
					return m.Close()
				}()
			}()
			defer func() {
				if err := <-serverCh; err != nil && err != ErrPeerClosedConn {
					b.Fatal(err)
				}
			}()

			conn, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				b.Fatal(err)
			}
			m, err := Dial(conn, serverKey.Public().(ed25519.PublicKey))
			if err != nil {
				b.Fatal(err)
			}
			defer m.Close()

			// open each stream in a separate goroutine
			bufSize := defaultConnSettings.maxPayloadSize()
			buf := make([]byte, bufSize)
			b.ResetTimer()
			b.SetBytes(int64(bufSize * numStreams))
			b.ReportAllocs()
			start := time.Now()
			var wg sync.WaitGroup
			wg.Add(numStreams)
			for j := 0; j < numStreams; j++ {
				go func() {
					defer wg.Done()
					s := m.DialStream()
					defer s.Close()
					for i := 0; i < b.N; i++ {
						if _, err := s.Write(buf); err != nil {
							panic(err)
						}
					}
				}()
			}
			wg.Wait()
			b.ReportMetric(float64(b.N*numStreams)/time.Since(start).Seconds(), "conns/sec")
		})
	}
}

func BenchmarkConn(b *testing.B) {
	// benchmark throughput of raw TCP conn (plus encryption overhead to make it fair)
	encryptionKey := make([]byte, 32)
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		b.Fatal(err)
	}
	serverCh := make(chan error, 1)
	go func() {
		serverCh <- func() error {
			conn, err := l.Accept()
			if err != nil {
				return err
			}
			defer conn.Close()
			aead, _ := chacha20poly1305.New(encryptionKey)
			buf := make([]byte, defaultConnSettings.PacketSize)
			for {
				_, err := io.ReadFull(conn, buf)
				if err != nil {
					return err
				}
				if _, err := decryptInPlace(buf, aead); err != nil {
					return err
				}
			}
		}()
	}()
	defer func() {
		if err := <-serverCh; err != nil && err != io.EOF {
			b.Fatal(err)
		}
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()

	aead, _ := chacha20poly1305.New(encryptionKey)
	buf := make([]byte, defaultConnSettings.PacketSize)
	b.ResetTimer()
	b.SetBytes(int64(defaultConnSettings.maxPayloadSize()))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		encryptInPlace(buf, aead)
		if _, err := conn.Write(buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCovertStream(b *testing.B) {
	serverKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()
	serverCh := make(chan error, 1)
	go func() {
		serverCh <- func() error {
			conn, err := l.Accept()
			if err != nil {
				return err
			}
			m, err := Accept(conn, serverKey)
			if err != nil {
				return err
			}

			// background stream, to provide padding for covert streams
			bs, err := m.AcceptStream()
			if err != nil {
				return err
			}
			defer bs.Close()
			go io.Copy(bs, bs)

			cs, err := m.AcceptStream()
			if err != nil {
				return err
			}

			for n := 0; n < b.N*defaultConnSettings.maxPayloadSize(); {
				buf := make([]byte, defaultConnSettings.maxPayloadSize())
				r, err := cs.Read(buf)
				if err != nil {
					return err
				}
				n += r
			}
			cs.Write([]byte{1})
			cs.Close()
			return m.Close()
		}()
	}()
	defer func() {
		if err := <-serverCh; err != nil && err != ErrPeerClosedConn {
			b.Fatal(err)
		}
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	m, err := Dial(conn, serverKey.Public().(ed25519.PublicKey))
	if err != nil {
		b.Fatal(err)
	}
	defer m.Close()

	// background stream, to provide padding for covert streams
	backBuf := make([]byte, 100)
	for i := range backBuf {
		backBuf[i] = 0x77
	}
	bs := m.DialStream()
	defer bs.Close()
	if _, err := bs.Write(backBuf); err != nil {
		b.Fatal(err)
	}
	go io.Copy(bs, bs)

	// open each stream in a separate goroutine
	bufSize := defaultConnSettings.maxPayloadSize()
	buf := make([]byte, bufSize)
	for i := range buf {
		buf[i] = 0xFF
	}
	b.ResetTimer()
	b.SetBytes(int64(bufSize))
	b.ReportAllocs()
	cs := m.DialCovertStream()
	defer cs.Close()
	for i := 0; i < b.N; i++ {
		if _, err := cs.Write(buf); err != nil {
			b.Fatal(err)
		}
	}
	cs.Read(buf[:1])
}
