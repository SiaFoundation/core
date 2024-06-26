package smux

import (
	"bytes"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Stream implements net.Conn
type Stream struct {
	id            uint32
	rstflag       int32
	sess          *Session
	buffer        bytes.Buffer
	bufferLock    sync.Mutex
	frameSize     int
	chReadEvent   chan struct{} // notify a read event
	die           chan struct{} // flag the stream has closed
	dieLock       sync.Mutex
	readDeadline  atomic.Value
	writeDeadline atomic.Value
}

// newStream initiates a Stream struct
func newStream(id uint32, frameSize int, sess *Session) *Stream {
	s := new(Stream)
	s.id = id
	s.chReadEvent = make(chan struct{}, 1)
	s.frameSize = frameSize
	s.sess = sess
	s.die = make(chan struct{})
	return s
}

// ID returns the unique stream ID.
func (s *Stream) ID() uint32 {
	return s.id
}

// Read implements net.Conn
func (s *Stream) Read(b []byte) (n int, err error) {
	var deadline <-chan time.Time
	if d, ok := s.readDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer := time.NewTimer(time.Until(d))
		defer func() {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}()
		deadline = timer.C
	}

	// privilege shutdown
	select {
	case <-s.die:
		return 0, errBrokenPipe
	default:
	}

READ:
	s.bufferLock.Lock()
	n, err = s.buffer.Read(b)
	s.bufferLock.Unlock()

	if n > 0 {
		s.sess.returnTokens(n)
		return n, nil
	} else if atomic.LoadInt32(&s.rstflag) == 1 {
		_ = s.Close()
		return 0, io.EOF
	}

	select {
	case <-s.chReadEvent:
		goto READ
	case <-deadline:
		return n, errTimeout
	case <-s.die:
		return 0, errBrokenPipe
	}
}

// Write implements net.Conn
func (s *Stream) Write(b []byte) (int, error) {
	// Load the deadline, leaving it a default empty time if the load is
	// unsuccessful.
	var deadline time.Time
	if d, ok := s.writeDeadline.Load().(time.Time); ok && !d.IsZero() {
		deadline = d
	}

	select {
	case <-s.die:
		return 0, errBrokenPipe
	default:
	}

	// Send the data as a series of frames.
	frames := s.split(b, cmdPSH, s.id)
	sent := 0 // total bytes sent
	for k := range frames {
		n, err := s.sess.writeFrame(frames[k], deadline)
		sent += n
		if err != nil {
			return sent, err
		}
	}
	return sent, nil
}

// Close implements net.Conn
func (s *Stream) Close() error {
	s.dieLock.Lock()

	select {
	case <-s.die:
		s.dieLock.Unlock()
		return errBrokenPipe
	default:
		close(s.die)
		s.dieLock.Unlock()
		s.sess.streamClosed(s.id)
		_, err := s.sess.writeFrame(newFrame(cmdFIN, s.id), time.Now().Add(s.sess.config.WriteTimeout))
		return err
	}
}

// SetReadDeadline sets the read deadline as defined by
// net.Conn.SetReadDeadline.
// A zero time value disables the deadline.
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.readDeadline.Store(t)
	return nil
}

// SetWriteDeadline sets the write deadline as defined by
// net.Conn.SetWriteDeadline.
// A zero time value disables the deadline.
func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.writeDeadline.Store(t)
	return nil
}

// SetDeadline sets both read and write deadlines as defined by
// net.Conn.SetDeadline.
// A zero time value disables the deadlines.
func (s *Stream) SetDeadline(t time.Time) error {
	if err := s.SetReadDeadline(t); err != nil {
		return err
	}
	return s.SetWriteDeadline(t)
}

// session closes the stream
func (s *Stream) sessionClose() {
	s.dieLock.Lock()
	defer s.dieLock.Unlock()

	select {
	case <-s.die:
	default:
		close(s.die)
	}
}

// LocalAddr satisfies net.Conn interface
func (s *Stream) LocalAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface {
		LocalAddr() net.Addr
	}); ok {
		return ts.LocalAddr()
	}
	return nil
}

// RemoteAddr satisfies net.Conn interface
func (s *Stream) RemoteAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface {
		RemoteAddr() net.Addr
	}); ok {
		return ts.RemoteAddr()
	}
	return nil
}

// pushBytes a slice into buffer
func (s *Stream) pushBytes(p []byte) {
	s.bufferLock.Lock()
	s.buffer.Write(p)
	s.bufferLock.Unlock()
}

// recycleTokens transform remaining bytes to tokens(will truncate buffer)
func (s *Stream) recycleTokens() (n int) {
	s.bufferLock.Lock()
	n = s.buffer.Len()
	s.buffer.Reset()
	s.bufferLock.Unlock()
	return
}

// split large byte buffer into smaller frames, reference only
func (s *Stream) split(bts []byte, cmd byte, sid uint32) []Frame {
	frames := make([]Frame, 0, len(bts)/s.frameSize+1)
	for len(bts) > s.frameSize {
		frame := newFrame(cmd, sid)
		frame.data = bts[:s.frameSize]
		bts = bts[s.frameSize:]
		frames = append(frames, frame)
	}
	if len(bts) > 0 {
		frame := newFrame(cmd, sid)
		frame.data = bts
		frames = append(frames, frame)
	}
	return frames
}

// notify read event
func (s *Stream) notifyReadEvent() {
	select {
	case s.chReadEvent <- struct{}{}:
	default:
	}
}

// mark this stream has been reset
func (s *Stream) markRST() {
	atomic.StoreInt32(&s.rstflag, 1)
}

var errTimeout error = &timeoutError{}

type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }
