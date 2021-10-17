package gateway

import (
	"fmt"
	"go.sia.tech/core/net/mux"
	"go.sia.tech/core/net/rpc"
	"go.sia.tech/core/types"
	"io"
	"net"
	"sync"
)

type Session struct {
	uniqueID   [8]byte
	netAddress string

	err    error
	closed bool
	mu     sync.Mutex

	mux *mux.Mux
}

func (s *Session) IsClosed() bool {
	return s.closed
}

func (s *Session) Close() error {
	if s.IsClosed() {
		return nil
	}

	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()

	return s.mux.Close()
}

// PrematureCloseErr returns the error that resulted in the Session being closed
// prematurely.
func (s *Session) PrematureCloseErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *Session) setErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil && s.err == nil {
		if ne, ok := err.(net.Error); !ok || !ne.Temporary() {
			s.err = err
			s.mux.Close()
		}
	}
}

func (s *Session) writeMessage(obj rpc.ProtocolObject) error {
	if err := s.PrematureCloseErr(); err != nil {
		return err
	}

	stream, err := s.mux.DialStream()
	if err != nil {
		s.setErr(err)
		return err
	}

	e := types.NewEncoder(stream)
	obj.EncodeTo(e)
	if err := e.Flush(); err != nil {
		s.setErr(err)
		return err
	}
	return nil
}

func (s *Session) readMessage(obj rpc.ProtocolObject, maxLen uint64) error {
	if err := s.PrematureCloseErr(); err != nil {
		return err
	}

	stream, err := s.mux.AcceptStream()
	if err != nil {
		s.setErr(err)
		return err
	}

	d := types.NewDecoder(io.LimitedReader{R: stream, N: int64(maxLen)})
	obj.DecodeFrom(d)
	if err := d.Err(); err != nil {
		s.setErr(err)
		return err
	}
	if err := stream.Close(); err != nil {
		s.setErr(err)
		return err
	}
	return nil
}

// WriteRequest sends an RPC request, comprising an RPC ID and a request object.
func (s *Session) WriteRequest(rpcID rpc.Specifier, req rpc.ProtocolObject) error {
	if err := s.writeMessage(&rpcID); err != nil {
		return fmt.Errorf("WriteRequestID: %w", err)
	}
	if req != nil {
		if err := s.writeMessage(req); err != nil {
			return fmt.Errorf("WriteRequest: %w", err)
		}
	}
	return nil
}

// ReadRequest reads an RPC request.
func (s *Session) ReadRequest(req rpc.ProtocolObject, maxLen uint64) error {
	if err := s.readMessage(req, maxLen); err != nil {
		return fmt.Errorf("ReadRequest: %w", err)
	}
	return nil
}

// WriteResponse writes an RPC response object or error. Either resp or err must
// be nil. If err is an *RPCError, it is sent directly; otherwise, a generic
// RPCError is created from err's Error strins.
func (s *Session) WriteResponse(resp rpc.ProtocolObject, err error) error {
	re, ok := err.(*rpc.Error)
	if err != nil && !ok {
		re = &rpc.Error{Description: err.Error()}
	}

	if err := s.writeMessage(&rpc.Response{re, resp}); err != nil {
		return fmt.Errorf("WriteResponse: %w", err)
	}
	return nil
}

// ReadResponse reads an RPC response. If the response is an error, it is
// returned directly.
func (s *Session) ReadResponse(resp rpc.ProtocolObject, maxLen uint64) error {
	rr := rpc.Response{nil, resp}
	if err := s.readMessage(&rr, maxLen); err != nil {
		return fmt.Errorf("failed to read message: %w", err)
	} else if rr.Err != nil {
		return fmt.Errorf("response error: %w", rr.Err)
	}
	return nil
}

// ReadID reads an RPC request ID.
func (s *Session) ReadID() (rpcID rpc.Specifier, err error) {
	err = s.readMessage(&rpcID, 16)
	return
}
