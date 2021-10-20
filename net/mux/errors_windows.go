package mux

import (
	"errors"
	"io"
	"syscall"
)

// isConnCloseError returns true if the error is from the peer closing the
// connection early.
func isConnCloseError(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.EPROTOTYPE) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.WSAECONNRESET)
}
