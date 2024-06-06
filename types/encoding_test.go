package types

import (
	"io"
	"testing"
)

type readErrorer struct {
	err error
	r   io.Reader
}

func (r *readErrorer) Read(p []byte) (n int, err error) {
	if r.err != nil {
		return 0, r.err
	}
	return r.r.Read(p)
}

func TestDecoderError(t *testing.T) {
	r, w := io.Pipe()
	re := &readErrorer{r: r}
	enc := NewEncoder(w)
	d := NewDecoder(io.LimitedReader{R: re, N: 1e6})

	go func() {
		// writing to the pipe blocks until we read from it
		enc.WritePrefix(1000)
		enc.Flush()
	}()

	// read the value from the encoder
	n := d.ReadPrefix()
	if n != 1000 {
		t.Fatalf("expected 1000, got %d", n)
	}

	// set the error and try to read again
	re.err = io.EOF

	// should return 0 since the decoder errored
	n = d.ReadPrefix()
	if n != 0 {
		t.Fatalf("expected 0, got %d", n)
	}
}
