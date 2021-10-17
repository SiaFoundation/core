package rpc

import (
	"bytes"
	"go.sia.tech/core/types"
	"strings"
)

// A ProtocolObject is an object that can be serialized for transport in the
// renter-host protocol.
type ProtocolObject interface {
	EncodeTo(e *types.Encoder)
	DecodeFrom(d *types.Decoder)
}

// A Specifier is a generic identification tag.
type Specifier [16]byte

func (s *Specifier) EncodeTo(e *types.Encoder)   { e.Write(s[:]) }
func (s *Specifier) DecodeFrom(d *types.Decoder) { d.Read(s[:]) }

func (s Specifier) String() string { return string(bytes.Trim(s[:], "\x00")) }

func NewSpecifier(str string) Specifier {
	if len(str) > 16 {
		panic("specifier is too long")
	}
	var s Specifier
	copy(s[:], str)
	return s
}

// An Error may be sent instead of a response object to any RPC.
type Error struct {
	Type        Specifier
	Data        []byte // structure depends on Type
	Description string // human-readable error string
}

func (err *Error) EncodeTo(e *types.Encoder) {
	writePrefixedBytes := func(e *types.Encoder, b []byte) {
		e.WritePrefix(len(b))
		e.Write(b)
	}

	err.Type.EncodeTo(e)
	writePrefixedBytes(e, err.Data)
	writePrefixedBytes(e, []byte(err.Description))
}

func (err *Error) DecodeFrom(d *types.Decoder) {
	readPrefixedBytes := func(d *types.Decoder) []byte {
		b := make([]byte, d.ReadPrefix())
		d.Read(b)
		return b
	}

	err.Type.DecodeFrom(d)
	err.Data = readPrefixedBytes(d)
	err.Description = string(readPrefixedBytes(d))
}

// Error implements the error interface.
func (err *Error) Error() string {
	return err.Description
}

// Is reports whether this error matches target.
func (err *Error) Is(target error) bool {
	return strings.Contains(err.Description, target.Error())
}

// Response is a helper type for encoding and decoding RPC response messages,
// which can represent either valid data or an error.
type Response struct {
	Err  *Error
	Data ProtocolObject
}

func (resp *Response) EncodeTo(e *types.Encoder) {
	e.WriteBool(resp.Err != nil)
	if resp.Err != nil {
		resp.Err.EncodeTo(e)
	} else {
		resp.Data.EncodeTo(e)
	}
}

func (resp *Response) DecodeFrom(d *types.Decoder) {
	if isErr := d.ReadBool(); isErr {
		resp.Err = new(Error)
		resp.Err.DecodeFrom(d)
	} else {
		resp.Data.DecodeFrom(d)
	}
}
