package rhp

import (
	"errors"
	"fmt"
)

// Error codes.
const (
	ErrorCodeTransport = iota + 1
	ErrorCodeHostError
	ErrorCodeBadRequest
	ErrorCodeDecoding
	ErrorCodePayment
)

// An RPCError pairs a human-readable error description with a status code.
type RPCError struct {
	Code        uint8
	Description string
}

var (
	// ErrTokenExpired is returned when an account token has expired.
	ErrTokenExpired = NewRPCError(ErrorCodeBadRequest, "account token expired")
	// ErrPricesExpired is returned when the host's prices have expired.
	ErrPricesExpired = NewRPCError(ErrorCodeBadRequest, "prices expired")
	// ErrInvalidSignature is returned when a signature is invalid.
	ErrInvalidSignature = NewRPCError(ErrorCodeBadRequest, "invalid signature")
	// ErrNotEnoughFunds is returned when a client has insufficient funds to
	// pay for an RPC.
	ErrNotEnoughFunds = NewRPCError(ErrorCodePayment, "not enough funds")
	// ErrHostFundError is returned when the host encounters an error while
	// funding a formation or renewal transaction.
	ErrHostFundError = NewRPCError(ErrorCodeHostError, "host funding error")
	// ErrSectorNotFound is returned when the host is not storing a sector.
	ErrSectorNotFound = NewRPCError(ErrorCodeHostError, "sector not found")
	// ErrNotAcceptingContracts is returned when the host is not accepting
	// contracts.
	ErrNotAcceptingContracts = NewRPCError(ErrorCodeHostError, "not accepting contracts")
	// ErrNotEnoughStorage is returned when the host does not have enough
	// storage to store a sector.
	ErrNotEnoughStorage = NewRPCError(ErrorCodeHostError, "not enough storage")

	// ErrHostInternalError is a catch-all for any error that occurs on the host
	// side and is not the client's fault.
	ErrHostInternalError = NewRPCError(ErrorCodeHostError, "internal error")
)

// Error implements error.
func (e *RPCError) Error() string {
	return fmt.Sprintf("%v (%v)", e.Description, e.Code)
}

// Is returns true if the target is an RPCError and its
// code and description match the receiver's.
func (e *RPCError) Is(target error) bool {
	re, ok := target.(*RPCError)
	return ok && e.Code == re.Code && e.Description == re.Description
}

// NewRPCError returns a new RPCError with the given code and description.
func NewRPCError(code uint8, desc string) error {
	return &RPCError{Code: code, Description: desc}
}

// ErrorCode returns the code of err. If err is not an RPCError, ErrorCode
// returns ErrorCodeTransport.
func ErrorCode(err error) uint8 {
	if re := new(RPCError); errors.As(err, &re) {
		return re.Code
	}
	return ErrorCodeTransport
}
