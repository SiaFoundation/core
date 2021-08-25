package types

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// A SpendPolicy describes the conditions under which an input may be spent.
type SpendPolicy interface {
	isPolicy()
}

// PolicyAbove requires the input to be spent above a given block height.
type PolicyAbove uint64

// PolicyPublicKey requires the input to be signed by a given key.
type PolicyPublicKey PublicKey

// PolicyThreshold requires at least N sub-policies to be satisfied.
type PolicyThreshold struct {
	N  uint8
	Of []SpendPolicy
}

func (PolicyAbove) isPolicy()     {}
func (PolicyPublicKey) isPolicy() {}
func (PolicyThreshold) isPolicy() {}

// String implements fmt.Stringer
func (p PolicyPublicKey) String() string { return fmt.Sprintf("pk(%x)", p[:]) }

// String implements fmt.Stringer
func (p PolicyAbove) String() string { return fmt.Sprintf("above(%v)", uint64(p)) }

// String implements fmt.Stringer
func (p PolicyThreshold) String() string {
	ps := make([]string, len(p.Of))
	for i := range ps {
		ps[i] = fmt.Sprint(p.Of[i])
	}
	switch p.N {
	case 1:
		return fmt.Sprintf("any(%v)", strings.Join(ps, ", "))
	case uint8(len(p.Of)):
		return fmt.Sprintf("all(%v)", strings.Join(ps, ", "))
	default:
		return fmt.Sprintf("atleast(%v, %v)", p.N, strings.Join(ps, ", "))
	}
}

// PolicyAddress computes the opaque address for a given policy.
func PolicyAddress(p SpendPolicy) Address {
	return Address(HashBytes(EncodePolicy(p)))
}

// StandardAddress computes the address for a single public key policy.
func StandardAddress(pk PublicKey) Address {
	return PolicyAddress(PolicyPublicKey(pk))
}

const (
	opInvalid uint8 = iota
	opAbove
	opPublicKey
	opThreshold
)

// EncodePolicy encodes the given policy.
func EncodePolicy(p SpendPolicy) (b []byte) {
	appendUint8 := func(u uint8) {
		b = append(b, u)
	}
	appendUint32 := func(u uint32) {
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, u)
		b = append(b, buf...)
	}
	appendPublicKey := func(pk PublicKey) {
		b = append(b, pk[:]...)
	}
	var appendPolicy func(SpendPolicy)
	appendPolicy = func(p SpendPolicy) {
		switch p := p.(type) {
		case PolicyAbove:
			appendUint8(opAbove)
			appendUint32(uint32(p))
		case PolicyPublicKey:
			appendUint8(opPublicKey)
			appendPublicKey(PublicKey(p))
		case PolicyThreshold:
			appendUint8(opThreshold)
			appendUint8(p.N)
			appendUint8(uint8(len(p.Of)))
			for i := range p.Of {
				appendPolicy(p.Of[i])
			}
		default:
			panic("unhandled policy type")
		}
	}

	appendUint8(1) // version
	appendPolicy(p)
	return
}

// DecodePolicy decodes the policy encoded in b.
func DecodePolicy(b []byte) (SpendPolicy, error) {
	var err error
	setErr := func(serr error) {
		if err != nil {
			err = serr
		}
	}
	next := func(n int) []byte {
		if len(b) < n {
			setErr(io.EOF)
			return nil
		}
		s := b[:n]
		b = b[n:]
		return s
	}
	readUint8 := func() uint8 {
		s := next(1)
		if s == nil {
			return 0
		}
		return s[0]
	}
	readUint32 := func() uint32 {
		s := next(4)
		if s == nil {
			return 0
		}
		return binary.LittleEndian.Uint32(s[:4])
	}
	readPublicKey := func() (pk PublicKey) {
		copy(pk[:], next(len(pk)))
		return
	}

	const maxPolicies = 1024
	totalPolicies := 1
	var readPolicy func() SpendPolicy
	readPolicy = func() SpendPolicy {
		switch op := readUint8(); op {
		case opAbove:
			return PolicyAbove(readUint32())
		case opPublicKey:
			return PolicyPublicKey(readPublicKey())
		case opThreshold:
			thresh := PolicyThreshold{
				N:  readUint8(),
				Of: make([]SpendPolicy, readUint8()),
			}
			totalPolicies += len(thresh.Of)
			if totalPolicies > maxPolicies {
				setErr(errors.New("policy is too complex"))
				return nil
			}
			for i := range thresh.Of {
				thresh.Of[i] = readPolicy()
				if err != nil {
					return nil
				}
			}
			return thresh
		default:
			setErr(fmt.Errorf("unknown policy (opcode %v)", op))
			return nil
		}
	}

	if version := readUint8(); version != 1 {
		return nil, fmt.Errorf("unsupported version (%v)", version)
	}
	p := readPolicy()
	if err != nil {
		return nil, err
	} else if len(b) != 0 {
		return nil, errors.New("encoded policy has trailing bytes")
	}
	return p, nil
}
