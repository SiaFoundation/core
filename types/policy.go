package types

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
)

// A SpendPolicy describes the conditions under which an input may be spent.
type SpendPolicy interface {
	isPolicy()
}

// AnyoneCanSpend returns a policy that has no requirements.
func AnyoneCanSpend() SpendPolicy { return PolicyThreshold{N: 0} }

// PolicyAbove requires the input to be spent above a given block height.
type PolicyAbove uint64

// PolicyPublicKey requires the input to be signed by a given key.
type PolicyPublicKey PublicKey

// PolicyThreshold requires at least N sub-policies to be satisfied.
type PolicyThreshold struct {
	N  uint8
	Of []SpendPolicy
}

// PolicyUnlockConditions reproduces the requirements imposed by Sia's original
// "UnlockConditions" type. It exists for compatibility purposes and should not
// be used to construct new policies.
type PolicyUnlockConditions struct {
	Timelock           uint64
	PublicKeys         []PublicKey
	SignaturesRequired uint8
}

func (PolicyAbove) isPolicy()            {}
func (PolicyPublicKey) isPolicy()        {}
func (PolicyThreshold) isPolicy()        {}
func (PolicyUnlockConditions) isPolicy() {}

func unlockConditionsRoot(uc PolicyUnlockConditions) Hash256 {
	buf := make([]byte, 65)
	uint64Leaf := func(u uint64) Hash256 {
		buf[0] = 0
		binary.LittleEndian.PutUint64(buf[1:], u)
		return HashBytes(buf[:9])
	}
	pubkeyLeaf := func(pk PublicKey) Hash256 {
		buf[0] = 0
		copy(buf[1:], "ed25519\x00\x00\x00\x00\x00\x00\x00\x00\x00")
		binary.LittleEndian.PutUint64(buf[17:], uint64(len(pk)))
		copy(buf[25:], pk[:])
		return HashBytes(buf[:57])
	}
	nodeHash := func(left, right Hash256) Hash256 {
		buf[0] = 1
		copy(buf[1:], left[:])
		copy(buf[33:], right[:])
		return HashBytes(buf[:65])
	}
	var trees [8]Hash256
	var numLeaves uint8
	addLeaf := func(h Hash256) {
		i := 0
		for ; numLeaves&(1<<i) != 0; i++ {
			h = nodeHash(trees[i], h)
		}
		trees[i] = h
		numLeaves++
	}
	treeRoot := func() Hash256 {
		i := bits.TrailingZeros8(numLeaves)
		root := trees[i]
		for i++; i < len(trees); i++ {
			if numLeaves&(1<<i) != 0 {
				root = nodeHash(trees[i], root)
			}
		}
		return root
	}

	addLeaf(uint64Leaf(uc.Timelock))
	for _, key := range uc.PublicKeys {
		addLeaf(pubkeyLeaf(key))
	}
	addLeaf(uint64Leaf(uint64(uc.SignaturesRequired)))
	return treeRoot()
}

// PolicyAddress computes the opaque address for a given policy.
func PolicyAddress(p SpendPolicy) Address {
	if uc, ok := p.(PolicyUnlockConditions); ok {
		// NOTE: to preserve compatibility, we use the original address
		// derivation code for these policies
		return Address(unlockConditionsRoot(uc))
	}
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
	opUnlockConditions
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
		case PolicyUnlockConditions:
			appendUint8(opUnlockConditions)
			appendUint32(uint32(p.Timelock))
			appendUint8(uint8(len(p.PublicKeys)))
			for i := range p.PublicKeys {
				appendPublicKey(PublicKey(p.PublicKeys[i]))
			}
			appendUint8(p.SignaturesRequired)
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
		case opUnlockConditions:
			uc := PolicyUnlockConditions{
				Timelock:   uint64(readUint32()),
				PublicKeys: make([]PublicKey, readUint8()),
			}
			for i := range uc.PublicKeys {
				uc.PublicKeys[i] = readPublicKey()
			}
			uc.SignaturesRequired = readUint8()
			return uc
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
