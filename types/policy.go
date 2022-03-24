package types

import (
	"encoding/binary"
	"encoding/hex"
	"math/bits"
	"strconv"
	"strings"
)

// A SpendPolicy describes the conditions under which an input may be spent.
type SpendPolicy struct {
	Type interface{ isPolicy() }
}

// PolicyTypeAbove requires the input to be spent above a given block height.
type PolicyTypeAbove uint64

// PolicyAbove returns a policy that requires the input to be spent above a
// given block height.
func PolicyAbove(height uint64) SpendPolicy { return SpendPolicy{PolicyTypeAbove(height)} }

// PolicyTypePublicKey requires the input to be signed by a given key.
type PolicyTypePublicKey PublicKey

// PolicyPublicKey returns a policy that requires the input to be signed by a
// given key.
func PolicyPublicKey(pk PublicKey) SpendPolicy { return SpendPolicy{PolicyTypePublicKey(pk)} }

// PolicyTypeThreshold requires at least N sub-policies to be satisfied.
type PolicyTypeThreshold struct {
	N  uint8
	Of []SpendPolicy
}

// PolicyThreshold returns a policy that requires at least N sub-policies to be
// satisfied.
func PolicyThreshold(n uint8, of []SpendPolicy) SpendPolicy {
	return SpendPolicy{PolicyTypeThreshold{n, of}}
}

// AnyoneCanSpend returns a policy that has no requirements.
func AnyoneCanSpend() SpendPolicy { return PolicyThreshold(0, nil) }

// PolicyTypeUnlockConditions reproduces the requirements imposed by Sia's
// original "UnlockConditions" type. It exists for compatibility purposes and
// should not be used to construct new policies.
type PolicyTypeUnlockConditions struct {
	Timelock           uint64
	PublicKeys         []PublicKey
	SignaturesRequired uint8
}

func (PolicyTypeAbove) isPolicy()            {}
func (PolicyTypePublicKey) isPolicy()        {}
func (PolicyTypeThreshold) isPolicy()        {}
func (PolicyTypeUnlockConditions) isPolicy() {}

func (uc PolicyTypeUnlockConditions) root() Hash256 {
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

// Address computes the opaque address for a given policy.
func (p SpendPolicy) Address() Address {
	if uc, ok := p.Type.(PolicyTypeUnlockConditions); ok {
		// NOTE: to preserve compatibility, we use the original address
		// derivation code for these policies
		return Address(uc.root())
	}
	h := hasherPool.Get().(*Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	h.E.WriteString("sia/address")
	p.EncodeTo(h.E)
	return Address(h.Sum())
}

// StandardAddress computes the address for a single public key policy.
func StandardAddress(pk PublicKey) Address { return PolicyPublicKey(pk).Address() }

// String implements fmt.Stringer.
func (p SpendPolicy) String() string {
	var sb strings.Builder
	switch p := p.Type.(type) {
	case PolicyTypeAbove:
		sb.WriteString("above(")
		sb.WriteString(strconv.FormatUint(uint64(p), 10))
		sb.WriteByte(')')

	case PolicyTypePublicKey:
		sb.WriteString("pk(")
		sb.WriteString(hex.EncodeToString(p[:]))
		sb.WriteByte(')')

	case PolicyTypeThreshold:
		sb.WriteString("thresh(")
		sb.WriteString(strconv.FormatUint(uint64(p.N), 10))
		sb.WriteString(",[")
		for i, sp := range p.Of {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(sp.String())
		}
		sb.WriteString("])")

	case PolicyTypeUnlockConditions:
		sb.WriteString("uc(")
		sb.WriteString(strconv.FormatUint(p.Timelock, 10))
		sb.WriteString(",[")
		for i, pk := range p.PublicKeys {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(hex.EncodeToString(pk[:]))
		}
		sb.WriteString("],")
		sb.WriteString(strconv.FormatUint(uint64(p.SignaturesRequired), 10))
		sb.WriteByte(')')
	}
	return sb.String()
}

// MarshalJSON implements json.Marshaler.
func (p SpendPolicy) MarshalJSON() ([]byte, error) {
	return []byte(`"` + p.String() + `"`), nil
}
