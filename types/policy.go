package types

import (
	"encoding/binary"
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
	h := hasherPool.Get().(*Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	h.E.WriteString("sia/address")
	h.E.WritePolicy(p)
	return Address(h.Sum())
}

// StandardAddress computes the address for a single public key policy.
func StandardAddress(pk PublicKey) Address {
	return PolicyAddress(PolicyPublicKey(pk))
}
