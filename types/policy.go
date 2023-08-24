package types

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
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
func PolicyAbove(height uint64) SpendPolicy {
	return SpendPolicy{PolicyTypeAbove(height)}
}

// PolicyTypePublicKey requires the input to be signed by a given key.
type PolicyTypePublicKey PublicKey

// PolicyPublicKey returns a policy that requires the input to be signed by a
// given key.
func PolicyPublicKey(pk PublicKey) SpendPolicy {
	return SpendPolicy{PolicyTypePublicKey(pk)}
}

// PolicyTypeThreshold requires at least N sub-policies to be satisfied.
type PolicyTypeThreshold struct {
	N  uint8
	Of []SpendPolicy
}

// PolicyThreshold returns a policy that requires at least N sub-policies to be
// satisfied. When satisfying a threshold policy, all unsatisfied sub-policies
// must be replaced with PolicyOpaque.
func PolicyThreshold(n uint8, of []SpendPolicy) SpendPolicy {
	return SpendPolicy{PolicyTypeThreshold{n, of}}
}

// PolicyTypeOpaque is the opaque hash of a policy. It is not satisfiable.
type PolicyTypeOpaque Address

// PolicyOpaque returns a policy with the same address as p, but without its
// semantics.
func PolicyOpaque(p SpendPolicy) SpendPolicy {
	if _, ok := p.Type.(PolicyTypeOpaque); ok {
		return p
	}
	return SpendPolicy{PolicyTypeOpaque(p.Address())}
}

// AnyoneCanSpend returns a policy that has no requirements.
func AnyoneCanSpend() SpendPolicy {
	return PolicyThreshold(0, nil)
}

// PolicyTypeUnlockConditions reproduces the requirements imposed by Sia's
// original "UnlockConditions" type. It exists for compatibility purposes and
// should not be used to construct new policies.
type PolicyTypeUnlockConditions UnlockConditions

func (PolicyTypeAbove) isPolicy()            {}
func (PolicyTypePublicKey) isPolicy()        {}
func (PolicyTypeThreshold) isPolicy()        {}
func (PolicyTypeOpaque) isPolicy()           {}
func (PolicyTypeUnlockConditions) isPolicy() {}

// Address computes the opaque address for a given policy.
func (p SpendPolicy) Address() Address {
	if uc, ok := p.Type.(PolicyTypeUnlockConditions); ok {
		// NOTE: to preserve compatibility, we use the original address
		// derivation code for these policies
		return unlockConditionsRoot(UnlockConditions(uc))
	}
	h := hasherPool.Get().(*Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	h.E.WriteString("sia/address|")
	if pt, ok := p.Type.(PolicyTypeThreshold); ok {
		pt.Of = append([]SpendPolicy(nil), pt.Of...)
		for i := range pt.Of {
			pt.Of[i] = PolicyOpaque(pt.Of[i])
		}
		p = SpendPolicy{pt}
	}
	p.EncodeTo(h.E)
	return Address(h.Sum())
}

// String implements fmt.Stringer.
func (p SpendPolicy) String() string {
	var sb strings.Builder
	writeHex := func(p []byte) {
		sb.WriteString("0x")
		sb.WriteString(hex.EncodeToString(p))
	}
	switch p := p.Type.(type) {
	case PolicyTypeAbove:
		sb.WriteString("above(")
		sb.WriteString(strconv.FormatUint(uint64(p), 10))
		sb.WriteByte(')')

	case PolicyTypePublicKey:
		sb.WriteString("pk(")
		writeHex(p[:])
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

	case PolicyTypeOpaque:
		sb.WriteString("opaque(")
		writeHex(p[:])
		sb.WriteByte(')')

	case PolicyTypeUnlockConditions:
		sb.WriteString("uc(")
		sb.WriteString(strconv.FormatUint(p.Timelock, 10))
		sb.WriteString(",[")
		for i, pk := range p.PublicKeys {
			if i > 0 {
				sb.WriteByte(',')
			}
			writeHex(pk.Key[:])
		}
		sb.WriteString("],")
		sb.WriteString(strconv.FormatUint(uint64(p.SignaturesRequired), 10))
		sb.WriteByte(')')
	}
	return sb.String()
}

// ParseSpendPolicy parses a spend policy from a string.
func ParseSpendPolicy(s string) (SpendPolicy, error) {
	var err error // sticky
	nextToken := func() string {
		s = strings.TrimSpace(s)
		i := strings.IndexAny(s, "(),[]")
		if err != nil || i == -1 {
			return ""
		}
		t := s[:i]
		s = s[i:]
		return t
	}
	consume := func(b byte) {
		if err != nil {
			return
		}
		s = strings.TrimSpace(s)
		if len(s) == 0 {
			err = io.ErrUnexpectedEOF
		} else if s[0] != b {
			err = fmt.Errorf("expected %q, got %q", b, s[0])
		} else {
			s = s[1:]
		}
	}
	peek := func() byte {
		if err != nil || len(s) == 0 {
			return 0
		}
		return s[0]
	}
	parseInt := func(bitSize int) (u uint64) {
		t := nextToken()
		if err != nil {
			return 0
		}
		u, err = strconv.ParseUint(t, 10, bitSize)
		return
	}
	parsePubkey := func() (pk PublicKey) {
		t := nextToken()
		if err != nil {
			return
		} else if len(t) != 66 {
			err = fmt.Errorf("invalid pubkey length (%d)", len(t))
			return
		} else if t[:2] != "0x" {
			err = fmt.Errorf("invalid pubkey prefix %q", t[:2])
			return
		}
		_, err = hex.Decode(pk[:], []byte(t[2:]))
		return
	}
	var parseSpendPolicy func() SpendPolicy
	parseSpendPolicy = func() SpendPolicy {
		typ := nextToken()
		consume('(')
		defer consume(')')
		switch typ {
		case "above":
			return PolicyAbove(parseInt(64))
		case "pk":
			return PolicyPublicKey(parsePubkey())
		case "thresh":
			n := parseInt(8)
			consume(',')
			consume('[')
			var of []SpendPolicy
			for err == nil && peek() != ']' {
				of = append(of, parseSpendPolicy())
				if peek() != ']' {
					consume(',')
				}
			}
			consume(']')
			return PolicyThreshold(uint8(n), of)
		case "opaque":
			return SpendPolicy{PolicyTypeOpaque(parsePubkey())}
		case "uc":
			timelock := parseInt(64)
			consume(',')
			consume('[')
			var pks []UnlockKey
			for err == nil && peek() != ']' {
				pks = append(pks, parsePubkey().UnlockKey())
				if peek() != ']' {
					consume(',')
				}
			}
			consume(']')
			consume(',')
			sigsRequired := parseInt(8)
			return SpendPolicy{
				PolicyTypeUnlockConditions{
					Timelock:           timelock,
					PublicKeys:         pks,
					SignaturesRequired: sigsRequired,
				},
			}
		default:
			if err == nil {
				err = fmt.Errorf("unrecognized policy type %q", typ)
			}
			return SpendPolicy{}
		}
	}

	p := parseSpendPolicy()
	if err == nil && len(s) > 0 {
		err = fmt.Errorf("trailing bytes: %q", s)
	}
	return p, err
}

// MarshalText implements encoding.TextMarshaler.
func (p SpendPolicy) MarshalText() ([]byte, error) {
	return []byte(p.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (p *SpendPolicy) UnmarshalText(b []byte) (err error) {
	*p, err = ParseSpendPolicy(string(b))
	return
}

// MarshalJSON implements json.Marshaler.
func (p SpendPolicy) MarshalJSON() ([]byte, error) {
	return []byte(`"` + p.String() + `"`), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (p *SpendPolicy) UnmarshalJSON(b []byte) (err error) {
	return p.UnmarshalText(bytes.Trim(b, `"`))
}
