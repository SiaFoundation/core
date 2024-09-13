package types

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
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

// PolicyTypeAfter requires the input to be spent after a given timestamp.
type PolicyTypeAfter time.Time

// PolicyAfter returns a policy that requires the input to be spent after a
// given timestamp.
func PolicyAfter(t time.Time) SpendPolicy {
	return SpendPolicy{PolicyTypeAfter(t)}
}

// PolicyTypePublicKey requires the input to be signed by a given key.
type PolicyTypePublicKey PublicKey

// PolicyPublicKey returns a policy that requires the input to be signed by a
// given key.
func PolicyPublicKey(pk PublicKey) SpendPolicy {
	return SpendPolicy{PolicyTypePublicKey(pk)}
}

// PolicyTypeHash requires the input to reveal a SHA256 hash preimage.
type PolicyTypeHash Hash256

// PolicyHash returns a policy that requires the input to reveal a SHA256 hash
// preimage.
func PolicyHash(h Hash256) SpendPolicy {
	return SpendPolicy{PolicyTypeHash(h)}
}

// PolicyTypeThreshold requires at least N sub-policies to be satisfied.
type PolicyTypeThreshold struct {
	N  uint8         `json:"n"`
	Of []SpendPolicy `json:"of"`
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
func (PolicyTypeAfter) isPolicy()            {}
func (PolicyTypePublicKey) isPolicy()        {}
func (PolicyTypeHash) isPolicy()             {}
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
	h.WriteDistinguisher("address")
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

// Verify verifies that p is satisfied by the supplied inputs.
func (p SpendPolicy) Verify(height uint64, medianTimestamp time.Time, sigHash Hash256, sigs []Signature, preimages [][]byte) error {
	nextSig := func() (sig Signature, ok bool) {
		if ok = len(sigs) > 0; ok {
			sig, sigs = sigs[0], sigs[1:]
		}
		return
	}
	nextPreimage := func() (preimage []byte, ok bool) {
		if ok = len(preimages) > 0; ok {
			preimage, preimages = preimages[0], preimages[1:]
		}
		return
	}
	errInvalidSignature := errors.New("invalid signature")
	errInvalidPreimage := errors.New("invalid preimage")
	var verify func(SpendPolicy) error
	verify = func(p SpendPolicy) error {
		switch p := p.Type.(type) {
		case PolicyTypeAbove:
			if height >= uint64(p) {
				return nil
			}
			return fmt.Errorf("height not above %v", uint64(p))
		case PolicyTypeAfter:
			if medianTimestamp.After(time.Time(p)) {
				return nil
			}
			return fmt.Errorf("median timestamp not after %v", time.Time(p))
		case PolicyTypePublicKey:
			if sig, ok := nextSig(); ok && PublicKey(p).VerifyHash(sigHash, sig) {
				return nil
			}
			return errInvalidSignature
		case PolicyTypeHash:
			if preimage, ok := nextPreimage(); ok && p == sha256.Sum256(preimage) {
				return nil
			}
			return errInvalidPreimage
		case PolicyTypeThreshold:
			for i := 0; i < len(p.Of) && p.N > 0 && len(p.Of[i:]) >= int(p.N); i++ {
				if _, ok := p.Of[i].Type.(PolicyTypeUnlockConditions); ok {
					return errors.New("unlock conditions cannot be sub-policies")
				} else if err := verify(p.Of[i]); err == errInvalidSignature || err == errInvalidPreimage {
					return err // fatal; should have been opaque
				} else if err == nil {
					p.N--
				}
			}
			if p.N == 0 {
				return nil
			}
			return errors.New("threshold not reached")
		case PolicyTypeOpaque:
			return errors.New("opaque policy")
		case PolicyTypeUnlockConditions:
			if err := verify(PolicyAbove(p.Timelock)); err != nil {
				return err
			}
			for i, pk := range p.PublicKeys {
				if p.SignaturesRequired == 0 || p.SignaturesRequired > uint64(len(p.PublicKeys[i:])) || p.SignaturesRequired > uint64(len(sigs)) {
					break
				}
				switch pk.Algorithm {
				case SpecifierEntropy:
					return errors.New("policy uses an entropy public key")
				case SpecifierEd25519:
					var epk PublicKey
					copy(epk[:], pk.Key)
					if epk.VerifyHash(sigHash, sigs[0]) {
						sigs = sigs[1:]
						p.SignaturesRequired--
					}
				default:
					// all other algorithms are considered valid by default
					sigs = sigs[1:]
					p.SignaturesRequired--
				}
			}
			if p.SignaturesRequired == 0 {
				return nil
			}
			return errors.New("threshold not reached")
		default:
			panic("invalid policy type") // developer error
		}
	}
	if err := verify(p); err != nil {
		return err
	} else if len(sigs) > 0 {
		return errors.New("superfluous signature(s)")
	} else if len(preimages) > 0 {
		return errors.New("superfluous preimage(s)")
	}
	return nil
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

	case PolicyTypeAfter:
		sb.WriteString("after(")
		sb.WriteString(strconv.FormatInt(time.Time(p).Unix(), 10))
		sb.WriteByte(')')

	case PolicyTypePublicKey:
		sb.WriteString("pk(")
		writeHex(p[:])
		sb.WriteByte(')')

	case PolicyTypeHash:
		sb.WriteString("h(")
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
			buf, _ := pk.MarshalText() // never fails
			sb.Write(buf)
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
		return strings.TrimSpace(t)
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
		s = strings.TrimSpace(s)
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
	parseTime := func() time.Time {
		t := nextToken()
		if err != nil {
			return time.Time{}
		}
		var unix int64
		unix, err = strconv.ParseInt(t, 10, 64)
		return time.Unix(unix, 0)
	}
	parsePubkey := func() (pk PublicKey) {
		t := nextToken()
		if err != nil {
			return
		} else if len(t) != 66 {
			err = fmt.Errorf("invalid hex string length (%d)", len(t))
			return
		} else if t[:2] != "0x" {
			err = fmt.Errorf("invalid hex string prefix %q", t[:2])
			return
		}
		_, err = hex.Decode(pk[:], []byte(t[2:]))
		return
	}
	parseUnlockKey := func() (uk UnlockKey) {
		t := nextToken()
		if err != nil {
			return
		}
		err = uk.UnmarshalText([]byte(t))
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
		case "after":
			return PolicyAfter(parseTime())
		case "pk":
			return PolicyPublicKey(parsePubkey())
		case "h":
			return PolicyHash(Hash256(parsePubkey()))
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
				pks = append(pks, parseUnlockKey())
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

// MarshalJSON implements json.Marshaler.
func (p SpendPolicy) MarshalJSON() ([]byte, error) {
	var v struct {
		Type   string      `json:"type"`
		Policy interface{} `json:"policy"`
	}
	switch p := p.Type.(type) {
	case PolicyTypeAbove:
		v.Type = "above"
		v.Policy = uint64(p)
	case PolicyTypeAfter:
		v.Type = "after"
		v.Policy = time.Time(p).Unix()
	case PolicyTypePublicKey:
		v.Type = "pk"
		v.Policy = PublicKey(p)
	case PolicyTypeHash:
		v.Type = "h"
		v.Policy = Hash256(p)
	case PolicyTypeThreshold:
		v.Type = "thresh"
		v.Policy = p
	case PolicyTypeOpaque:
		v.Type = "opaque"
		v.Policy = Address(p)
	case PolicyTypeUnlockConditions:
		v.Type = "uc"
		v.Policy = UnlockConditions(p)
	}
	return json.Marshal(v)
}

// UnmarshalJSON implements json.Unmarshaler.
func (p *SpendPolicy) UnmarshalJSON(b []byte) (err error) {
	var v struct {
		Type   string          `json:"type"`
		Policy json.RawMessage `json:"policy"`
	}
	if err = json.Unmarshal(b, &v); err != nil {
		return
	}
	switch v.Type {
	case "above":
		var pt PolicyTypeAbove
		err = json.Unmarshal(v.Policy, (*uint64)(&pt))
		p.Type = pt
	case "after":
		var pt int64
		err = json.Unmarshal(v.Policy, &pt)
		p.Type = PolicyTypeAfter(time.Unix(pt, 0))
	case "pk":
		var pt PolicyTypePublicKey
		err = json.Unmarshal(v.Policy, (*PublicKey)(&pt))
		p.Type = pt
	case "h":
		var pt PolicyTypeHash
		err = json.Unmarshal(v.Policy, (*Hash256)(&pt))
		p.Type = pt
	case "thresh":
		var pt PolicyTypeThreshold
		err = json.Unmarshal(v.Policy, &pt)
		p.Type = pt
	case "opaque":
		var pt PolicyTypeOpaque
		err = json.Unmarshal(v.Policy, (*Address)(&pt))
		p.Type = pt
	case "uc":
		var pt PolicyTypeUnlockConditions
		err = json.Unmarshal(v.Policy, (*UnlockConditions)(&pt))
		p.Type = pt
	}
	return
}

// A SatisfiedPolicy pairs a policy with the signatures and preimages that
// satisfy it.
type SatisfiedPolicy struct {
	Policy     SpendPolicy
	Signatures []Signature
	Preimages  [][]byte
}

// MarshalJSON implements json.Marshaler.
func (sp SatisfiedPolicy) MarshalJSON() ([]byte, error) {
	pre := make([]string, len(sp.Preimages))
	for i := range pre {
		pre[i] = hex.EncodeToString(sp.Preimages[i])
	}
	return json.Marshal(struct {
		Policy     SpendPolicy `json:"policy"`
		Signatures []Signature `json:"signatures,omitempty"`
		Preimages  []string    `json:"preimages,omitempty"`
	}{sp.Policy, sp.Signatures, pre})
}

// UnmarshalJSON implements json.Unmarshaler.
func (sp *SatisfiedPolicy) UnmarshalJSON(b []byte) error {
	var pre []string
	err := json.Unmarshal(b, &struct {
		Policy     *SpendPolicy
		Signatures *[]Signature
		Preimages  *[]string
	}{&sp.Policy, &sp.Signatures, &pre})
	if err != nil {
		return err
	}
	sp.Preimages = make([][]byte, len(pre))
	for i := range sp.Preimages {
		if sp.Preimages[i], err = hex.DecodeString(pre[i]); err != nil {
			return err
		}
	}
	return nil
}
