package types

import (
	"bytes"
	"testing"
)

func roundtrip(from EncoderTo, to DecoderFrom) {
	var buf bytes.Buffer
	e := NewEncoder(&buf)
	from.EncodeTo(e)
	e.Flush()
	d := NewBufDecoder(buf.Bytes())
	to.DecodeFrom(d)
	if d.Err() != nil {
		panic(d.Err())
	}
}

func TestPolicyGolden(t *testing.T) {
	p := SpendPolicy{PolicyTypeUnlockConditions{
		PublicKeys: []UnlockKey{PublicKey{1, 2, 3}.UnlockKey()},
	}}
	if p.Address().String() != "addr:9ca6476864f75dff7908dadf137fb0e8044213f49935428adcf1070c71f512c62462150f0186" {
		t.Fatal("wrong address:", p, p.Address())
	}

	p = PolicyThreshold(2, []SpendPolicy{
		PolicyAbove(100),
		PolicyPublicKey(PublicKey{1, 2, 3}),
		PolicyThreshold(2, []SpendPolicy{
			PolicyAbove(200),
			PolicyPublicKey(PublicKey{4, 5, 6}),
		}),
	})
	if p.Address().String() != "addr:6079542a7cdabf033c500a3f49955e1b54788f48d7da08a84617236124540f958833ddf29445" {
		t.Fatal("wrong address:", p, p.Address())
	}
}

func TestPolicyOpaque(t *testing.T) {
	sub := []SpendPolicy{
		PolicyAbove(100),
		PolicyPublicKey(PublicKey{1, 2, 3}),
		PolicyThreshold(2, []SpendPolicy{
			PolicyAbove(200),
			PolicyPublicKey(PublicKey{4, 5, 6}),
		}),
	}
	p := PolicyThreshold(2, sub)
	addr := p.Address()

	for i := range sub {
		sub[i] = PolicyOpaque(sub[i])
		p = PolicyThreshold(2, sub)
		if p.Address() != addr {
			t.Fatal("opaque policy should have same address")
		}
	}
}

func TestPolicyRoundtrip(t *testing.T) {
	for _, p := range []SpendPolicy{
		PolicyAbove(100),

		PolicyPublicKey(PublicKey{1, 2, 3}),

		PolicyThreshold(2, []SpendPolicy{
			PolicyAbove(100),
			PolicyPublicKey(PublicKey{1, 2, 3}),
			PolicyThreshold(2, []SpendPolicy{
				PolicyAbove(200),
				PolicyPublicKey(PublicKey{4, 5, 6}),
			}),
		}),

		PolicyOpaque(PolicyPublicKey(PublicKey{1, 2, 3})),

		{PolicyTypeUnlockConditions{PublicKeys: []UnlockKey{PublicKey{1, 2, 3}.UnlockKey()}}},
	} {
		var p2 SpendPolicy
		roundtrip(p, &p2)
		if p.Address() != p2.Address() {
			t.Fatal("policy did not survive roundtrip")
		}

		s := p.String()
		p2, err := ParseSpendPolicy(s)
		if err != nil {
			t.Fatal(err)
		} else if p.Address() != p2.Address() {
			t.Fatal("policy did not survive roundtrip")
		}
	}
}
