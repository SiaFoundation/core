package types

import (
	"bytes"
	"testing"
	"time"
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

func TestPolicyVerify(t *testing.T) {
	key := GeneratePrivateKey()
	pk := key.PublicKey()
	sigHash := Hash256{1, 2, 3}

	for _, test := range []struct {
		desc   string
		p      SpendPolicy
		height uint64
		sigs   []Signature
		valid  bool
	}{
		{
			"above 0",
			PolicyAbove(0),
			0,
			nil,
			true,
		},
		{
			"below 1",
			PolicyAbove(1),
			0,
			nil,
			false,
		},
		{
			"above 1",
			PolicyAbove(1),
			1,
			nil,
			true,
		},
		{
			"no signature",
			PolicyPublicKey(pk),
			1,
			nil,
			false,
		},
		{
			"invalid signature",
			PolicyPublicKey(pk),
			1,
			[]Signature{key.SignHash(Hash256{})},
			false,
		},
		{
			"valid signature",
			PolicyPublicKey(pk),
			1,
			[]Signature{key.SignHash(sigHash)},
			true,
		},
		{
			"valid signature, invalid height",
			PolicyThreshold(2, []SpendPolicy{
				PolicyAbove(10),
				PolicyPublicKey(pk),
			}),
			1,
			[]Signature{key.SignHash(sigHash)},
			false,
		},
		{
			"valid height, invalid signature",
			PolicyThreshold(2, []SpendPolicy{
				PolicyAbove(10),
				PolicyPublicKey(pk),
			}),
			11,
			nil,
			false,
		},
		{
			"valid height, valid signature",
			PolicyThreshold(2, []SpendPolicy{
				PolicyAbove(10),
				PolicyPublicKey(pk),
			}),
			11,
			[]Signature{key.SignHash(sigHash)},
			true,
		},
		{
			"lower threshold, valid height",
			PolicyThreshold(1, []SpendPolicy{
				PolicyAbove(10),
				PolicyOpaque(PolicyPublicKey(pk)),
			}),
			11,
			nil,
			true,
		},
		{
			"lower threshold, valid signature",
			PolicyThreshold(1, []SpendPolicy{
				PolicyOpaque(PolicyAbove(10)),
				PolicyPublicKey(pk),
			}),
			11,
			[]Signature{key.SignHash(sigHash)},
			true,
		},
		{
			"exceed threshold",
			PolicyThreshold(1, []SpendPolicy{
				PolicyAbove(10),
				PolicyPublicKey(pk),
			}),
			11,
			[]Signature{key.SignHash(sigHash)},
			false,
		},
		{
			"lower threshold, neither valid",
			PolicyThreshold(1, []SpendPolicy{
				PolicyOpaque(PolicyAbove(10)),
				PolicyOpaque(PolicyPublicKey(pk)),
			}),
			11,
			[]Signature{key.SignHash(sigHash)},
			false,
		},
		{
			"unlock conditions within threshold",
			PolicyThreshold(1, []SpendPolicy{
				{PolicyTypeUnlockConditions{
					PublicKeys:         []UnlockKey{pk.UnlockKey()},
					SignaturesRequired: 1,
				}},
			}),
			1,
			[]Signature{key.SignHash(sigHash)},
			false,
		},
		{
			"unlock conditions, invalid height",
			SpendPolicy{PolicyTypeUnlockConditions{
				Timelock: 10,
			}},
			1,
			nil,
			false,
		},
		{
			"unlock conditions, insufficient signatures",
			SpendPolicy{PolicyTypeUnlockConditions{
				SignaturesRequired: 1000,
			}},
			1,
			nil,
			false,
		},
		{
			"unlock conditions, wrong signature algorithm",
			SpendPolicy{PolicyTypeUnlockConditions{
				PublicKeys: []UnlockKey{{
					Algorithm: SpecifierEntropy,
					Key:       nil,
				}},
				SignaturesRequired: 1,
			}},
			1,
			[]Signature{key.SignHash(sigHash)},
			false,
		},
		{
			"unlock conditions, wrong pubkey",
			SpendPolicy{PolicyTypeUnlockConditions{
				PublicKeys: []UnlockKey{{
					Algorithm: SpecifierEd25519,
					Key:       nil,
				}},
				SignaturesRequired: 1,
			}},
			1,
			[]Signature{key.SignHash(sigHash)},
			false,
		},
		{
			"unlock conditions, insufficient signatures",
			SpendPolicy{PolicyTypeUnlockConditions{
				PublicKeys:         []UnlockKey{pk.UnlockKey()},
				SignaturesRequired: 2,
			}},
			1,
			[]Signature{key.SignHash(sigHash)},
			false,
		},
		{
			"unlock conditions, valid",
			SpendPolicy{PolicyTypeUnlockConditions{
				PublicKeys:         []UnlockKey{pk.UnlockKey()},
				SignaturesRequired: 1,
			}},
			1,
			[]Signature{key.SignHash(sigHash)},
			true,
		},
	} {
		if err := test.p.Verify(test.height, time.Time{}, sigHash, test.sigs, nil); err != nil && test.valid {
			t.Fatalf("%v: %v", test.desc, err)
		} else if err == nil && !test.valid {
			t.Fatal("expected error")
		}
	}
}

func TestPolicyGolden(t *testing.T) {
	pk := PublicKey{1, 2, 3}
	p := SpendPolicy{PolicyTypeUnlockConditions(StandardUnlockConditions(pk))}
	if p.Address().String() != "addr:72b0762b382d4c251af5ae25b6777d908726d75962e5224f98d7f619bb39515dd64b9a56043a" {
		t.Fatal("wrong address:", p, p.Address())
	} else if StandardUnlockHash(pk) != p.Address() {
		t.Fatal("StandardUnlockHash differs from Policy.Address")
	}
	if StandardAddress(pk) != PolicyPublicKey(pk).Address() {
		t.Fatal("StandardAddress differs from Policy.Address")
	}

	p = PolicyThreshold(2, []SpendPolicy{
		PolicyAbove(100),
		PolicyPublicKey(pk),
		PolicyThreshold(2, []SpendPolicy{
			PolicyAbove(200),
			PolicyPublicKey(PublicKey{4, 5, 6}),
		}),
	})
	if p.Address().String() != "addr:111d2995afa8bf162180a647b9f1eb6a275fe8818e836b69b351871d5caf9c590ed25aec0616" {
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

		{PolicyTypeUnlockConditions{PublicKeys: []UnlockKey{PublicKey{1, 2, 3}.UnlockKey(), PublicKey{4, 5, 6}.UnlockKey()}}},
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
