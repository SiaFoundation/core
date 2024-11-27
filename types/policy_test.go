package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"lukechampine.com/frand"
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

func jsonRoundtrip(from json.Marshaler, to json.Unmarshaler) {
	if js, err := from.MarshalJSON(); err != nil {
		panic(err)
	} else if err := to.UnmarshalJSON(js); err != nil {
		panic(err)
	}
}

func TestPolicyVerify(t *testing.T) {
	key := GeneratePrivateKey()
	pk := key.PublicKey()
	sigHash := Hash256{1, 2, 3}
	currentTime := CurrentTimestamp()
	for _, test := range []struct {
		desc      string
		p         SpendPolicy
		height    uint64
		sigs      []Signature
		preimages [][32]byte
		err       string
	}{
		{
			desc: "above 0",
			p:    PolicyAbove(0),
		},
		{
			desc: "below 1",
			p:    PolicyAbove(1),
			err:  "not above 1",
		},
		{
			desc:   "above 1",
			p:      PolicyAbove(1),
			height: 1,
		},
		{
			desc: "after now",
			p:    PolicyAfter(currentTime),
			err:  "not after",
		},
		{
			desc: "after before",
			p:    PolicyAfter(currentTime.Add(-time.Second)),
		},
		{
			desc: "opaque",
			p:    PolicyOpaque(AnyoneCanSpend()),
			err:  "opaque",
		},
		{
			desc: "no signature",
			p:    PolicyPublicKey(pk),
			err:  "invalid signature",
		},
		{
			desc: "invalid signature",
			p:    PolicyPublicKey(pk),
			sigs: []Signature{key.SignHash(Hash256{})},
			err:  "invalid signature",
		},
		{
			desc: "valid signature",
			p:    PolicyPublicKey(pk),
			sigs: []Signature{key.SignHash(sigHash)},
		},
		{
			desc:      "invalid preimage",
			p:         PolicyHash(sha256.Sum256([]byte{31: 1})),
			preimages: [][32]byte{{31: 2}},
			err:       "invalid preimage",
		},
		{
			desc:      "valid preimage",
			p:         PolicyHash(sha256.Sum256([]byte{31: 1})),
			preimages: [][32]byte{{31: 1}},
		},
		{
			desc:      "superfluous preimage",
			p:         PolicyHash(sha256.Sum256([]byte{31: 1})),
			preimages: [][32]byte{{31: 1}, {31: 1}},
			err:       "superfluous preimage(s)",
		},
		{
			desc: "valid signature, invalid height",
			p: PolicyThreshold(2, []SpendPolicy{
				PolicyAbove(10),
				PolicyPublicKey(pk),
			}),
			sigs: []Signature{key.SignHash(sigHash)},
			err:  "not above 10",
		},
		{
			desc: "valid height, invalid signature",
			p: PolicyThreshold(2, []SpendPolicy{
				PolicyAbove(10),
				PolicyPublicKey(pk),
			}),
			height: 11,
			err:    "invalid signature",
		},
		{
			desc: "valid height, valid signature",
			p: PolicyThreshold(2, []SpendPolicy{
				PolicyAbove(10),
				PolicyPublicKey(pk),
			}),
			height: 11,
			sigs:   []Signature{key.SignHash(sigHash)},
		},
		{
			desc: "lower threshold, valid height",
			p: PolicyThreshold(1, []SpendPolicy{
				PolicyAbove(10),
				PolicyOpaque(PolicyPublicKey(pk)),
			}),
			height: 11,
		},
		{
			desc: "lower threshold, valid signature",
			p: PolicyThreshold(1, []SpendPolicy{
				PolicyOpaque(PolicyAbove(10)),
				PolicyPublicKey(pk),
			}),
			height: 11,
			sigs:   []Signature{key.SignHash(sigHash)},
		},
		{
			desc: "exceed threshold",
			p: PolicyThreshold(1, []SpendPolicy{
				PolicyAbove(10),
				PolicyPublicKey(pk),
			}),
			height: 11,
			sigs:   []Signature{key.SignHash(sigHash)},
			err:    "threshold exceeded",
		},
		{
			desc: "exceed threshold with keys",
			p: PolicyThreshold(1, []SpendPolicy{
				PolicyPublicKey(pk),
				PolicyPublicKey(pk),
			}),
			height: 11,
			sigs:   []Signature{key.SignHash(sigHash), key.SignHash(sigHash)},
			err:    "threshold exceeded",
		},
		{
			desc: "exceed threshold with above",
			p: PolicyThreshold(1, []SpendPolicy{
				PolicyAbove(10),
				PolicyAfter(currentTime.Add(-time.Second)),
			}),
			height: 11,
			err:    "threshold exceeded",
		},
		{
			desc: "opaque above subpolicy",
			p: PolicyThreshold(1, []SpendPolicy{
				PolicyOpaque(PolicyAbove(10)),
				PolicyAfter(currentTime.Add(-time.Second)),
			}),
		},
		{
			desc: "lower threshold, neither valid",
			p: PolicyThreshold(1, []SpendPolicy{
				PolicyOpaque(PolicyAbove(10)),
				PolicyOpaque(PolicyPublicKey(pk)),
			}),
			height: 11,
			sigs:   []Signature{key.SignHash(sigHash)},
			err:    "threshold not reached",
		},
		{
			desc: "too many subpolicies",
			p:    PolicyThreshold(1, make([]SpendPolicy, 256)),
			err:  "too complex",
		},
		{
			desc: "too many cumulative subpolicies",
			p: PolicyThreshold(1, append([]SpendPolicy{
				PolicyThreshold(1, append([]SpendPolicy{
					PolicyThreshold(1, append([]SpendPolicy{
						PolicyThreshold(1, append([]SpendPolicy{
							PolicyThreshold(1, append([]SpendPolicy{
								PolicyAbove(0),
							}, make([]SpendPolicy, 250)...)),
						}, make([]SpendPolicy, 250)...)),
					}, make([]SpendPolicy, 250)...)),
				}, make([]SpendPolicy, 250)...)),
			}, make([]SpendPolicy, 250)...)),
			err: "too complex",
		},
		{
			desc: "unlock conditions within threshold",
			p: PolicyThreshold(1, []SpendPolicy{
				{PolicyTypeUnlockConditions{
					PublicKeys:         []UnlockKey{pk.UnlockKey()},
					SignaturesRequired: 1,
				}},
			}),
			height: 1,
			sigs:   []Signature{key.SignHash(sigHash)},
			err:    "unlock conditions cannot be sub-policies",
		},
		{
			desc: "unlock conditions, invalid height",
			p: SpendPolicy{PolicyTypeUnlockConditions{
				Timelock: 10,
			}},
			err: "not above 10",
		},
		{
			desc: "unlock conditions, insufficient signatures",
			p: SpendPolicy{PolicyTypeUnlockConditions{
				SignaturesRequired: 1000,
			}},
			height: 1,
			sigs:   nil,
			err:    "threshold not reached",
		},
		{
			desc: "unlock conditions, superfluous signatures",
			p: SpendPolicy{PolicyTypeUnlockConditions{
				SignaturesRequired: 0,
			}},
			height: 1,
			sigs:   []Signature{key.SignHash(sigHash)},
			err:    "superfluous signature(s)",
		},
		{
			desc: "unlock conditions, wrong signature algorithm",
			p: SpendPolicy{PolicyTypeUnlockConditions{
				PublicKeys: []UnlockKey{{
					Algorithm: SpecifierEntropy,
					Key:       nil,
				}},
				SignaturesRequired: 1,
			}},
			height: 1,
			sigs:   []Signature{key.SignHash(sigHash)},
			err:    "entropy public key",
		},
		{
			desc: "unlock conditions, unknown signature algorithm",
			p: SpendPolicy{PolicyTypeUnlockConditions{
				PublicKeys: []UnlockKey{{
					Algorithm: NewSpecifier("trust me bro"),
				}},
				SignaturesRequired: 1,
			}},
			height: 1,
			sigs:   []Signature{key.SignHash(sigHash)},
		},
		{
			desc: "unlock conditions, wrong pubkey",
			p: SpendPolicy{PolicyTypeUnlockConditions{
				PublicKeys: []UnlockKey{{
					Algorithm: SpecifierEd25519,
					Key:       nil,
				}},
				SignaturesRequired: 1,
			}},
			height: 1,
			sigs:   []Signature{key.SignHash(sigHash)},
			err:    "threshold not reached",
		},
		{
			desc: "unlock conditions, insufficient signatures",
			p: SpendPolicy{PolicyTypeUnlockConditions{
				PublicKeys:         []UnlockKey{pk.UnlockKey()},
				SignaturesRequired: 2,
			}},
			height: 1,
			sigs:   []Signature{key.SignHash(sigHash)},
			err:    "threshold not reached",
		},
		{
			desc: "unlock conditions, valid",
			p: SpendPolicy{PolicyTypeUnlockConditions{
				PublicKeys:         []UnlockKey{pk.UnlockKey()},
				SignaturesRequired: 1,
			}},
			height: 1,
			sigs:   []Signature{key.SignHash(sigHash)},
		},
		{
			desc: "unlock conditions, valid with extra pubkeys",
			p: SpendPolicy{PolicyTypeUnlockConditions{
				PublicKeys:         []UnlockKey{pk.UnlockKey(), PublicKey{1, 2, 3}.UnlockKey(), pk.UnlockKey()},
				SignaturesRequired: 2,
			}},
			height: 1,
			sigs:   []Signature{key.SignHash(sigHash), key.SignHash(sigHash)},
		},
	} {
		if err := test.p.Verify(test.height, currentTime, sigHash, test.sigs, test.preimages); test.err == "" && err != nil {
			t.Fatalf("%v: %v", test.desc, err)
		} else if test.err != "" && (err == nil || !strings.Contains(err.Error(), test.err)) {
			t.Fatalf("%v: expected error containing %q, got %v", test.desc, test.err, err)
		}
	}
}

func TestPolicyGolden(t *testing.T) {
	pk := PublicKey{1, 2, 3}
	p := SpendPolicy{PolicyTypeUnlockConditions(StandardUnlockConditions(pk))}
	if p.Address().String() != "72b0762b382d4c251af5ae25b6777d908726d75962e5224f98d7f619bb39515dd64b9a56043a" {
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
	if p.Address().String() != "111d2995afa8bf162180a647b9f1eb6a275fe8818e836b69b351871d5caf9c590ed25aec0616" {
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
		jsonRoundtrip(p, &p2)
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

	// also check satisfied policy
	sp := SatisfiedPolicy{
		Policy: SpendPolicy{PolicyTypeUnlockConditions{
			PublicKeys: []UnlockKey{
				PublicKey{1, 2, 3}.UnlockKey(),
				PublicKey{4, 5, 6}.UnlockKey(),
				PublicKey{7, 8, 9}.UnlockKey(),
			},
		}},
		Signatures: []Signature{
			{1, 2, 3},
			{4, 5, 6},
			{7, 8, 9},
		},
	}
	var sp2 SatisfiedPolicy
	roundtrip(sp, &sp2)
	jsonRoundtrip(sp, &sp2)
	if fmt.Sprint(sp) != fmt.Sprint(sp2) {
		t.Fatal("satisfied policy did not survive roundtrip:", sp, sp2)
	}
}

func TestSpendPolicyMarshalJSON(t *testing.T) {
	publicKey := NewPrivateKeyFromSeed(make([]byte, 32)).PublicKey()
	hash := HashBytes(nil)

	tests := []struct {
		sp  SpendPolicy
		exp string
	}{
		{
			sp:  PolicyAbove(100),
			exp: `{"type":"above","policy":100}`,
		},
		{
			sp:  PolicyAfter(time.Unix(1234567890, 0)),
			exp: `{"type":"after","policy":1234567890}`,
		},
		{
			sp:  PolicyPublicKey(publicKey),
			exp: fmt.Sprintf(`{"type":"pk","policy":"ed25519:%x"}`, publicKey[:]),
		},
		{
			sp:  PolicyHash(hash),
			exp: fmt.Sprintf(`{"type":"h","policy":"%x"}`, hash[:]),
		},
		{
			sp: PolicyThreshold(2, []SpendPolicy{
				PolicyAbove(100),
				PolicyPublicKey(publicKey),
				PolicyThreshold(2, []SpendPolicy{
					PolicyAbove(200),
					PolicyPublicKey(publicKey),
				}),
			}),
			exp: fmt.Sprintf(`{"type":"thresh","policy":{"n":2,"of":[{"type":"above","policy":100},{"type":"pk","policy":"ed25519:%x"},{"type":"thresh","policy":{"n":2,"of":[{"type":"above","policy":200},{"type":"pk","policy":"ed25519:%x"}]}}]}}`, publicKey[:], publicKey[:]),
		},
		{
			sp: SpendPolicy{PolicyTypeUnlockConditions{
				Timelock:           123,
				PublicKeys:         []UnlockKey{publicKey.UnlockKey()},
				SignaturesRequired: 2,
			}},
			exp: fmt.Sprintf(`{"type":"uc","policy":{"timelock":123,"publicKeys":["ed25519:%x"],"signaturesRequired":2}}`, publicKey[:]),
		},
	}

	for _, tt := range tests {
		data, err := json.Marshal(tt.sp)
		if err != nil {
			t.Errorf("Expected no error, but got %v", err)
		} else if string(data) != tt.exp {
			t.Errorf("Expected %s, but got %s", tt.exp, string(data))
		}
	}
}

func TestSatisfiedPolicyMarshalJSON(t *testing.T) {
	publicKey := NewPrivateKeyFromSeed(make([]byte, 32)).PublicKey()
	hash := HashBytes(nil)

	privateKey := NewPrivateKeyFromSeed(make([]byte, 32))
	signature := privateKey.SignHash(hash)

	tests := []struct {
		name       string
		sp         SpendPolicy
		signatures []Signature
		preimages  [][32]byte
		exp        string
	}{
		{
			name:       "PolicyWithSignature",
			sp:         PolicyPublicKey(publicKey),
			signatures: []Signature{signature},
			exp:        fmt.Sprintf(`{"policy":{"type":"pk","policy":"ed25519:%x"},"signatures":[%q]}`, publicKey[:], signature),
		},
		{
			name:       "PolicyWithSignaturesAndPreimages",
			sp:         PolicyThreshold(1, []SpendPolicy{PolicyPublicKey(publicKey), PolicyHash(hash)}),
			signatures: []Signature{signature},
			preimages:  [][32]byte{{1, 2, 3}},
			exp:        fmt.Sprintf(`{"policy":{"type":"thresh","policy":{"n":1,"of":[{"type":"pk","policy":"ed25519:%x"},{"type":"h","policy":"%x"}]}},"signatures":[%q],"preimages":["0102030000000000000000000000000000000000000000000000000000000000"]}`, publicKey[:], hash[:], signature),
		},
		{
			name:      "PolicyWithPreimagesOnly",
			sp:        PolicyHash(hash),
			preimages: [][32]byte{{4, 5, 6}},
			exp:       fmt.Sprintf(`{"policy":{"type":"h","policy":"%x"},"preimages":["0405060000000000000000000000000000000000000000000000000000000000"]}`, hash[:]),
		},
		{
			name: "PolicyWithEmptySignatures",
			sp:   PolicyPublicKey(publicKey),
			exp:  fmt.Sprintf(`{"policy":{"type":"pk","policy":"ed25519:%x"}}`, publicKey[:]),
		},
		{
			name: "PolicyWithEmptyPreimages",
			sp:   PolicyHash(hash),
			exp:  fmt.Sprintf(`{"policy":{"type":"h","policy":"%x"}}`, hash[:]),
		},
	}

	for _, tt := range tests {
		satisfiedSP := SatisfiedPolicy{
			Policy:     tt.sp,
			Signatures: tt.signatures,
			Preimages:  tt.preimages,
		}

		data, err := json.Marshal(satisfiedSP)
		if err != nil {
			t.Errorf("%s: Marshal() error = %v", tt.name, err)
		}
		if string(data) != tt.exp {
			t.Errorf("%s: expected %s, got %s", tt.name, tt.exp, string(data))
		}
	}
}

func TestSatisfiedPolicyUnmarshaling(t *testing.T) {
	tests := []struct {
		name      string
		jsonData  string
		expectErr bool
		preimages [][32]byte
	}{
		{
			name:      "InvalidHex",
			jsonData:  `{"Policy": null, "Signatures": null, "Preimages": ["InvalidHex"]}`,
			expectErr: true,
		},
		{
			name:      "InvalidPolicy",
			jsonData:  `{"Policy": "ShouldBeAnObjectOrValidType", "Signatures": null, "Preimages": []}`,
			expectErr: true,
		},
		{
			name:      "ValidPreimage",
			jsonData:  `{"Policy": null, "Signatures": null, "Preimages": ["d23ddde9d4e38ad78261adbc2288100accc33eec3d7b031e27b01b9810061636"]}`,
			expectErr: false,
			preimages: [][32]byte{{0xd2, 0x3d, 0xdd, 0xe9, 0xd4, 0xe3, 0x8a, 0xd7, 0x82, 0x61, 0xad, 0xbc, 0x22, 0x88, 0x10, 0x0a, 0xcc, 0xc3, 0x3e, 0xec, 0x3d, 0x7b, 0x03, 0x1e, 0x27, 0xb0, 0x1b, 0x98, 0x10, 0x06, 0x16, 0x36}},
		},
	}

	for _, tt := range tests {
		var sp SatisfiedPolicy
		if err := sp.UnmarshalJSON([]byte(tt.jsonData)); (err != nil) != tt.expectErr {
			t.Errorf("%s: UnmarshalJSON() error = %v, expectErr %v", tt.name, err, tt.expectErr)
		}
		if len(tt.preimages) != 0 && !reflect.DeepEqual(tt.preimages, sp.Preimages) {
			t.Error("preimage mismatch")
		}
	}
}

func TestPolicyTypeUnlockConditionsRoundtrip(t *testing.T) {
	sp := SpendPolicy{PolicyTypeUnlockConditions(UnlockConditions{
		Timelock: 0,
		PublicKeys: []UnlockKey{
			{
				Algorithm: NewSpecifier("blank"),
				Key:       frand.Bytes(40),
			},
		},
		SignaturesRequired: 1,
	})}
	parsed, err := ParseSpendPolicy(sp.String())
	if err != nil {
		t.Fatal(err)
	} else if sp.String() != parsed.String() {
		t.Fatalf("expected %q = %q", sp.String(), parsed.String())
	}
}

func TestParseSpendPolicy(t *testing.T) {
	tests := []struct {
		str   string
		valid bool
	}{
		{
			str:   "invalid",
			valid: false,
		},
		{
			str:   "pk(invalid)",
			valid: false,
		},
		{
			str:   "pk(0x0102030000000000000000000000000000000000000000000000000000000000)",
			valid: true,
		},
		{
			str:   "pk( 0x0102030000000000000000000000000000000000000000000000000000000000 )",
			valid: true,
		},
		{
			str:   "pk(0x01020300000000000000000000 00000000000000000000000000000000000000)",
			valid: false,
		},
		{
			str: `
		thresh(1, [
		    thresh(2, [
		        pk(  0x0102030000000000000000000000000000000000000000000000000000000000  ),
		        h( 0x0100000000000000000000000000000000000000000000000000000000000000
				)
		    ]),
		    opaque(
			0xf72e84ee9e344e424a6764068ffd7fdce4b4e50609892c6801bc1ead79d3ae0d)
		])
					`,
			valid: true,
		},
	}

	for _, tt := range tests {
		if _, err := ParseSpendPolicy(tt.str); (err == nil) != tt.valid {
			t.Errorf("ParseSpendPolicy(%q) -> %v", tt.str, err)
		}
	}
}
