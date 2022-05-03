package types

import (
	"encoding/json"
	"reflect"
	"testing"
)

func mustParsePublicKey(s string) (pk PublicKey) {
	err := pk.UnmarshalJSON([]byte(`"` + s + `"`))
	if err != nil {
		panic(err)
	}
	return
}

func TestPolicyAddressString(t *testing.T) {
	publicKeys := []PublicKey{
		mustParsePublicKey("ed25519:42d33219eb9e7d52d4a4edff215e36535d9d82c9439497a05ab7712193d43282"),
		mustParsePublicKey("ed25519:b908477c624679a2dc934a662e43c22844595902f1c8dc29b7f8caf2e0369cc9"),
		mustParsePublicKey("ed25519:11aa63482223329fb8b8313da78cc58820f2933cc621e0ef275c305092ea3704"),
	}

	tests := []struct {
		policy SpendPolicy
		want   string
	}{
		{
			PolicyAbove(50),
			"addr:f0e864efc7226eb90f79f71caf1d839daf11d1c7f0fb7e25abc3cedd38637f32954986043e6a",
		},
		{
			PolicyPublicKey(publicKeys[0]),
			"addr:4c9de1b2775091af2be8f427b1886f2120cdfe074fb3bc3b6011e281f36309e2468424667b70",
		},
		{
			AnyoneCanSpend(),
			"addr:a1b418e9905dd086e2d0c25ec3675568f849c18f401512d704eceafe1574ee19c48049c5f2b3",
		},
		{
			PolicyThreshold(0, nil),
			"addr:a1b418e9905dd086e2d0c25ec3675568f849c18f401512d704eceafe1574ee19c48049c5f2b3",
		},
		{
			PolicyThreshold(
				1,
				[]SpendPolicy{
					PolicyPublicKey(publicKeys[0]),
				},
			),
			"addr:88a889bd46420209db5a41b164956e53ff3da9c4b3d1491d81f9c374f742dd3b0a7c72f58aff",
		},
		{
			PolicyThreshold(
				1,
				[]SpendPolicy{
					PolicyPublicKey(publicKeys[0]),
					PolicyThreshold(
						2,
						[]SpendPolicy{
							PolicyAbove(50),
							PolicyPublicKey(publicKeys[1]),
						},
					),
				},
			),
			"addr:2ce609abbd8bc26d0f22c8f6447d3144bc2ae2391f9b09685aca03237329c339ba3ec4a35133",
		},
		{
			PolicyThreshold(
				2,
				[]SpendPolicy{
					PolicyPublicKey(publicKeys[0]),
					PolicyPublicKey(publicKeys[1]),
					PolicyPublicKey(publicKeys[2]),
				},
			),
			"addr:0ca4d365f06ebf0de342ed617498521f0c0bcdc133c414428480e8826875c0a565ccaee80fb6",
		},
		{
			policy: SpendPolicy{PolicyTypeUnlockConditions{
				PublicKeys: []PublicKey{
					publicKeys[0],
				},
				SignaturesRequired: 1,
			}},
			want: "addr:2f4a4a64712545bde8d38776377da2794d54685284a3768f78884643dad33a9a3822a0f4dc39",
		},
	}
	for _, tt := range tests {
		if got := tt.policy.Address().String(); got != tt.want {
			t.Errorf("wrong address for %T(%v)", tt.policy, tt.policy)
		}
	}
}

func TestPolicyJSON(t *testing.T) {
	publicKeys := []PublicKey{
		mustParsePublicKey("ed25519:42d33219eb9e7d52d4a4edff215e36535d9d82c9439497a05ab7712193d43282"),
		mustParsePublicKey("ed25519:b908477c624679a2dc934a662e43c22844595902f1c8dc29b7f8caf2e0369cc9"),
		mustParsePublicKey("ed25519:11aa63482223329fb8b8313da78cc58820f2933cc621e0ef275c305092ea3704"),
	}

	tests := []struct {
		policy SpendPolicy
		want   string
	}{
		{
			PolicyAbove(50),
			"above(50)",
		},
		{
			PolicyPublicKey(publicKeys[0]),
			"pk(42d33219eb9e7d52d4a4edff215e36535d9d82c9439497a05ab7712193d43282)",
		},
		{
			AnyoneCanSpend(),
			"thresh(0,[])",
		},
		{
			PolicyThreshold(0, nil),
			"thresh(0,[])",
		},
		{
			PolicyThreshold(
				1,
				[]SpendPolicy{
					PolicyPublicKey(publicKeys[0]),
				},
			),
			"thresh(1,[pk(42d33219eb9e7d52d4a4edff215e36535d9d82c9439497a05ab7712193d43282)])",
		},
		{
			PolicyThreshold(
				1,
				[]SpendPolicy{
					PolicyPublicKey(publicKeys[0]),
					PolicyThreshold(
						2,
						[]SpendPolicy{
							PolicyAbove(50),
							PolicyPublicKey(publicKeys[1]),
						},
					),
				},
			),
			"thresh(1,[pk(42d33219eb9e7d52d4a4edff215e36535d9d82c9439497a05ab7712193d43282),thresh(2,[above(50),pk(b908477c624679a2dc934a662e43c22844595902f1c8dc29b7f8caf2e0369cc9)])])",
		},
		{
			PolicyThreshold(
				2,
				[]SpendPolicy{
					PolicyPublicKey(publicKeys[0]),
					PolicyThreshold(
						2,
						[]SpendPolicy{
							PolicyAbove(50),
							PolicyPublicKey(publicKeys[1]),
							PolicyThreshold(
								2,
								[]SpendPolicy{
									PolicyAbove(50),
									PolicyPublicKey(publicKeys[1]),
								},
							),
						},
					),
					PolicyPublicKey(publicKeys[1]),
					PolicyPublicKey(publicKeys[2]),
				},
			), "thresh(2,[pk(42d33219eb9e7d52d4a4edff215e36535d9d82c9439497a05ab7712193d43282),thresh(2,[above(50),pk(b908477c624679a2dc934a662e43c22844595902f1c8dc29b7f8caf2e0369cc9),thresh(2,[above(50),pk(b908477c624679a2dc934a662e43c22844595902f1c8dc29b7f8caf2e0369cc9)])]),pk(b908477c624679a2dc934a662e43c22844595902f1c8dc29b7f8caf2e0369cc9),pk(11aa63482223329fb8b8313da78cc58820f2933cc621e0ef275c305092ea3704)])"},
		{
			SpendPolicy{PolicyTypeUnlockConditions{
				PublicKeys: []PublicKey{
					publicKeys[0],
				},
				SignaturesRequired: 1,
			}},
			"uc(0,[42d33219eb9e7d52d4a4edff215e36535d9d82c9439497a05ab7712193d43282],1)",
		},
		{
			SpendPolicy{PolicyTypeUnlockConditions{}},
			"uc(0,[],0)",
		},
	}

	for _, test := range tests {
		data, err := json.Marshal(test.policy)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != (`"` + test.want + `"`) {
			t.Fatalf("expected %s got %s", test.want, string(data))
		}

		var p SpendPolicy
		if err := json.Unmarshal(data, &p); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(p, test.policy) {
			t.Fatalf("expected %v got %v", test.policy, p)
		}
	}

	invalidPolicies := []string{
		"",
		")(",
		"aaa(5)",
		"above()",
		"above(zzz)",
		"above(0)trailingbytes",
		"pk()",
		"pk(zzz)",
		"thresh(zzz)",
		"thresh(1)",
		"thresh(a)",
		"thresh(1, [)",
		"thresh(1, ][)",
		"thresh(1, a)",
		`thresh(1, [aaa(50)])`,
		`uc(1)`,
		`uc(1,)`,
		`uc(1, [)`,
		`uc(1, ][)`,
		`uc(1, [])`,
		`uc(1, [],)`,
		`uc(1, [],a)`,
		`uc(1, [aa], 1)`,
	}
	for _, test := range invalidPolicies {
		var p SpendPolicy
		if err := json.Unmarshal([]byte(`"`+test+`"`), &p); err == nil {
			t.Fatalf("unmarshal should have errored on input %s", test)
		}
	}
}
