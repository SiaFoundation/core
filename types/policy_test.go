package types

import (
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
			PolicyThreshold{},
			"addr:a1b418e9905dd086e2d0c25ec3675568f849c18f401512d704eceafe1574ee19c48049c5f2b3",
		},
		{
			PolicyThreshold{
				N: 1,
				Of: []SpendPolicy{
					PolicyPublicKey(publicKeys[0]),
				},
			},
			"addr:88a889bd46420209db5a41b164956e53ff3da9c4b3d1491d81f9c374f742dd3b0a7c72f58aff",
		},
		{
			PolicyThreshold{
				N: 1,
				Of: []SpendPolicy{
					PolicyPublicKey(publicKeys[0]),
					PolicyThreshold{
						N: 2,
						Of: []SpendPolicy{
							PolicyAbove(50),
							PolicyPublicKey(publicKeys[1]),
						},
					},
				},
			},
			"addr:2ce609abbd8bc26d0f22c8f6447d3144bc2ae2391f9b09685aca03237329c339ba3ec4a35133",
		},
		{
			PolicyThreshold{
				N: 2,
				Of: []SpendPolicy{
					PolicyPublicKey(publicKeys[0]),
					PolicyPublicKey(publicKeys[1]),
					PolicyPublicKey(publicKeys[2]),
				},
			},
			"addr:0ca4d365f06ebf0de342ed617498521f0c0bcdc133c414428480e8826875c0a565ccaee80fb6",
		},
		{
			policy: PolicyUnlockConditions{
				PublicKeys: []PublicKey{
					publicKeys[0],
				},
				SignaturesRequired: 1,
			},
			want: "addr:2f4a4a64712545bde8d38776377da2794d54685284a3768f78884643dad33a9a3822a0f4dc39",
		},
	}
	for _, tt := range tests {
		if got := PolicyAddress(tt.policy).String(); got != tt.want {
			t.Errorf("wrong address for %T(%v)", tt.policy, tt.policy)
		}
	}
}
