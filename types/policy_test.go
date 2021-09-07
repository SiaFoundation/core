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
			"addr:e38c9fe65f9297af77381dc718b1c8a775262cfdde08dc3da1116dee081fadf26ca7e015dd71",
		},
		{
			PolicyPublicKey(publicKeys[0]),
			"addr:e4b6f506599b1fdc27545f5d3cfd0bcd2fed2940bc9aaa74142d3279c0687b529e1d70be6def",
		},
		{
			AnyoneCanSpend(),
			"addr:d0f42fc75e6d3c7b21429ab2f60c78a04f8a599bf8d5a89ca6a299c6f88b738d671c9d57183a",
		},
		{
			PolicyThreshold{},
			"addr:d0f42fc75e6d3c7b21429ab2f60c78a04f8a599bf8d5a89ca6a299c6f88b738d671c9d57183a",
		},
		{
			PolicyThreshold{
				N: 1,
				Of: []SpendPolicy{
					PolicyPublicKey(publicKeys[0]),
				},
			},
			"addr:36375ad986e8c064a5c3a73ade03c72da0f3b4cacfb69eef39fe3c115c4ac4c63299c631a5b4",
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
			"addr:5ce2aadfd0c5c5009491974960938ba2e19260110394d10a26578d8c3fcd7f0976d0b369a732",
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
			"addr:c186c3563a4c6a98343a64c0f4981d809fd95f2630df15cb266e809424ec11f44de4a902c222",
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
