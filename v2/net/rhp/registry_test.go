package rhp

import (
	"encoding/hex"
	"testing"

	"go.sia.tech/core/v2/types"
)

func mustParseKey(key string) (p [32]byte) {
	n, err := hex.Decode(p[:], []byte(key))
	if err != nil {
		panic(err)
	} else if n != 32 {
		panic("invalid key")
	}
	return
}

// TestRegistryKeyCompat tests that registry keys remain compatible with Sia v1.
// Keys were generated using go.sia.tech/siad/modules.DeriveRegistryEntryID
func TestRegistryKeyCompat(t *testing.T) {
	tests := []struct {
		pub   types.PublicKey
		tweak types.Hash256
		want  types.Hash256
	}{
		{
			mustParseKey("8cde791eae011cdd06066f6c3518fdc4064461a3e2c8733e5206cca8aba373e2"),
			mustParseKey("f245223322f20f4809825d473450067087f5884c13022256cb76a700458a509a"),
			mustParseKey("34dda442a65dd3a7a3c0ac09f88b620c42d850cd7890efc13b4c68889f5e7173"),
		},
		{
			mustParseKey("9d29a49770bb2dd560150977d49d23c434ff2851457d5496787e514b1cca83b5"),
			mustParseKey("cffb1827fb71ac03dfc3fbab91718149d0381d98c3782ccd7612c11b1b21d805"),
			mustParseKey("d2cfff9578531baabb583d9c81afbeb1484a2a35257d91824636475e84eff434"),
		},
		{
			mustParseKey("82966a49411b1fc4c1458b8cbc44b53a98a4bdeb362eb8c6978c91b9c5797bc9"),
			mustParseKey("80d5524d1a387a48d424e00fcd847b92d2b42d6d3a4d9e86857831cd3bece3c5"),
			mustParseKey("1df61f3f42a0308ecc693fb80a834a2af86b82d7d486444ffcdc61becbb2803d"),
		},
		{
			mustParseKey("a802b890c70b68c1c2b4825f9164c4ec7baf82f645b315fe3083ca638a8715b3"),
			mustParseKey("7bc3b72a1c6e1c3d206fad2eb4f0cfa47988fd60563dfb237a4c2c4d1490d625"),
			mustParseKey("2328b2deed4f8094f560fa8091c7d4dae07806da4748324d4d67cae89f0838fc"),
		},
		{
			mustParseKey("f76f05154d7ac34edcd0bb6b352d4b71f4cbd28a83c1c052bed7ad99b2437461"),
			mustParseKey("427ab98605015233d4520edfc4d93437eb55814fd225ba7c9d8fab2aa73ff956"),
			mustParseKey("2c9732226007b9784e8b248d0c8fc285f205d8504fd66a039d283671b11959ba"),
		},
		{
			mustParseKey("8fe685ea6759124abc5dde9c7fecfcd887885a9dea3587b918fd1f5cab6d636b"),
			mustParseKey("6314826c074e2dd622e2d54c4353b1f867b4d43c4d07e4abd74ebf17a9165980"),
			mustParseKey("3850c8838e5dc74e560313034c60117637003c4bd675f782f230083bcd6ffb6b"),
		},
		{
			mustParseKey("7814ba3c6148222fd3fea4eb70fa65bec9ce816691e6c9edab025ffed4ea832c"),
			mustParseKey("ccd0a7774a67280ec9fdf2b6811f576e92a68b474c8ff4a24c2afd188bb010ab"),
			mustParseKey("340e7d292ad5f730a20a7179163238373b9765cfb8dd3bc3981882e61e7c89a4"),
		},
		{
			mustParseKey("aedb3b96ad13a149644baa819d92b134125bf8f5d6d4c22c8601e9e6488b3c82"),
			mustParseKey("eb5df78f2eb11dbb385506f2dfae35bc0514054abce3c150aecb53a0af1df096"),
			mustParseKey("79feab234c2872c9d5cf1faebb88006854e2642053f7d0eaf71aec139838716e"),
		},
		{
			mustParseKey("219ca56c819b394857b37015acde1c4f30c620b6bcf4fbc0d32ae63793e8a979"),
			mustParseKey("fd1e350540fefe957bc093c00b05b10da2f22fdb8b4b4b8898877478785715f2"),
			mustParseKey("15b55c040eb5876b72b8cb59c37e470fdba2f7b60f7d94fb00b8cdcfc88d7784"),
		},
		{
			mustParseKey("0bcce4ac4e18f7e406a2e60556735048c88cbde6597c223b46f50bd780106830"),
			mustParseKey("eabe733e323b4b35b9e820ae17150c0215c7566747258075c0a15845c371dd77"),
			mustParseKey("36e5da5e2000fd884a509e1fcb98b0b9690371af7f0bc8124ef07cc36ddccd60"),
		},
	}
	for _, tt := range tests {
		if key := RegistryKey(tt.pub, tt.tweak); key != tt.want {
			t.Errorf("RegistryKey() = %v, want %v", key, tt.want)
		}
	}
}
