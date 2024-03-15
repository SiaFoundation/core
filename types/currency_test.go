package types

import (
	"encoding/json"
	"math"
	"testing"
)

func mustParseCurrency(s string) Currency {
	c, err := ParseCurrency(s)
	if err != nil {
		panic(err)
	}
	return c
}

func TestCurrencyCmp(t *testing.T) {
	tests := []struct {
		a, b Currency
		want int
	}{
		{
			ZeroCurrency,
			ZeroCurrency,
			0,
		},
		{
			ZeroCurrency,
			NewCurrency64(5),
			-1,
		},
		{
			NewCurrency64(5),
			ZeroCurrency,
			1,
		},
		{
			NewCurrency(0, 1),
			NewCurrency(0, 1),
			0,
		},
		{
			NewCurrency(math.MaxUint64, 0),
			NewCurrency(0, 1),
			-1,
		},
		{
			NewCurrency(0, 1),
			NewCurrency(math.MaxUint64, 0),
			1,
		},
	}
	for _, tt := range tests {
		if got := tt.a.Cmp(tt.b); got != tt.want {
			t.Errorf("Currency.Cmp(%d, %d) expected = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestCurrencyAdd(t *testing.T) {
	tests := []struct {
		a, b, want Currency
	}{
		{
			ZeroCurrency,
			ZeroCurrency,
			ZeroCurrency,
		},
		{
			NewCurrency(1, 0),
			NewCurrency(1, 0),
			NewCurrency(2, 0),
		},
		{
			NewCurrency(200, 0),
			NewCurrency(50, 0),
			NewCurrency(250, 0),
		},
		{
			NewCurrency(0, 1),
			NewCurrency(0, 1),
			NewCurrency(0, 2),
		},
		{
			NewCurrency(0, 71),
			NewCurrency(math.MaxUint64, 0),
			NewCurrency(math.MaxUint64, 71),
		},
	}
	for _, tt := range tests {
		if got := tt.a.Add(tt.b); !got.Equals(tt.want) {
			t.Errorf("Currency.Add(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestCurrencyAddWithOverflow(t *testing.T) {
	tests := []struct {
		a, b, want Currency
		overflows  bool
	}{
		{
			ZeroCurrency,
			ZeroCurrency,
			ZeroCurrency,
			false,
		},
		{
			NewCurrency(1, 0),
			NewCurrency(1, 0),
			NewCurrency(2, 0),
			false,
		},
		{
			NewCurrency(200, 0),
			NewCurrency(50, 0),
			NewCurrency(250, 0),
			false,
		},
		{
			NewCurrency(0, 1),
			NewCurrency(0, 1),
			NewCurrency(0, 2),
			false,
		},
		{
			NewCurrency(0, 71),
			NewCurrency(math.MaxUint64, 0),
			NewCurrency(math.MaxUint64, 71),
			false,
		},
		{
			MaxCurrency,
			NewCurrency64(1),
			ZeroCurrency,
			true,
		},
	}
	for _, tt := range tests {
		got, overflows := tt.a.AddWithOverflow(tt.b)
		if tt.overflows != overflows {
			t.Errorf("Currency.AddWithOverflow(%d, %d) overflow %t, want %t", tt.a, tt.b, overflows, tt.overflows)
		} else if !got.Equals(tt.want) {
			t.Errorf("Currency.AddWithOverflow(%d, %d) expected = %v, got %v", tt.a, tt.b, tt.want, got)
		}
	}
}

func TestCurrencySub(t *testing.T) {
	tests := []struct {
		a, b, want Currency
	}{
		{
			ZeroCurrency,
			ZeroCurrency,
			ZeroCurrency,
		},
		{
			NewCurrency(1, 0),
			NewCurrency(1, 0),
			ZeroCurrency,
		},
		{
			NewCurrency(1, 0),
			ZeroCurrency,
			NewCurrency(1, 0),
		},
		{
			NewCurrency(0, 1),
			NewCurrency(math.MaxUint64, 0),
			NewCurrency(1, 0),
		},
		{
			NewCurrency(0, 1),
			NewCurrency(1, 0),
			NewCurrency(math.MaxUint64, 0),
		},
	}
	for _, tt := range tests {
		if got := tt.a.Sub(tt.b); !got.Equals(tt.want) {
			t.Errorf("Currency.Sub(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestCurrencySubWithUnderflow(t *testing.T) {
	tests := []struct {
		a, b, want Currency
		underflows bool
	}{
		{
			ZeroCurrency,
			ZeroCurrency,
			ZeroCurrency,
			false,
		},
		{
			NewCurrency(1, 0),
			NewCurrency(1, 0),
			ZeroCurrency,
			false,
		},
		{
			NewCurrency(1, 0),
			ZeroCurrency,
			NewCurrency(1, 0),
			false,
		},
		{
			NewCurrency(0, 1),
			NewCurrency(math.MaxUint64, 0),
			NewCurrency(1, 0),
			false,
		},
		{
			NewCurrency(0, 1),
			NewCurrency(1, 0),
			NewCurrency(math.MaxUint64, 0),
			false,
		},
		{
			ZeroCurrency,
			NewCurrency64(1),
			MaxCurrency,
			true,
		},
		{
			NewCurrency(0, 1),
			NewCurrency(1, 1),
			MaxCurrency,
			true,
		},
		{
			NewCurrency(1, 0),
			NewCurrency(20, 0),
			NewCurrency(math.MaxUint64-18, math.MaxUint64),
			true,
		},
		{
			NewCurrency(1, 1),
			NewCurrency(20, 1),
			NewCurrency(math.MaxUint64-18, math.MaxUint64),
			true,
		},
		{
			NewCurrency(math.MaxUint64, 0),
			NewCurrency(0, 1),
			MaxCurrency,
			true,
		},
	}
	for _, tt := range tests {
		diff, underflows := tt.a.SubWithUnderflow(tt.b)
		if tt.underflows != underflows {
			t.Fatalf("Currency.SubWithUnderflow(%d, %d) underflow %t, want %t", tt.a, tt.b, underflows, tt.underflows)
		} else if !diff.Equals(tt.want) {
			t.Fatalf("Currency.SubWithUnderflow(%d, %d) expected = %d, got %d", tt.a, tt.b, tt.want, diff)
		}
	}
}

func TestCurrencyMul(t *testing.T) {
	tests := []struct {
		a    Currency
		b    Currency
		want Currency
	}{
		{
			ZeroCurrency,
			ZeroCurrency,
			ZeroCurrency,
		},
		{
			NewCurrency(1, 0),
			NewCurrency(1, 0),
			NewCurrency(1, 0),
		},
		{
			NewCurrency(0, 1),
			NewCurrency(1, 0),
			NewCurrency(0, 1),
		},
		{
			NewCurrency(0, 1),
			NewCurrency(math.MaxUint64, 0),
			NewCurrency(0, math.MaxUint64),
		},
		{
			Siacoins(30),
			NewCurrency(50, 0),
			Siacoins(1500),
		},
		{
			NewCurrency(math.MaxUint64, 0),
			NewCurrency(2, 0),
			NewCurrency(math.MaxUint64-1, 1),
		},
	}
	for _, tt := range tests {
		if got := tt.a.Mul(tt.b); !got.Equals(tt.want) {
			t.Errorf("Currency.Mul(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestCurrencyMul64WithOverflow(t *testing.T) {
	tests := []struct {
		a         Currency
		b         uint64
		want      Currency
		overflows bool
	}{
		{
			ZeroCurrency,
			0,
			ZeroCurrency,
			false,
		},
		{
			NewCurrency(1, 0),
			1,
			NewCurrency(1, 0),
			false,
		},
		{
			NewCurrency(200, 0),
			50,
			NewCurrency(10000, 0),
			false,
		},
		{
			MaxCurrency,
			1,
			MaxCurrency,
			false,
		},
		{
			MaxCurrency,
			2,
			NewCurrency(math.MaxUint64-1, math.MaxUint64),
			true,
		},
	}
	for _, tt := range tests {
		got, overflows := tt.a.Mul64WithOverflow(tt.b)
		if tt.overflows != overflows {
			t.Errorf("Currency.MulWithOverflow(%d, %d) overflow %t, want %t", tt.a, tt.b, overflows, tt.overflows)
		} else if !got.Equals(tt.want) {
			t.Errorf("Currency.MulWithOverflow(%d, %d) expected = %v, got %v", tt.a, tt.b, tt.want, got)
		}
	}
}

func TestCurrencyMulWithOverflow(t *testing.T) {
	tests := []struct {
		a, b, want Currency
		overflows  bool
	}{
		{
			ZeroCurrency,
			ZeroCurrency,
			ZeroCurrency,
			false,
		},
		{
			NewCurrency(1, 0),
			NewCurrency(1, 0),
			NewCurrency(1, 0),
			false,
		},
		{
			NewCurrency(200, 0),
			NewCurrency(50, 0),
			NewCurrency(10000, 0),
			false,
		},
		{
			MaxCurrency,
			NewCurrency64(1),
			MaxCurrency,
			false,
		},
		{
			MaxCurrency,
			MaxCurrency,
			NewCurrency(1, 0),
			true,
		},
	}
	for _, tt := range tests {
		got, overflows := tt.a.MulWithOverflow(tt.b)
		if tt.overflows != overflows {
			t.Errorf("Currency.MulWithOverflow(%d, %d) overflow %t, want %t", tt.a, tt.b, overflows, tt.overflows)
		} else if !got.Equals(tt.want) {
			t.Errorf("Currency.MulWithOverflow(%d, %d) expected = %v, got %v", tt.a, tt.b, tt.want, got)
		}
	}
}

func TestCurrencyMul64(t *testing.T) {
	tests := []struct {
		a    Currency
		b    uint64
		want Currency
	}{
		{
			ZeroCurrency,
			0,
			ZeroCurrency,
		},
		{
			NewCurrency(1, 0),
			1,
			NewCurrency(1, 0),
		},
		{
			NewCurrency(0, 1),
			1,
			NewCurrency(0, 1),
		},
		{
			NewCurrency(0, 1),
			math.MaxUint64,
			NewCurrency(0, math.MaxUint64),
		},
		{
			Siacoins(30),
			50,
			Siacoins(1500),
		},
		{
			NewCurrency(math.MaxUint64, 0),
			2,
			NewCurrency(math.MaxUint64-1, 1),
		},
	}
	for _, tt := range tests {
		if got := tt.a.Mul64(tt.b); !got.Equals(tt.want) {
			t.Errorf("Currency.Mul64(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestCurrencyDiv(t *testing.T) {
	tests := []struct {
		a, b, want Currency
	}{
		{
			ZeroCurrency,
			NewCurrency64(1),
			ZeroCurrency,
		},
		{
			NewCurrency(1, 0),
			NewCurrency(1, 0),
			NewCurrency(1, 0),
		},
		{
			Siacoins(156),
			NewCurrency(2, 0),
			Siacoins(78),
		},
		{
			Siacoins(300),
			Siacoins(2),
			NewCurrency(150, 0),
		},
		{
			NewCurrency(0, 1),
			NewCurrency(1, 0),
			NewCurrency(0, 1),
		},
		{
			NewCurrency(0, 1),
			NewCurrency(0, 1),
			NewCurrency(1, 0),
		},
		{
			NewCurrency(0, 1),
			NewCurrency(2, 0),
			NewCurrency(math.MaxUint64/2+1, 0),
		},
		{
			NewCurrency(8262254095159001088, 2742357),
			NewCurrency64(2),
			NewCurrency(13354499084434276352, 1371178),
		},
		{
			MaxCurrency,
			NewCurrency64(2),
			NewCurrency(math.MaxUint64, math.MaxUint64/2),
		},
	}
	for _, tt := range tests {
		if got := tt.a.Div(tt.b); !got.Equals(tt.want) {
			t.Errorf("Currency.Div(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestCurrencyDiv64(t *testing.T) {
	tests := []struct {
		a    Currency
		b    uint64
		want Currency
	}{
		{
			ZeroCurrency,
			1,
			ZeroCurrency,
		},
		{
			NewCurrency64(1),
			1,
			NewCurrency64(1),
		},
		{
			Siacoins(156),
			2,
			Siacoins(78),
		},
		{
			MaxCurrency,
			2,
			NewCurrency(math.MaxUint64, math.MaxUint64/2),
		},
	}
	for _, tt := range tests {
		if got := tt.a.Div64(tt.b); !got.Equals(tt.want) {
			t.Errorf("Currency.Div64(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestCurrencyString(t *testing.T) {
	tests := []struct {
		val  Currency
		want string
	}{
		{
			ZeroCurrency,
			"0 SC",
		},
		{
			NewCurrency64(10000),
			"10000 H",
		},
		{
			Siacoins(1).Div64(1e12),
			"1 pS",
		},
		{
			Siacoins(1),
			"1 SC",
		},
		{
			Siacoins(10),
			"10 SC",
		},
		{
			Siacoins(100),
			"100 SC",
		},
		{
			Siacoins(1000),
			"1 KS",
		},
		{
			Siacoins(1).Mul64(1e12),
			"1 TS",
		},
		{
			Siacoins(10).Sub(Siacoins(1)),
			"9 SC",
		},
		{
			Siacoins(10).Sub(Siacoins(1).Div64(10)),
			"9.9 SC",
		},
		{
			Siacoins(10).Sub(Siacoins(1).Div64(100)),
			"9.99 SC",
		},
		{
			Siacoins(10).Sub(Siacoins(1).Div64(1000)),
			"9.999 SC",
		},
		{
			Siacoins(10).Sub(Siacoins(1).Div64(10000)),
			"9.9999 SC",
		},
		{
			Siacoins(10).Sub(NewCurrency64(1)),
			"9.999999999999999999999999 SC",
		},
		{
			NewCurrency(8262254095159001088, 2742357),
			"50.587566 SC",
		},
		{
			NewCurrency(2174395257947586975, 137),
			"2.529378333356156158367 mS",
		},
		{
			NewCurrency(math.MaxUint64, math.MaxUint64),
			"340.282366920938463463374607431768211455 TS",
		},
	}
	for _, tt := range tests {
		if got := tt.val.String(); got != tt.want {
			t.Errorf("Currency.String() = %v (%d H), want %v", got, tt.val, tt.want)
		}
	}
}

func TestCurrencyJSON(t *testing.T) {
	tests := []struct {
		val  Currency
		want string
	}{
		{
			ZeroCurrency,
			`"0"`,
		},
		{
			NewCurrency64(10000),
			`"10000"`,
		},
		{
			mustParseCurrency("50587566000000000000000000"),
			`"50587566000000000000000000"`,
		},
		{
			mustParseCurrency("2529378333356156158367"),
			`"2529378333356156158367"`,
		},
	}
	for _, tt := range tests {
		var c Currency
		buf, _ := json.Marshal(tt.val)
		if string(buf) != tt.want {
			t.Errorf("Currency.MarshalJSON(%d) = %s, want %s", tt.val, buf, tt.want)
		} else if err := json.Unmarshal(buf, &c); err != nil {
			t.Errorf("Currency.UnmarshalJSON(%s) err = %v", buf, err)
		} else if !c.Equals(tt.val) {
			t.Errorf("Currency.UnmarshalJSON(%s) = %d, want %d", buf, c, tt.val)
		}
	}
}

func TestParseCurrency(t *testing.T) {
	tests := []struct {
		s       string
		want    Currency
		wantErr bool
	}{
		{
			"",
			ZeroCurrency,
			true,
		},
		{
			"-1",
			ZeroCurrency,
			true,
		},
		{
			"340282366920938463463374607431768211456",
			ZeroCurrency,
			true,
		},
		{
			"0",
			ZeroCurrency,
			false,
		},
		{
			"10000",
			NewCurrency64(10000),
			false,
		},
		{
			"50587566000000000000000000",
			NewCurrency(8262254095159001088, 2742357),
			false,
		},
		{
			"2529378333356156158367",
			NewCurrency(2174395257947586975, 137),
			false,
		},
		{
			"2529378333356156158367",
			NewCurrency(2174395257947586975, 137),
			false,
		},
		{
			"1 SC",
			Siacoins(1),
			false,
		},
		{
			"1000 mS",
			Siacoins(1),
			false,
		},
		{
			"123 mS",
			Siacoins(123).Div64(1000),
			false,
		},
		{
			"2.000000000000000000000001 SC",
			Siacoins(2).Add(NewCurrency64(1)),
			false,
		},
		{
			"12.345 GS",
			Siacoins(12345).Mul64(1e6),
			false,
		},
		{
			"1 foo",
			ZeroCurrency,
			true,
		},
		{
			"foo MS",
			ZeroCurrency,
			true,
		},
		{
			".... SC",
			ZeroCurrency,
			true,
		},
		{
			"0.0000000000000000000000001 SC",
			ZeroCurrency,
			true,
		},
	}
	for _, tt := range tests {
		got, err := ParseCurrency(tt.s)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseCurrency(%v) error = %v, wantErr %v", tt.s, err, tt.wantErr)
		} else if !got.Equals(tt.want) {
			t.Errorf("ParseCurrency(%v) = %d, want %d", tt.s, got, tt.want)
		}
		if err := got.UnmarshalText([]byte(tt.s)); (err != nil) != tt.wantErr {
			t.Errorf("UnmarshalText(%v) error = %v, wantErr %v", tt.s, err, tt.wantErr)
		} else if !got.Equals(tt.want) {
			t.Errorf("UnmarshalText(%v) = %d, want %d", tt.s, got, tt.want)
		}
	}
}
