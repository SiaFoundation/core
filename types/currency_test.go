package types

import (
	"math"
	"testing"
)

var maxCurrency = NewCurrency(math.MaxUint64, math.MaxUint64)

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
			maxCurrency,
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
			maxCurrency,
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
			maxCurrency,
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

func TestCurrencyExactString(t *testing.T) {
	tests := []struct {
		val  Currency
		want string
	}{
		{
			ZeroCurrency,
			"0",
		},
		{
			Siacoins(128),
			"128000000000000000000000000",
		},
		{
			NewCurrency64(math.MaxUint64),
			"18446744073709551615",
		},
		{
			NewCurrency(8262254095159001088, 2742357),
			"50587566000000000000000000",
		},
		{
			maxCurrency,
			"340282366920938463463374607431768211455",
		},
	}
	for _, tt := range tests {
		if got := tt.val.ExactString(); got != tt.want {
			t.Errorf("Currency.ExactString() = %v, want %v", got, tt.want)
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
			"0",
		},
		{
			NewCurrency64(10000),
			"0",
		},
		{
			NewCurrency(8262254095159001088, 2742357),
			"50.588",
		},
		{
			NewCurrency(2174395257947586975, 137),
			"0.003",
		},
	}
	for _, tt := range tests {
		if got := tt.val.String(); got != tt.want {
			t.Errorf("Currency.String() = %v (%d), want %v", got, tt.val, tt.want)
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
		// MarshalJSON cannot error
		buf, _ := tt.val.MarshalJSON()
		if string(buf) != tt.want {
			t.Errorf("Currency.MarshalJSON(%d) = %v, want %v", tt.val, buf, tt.want)
			continue
		}

		var c Currency
		if err := c.UnmarshalJSON(buf); err != nil {
			t.Errorf("Currency.UnmarshalJSON(%s) err = %v", buf, err)
		} else if !c.Equals(tt.val) {
			t.Errorf("Currency.UnmarshalJSON(%s) = %d, want %d", buf, c, tt.val)
		}
	}
}

func TestParseCurrency(t *testing.T) {
	tests := []struct {
		desc    string
		s       string
		want    Currency
		wantErr bool
	}{
		{
			"empty value",
			"",
			ZeroCurrency,
			true,
		},
		{
			"negative value",
			"-1",
			ZeroCurrency,
			true,
		},
		{
			"overflow",
			"340282366920938463463374607431768211456",
			ZeroCurrency,
			true,
		},
		{
			"0 SC",
			"0",
			ZeroCurrency,
			false,
		},
		{
			"10000 H",
			"10000",
			NewCurrency64(10000),
			false,
		},
		{
			"50.587566 SC",
			"50587566000000000000000000",
			NewCurrency(8262254095159001088, 2742357),
			false,
		},
		{
			"0.00252934 SC",
			"2529378333356156158367",
			NewCurrency(2174395257947586975, 137),
			false,
		},
	}
	for _, tt := range tests {
		got, err := ParseCurrency(tt.s)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseCurrency(%v) error = %v, wantErr %v", tt.s, err, tt.wantErr)
		} else if !got.Equals(tt.want) {
			t.Errorf("ParseCurrency(%v) = %d, want %d", tt.s, got, tt.want)
		}
	}
}
