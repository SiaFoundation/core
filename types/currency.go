package types

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"math/bits"
	"strings"
)

var (
	// ZeroCurrency represents zero base units.
	ZeroCurrency Currency

	// MaxCurrency represents the largest possible value for the Currency type.
	MaxCurrency = NewCurrency(math.MaxUint64, math.MaxUint64)

	// HastingsPerSiacoin is the number of hastings (base units) in a siacoin.
	HastingsPerSiacoin = NewCurrency(2003764205206896640, 54210) // 10^24
)

// Currency represents a quantity of hastings as an unsigned 128-bit number.
type Currency struct {
	Lo, Hi uint64
}

// NewCurrency returns the Currency value (lo,hi).
func NewCurrency(lo, hi uint64) Currency {
	return Currency{lo, hi}
}

// NewCurrency64 converts c to a Currency value.
func NewCurrency64(c uint64) Currency {
	return Currency{c, 0}
}

// Siacoins returns a Currency value representing n siacoins.
func Siacoins(n uint32) Currency { return HastingsPerSiacoin.Mul64(uint64(n)) }

// IsZero returns true if c == 0.
func (c Currency) IsZero() bool {
	return c == ZeroCurrency
}

// Equals returns true if c == v.
//
// Currency values can be compared directly with ==, but use of the Equals method
// is preferred for consistency.
func (c Currency) Equals(v Currency) bool {
	return c == v
}

// Cmp compares c and v and returns:
//
//	-1 if c <  v
//	 0 if c == v
//	+1 if c >  v
func (c Currency) Cmp(v Currency) int {
	if c == v {
		return 0
	} else if c.Hi < v.Hi || (c.Hi == v.Hi && c.Lo < v.Lo) {
		return -1
	} else {
		return 1
	}
}

// Add returns c+v. If the result would overflow, Add panics.
//
// It is safe to use Add in any context where the sum cannot exceed the total
// supply of Currency (such as when calculating the balance of a wallet). In
// less-trusted contexts (such as when validating a transaction),
// AddWithOverflow should be used instead.
func (c Currency) Add(v Currency) Currency {
	s, overflow := c.AddWithOverflow(v)
	if overflow {
		panic("overflow")
	}
	return s
}

// AddWithOverflow returns c+v, along with a boolean indicating whether the
// result overflowed.
func (c Currency) AddWithOverflow(v Currency) (Currency, bool) {
	lo, carry := bits.Add64(c.Lo, v.Lo, 0)
	hi, carry := bits.Add64(c.Hi, v.Hi, carry)
	return Currency{lo, hi}, carry != 0
}

// Sub returns c-v. If the result would underflow, Sub panics.
func (c Currency) Sub(v Currency) Currency {
	s, underflow := c.SubWithUnderflow(v)
	if underflow {
		panic("underflow")
	}
	return s
}

// SubWithUnderflow returns c-v, along with a boolean indicating whether the result
// underflowed.
func (c Currency) SubWithUnderflow(v Currency) (Currency, bool) {
	lo, borrow := bits.Sub64(c.Lo, v.Lo, 0)
	hi, borrow := bits.Sub64(c.Hi, v.Hi, borrow)
	return Currency{lo, hi}, borrow != 0
}

// Mul returns c*v. If the result would overflow, Mul panics.
//
// Note that it is safe to multiply any two Currency values that are below 2^64.
func (c Currency) Mul(v Currency) Currency {
	s, overflow := c.MulWithOverflow(v)
	if overflow {
		panic("overflow")
	}
	return s
}

// MulWithOverflow returns c*v, along with a boolean indicating whether the
// result overflowed.
//
// Note that it is safe to multiply any two Currency values that are below 2^64.
func (c Currency) MulWithOverflow(v Currency) (Currency, bool) {
	// NOTE: this is the overflow-checked equivalent of:
	//
	//   hi, lo := bits.Mul64(c.Lo, v.Lo)
	//   hi += c.Hi*v.Lo + c.Lo*v.Hi
	//
	hi, lo := bits.Mul64(c.Lo, v.Lo)
	p0, p1 := bits.Mul64(c.Hi, v.Lo)
	p2, p3 := bits.Mul64(c.Lo, v.Hi)
	hi, c0 := bits.Add64(hi, p1, 0)
	hi, c1 := bits.Add64(hi, p3, c0)
	return Currency{lo, hi}, (c.Hi != 0 && v.Hi != 0) || p0 != 0 || p2 != 0 || c1 != 0
}

// Mul64 returns c*v. If the result would overflow, Mul64 panics.
//
// Note that it is safe to multiply any two Currency values that are below 2^64.
func (c Currency) Mul64(v uint64) Currency {
	s, overflow := c.Mul64WithOverflow(v)
	if overflow {
		panic("overflow")
	}
	return s
}

// Mul64WithOverflow returns c*v along with a boolean indicating whether the
// result overflowed.
//
// Note that it is safe to multiply any two Currency values that are below 2^64.
func (c Currency) Mul64WithOverflow(v uint64) (Currency, bool) {
	// NOTE: this is the overflow-checked equivalent of:
	//
	//   hi, lo := bits.Mul64(c.Lo, v)
	//   hi += c.Hi * v
	//
	hi0, lo0 := bits.Mul64(c.Lo, v)
	hi1, lo1 := bits.Mul64(c.Hi, v)
	hi2, c0 := bits.Add64(hi0, lo1, 0)
	return Currency{lo0, hi2}, hi1 != 0 || c0 != 0
}

// Div returns c/v. If v == 0, Div panics.
func (c Currency) Div(v Currency) Currency {
	q, _ := c.quoRem(v)
	return q
}

// Div64 returns c/v. If v == 0, Div panics.
func (c Currency) Div64(v uint64) Currency {
	q, _ := c.quoRem64(v)
	return q
}

// quoRem returns q = c/v and r = c%v. If v == ZeroCurrency, Div panics.
func (c Currency) quoRem(v Currency) (q, r Currency) {
	if v.Hi == 0 {
		var r64 uint64
		q, r64 = c.quoRem64(v.Lo)
		r = NewCurrency64(r64)
	} else {
		// generate a "trial quotient," guaranteed to be within 1 of the actual
		// quotient, then adjust.
		n := bits.LeadingZeros64(v.Hi)
		v1 := NewCurrency(v.Lo<<n, v.Hi<<n|v.Lo>>(64-n)) // v << n
		u1 := NewCurrency(c.Lo>>1|c.Hi<<63, c.Hi>>1)     // c >> 1
		tq, _ := bits.Div64(u1.Hi, u1.Lo, v1.Hi)
		tq >>= 63 - n
		if tq != 0 {
			tq--
		}
		q = NewCurrency64(tq)
		// calculate remainder using trial quotient, then adjust if remainder is
		// greater than divisor
		r = c.Sub(v.Mul64(tq))
		if r.Cmp(v) >= 0 {
			// increment q
			if q.Lo++; q.Lo == 0 {
				q.Hi++
			}
			r = r.Sub(v)
		}
	}
	return
}

// quoRem64 returns q = c/v and r = c%v.
func (c Currency) quoRem64(v uint64) (q Currency, r uint64) {
	if c.Hi < v {
		q.Lo, r = bits.Div64(c.Hi, c.Lo, v)
	} else {
		q.Hi, r = bits.Div64(0, c.Hi, v)
		q.Lo, r = bits.Div64(r, c.Lo, v)
	}
	return
}

// Big returns c as a *big.Int.
func (c Currency) Big() *big.Int {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b[:8], c.Hi)
	binary.BigEndian.PutUint64(b[8:], c.Lo)
	return new(big.Int).SetBytes(b)
}

// ExactString returns the base-10 representation of c as a string.
func (c Currency) ExactString() string {
	if c.IsZero() {
		return "0"
	}
	buf := []byte("0000000000000000000000000000000000000000") // log10(2^128) < 40
	for i := len(buf); ; i -= 19 {
		q, r := c.quoRem64(1e19) // largest power of 10 that fits in a uint64
		var n int
		for ; r != 0; r /= 10 {
			n++
			buf[i-n] += byte(r % 10)
		}
		if q.IsZero() {
			return string(buf[i-n:])
		}
		c = q
	}
}

// String returns base-10 representation of c with a unit suffix. The value may
// be rounded. To avoid loss of precision, use ExactString.
func (c Currency) String() string {
	pico := Siacoins(1).Div64(1e12)
	if c.Cmp(pico) < 0 {
		return c.ExactString() + " H"
	}

	// iterate until we find a unit greater than c
	//
	// NOTE: MaxCurrency is ~340.3 TS
	mag := pico
	unit := ""
	for _, unit = range []string{"pS", "nS", "uS", "mS", "SC", "KS", "MS", "GS", "TS"} {
		j, overflow := mag.Mul64WithOverflow(1000)
		if overflow || c.Cmp(j) < 0 || unit == "TS" {
			break
		}
		mag = j
	}

	f, _ := new(big.Rat).SetFrac(c.Big(), mag.Big()).Float64()
	s := fmt.Sprintf("%.4g %s", f, unit)
	// test for exactness
	if p, _ := ParseCurrency(s); !p.Equals(c) {
		s = "~" + s
	}
	return s
}

// Siacoins converts the value of c from Hastings to Siacoins (SC) and returns
// it as a float64.
func (c Currency) Siacoins() float64 {
	f, _ := new(big.Rat).SetFrac(c.Big(), HastingsPerSiacoin.Big()).Float64()
	return f
}

// Format implements fmt.Formatter. It accepts the following formats:
//
//	d: raw integer (equivalent to ExactString())
//	s: rounded integer with unit suffix (equivalent to String())
//	v: same as s
func (c Currency) Format(f fmt.State, v rune) {
	switch v {
	case 'd':
		io.WriteString(f, c.ExactString())
	case 's', 'v':
		io.WriteString(f, c.String())
	default:
		fmt.Fprintf(f, "%%!%c(unsupported,Currency=%d)", v, c)
	}
}

// MarshalJSON implements json.Marshaler.
func (c Currency) MarshalJSON() ([]byte, error) {
	return []byte(`"` + c.ExactString() + `"`), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (c *Currency) UnmarshalJSON(b []byte) (err error) {
	*c, err = parseExactCurrency(strings.Trim(string(b), `"`))
	return
}

func parseExactCurrency(s string) (Currency, error) {
	i, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return ZeroCurrency, errors.New("not an integer")
	} else if i.Sign() < 0 {
		return ZeroCurrency, errors.New("value cannot be negative")
	} else if i.BitLen() > 128 {
		return ZeroCurrency, errors.New("value overflows Currency representation")
	}
	return NewCurrency(i.Uint64(), new(big.Int).Rsh(i, 64).Uint64()), nil
}

func expToUnit(exp int64) *big.Rat {
	return new(big.Rat).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(exp), nil))
}

var currencyUnits = map[string]*big.Rat{
	"pS": expToUnit(12),
	"nS": expToUnit(15),
	"uS": expToUnit(18),
	"mS": expToUnit(21),
	"SC": expToUnit(24),
	"KS": expToUnit(27),
	"MS": expToUnit(30),
	"GS": expToUnit(33),
	"TS": expToUnit(36),
}

// ParseCurrency parses s as a Currency value. The format of s should match one
// of the representations provided by (Currency).Format.
func ParseCurrency(s string) (Currency, error) {
	i := strings.LastIndexAny(s, "0123456789.") + 1
	if i == 0 {
		return ZeroCurrency, errors.New("not a number")
	}
	n, unit := s[:i], strings.TrimSpace(s[i:])
	if unit == "" || unit == "H" {
		return parseExactCurrency(n)
	}
	// parse numeric part as a big.Rat
	r, ok := new(big.Rat).SetString(n)
	if !ok {
		return ZeroCurrency, errors.New("not a number")
	}
	// multiply by unit
	u, ok := currencyUnits[unit]
	if !ok {
		return ZeroCurrency, fmt.Errorf("invalid unit %q", unit)
	}
	r.Mul(r, u)
	// r must be an integer at this point
	if !r.IsInt() {
		return ZeroCurrency, errors.New("not an integer")
	}
	return parseExactCurrency(r.RatString())
}
