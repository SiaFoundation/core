package types

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"math/bits"
	"strings"
)

// ZeroCurrency represents zero base units.
var ZeroCurrency Currency

// HastingsPerSiacoin is the number of hastings (base units) in a siacoin.
var HastingsPerSiacoin = NewCurrency(2003764205206896640, 54210) // 10^24

// Siacoins returns a Currency value representing n siacoins.
func Siacoins(n uint32) Currency { return HastingsPerSiacoin.Mul64(uint64(n)) }

// Siafunds returns a Currency value representing n siafunds.
func Siafunds(n uint16) Currency { return NewCurrency64(uint64(n)) }

// Currency represents a quantity of hastings as an unsigned 128-bit number.
type Currency struct {
	Lo, Hi uint64
}

// Format implements fmt.Formatter. It accepts the formats
// 's', 'v' (Siacoin representation - rounded to 3 decimal places), or
// 'd' (exact value, useful for outputing Siafunds or Hastings).
func (c Currency) Format(f fmt.State, v rune) {
	switch v {
	case 's', 'v':
		f.Write([]byte(c.String()))
	case 'd':
		f.Write([]byte(c.ExactString()))
	default:
		fmt.Fprintf(f, "%%!%c(unsupported,Currency=%d)", v, c)
	}
}

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
//   -1 if c <  v
//    0 if c == v
//   +1 if c >  v
//
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
	lo, borrow := bits.Sub64(c.Lo, v.Lo, 0)
	hi, borrow := bits.Sub64(c.Hi, v.Hi, borrow)
	if borrow != 0 {
		panic("underflow")
	}
	return Currency{lo, hi}
}

// Mul64 returns c*v. If the result would overflow, Mul64 panics.
//
// Note that it is safe to multiply any two Currency values that are below 2^64.
func (c Currency) Mul64(v uint64) Currency {
	// NOTE: this is the overflow-checked equivalent of:
	//
	//   hi, lo := bits.Mul64(c.Lo, v)
	//   hi += c.Hi * v
	//
	hi0, lo0 := bits.Mul64(c.Lo, v)
	hi1, lo1 := bits.Mul64(c.Hi, v)
	hi2, c0 := bits.Add64(hi0, lo1, 0)
	if hi1 != 0 || c0 != 0 {
		panic("overflow")
	}
	return Currency{lo0, hi2}
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

// String returns the base-10 representation of c as a string, in units of
// HastingsPerSiacoin, rounded to three decimal places.
func (c Currency) String() string {
	fs := new(big.Rat).SetFrac(c.Big(), HastingsPerSiacoin.Big()).FloatString(3)
	return strings.TrimSuffix(strings.TrimRight(fs, "0"), ".")
}

// MarshalJSON implements json.Marshaler.
func (c Currency) MarshalJSON() ([]byte, error) {
	return []byte(`"` + c.ExactString() + `"`), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (c *Currency) UnmarshalJSON(b []byte) (err error) {
	*c, err = ParseCurrency(strings.Trim(string(b), `"`))
	return
}

// Big returns c as a *big.Int.
func (c Currency) Big() *big.Int {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b[:8], c.Hi)
	binary.BigEndian.PutUint64(b[8:], c.Lo)
	return new(big.Int).SetBytes(b)
}

// NewCurrency returns the Currency value (lo,hi).
func NewCurrency(lo, hi uint64) Currency {
	return Currency{lo, hi}
}

// NewCurrency64 converts c to a Currency value.
func NewCurrency64(c uint64) Currency {
	return Currency{c, 0}
}

// ParseCurrency parses s as a Currency value. The format of s should match the
// return value of the ExactString method, i.e. an unsigned base-10 integer.
func ParseCurrency(s string) (Currency, error) {
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
