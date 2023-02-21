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

	errUnderflow = errors.New("underflow detected during currency conversion")
	errOverflow  = errors.New("overflow detected during currency conversion")
)

type (
	// Currency represents a quantity of hastings as an unsigned 128-bit number.
	// It can't be used to perform arithmetic operations without calling
	// Intermediate() first. This turns the Currency into an iCurrency which
	// then has to be converted back to a Currency by calling Result.
	// That's because the size of a Currency was chosen with the total supply of
	// Hastings in mind. Due to various reasons performing arithmetic operations
	// on a Currency might push it beyond its limit temporarily. That's why the
	// iCurrency type exists which can hold arbitrary-sized numbers.
	Currency struct {
		Lo, Hi uint64
	}

	// iCurrency is an intermediary currency type which can hold arbitrary-sized
	// and even negative numbers. A Currency has to be converted to an iCurrency
	// before performing arithmetic operations and turned back once done.
	iCurrency struct {
		i      *big.Int
		lo, hi uint64
	}
)

// NewCurrency returns the Currency value (lo,hi).
func NewCurrency(lo, hi uint64) Currency {
	return Currency{lo, hi}
}

// NewCurrency64 converts c to a Currency value.
func NewCurrency64(c uint64) Currency {
	return Currency{c, 0}
}

// Siacoins returns a Currency value representing n siacoins.
func Siacoins(n uint32) Currency {
	r := HastingsPerSiacoin.Intermediate().Mul64(uint64(n))
	siacoins, err := r.Result()
	if err != nil {
		panic(err) // should never happen
	}
	return siacoins
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

// Intermediate converts a Currency to an iCurrency to perform arithmetic
// operations on.
func (c Currency) Intermediate() iCurrency {
	return iCurrency{lo: c.Lo, hi: c.Hi}
}

// Equals returns true if c == v.
func (c iCurrency) Equals(v iCurrency) bool {
	return c.Cmp(v) == 0
}

// IsZero returns true if c == 0.
func (c iCurrency) IsZero() bool {
	if c.isBig() {
		return c.Big().BitLen() == 0
	}
	return c.lo == 0 && c.hi == 0
}

// Result converts an iCurrency back into a Currency if possible. Otherwise an
// error is returned.
func (c iCurrency) Result() (Currency, error) {
	if c.i == nil {
		return Currency{c.lo, c.hi}, nil
	} else if c.i.Sign() < 0 {
		return ZeroCurrency, errUnderflow
	} else if c.i.BitLen() > 128 {
		return ZeroCurrency, errOverflow
	}
	return NewCurrency(c.i.Uint64(), new(big.Int).Rsh(c.i, 64).Uint64()), nil
}

// Cmp compares c and v and returns:
//
//	-1 if c <  v
//	 0 if c == v
//	+1 if c >  v
func (c iCurrency) Cmp(v iCurrency) int {
	if c.isBig() || v.isBig() {
		return c.Big().Cmp(v.Big())
	} else if c == v {
		return 0
	} else if c.hi < v.hi || (c.hi == v.hi && c.lo < v.lo) {
		return -1
	} else {
		return 1
	}
}

// Add returns c+v.
func (c iCurrency) Add(v iCurrency) iCurrency {
	// If one of the inputs is already a big.Int, use big.Int math.
	if c.isBig() || v.isBig() {
		return iCurrency{
			i: new(big.Int).Add(c.Big(), v.Big()),
		}
	}
	// Otherwise we try the fast math and only use big.Int math as a fallback.
	lo, carry := bits.Add64(c.lo, v.lo, 0)
	hi, carry := bits.Add64(c.hi, v.hi, carry)
	if carry != 0 {
		return iCurrency{
			i: new(big.Int).Add(c.Big(), v.Big()),
		}
	}
	return iCurrency{nil, lo, hi}
}

// Sub returns c-v.
func (c iCurrency) Sub(v iCurrency) iCurrency {
	// If one of the inputs is already a big.Int, use big.Int math.
	if c.isBig() || v.isBig() {
		return iCurrency{
			i: new(big.Int).Sub(c.Big(), v.Big()),
		}
	}
	// Otherwise we try the fast math and only use big.Int math as a fallback.
	lo, borrow := bits.Sub64(c.lo, v.lo, 0)
	hi, borrow := bits.Sub64(c.hi, v.hi, borrow)
	if borrow != 0 {
		return iCurrency{
			i: new(big.Int).Sub(c.Big(), v.Big()),
		}
	}
	return iCurrency{nil, lo, hi}
}

// Mul returns c*v.
func (c iCurrency) Mul(v iCurrency) iCurrency {
	// If one of the inputs is already a big.Int, use big.Int math.
	if c.isBig() || v.isBig() {
		return iCurrency{
			i: new(big.Int).Mul(c.Big(), v.Big()),
		}
	}
	// Otherwise we try the fast math and only use big.Int math as a fallback.
	// NOTE: this is the overflow-checked equivalent of:
	//
	//   hi, lo := bits.Mul64(c.Lo, v.Lo)
	//   hi += c.Hi*v.Lo + c.Lo*v.Hi
	//
	hi, lo := bits.Mul64(c.lo, v.lo)
	p0, p1 := bits.Mul64(c.hi, v.lo)
	p2, p3 := bits.Mul64(c.lo, v.hi)
	hi, c0 := bits.Add64(hi, p1, 0)
	hi, c1 := bits.Add64(hi, p3, c0)
	if (c.hi != 0 && v.hi != 0) || p0 != 0 || p2 != 0 || c1 != 0 {
		return iCurrency{
			i: new(big.Int).Mul(c.Big(), v.Big()),
		}
	}
	return iCurrency{nil, lo, hi}
}

// Mul64 returns c*v.
func (c iCurrency) Mul64(v uint64) iCurrency {
	// If c is already a big.Int, use big.Int math.
	if c.isBig() {
		return iCurrency{
			i: new(big.Int).Mul(c.Big(), new(big.Int).SetUint64(v)),
		}
	}
	// Otherwise we try the fast math and only use big.Int math as a fallback.
	// NOTE: this is the overflow-checked equivalent of:
	//
	//   hi, lo := bits.Mul64(c.Lo, v)
	//   hi += c.Hi * v
	//
	hi0, lo0 := bits.Mul64(c.lo, v)
	hi1, lo1 := bits.Mul64(c.hi, v)
	hi2, c0 := bits.Add64(hi0, lo1, 0)
	if hi1 != 0 || c0 != 0 {
		return iCurrency{
			i: new(big.Int).Mul(c.Big(), new(big.Int).SetUint64(v)),
		}
	}
	return iCurrency{nil, lo0, hi2}
}

// Div returns c/v. If v == 0, Div panics.
func (c iCurrency) Div(v iCurrency) iCurrency {
	q, _ := c.quoRem(v)
	return q
}

// Div64 returns c/v. If v == 0, Div panics.
func (c iCurrency) Div64(v uint64) iCurrency {
	q, _ := c.quoRem64(v)
	return q
}

// quoRem returns q = c/v and r = c%v. If v == ZeroCurrency, Div panics.
func (c iCurrency) quoRem(v iCurrency) (q, r iCurrency) {
	if v.hi == 0 {
		var r64 uint64
		q, r64 = c.quoRem64(v.lo)
		r = iCurrency{lo: r64}
	} else {
		// generate a "trial quotient," guaranteed to be within 1 of the actual
		// quotient, then adjust.
		n := bits.LeadingZeros64(v.hi)
		v1 := NewCurrency(v.lo<<n, v.hi<<n|v.lo>>(64-n)) // v << n
		u1 := NewCurrency(c.lo>>1|c.hi<<63, c.hi>>1)     // c >> 1
		tq, _ := bits.Div64(u1.Hi, u1.Lo, v1.Hi)
		tq >>= 63 - n
		if tq != 0 {
			tq--
		}
		q = iCurrency{lo: tq}
		// calculate remainder using trial quotient, then adjust if remainder is
		// greater than divisor
		r = c.Sub(v.Mul64(tq))
		if r.Cmp(v) >= 0 {
			// increment q
			if q.lo++; q.lo == 0 {
				q.hi++
			}
			r = r.Sub(v)
		}
	}
	return
}

// quoRem64 returns q = c/v and r = c%v.
func (c iCurrency) quoRem64(v uint64) (q iCurrency, r uint64) {
	if c.hi < v {
		q.lo, r = bits.Div64(c.hi, c.lo, v)
	} else {
		q.hi, r = bits.Div64(0, c.hi, v)
		q.lo, r = bits.Div64(r, c.lo, v)
	}
	return
}

// isBig returns true if iCurrency has either become too big or too small to be
// represented by 128 bits.
func (c iCurrency) isBig() bool {
	return c.i != nil
}

// Big returns c as a *big.Int.
func (c iCurrency) Big() *big.Int {
	if c.isBig() {
		return new(big.Int).Set(c.i)
	}
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b[:8], c.hi)
	binary.BigEndian.PutUint64(b[8:], c.lo)
	return new(big.Int).SetBytes(b)
}

// ExactString returns the base-10 representation of c as a string.
func (c Currency) ExactString() string {
	if c.IsZero() {
		return "0"
	}
	buf := []byte("0000000000000000000000000000000000000000") // log10(2^128) < 40
	for i := len(buf); ; i -= 19 {
		q, r := c.Intermediate().quoRem64(1e19) // largest power of 10 that fits in a uint64
		var n int
		for ; r != 0; r /= 10 {
			n++
			buf[i-n] += byte(r % 10)
		}
		if q.IsZero() {
			return string(buf[i-n:])
		}
		res, err := q.Result()
		if err != nil {
			panic(err) // can't happen since we only divide
		}
		c = res
	}
}

// String returns base-10 representation of c with a unit suffix. The value may
// be rounded. To avoid loss of precision, use ExactString.
func (c Currency) String() string {
	pico := Siacoins(1).Intermediate().Div64(1e12)
	if c.Intermediate().Cmp(pico) < 0 {
		return c.ExactString() + " H"
	}

	// iterate until we find a unit greater than c
	mag := pico
	unit := ""
	for _, unit = range []string{"pS", "nS", "uS", "mS", "SC", "KS", "MS", "GS", "TS"} {
		j := mag.Mul64(1000)
		if c.Intermediate().Cmp(j) < 0 || unit == "TS" {
			break
		}
		mag = j
	}

	f, _ := new(big.Rat).SetFrac(c.Intermediate().Big(), mag.Big()).Float64()
	s := fmt.Sprintf("%.4g %s", f, unit)
	// test for exactness
	if p, _ := ParseCurrency(s); !p.Equals(c) {
		s = "~" + s
	}
	return s
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
