// Package money implements exact currency amounts as integer minor units.
// Floats are never used. Conversion to PayPal's string amounts happens only
// at the edge (String / Parse).
package money

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Amount is a non-negative-or-negative integer amount in minor units
// (cents for USD) plus an ISO-4217 currency code.
type Amount struct {
	Minor    int64  `json:"minor"`
	Currency string `json:"currency"`
}

// ErrInvalid is returned for any malformed amount or currency.
var ErrInvalid = errors.New("money: invalid amount")

// PayPal does not support decimals for these currencies.
var zeroDecimal = map[string]bool{"JPY": true, "HUF": true, "TWD": true}

// Exponent returns the number of decimal places for a currency.
func Exponent(currency string) int {
	if zeroDecimal[currency] {
		return 0
	}
	return 2
}

// ValidCurrency reports whether c looks like an ISO-4217 code (3 upper-case letters).
func ValidCurrency(c string) bool {
	if len(c) != 3 {
		return false
	}
	for i := 0; i < 3; i++ {
		if c[i] < 'A' || c[i] > 'Z' {
			return false
		}
	}
	return true
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// Parse converts a decimal string such as "40.00" into minor units.
// It is strict: no sign, no exponent, no whitespace, no more fractional
// digits than the currency allows.
func Parse(value, currency string) (Amount, error) {
	if !ValidCurrency(currency) {
		return Amount{}, fmt.Errorf("%w: bad currency %q", ErrInvalid, currency)
	}
	exp := Exponent(currency)
	intPart, frac, hasDot := strings.Cut(value, ".")
	if !allDigits(intPart) {
		return Amount{}, fmt.Errorf("%w: %q", ErrInvalid, value)
	}
	if hasDot {
		if exp == 0 || !allDigits(frac) || len(frac) > exp {
			return Amount{}, fmt.Errorf("%w: %q", ErrInvalid, value)
		}
	}
	for len(frac) < exp {
		frac += "0"
	}
	minor, err := strconv.ParseInt(intPart+frac, 10, 64)
	if err != nil {
		return Amount{}, fmt.Errorf("%w: %q out of range", ErrInvalid, value)
	}
	return Amount{Minor: minor, Currency: currency}, nil
}

// MustParse is for tests and constants.
func MustParse(value, currency string) Amount {
	a, err := Parse(value, currency)
	if err != nil {
		panic(err)
	}
	return a
}

// String renders the amount without the currency, e.g. "40.00".
func (a Amount) String() string {
	exp := Exponent(a.Currency)
	neg := a.Minor < 0
	var u uint64
	if neg {
		u = uint64(-(a.Minor + 1)) + 1 // safe for MinInt64
	} else {
		u = uint64(a.Minor)
	}
	s := strconv.FormatUint(u, 10)
	if exp > 0 {
		for len(s) <= exp {
			s = "0" + s
		}
		s = s[:len(s)-exp] + "." + s[len(s)-exp:]
	}
	if neg {
		s = "-" + s
	}
	return s
}

// Display renders "40.00 USD" for human-readable reasons.
func (a Amount) Display() string { return a.String() + " " + a.Currency }

// Add returns a+b, checking currency and overflow.
func (a Amount) Add(b Amount) (Amount, error) {
	if a.Currency != b.Currency {
		return Amount{}, fmt.Errorf("%w: currency mismatch %s vs %s", ErrInvalid, a.Currency, b.Currency)
	}
	if (b.Minor > 0 && a.Minor > math.MaxInt64-b.Minor) || (b.Minor < 0 && a.Minor < math.MinInt64-b.Minor) {
		return Amount{}, fmt.Errorf("%w: overflow", ErrInvalid)
	}
	return Amount{Minor: a.Minor + b.Minor, Currency: a.Currency}, nil
}
