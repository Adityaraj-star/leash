package money

import (
	"math"
	"testing"
)

func TestParseAndString(t *testing.T) {
	cases := []struct {
		in, cur string
		minor   int64
		out     string
	}{
		{"40.00", "USD", 4000, "40.00"},
		{"40", "USD", 4000, "40.00"},
		{"0.05", "USD", 5, "0.05"},
		{"0", "USD", 0, "0.00"},
		{"7.5", "USD", 750, "7.50"},
		{"100", "JPY", 100, "100"},
		{"1234567.89", "EUR", 123456789, "1234567.89"},
	}
	for _, c := range cases {
		a, err := Parse(c.in, c.cur)
		if err != nil {
			t.Fatalf("Parse(%q,%q): %v", c.in, c.cur, err)
		}
		if a.Minor != c.minor {
			t.Errorf("Parse(%q) minor=%d want %d", c.in, a.Minor, c.minor)
		}
		if a.String() != c.out {
			t.Errorf("String()=%q want %q", a.String(), c.out)
		}
	}
}

func TestParseRejects(t *testing.T) {
	bad := []struct{ v, c string }{
		{"", "USD"}, {"-1.00", "USD"}, {"+1.00", "USD"}, {"1e3", "USD"}, {" 1.00", "USD"},
		{"1.005", "USD"}, {"1.", "USD"}, {".5", "USD"}, {"1,000.00", "USD"},
		{"1.00", "JPY"}, {"1.00", "usd"}, {"1.00", "US"}, {"1.00", ""},
		{"99999999999999999999", "USD"}, {"٣.٠٠", "USD"}, {"0x10", "USD"},
	}
	for _, b := range bad {
		if _, err := Parse(b.v, b.c); err == nil {
			t.Errorf("Parse(%q,%q) should fail", b.v, b.c)
		}
	}
}

func TestAddChecks(t *testing.T) {
	a := MustParse("1.00", "USD")
	if _, err := a.Add(MustParse("1.00", "EUR")); err == nil {
		t.Error("currency mismatch must fail")
	}
	if _, err := (Amount{Minor: math.MaxInt64, Currency: "USD"}).Add(Amount{Minor: 1, Currency: "USD"}); err == nil {
		t.Error("overflow must fail")
	}
	s, err := a.Add(MustParse("2.50", "USD"))
	if err != nil || s.Minor != 350 {
		t.Errorf("got %v %v", s, err)
	}
}

func TestStringMinInt64(t *testing.T) {
	a := Amount{Minor: math.MinInt64, Currency: "USD"}
	if got := a.String(); got != "-92233720368547758.08" {
		t.Errorf("got %q", got)
	}
}

func FuzzParseRoundTrip(f *testing.F) {
	for _, s := range []string{"40.00", "0", "0.01", "999999999.99", "1.5", "x", "1e5", "-3"} {
		f.Add(s, "USD")
	}
	f.Add("100", "JPY")
	f.Fuzz(func(t *testing.T, v, cur string) {
		a, err := Parse(v, cur)
		if err != nil {
			return
		}
		if a.Minor < 0 {
			t.Fatalf("Parse produced negative amount from %q", v)
		}
		b, err := Parse(a.String(), a.Currency)
		if err != nil || b != a {
			t.Fatalf("round trip failed: %q -> %v -> %q -> %v (%v)", v, a, a.String(), b, err)
		}
	})
}
