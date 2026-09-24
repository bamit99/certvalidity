package schedule

import (
	"testing"
	"time"
)

func mustDate(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestMaxLifetime(t *testing.T) {
	cases := []struct {
		notBefore string
		want      int
	}{
		{"2020-01-01", Lifetime398},
		{"2026-03-14", Lifetime398},
		{"2026-03-15", Lifetime200},
		{"2027-03-14", Lifetime200},
		{"2027-03-15", Lifetime100},
		{"2029-03-14", Lifetime100},
		{"2029-03-15", Lifetime47},
		{"2030-06-01", Lifetime47},
	}
	for _, c := range cases {
		if got := MaxLifetime(mustDate(c.notBefore)); got != c.want {
			t.Errorf("MaxLifetime(%s) = %d, want %d", c.notBefore, got, c.want)
		}
	}
}
