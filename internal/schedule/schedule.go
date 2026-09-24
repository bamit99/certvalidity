package schedule

import "time"

const (
	Lifetime398 = 398
	Lifetime200 = 200
	Lifetime100 = 100
	Lifetime47  = 47
)

type cap struct {
	start time.Time
	days  int
}

var caps = []cap{
	{time.Date(2026, time.March, 15, 0, 0, 0, 0, time.UTC), Lifetime200},
	{time.Date(2027, time.March, 15, 0, 0, 0, 0, time.UTC), Lifetime100},
	{time.Date(2029, time.March, 15, 0, 0, 0, 0, time.UTC), Lifetime47},
}

// MaxLifetime returns the maximum certificate validity period, in days,
// allowed by the CA/Browser Forum schedule in force on notBefore.
func MaxLifetime(notBefore time.Time) int {
	days := Lifetime398
	for _, c := range caps {
		if !notBefore.Before(c.start) {
			days = c.days
		}
	}
	return days
}

// DaysLeft returns the whole days between now and notAfter (negative if expired).
func DaysLeft(notAfter, now time.Time) int {
	d := notAfter.Sub(now).Hours() / 24
	if d < 0 {
		return int(d - 1)
	}
	return int(d)
}

// ValidityDays returns the whole days spanned by the certificate's validity.
func ValidityDays(notBefore, notAfter time.Time) int {
	return int(notAfter.Sub(notBefore).Hours()/24) + 1
}
