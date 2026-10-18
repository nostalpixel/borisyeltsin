// Package spend converts billing cycles and payment dates into dashboard numbers.
package spend

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// maxWhole is the largest whole amount accepted: one trillion.
const maxWhole = 1_000_000_000_000

// ParseMinor converts a decimal string with at most two fraction digits into minor units.
func ParseMinor(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "-") {
		return 0, fmt.Errorf("invalid amount")
	}
	parts := strings.Split(raw, ".")
	if len(parts) > 2 || parts[0] == "" {
		return 0, fmt.Errorf("invalid amount")
	}
	whole, err := strconv.ParseInt(parts[0], 10, 64)
	// The bound keeps whole*100 and monthly sums far from int64 overflow.
	if err != nil || whole > maxWhole {
		return 0, fmt.Errorf("invalid amount")
	}
	frac := int64(0)
	if len(parts) == 2 {
		fraction := parts[1]
		if len(fraction) > 2 {
			return 0, fmt.Errorf("invalid amount")
		}
		for len(fraction) < 2 {
			fraction += "0"
		}
		frac, err = strconv.ParseInt(fraction, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid amount")
		}
	}
	return whole*100 + frac, nil
}

// FormatMinor renders minor units as a decimal string.
func FormatMinor(value int64) string {
	sign := ""
	if value < 0 {
		sign = "-"
		value = -value
	}
	return fmt.Sprintf("%s%d.%02d", sign, value/100, value%100)
}

// MonthlyMinor is the monthly equivalent of a subscription cost, in minor units.
func MonthlyMinor(cost int64, cycle string, customDays int32) int64 {
	switch cycle {
	case "monthly":
		return cost
	case "quarterly":
		return divRound(cost, 3)
	case "annual":
		return divRound(cost, 12)
	case "custom":
		if customDays <= 0 {
			return 0
		}
		return cost * 30 / int64(customDays)
	default:
		return 0
	}
}

func divRound(cost, parts int64) int64 {
	if cost < 0 || parts <= 0 {
		return 0
	}
	return (cost + parts/2) / parts
}

// DaysUntil returns whole days from today to the renewal date.
// Both instants are interpreted as civil dates in loc.
func DaysUntil(renewal, today time.Time, loc *time.Location) int {
	if loc == nil {
		loc = time.UTC
	}
	r := dateOnly(renewal, loc)
	t := dateOnly(today, loc)
	return int(r.Sub(t).Hours() / 24)
}

func dateOnly(ts time.Time, loc *time.Location) time.Time {
	y, m, d := ts.In(loc).Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// DueLevel matches the reference ledger: 4–7 days is warning, 3 or fewer
// (including overdue) is danger.
func DueLevel(days int, dated bool) string {
	if !dated {
		return ""
	}
	if days <= 3 {
		return "danger"
	}
	if days <= 7 {
		return "warning"
	}
	return ""
}

// AlertHorizons lists the day marks that create a stored renewal alert.
func AlertHorizons(days int, dated bool) []int {
	if !dated {
		return nil
	}
	var out []int
	for _, horizon := range []int{7, 3, 1} {
		if days == horizon {
			out = append(out, horizon)
		}
	}
	return out
}

// NextRenewal moves a past renewal date forward by whole billing cycles to
// the first date on or after today. Month steps count from the original date
// and clamp to the month's last day, so Jan 31 renews Feb 28, then Mar 31.
// Both arguments are civil dates (midnight UTC); ok is false when nothing
// moved or the cycle is unknown.
func NextRenewal(renewal time.Time, cycle string, customDays int32, today time.Time) (time.Time, bool) {
	if !renewal.Before(today) {
		return renewal, false
	}
	months := map[string]int{"monthly": 1, "quarterly": 3, "annual": 12}[cycle]
	if cycle == "custom" {
		if customDays <= 0 {
			return renewal, false
		}
		gap := int(today.Sub(renewal).Hours() / 24)
		steps := (gap + int(customDays) - 1) / int(customDays)
		return renewal.AddDate(0, 0, steps*int(customDays)), true
	}
	if months == 0 {
		return renewal, false
	}
	for k := 1; ; k++ {
		next := addMonthsClamped(renewal, k*months)
		if !next.Before(today) {
			return next, true
		}
	}
}

func addMonthsClamped(date time.Time, months int) time.Time {
	y, m, d := date.Date()
	first := time.Date(y, m+time.Month(months), 1, 0, 0, 0, 0, time.UTC)
	last := first.AddDate(0, 1, -1).Day()
	if d > last {
		d = last
	}
	return time.Date(first.Year(), first.Month(), d, 0, 0, 0, 0, time.UTC)
}

// Today returns now as a civil date in loc, at midnight UTC like a Postgres date.
func Today(now time.Time, loc *time.Location) time.Time {
	if loc == nil {
		loc = time.UTC
	}
	return dateOnly(now, loc)
}
