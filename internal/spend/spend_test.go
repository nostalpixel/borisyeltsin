package spend

import (
	"testing"
	"time"
)

func TestParseMinor(t *testing.T) {
	got, err := ParseMinor("12.5")
	if err != nil || got != 1250 {
		t.Fatalf("%d %v", got, err)
	}
	if FormatMinor(1250) != "12.50" {
		t.Fatal(FormatMinor(1250))
	}
	if _, err := ParseMinor("-1"); err == nil {
		t.Fatal("negative")
	}
}

func TestMonthlyMinor(t *testing.T) {
	if MonthlyMinor(3000, "quarterly", 0) != 1000 {
		t.Fatal("quarter")
	}
	if MonthlyMinor(12000, "annual", 0) != 1000 {
		t.Fatal("year")
	}
	if MonthlyMinor(1000, "monthly", 0) != 1000 {
		t.Fatal("month")
	}
	if MonthlyMinor(1000, "custom", 30) != 1000 {
		t.Fatal("custom")
	}
}

func TestDueLevel(t *testing.T) {
	cases := map[int]string{8: "", 7: "warning", 4: "warning", 3: "danger", 0: "danger", -2: "danger"}
	for days, want := range cases {
		if got := DueLevel(days, true); got != want {
			t.Fatalf("days %d got %s", days, got)
		}
	}
	if DueLevel(0, false) != "" {
		t.Fatal("undated")
	}
}

func TestAlertHorizons(t *testing.T) {
	if len(AlertHorizons(7, true)) != 1 || AlertHorizons(7, true)[0] != 7 {
		t.Fatal("7")
	}
	if AlertHorizons(2, true) != nil {
		t.Fatal("2")
	}
}

func TestDaysUntil(t *testing.T) {
	loc := time.UTC
	renewal := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	today := time.Date(2026, 10, 16, 22, 0, 0, 0, time.UTC)
	if DaysUntil(renewal, today, loc) != 4 {
		t.Fatalf("%d", DaysUntil(renewal, today, loc))
	}
}

func TestNextRenewal(t *testing.T) {
	day := func(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }
	cases := []struct {
		name    string
		renewal time.Time
		cycle   string
		custom  int32
		today   time.Time
		want    time.Time
		moved   bool
	}{
		{"future stays", day(2026, 11, 1), "monthly", 0, day(2026, 10, 19), day(2026, 11, 1), false},
		{"today stays", day(2026, 10, 19), "monthly", 0, day(2026, 10, 19), day(2026, 10, 19), false},
		{"monthly one step", day(2026, 9, 25), "monthly", 0, day(2026, 10, 19), day(2026, 10, 25), true},
		{"monthly many steps", day(2025, 10, 5), "monthly", 0, day(2026, 10, 19), day(2026, 11, 5), true},
		{"month end clamps", day(2026, 1, 31), "monthly", 0, day(2026, 2, 1), day(2026, 2, 28), true},
		{"month end keeps day", day(2026, 1, 31), "monthly", 0, day(2026, 3, 1), day(2026, 3, 31), true},
		{"quarterly", day(2026, 7, 10), "quarterly", 0, day(2026, 10, 19), day(2027, 1, 10), true},
		{"annual leap day", day(2024, 2, 29), "annual", 0, day(2025, 1, 1), day(2025, 2, 28), true},
		{"custom", day(2026, 10, 1), "custom", 10, day(2026, 10, 19), day(2026, 10, 21), true},
		{"custom lands today", day(2026, 10, 9), "custom", 10, day(2026, 10, 19), day(2026, 10, 19), true},
		{"unknown cycle", day(2026, 1, 1), "weekly", 0, day(2026, 10, 19), day(2026, 1, 1), false},
	}
	for _, c := range cases {
		got, moved := NextRenewal(c.renewal, c.cycle, c.custom, c.today)
		if !got.Equal(c.want) || moved != c.moved {
			t.Errorf("%s: got %s %v, want %s %v", c.name, got.Format("2006-01-02"), moved, c.want.Format("2006-01-02"), c.moved)
		}
	}
}

func TestParseMinorRejectsOverflow(t *testing.T) {
	for _, raw := range []string{"92233720368547759", "1000000000001", "99999999999999999.99"} {
		if _, err := ParseMinor(raw); err == nil {
			t.Fatalf("%s accepted", raw)
		}
	}
	if v, err := ParseMinor("1000000000000.00"); err != nil || v != 100000000000000 {
		t.Fatalf("bound: %d %v", v, err)
	}
}
