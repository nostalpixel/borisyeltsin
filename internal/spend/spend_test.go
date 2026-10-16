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
