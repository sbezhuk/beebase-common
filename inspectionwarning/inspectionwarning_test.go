package inspectionwarning_test

import (
	"testing"
	"time"

	"github.com/sbezhuk/beebase-common/inspectionwarning"
)

func fixedNow() time.Time {
	return time.Date(2026, 3, 18, 15, 30, 0, 0, time.UTC)
}

func daysAgo(now time.Time, days int) time.Time {
	return now.AddDate(0, 0, -days)
}

func TestNeedsInspection_NeverInspected(t *testing.T) {
	if !inspectionwarning.NeedsInspection(nil, inspectionwarning.DefaultThresholdDays, fixedNow()) {
		t.Error("NeedsInspection(nil, ...) = false, want true (never inspected always needs inspection)")
	}
}

func TestNeedsInspection_InspectedToday(t *testing.T) {
	now := fixedNow()
	latest := now
	if inspectionwarning.NeedsInspection(&latest, 14, now) {
		t.Error("NeedsInspection(today, 14, now) = true, want false")
	}
}

func TestNeedsInspection_InspectedSevenDaysAgo(t *testing.T) {
	now := fixedNow()
	latest := daysAgo(now, 7)
	if inspectionwarning.NeedsInspection(&latest, 14, now) {
		t.Error("NeedsInspection(7 days ago, 14, now) = true, want false")
	}
}

func TestNeedsInspection_InspectedExactlyAtThreshold(t *testing.T) {
	now := fixedNow()
	latest := daysAgo(now, 14)
	if inspectionwarning.NeedsInspection(&latest, 14, now) {
		t.Error("NeedsInspection(exactly 14 days ago, 14, now) = true, want false (boundary is OK)")
	}
}

func TestNeedsInspection_InspectedPastThreshold(t *testing.T) {
	now := fixedNow()
	latest := daysAgo(now, 15)
	if !inspectionwarning.NeedsInspection(&latest, 14, now) {
		t.Error("NeedsInspection(15 days ago, 14, now) = false, want true")
	}
}

func TestNeedsInspection_ComparisonIsDateBasedNotTimeOfDay(t *testing.T) {
	// "Exactly 14 days ago" but at a much earlier time of day than now -
	// still the same calendar-day difference, so still OK. This is the
	// scenario a naive time.Sub/Hours-based check (rather than
	// date-truncated) would get wrong depending on time of day.
	now := time.Date(2026, 3, 18, 23, 59, 0, 0, time.UTC)
	latest := time.Date(2026, 3, 4, 0, 1, 0, 0, time.UTC) // 14 calendar days earlier
	if inspectionwarning.NeedsInspection(&latest, 14, now) {
		t.Error("NeedsInspection should compare calendar dates, not exact hours - got true, want false")
	}

	// Conversely, a hive inspected late yesterday but "now" is early
	// today should count as 1 day since, not 0, regardless of the
	// narrow wall-clock gap.
	now2 := time.Date(2026, 3, 18, 0, 5, 0, 0, time.UTC)
	latest2 := time.Date(2026, 3, 17, 23, 55, 0, 0, time.UTC)
	if inspectionwarning.NeedsInspection(&latest2, 0, now2) == false {
		t.Error("NeedsInspection with threshold 0 across a calendar-day boundary should need inspection")
	}
}

func TestNeedsInspection_ConfiguredThresholdIsUsed(t *testing.T) {
	now := fixedNow()
	latest := daysAgo(now, 10)

	if !inspectionwarning.NeedsInspection(&latest, 5, now) {
		t.Error("with a configured threshold of 5 days, 10 days ago should need inspection")
	}
	if inspectionwarning.NeedsInspection(&latest, 30, now) {
		t.Error("with a configured threshold of 30 days, 10 days ago should still be OK")
	}
}

func TestNeedsInspection_DefaultThresholdIsFourteenDays(t *testing.T) {
	if inspectionwarning.DefaultThresholdDays != 14 {
		t.Errorf("DefaultThresholdDays = %d, want 14", inspectionwarning.DefaultThresholdDays)
	}
}
