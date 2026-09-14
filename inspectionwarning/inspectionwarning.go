// Package inspectionwarning holds the single, shared definition of
// BeeBase's "needs inspection" business rule - a hive needs inspection
// when it has never been inspected, or when its latest inspection is
// older than the configured warning threshold - so every service that
// applies this rule (inspection-service, which owns the configured
// threshold and the raw inspection dates; hive-service, which filters
// hive listings by it; statistics-service, which reports it on the
// Dashboard) computes exactly the same answer for the same inputs.
//
// This package is deliberately tiny and pure: no I/O, no configuration
// loading. Each service still reads its own INSPECTION_WARNING_THRESHOLD_DAYS
// (or receives the threshold from whichever service is authoritative for
// it - see each service's own docs) and passes the resulting int in here;
// this package only owns the default value and the comparison itself.
package inspectionwarning

import "time"

// DefaultThresholdDays is the number of days after a hive's latest
// inspection (or, if it has none, always) that it's considered to need
// inspection, used whenever no configuration value overrides it.
const DefaultThresholdDays = 14

// NeedsInspection reports whether a hive needs inspection, given the date
// of its latest inspection (nil if it has never been inspected), the
// warning threshold in days, and the current time.
//
// The comparison is date-based (UTC calendar dates), not sensitive to
// time-of-day: a hive inspected exactly thresholdDays ago is still OK,
// so the result doesn't unexpectedly flip depending on what time of day
// "now" happens to be.
func NeedsInspection(latestInspectedAt *time.Time, thresholdDays int, now time.Time) bool {
	if latestInspectedAt == nil {
		return true
	}
	daysSince := dateOnly(now).Sub(dateOnly(*latestInspectedAt)) / (24 * time.Hour)
	return int(daysSince) > thresholdDays
}

// dateOnly truncates t to its UTC calendar date, at midnight.
func dateOnly(t time.Time) time.Time {
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
}
