package utils

import (
	"fmt"
	"time"
)

const (
	// DefaultTimeFormat is the default time format
	DefaultTimeFormat = time.RFC3339

	// DateFormat is the format for dates
	DateFormat = "2006-01-02"

	// TimeFormat is the format for times
	TimeFormat = "15:04:05"

	// DateTimeFormat is the format for date and time
	DateTimeFormat = "2006-01-02 15:04:05"

	// ISO8601Format is the ISO 8601 format
	ISO8601Format = "2006-01-02T15:04:05Z07:00"
)

// Now returns the current time in UTC
func Now() time.Time {
	return time.Now().UTC()
}

// FormatTime formats a time using the default format
func FormatTime(t time.Time) string {
	return t.Format(DefaultTimeFormat)
}

// FormatTimeWithFormat formats a time using the specified format
func FormatTimeWithFormat(t time.Time, format string) string {
	return t.Format(format)
}

// ParseTime parses a time string using the default format
func ParseTime(s string) (time.Time, error) {
	return time.Parse(DefaultTimeFormat, s)
}

// ParseTimeWithFormat parses a time string using the specified format
func ParseTimeWithFormat(s string, format string) (time.Time, error) {
	return time.Parse(format, s)
}

// TimeBetween checks if a time is between two times
func TimeBetween(t, start, end time.Time) bool {
	return (t.Equal(start) || t.After(start)) && (t.Equal(end) || t.Before(end))
}

// StartOfDay returns the start of the day for a given time
func StartOfDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}

// EndOfDay returns the end of the day for a given time
func EndOfDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 999999999, t.Location())
}

// StartOfWeek returns the start of the week for a given time
func StartOfWeek(t time.Time) time.Time {
	weekday := int(t.Weekday())
	if weekday == 0 {
		weekday = 7
	}
	return StartOfDay(t.AddDate(0, 0, -weekday+1))
}

// EndOfWeek returns the end of the week for a given time
func EndOfWeek(t time.Time) time.Time {
	return EndOfDay(StartOfWeek(t).AddDate(0, 0, 6))
}

// StartOfMonth returns the start of the month for a given time
func StartOfMonth(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, t.Location())
}

// EndOfMonth returns the end of the month for a given time
func EndOfMonth(t time.Time) time.Time {
	return EndOfDay(StartOfMonth(t).AddDate(0, 1, -1))
}

// StartOfYear returns the start of the year for a given time
func StartOfYear(t time.Time) time.Time {
	return time.Date(t.Year(), 1, 1, 0, 0, 0, 0, t.Location())
}

// EndOfYear returns the end of the year for a given time
func EndOfYear(t time.Time) time.Time {
	return time.Date(t.Year(), 12, 31, 23, 59, 59, 999999999, t.Location())
}

// Age calculates age from a birth date
func Age(birthDate time.Time) int {
	now := Now()
	years := now.Year() - birthDate.Year()

	// Adjust for months and days
	birthDay := time.Date(now.Year(), birthDate.Month(), birthDate.Day(), 0, 0, 0, 0, time.UTC)
	if now.Before(birthDay) {
		years--
	}

	return years
}

// AddDays adds days to a time
func AddDays(t time.Time, days int) time.Time {
	return t.AddDate(0, 0, days)
}

// AddMonths adds months to a time
func AddMonths(t time.Time, months int) time.Time {
	return t.AddDate(0, months, 0)
}

// AddYears adds years to a time
func AddYears(t time.Time, years int) time.Time {
	return t.AddDate(years, 0, 0)
}

// DaysDiff calculates the difference in days between two times
func DaysDiff(t1, t2 time.Time) int {
	hours := t2.Sub(t1).Hours()
	return int(hours / 24)
}

// MonthsDiff calculates the difference in months between two times
func MonthsDiff(t1, t2 time.Time) int {
	months := (t2.Year()-t1.Year())*12 + int(t2.Month()) - int(t1.Month())

	// Adjust for day of month
	if t2.Day() < t1.Day() {
		months--
	}

	return months
}

// YearsDiff calculates the difference in years between two times
func YearsDiff(t1, t2 time.Time) int {
	years := t2.Year() - t1.Year()

	// Adjust for month and day
	if t2.Month() < t1.Month() || (t2.Month() == t1.Month() && t2.Day() < t1.Day()) {
		years--
	}

	return years
}

// IsWeekend checks if a time is on a weekend
func IsWeekend(t time.Time) bool {
	day := t.Weekday()
	return day == time.Saturday || day == time.Sunday
}

// IsExpired checks if a time has expired
func IsExpired(t time.Time) bool {
	return t.Before(Now())
}

// TimeUntil returns the duration until a future time
func TimeUntil(t time.Time) time.Duration {
	return t.Sub(Now())
}

// TimeSince returns the duration since a past time
func TimeSince(t time.Time) time.Duration {
	return Now().Sub(t)
}

// FormatDuration formats a duration in a human-readable way
func FormatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

// HumanReadableDuration returns a human-readable duration
func HumanReadableDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
	days := int(d.Hours() / 24)
	if days == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", days)
}

// FormatRelativeTime formats a time relative to now
func FormatRelativeTime(t time.Time) string {
	now := Now()
	if t.After(now) {
		d := t.Sub(now)
		if d < time.Minute {
			return "in a few seconds"
		}
		if d < time.Hour {
			return fmt.Sprintf("in %d minutes", int(d.Minutes()))
		}
		if d < 24*time.Hour {
			return fmt.Sprintf("in %d hours", int(d.Hours()))
		}
		days := int(d.Hours() / 24)
		if days == 1 {
			return "tomorrow"
		}
		if days < 7 {
			return fmt.Sprintf("in %d days", days)
		}
		if days < 30 {
			weeks := days / 7
			return fmt.Sprintf("in %d weeks", weeks)
		}
		months := days / 30
		if months == 1 {
			return "in a month"
		}
		if months < 12 {
			return fmt.Sprintf("in %d months", months)
		}
		years := months / 12
		if years == 1 {
			return "in a year"
		}
		return fmt.Sprintf("in %d years", years)
	} else {
		d := now.Sub(t)
		if d < time.Minute {
			return "just now"
		}
		if d < time.Hour {
			return fmt.Sprintf("%d minutes ago", int(d.Minutes()))
		}
		if d < 24*time.Hour {
			return fmt.Sprintf("%d hours ago", int(d.Hours()))
		}
		days := int(d.Hours() / 24)
		if days == 1 {
			return "yesterday"
		}
		if days < 7 {
			return fmt.Sprintf("%d days ago", days)
		}
		if days < 30 {
			weeks := days / 7
			return fmt.Sprintf("%d weeks ago", weeks)
		}
		months := days / 30
		if months == 1 {
			return "a month ago"
		}
		if months < 12 {
			return fmt.Sprintf("%d months ago", months)
		}
		years := months / 12
		if years == 1 {
			return "a year ago"
		}
		return fmt.Sprintf("%d years ago", years)
	}
}

// // FormatDuration formats a time.Duration into a human-readable string
// func FormatDuration(d time.Duration) string {
// 	days := int(d.Hours() / 24)
// 	hours := int(d.Hours()) % 24
// 	minutes := int(d.Minutes()) % 60
// 	seconds := int(d.Seconds()) % 60
//
// 	if days > 0 {
// 		return strconv.FormatInt(int64(time.Duration(days*24+hours)*time.Hour+
// 			time.Duration(minutes)*time.Minute+
// 			time.Duration(seconds)*time.Second), 10)
// 	}
//
// 	if hours > 0 {
// 		return strconv.FormatInt(int64(time.Duration(hours)*time.Hour+
// 			time.Duration(minutes)*time.Minute+
// 			time.Duration(seconds)*time.Second), 10)
// 	}
//
// 	if minutes > 0 {
// 		return strconv.FormatInt(int64(time.Duration(minutes)*time.Minute+
// 			time.Duration(seconds)*time.Second), 10)
// 	}
//
// 	return strconv.FormatInt(int64(time.Duration(seconds)*time.Second), 10)
// }

// ExpiresIn calculates the duration until a time
func ExpiresIn(t time.Time) time.Duration {
	return time.Until(t)
}

// FormatTimeAgo formats a time as a human-readable "time ago" string
func FormatTimeAgo(t time.Time) string {
	duration := time.Since(t)

	seconds := int(duration.Seconds())
	minutes := seconds / 60
	hours := minutes / 60
	days := hours / 24
	months := days / 30
	years := months / 12

	if years > 0 {
		if years == 1 {
			return "1 year ago"
		}
		return time.Now().AddDate(-years, 0, 0).Format("Jan 2006")
	}

	if months > 0 {
		if months == 1 {
			return "1 month ago"
		}
		return time.Now().AddDate(0, -months, 0).Format("Jan 2")
	}

	if days > 0 {
		if days == 1 {
			return "yesterday"
		}
		if days < 7 {
			return time.Now().AddDate(0, 0, -days).Format("Monday")
		}
		return time.Now().AddDate(0, 0, -days).Format("Jan 2")
	}

	if hours > 0 {
		if hours == 1 {
			return "1 hour ago"
		}
		return RoundDuration(time.Duration(hours)*time.Hour).String() + " ago"
	}

	if minutes > 0 {
		if minutes == 1 {
			return "1 minute ago"
		}
		return RoundDuration(time.Duration(minutes)*time.Minute).String() + " ago"
	}

	if seconds > 30 {
		return RoundDuration(time.Duration(seconds)*time.Second).String() + " ago"
	}

	return "just now"
}

// RoundDuration rounds a duration to a human-friendly value
func RoundDuration(d time.Duration) time.Duration {
	switch {
	case d >= 24*time.Hour:
		// Round to days
		return (d / (24 * time.Hour)) * 24 * time.Hour
	case d >= time.Hour:
		// Round to hours
		return (d / time.Hour) * time.Hour
	case d >= time.Minute:
		// Round to minutes
		return (d / time.Minute) * time.Minute
	case d >= time.Second:
		// Round to seconds
		return (d / time.Second) * time.Second
	default:
		// Round to milliseconds
		return (d / time.Millisecond) * time.Millisecond
	}
}

// GetStartOfDay returns the start of the day (midnight) for a given time
func GetStartOfDay(t time.Time) time.Time {
	year, month, day := t.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, t.Location())
}

// GetEndOfDay returns the end of the day (23:59:59.999999999) for a given time
func GetEndOfDay(t time.Time) time.Time {
	year, month, day := t.Date()
	return time.Date(year, month, day, 23, 59, 59, 999999999, t.Location())
}

// GetStartOfWeek returns the start of the week (Sunday midnight) for a given time
func GetStartOfWeek(t time.Time) time.Time {
	// Adjust to get the previous Sunday (or the same day if already Sunday)
	weekday := t.Weekday()
	daysToSunday := int(weekday)
	startOfWeek := t.AddDate(0, 0, -daysToSunday)
	return GetStartOfDay(startOfWeek)
}

// GetEndOfWeek returns the end of the week (Saturday 23:59:59.999999999) for a given time
func GetEndOfWeek(t time.Time) time.Time {
	// Get the start of the week, then add 6 days to get to Saturday
	startOfWeek := GetStartOfWeek(t)
	endOfWeek := startOfWeek.AddDate(0, 0, 6)
	return GetEndOfDay(endOfWeek)
}

// GetStartOfMonth returns the start of the month for a given time
func GetStartOfMonth(t time.Time) time.Time {
	year, month, _ := t.Date()
	return time.Date(year, month, 1, 0, 0, 0, 0, t.Location())
}

// GetEndOfMonth returns the end of the month for a given time
func GetEndOfMonth(t time.Time) time.Time {
	// Get the start of the next month then subtract one nanosecond
	startOfNextMonth := GetStartOfMonth(t).AddDate(0, 1, 0)
	return startOfNextMonth.Add(-time.Nanosecond)
}

// GetStartOfYear returns the start of the year for a given time
func GetStartOfYear(t time.Time) time.Time {
	year, _, _ := t.Date()
	return time.Date(year, 1, 1, 0, 0, 0, 0, t.Location())
}

// GetEndOfYear returns the end of the year for a given time
func GetEndOfYear(t time.Time) time.Time {
	year, _, _ := t.Date()
	return time.Date(year, 12, 31, 23, 59, 59, 999999999, t.Location())
}

// Tomorrow returns the start of the next day
func Tomorrow() time.Time {
	return GetStartOfDay(time.Now().AddDate(0, 0, 1))
}

// Yesterday returns the start of the previous day
func Yesterday() time.Time {
	return GetStartOfDay(time.Now().AddDate(0, 0, -1))
}

// FormatDateTime formats a time according to the specified format or a default format
func FormatDateTime(t time.Time, format string) string {
	if format == "" {
		format = "2006-01-02 15:04:05"
	}
	return t.Format(format)
}

// ParseDateTime parses a string into a time.Time using the specified format
func ParseDateTime(s string, format string) (time.Time, error) {
	if format == "" {
		format = "2006-01-02 15:04:05"
	}
	return time.Parse(format, s)
}

// GetTimeElapsed returns the time elapsed since a time
func GetTimeElapsed(t time.Time) time.Duration {
	return time.Since(t)
}

// GetTimeRemaining returns the time remaining until a time
func GetTimeRemaining(t time.Time) time.Duration {
	return time.Until(t)
}

// Weekday returns whether a time is a weekday
func IsWeekday(t time.Time) bool {
	weekday := t.Weekday()
	return weekday >= time.Monday && weekday <= time.Friday
}
