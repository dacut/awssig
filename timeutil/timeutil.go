package timeutil

import (
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/palantir/stacktrace"
)

// ISO8601CompactFormat is a layout for time.Format that prints a time value
// in the most compact ISO8601 format available. This assumes the time value
// is in UTC, and returns the time zone as 'Z'.
const ISO8601CompactFormat = "20060102T150405Z"

var iso8601Variants [6]*regexp.Regexp

func init() {
	iso8601Variants[0] = regexp.MustCompile(`^([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])[Tt ]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|6[01])(?:[.,]([0-9]{1,9}))?(Z|[-+][01][0-9]:?(?:[0-5][0-9])?)$`)
	iso8601Variants[1] = regexp.MustCompile(`^([0-9]{4})(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])[Tt ]([01][0-9]|2[0-3])([0-5][0-9])([0-5][0-9]|6[01])(?:[.,]([0-9]{1,9}))?(Z|[-+][01][0-9]:?(?:[0-5][0-9])?)$`)
	iso8601Variants[2] = regexp.MustCompile(`^([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])[Tt ]([01][0-9]|2[0-3])([0-5][0-9])([0-5][0-9]|6[01])(?:[.,]([0-9]{1,9}))?(Z|[-+][01][0-9]:?(?:[0-5][0-9])?)$`)
	iso8601Variants[3] = regexp.MustCompile(`^([0-9]{4})(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])[Tt ]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|6[01])(?:[.,]([0-9]{1,9}))?(Z|[-+][01][0-9]:?(?:[0-5][0-9])?)$`)
	iso8601Variants[4] = regexp.MustCompile(`^([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$`)
	iso8601Variants[5] = regexp.MustCompile(`^([0-9]{4})(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])$`)
}

func atoip(s string) int {
	if value, err := strconv.Atoi(s); err != nil {
		panic(fmt.Sprintf("Failed to convert %#v to int", s))
	} else {
		return int(value)
	}
}

// ParseISO8601Timestamp converts an ISO 8601 timestamp into a time.Time
// result. Compared to time.Parse(time.RFC3339) and
// time.Parse(time.RFC3339Nano), this accepts the full range of ISO 8601
// formats and the RFC 3339 variants.
func ParseISO8601Timestamp(s string) (time.Time, error) {
	for _, re := range iso8601Variants {
		if re.MatchString(s) {
			var year, day, hour, minute, second, nanosecs int
			var month time.Month
			var fracSecStr, tzStr string

			parts := re.FindStringSubmatch(s)
			year = atoip(parts[1])
			month = time.Month(atoip(parts[2]))
			day = atoip(parts[3])
			nanosecs = 0

			if len(parts) > 4 {
				hour = atoip(parts[4])
				minute = atoip(parts[5])
				second = atoip(parts[6])
				fracSecStr = parts[7]

				if fracSecStr != "" {
					for len(fracSecStr) < 9 {
						fracSecStr = fracSecStr + "0"
					}

					nanosecs = atoip(fracSecStr)
				}
			}

			var loc *time.Location

			if len(parts) > 4 {
				tzStr = parts[8]
			} else {
				tzStr = "Z"
			}

			if tzStr == "Z" {
				loc = time.UTC
			} else {
				signStr := tzStr[0]
				sign := 1
				if signStr == '-' {
					sign = -1
				}

				tzHour := atoip(tzStr[1:3])
				var tzMin int

				if tzStr[3] == ':' {
					tzMin = atoip(tzStr[4:6])
				} else {
					tzMin = atoip(tzStr[3:5])
				}

				loc = time.FixedZone(
					fmt.Sprintf("%c%02d:%02d", signStr, tzHour, tzMin),
					sign*(tzHour*3600+tzMin*60))
			}

			return time.Date(year, month, day, hour, minute, second, nanosecs, loc), nil
		}
	}

	return time.Time{}, stacktrace.NewError("Invalid ISO 8601 timestamp: %#v", s)
}
