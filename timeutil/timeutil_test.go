package timeutil

import (
	"testing"
)

func TestValidDates(t *testing.T) {
	for _, s := range []string{"1900-12-31T00:10:20Z", "1900-12-31T001020Z", "19001231T00:10:20Z", "19001231T001020Z"} {
		if ts, err := ParseISO8601Timestamp(s); err != nil {
			t.Errorf("Failed to parse timestamp: %#v %#v\n", s, err)
		} else if ts.Year() != 1900 || ts.Month() != 12 || ts.Day() != 31 || ts.Hour() != 0 || ts.Minute() != 10 || ts.Second() != 20 {
			t.Errorf("Incorrect timestamp value for %#v: expected 1900-12-31T00:10:20Z, got %v", s, ts)
		}
	}

	for _, s := range []string{"1900-12-31", "19001231"} {
		if ts, err := ParseISO8601Timestamp(s); err != nil {
			t.Errorf("Failed to parse timestamp: %#v %#v\n", s, err)
		} else if ts.Year() != 1900 || ts.Month() != 12 || ts.Day() != 31 || ts.Hour() != 0 || ts.Minute() != 0 || ts.Second() != 0 {
			t.Errorf("Incorrect timestamp value for %#v: expected 1900-12-31T00:00:00Z, got %v", s, ts)
		}
	}

	if _, err := ParseISO8601Timestamp("2020-02-17T11:39:27.658731+00:00"); err != nil {
		t.Errorf("Failed to parse timestamp: %#v %#v\n", "2020-02-17T11:39:27.658731+00:00", err)
	}
}
