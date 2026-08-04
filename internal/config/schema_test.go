package config

import "testing"

func TestLoadSchemaCompilesTheEmbeddedSchema(t *testing.T) {
	if _, err := loadSchema(); err != nil {
		t.Fatalf("embedded configuration schema must compile: %v", err)
	}
}

func TestValidateStrictRFC3339RejectsLenientForms(t *testing.T) {
	for name, value := range map[string]string{
		"out-of-range offset minute": "2026-01-01T00:00:00+00:60",
		"out-of-range offset hour":   "2026-01-01T00:00:00+24:00",
		"comma fractional separator": "2026-01-01T00:00:00,000Z",
		"lowercase T and Z":          "2026-01-01t00:00:00z",
		"leap second":                "2016-12-31T23:59:60Z",
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateStrictRFC3339(value); err == nil {
				t.Fatalf("validateStrictRFC3339(%q) = nil, want an error", value)
			}
		})
	}
}

func TestValidateStrictRFC3339AcceptsValidForms(t *testing.T) {
	for name, value := range map[string]string{
		"basic":                      "2026-06-15T12:30:00Z",
		"fractional with offset":     "2026-01-01T00:00:00.5+05:30",
		"fraction beyond nanosecond": "2026-01-01T00:00:00.1234567890123Z",
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateStrictRFC3339(value); err != nil {
				t.Fatalf("validateStrictRFC3339(%q) = %v, want no error", value, err)
			}
		})
	}
}

func TestValidateStrictRFC3339RejectsInvalidCalendarDate(t *testing.T) {
	for name, value := range map[string]string{
		"February 30th":                "2026-02-30T00:00:00Z",
		"April 31st":                   "2026-04-31T00:00:00Z",
		"February 29th, non-leap year": "2023-02-29T00:00:00Z",
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateStrictRFC3339(value); err == nil {
				t.Fatalf("validateStrictRFC3339(%q) = nil, want an error: this calendar date does not exist", value)
			}
		})
	}
	if err := validateStrictRFC3339("2024-02-29T00:00:00Z"); err != nil {
		t.Fatalf("validateStrictRFC3339() = %v, want no error for a valid leap-year date", err)
	}
}

func TestValidateStrictRFC3339IgnoresNonStringValues(t *testing.T) {
	// The compiler only invokes a format validator when the instance is
	// already the type "string" requires; this documents that a non-string
	// value passed directly is not itself a format violation.
	if err := validateStrictRFC3339(true); err != nil {
		t.Fatalf("validateStrictRFC3339(true) = %v, want nil for a non-string value", err)
	}
}
