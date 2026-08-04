package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	configschema "github.com/dceoy/segh/schema"
)

// schemaResourceURL is an arbitrary, never-dereferenced identifier for the
// embedded schema document; AddResource registers it in-memory so Compile
// never performs network or filesystem I/O.
const schemaResourceURL = "segh-config-v5.schema.json"

var loadSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	// Overrides the built-in "date-time" format, which accepts a
	// lowercase "t"/"z" designator and a leap second - both valid RFC
	// 3339 but neither representable by the *time.Time the "expires"
	// value ultimately becomes. See rfc3339Pattern.
	compiler.RegisterFormat(&jsonschema.Format{Name: "date-time", Validate: validateStrictRFC3339})
	var document any
	if err := json.Unmarshal([]byte(configschema.ConfigV5()), &document); err != nil {
		return nil, fmt.Errorf("decode embedded configuration schema: %w", err)
	}
	if err := compiler.AddResource(schemaResourceURL, document); err != nil {
		return nil, fmt.Errorf("add embedded configuration schema resource: %w", err)
	}
	schema, err := compiler.Compile(schemaResourceURL)
	if err != nil {
		return nil, fmt.Errorf("compile embedded configuration schema: %w", err)
	}
	return schema, nil
})

func validateConfigDocument(document any) error {
	data, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("convert YAML to JSON-compatible data: %w", err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("decode JSON-compatible configuration: %w", err)
	}
	schema, err := loadSchema()
	if err != nil {
		return err
	}
	if err := schema.Validate(instance); err != nil {
		return fmt.Errorf("configuration does not match schema: %w", err)
	}
	return nil
}

// rfc3339Pattern enforces a deliberately narrower profile than raw RFC 3339,
// chosen to match exactly what decodes into the *time.Time the "expires"
// value ultimately becomes: it rejects an out-of-range zone-offset hour or
// minute (for example "+24:00" or "+00:60") and a comma fractional-second
// separator, which time.Parse(time.RFC3339, ...) wrongly accepts; and, since
// Go's time.Time has no representation for a leap second and time.Parse
// rejects one ("second out of range") while also being case-sensitive about
// "T"/"Z", this pattern requires uppercase "T"/"Z" and disallows a leap
// second (":60") outright rather than accepting a grammar the value can
// never actually round-trip through. Loosening this to accept the full RFC
// 3339 profile would let a value pass the schema's format check here only to
// fail later, with a worse error, at the typed-config decode.
var rfc3339Pattern = regexp.MustCompile(
	`^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])` +
		`T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?` +
		`(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$`,
)

func validateStrictRFC3339(v any) error {
	text, ok := v.(string)
	if !ok {
		return nil
	}
	if !rfc3339Pattern.MatchString(text) {
		return fmt.Errorf("must be an RFC 3339 date-time")
	}
	if _, err := time.Parse(time.RFC3339, text); err != nil {
		return fmt.Errorf("must be an RFC 3339 date-time")
	}
	return nil
}
