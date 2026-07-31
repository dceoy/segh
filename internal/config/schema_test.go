package config

import (
	"encoding/json"
	"testing"
)

func TestAuditSchemaSupportRejectsUnsupportedKeyword(t *testing.T) {
	schema := map[string]any{
		"type":       "object",
		"properties": map[string]any{},
		"oneOf":      []any{},
	}
	if err := auditSchemaSupport(schema); err == nil {
		t.Fatal("want an error for an unsupported top-level keyword")
	}
}

func TestAuditSchemaSupportRejectsUnsupportedKeywordInUnexercisedBranch(t *testing.T) {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"rarely_set": map[string]any{
				"type":  "string",
				"oneOf": []any{},
			},
		},
	}
	if err := auditSchemaSupport(schema); err == nil {
		t.Fatal("want an error for an unsupported keyword nested under properties, even though no instance reaches it")
	}
}

func TestAuditSchemaSupportRejectsUnsupportedTypeArrayForm(t *testing.T) {
	schema := map[string]any{"type": []any{"string", "null"}}
	if err := auditSchemaSupport(schema); err == nil {
		t.Fatal("want an error for the array form of \"type\", which schemaValidator cannot enforce")
	}
}

func TestAuditSchemaSupportRejectsUnsupportedItemsTupleForm(t *testing.T) {
	schema := map[string]any{"type": "array", "items": []any{map[string]any{"type": "string"}}}
	if err := auditSchemaSupport(schema); err == nil {
		t.Fatal("want an error for the tuple form of \"items\", which schemaValidator cannot enforce")
	}
}

func TestAuditSchemaSupportRejectsNonStringRequiredEntries(t *testing.T) {
	schema := map[string]any{"type": "object", "required": []any{"name", 1}}
	if err := auditSchemaSupport(schema); err == nil {
		t.Fatal("want an error when \"required\" contains a non-string entry")
	}
}

func TestAuditSchemaSupportWalksDefsItemsNotAnyOfAndAdditionalProperties(t *testing.T) {
	for name, schema := range map[string]map[string]any{
		"$defs":                {"$defs": map[string]any{"broken": map[string]any{"oneOf": []any{}}}},
		"items":                {"type": "array", "items": map[string]any{"oneOf": []any{}}},
		"not":                  {"not": map[string]any{"oneOf": []any{}}},
		"anyOf":                {"anyOf": []any{map[string]any{"oneOf": []any{}}}},
		"additionalProperties": {"additionalProperties": map[string]any{"oneOf": []any{}}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := auditSchemaSupport(schema); err == nil {
				t.Fatalf("want an unsupported-keyword error reachable through %q", name)
			}
		})
	}
}

func TestAuditSchemaSupportRejectsUnresolvedRefInUnexercisedBranch(t *testing.T) {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"rarely_set": map[string]any{"$ref": "#/$defs/missing"},
		},
		"$defs": map[string]any{
			"present": map[string]any{"type": "string"},
		},
	}
	if err := auditSchemaSupport(schema); err == nil {
		t.Fatal("want an error for a $ref that does not resolve, even under a property no instance exercises")
	}
}

func TestAuditSchemaSupportRejectsExternalRef(t *testing.T) {
	schema := map[string]any{"$ref": "https://example.test/other.schema.json#/def"}
	if err := auditSchemaSupport(schema); err == nil {
		t.Fatal("want an error for a non-local schema reference")
	}
}

func TestAuditSchemaSupportRejectsRefCycle(t *testing.T) {
	schema := map[string]any{
		"$defs": map[string]any{
			"a": map[string]any{"$ref": "#/$defs/b"},
			"b": map[string]any{"$ref": "#/$defs/a"},
		},
	}
	if err := auditSchemaSupport(schema); err == nil {
		t.Fatal("want an error for a $ref cycle that would recurse forever on an unchanged value")
	}
}

func TestAuditSchemaSupportRejectsRefCycleThroughProperties(t *testing.T) {
	schema := map[string]any{
		"$ref": "#/$defs/node",
		"$defs": map[string]any{
			"node": map[string]any{
				"type":       "object",
				"properties": map[string]any{"child": map[string]any{"$ref": "#/$defs/node"}},
			},
		},
	}
	if err := auditSchemaSupport(schema); err == nil {
		t.Fatal("want an error: this audit has no instance to bound recursion, so a self-referential schema reached through properties must still be rejected as a cycle")
	}
}

func TestAuditSchemaSupportAllowsSharedDefsReferencedFromSiblingProperties(t *testing.T) {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"a": map[string]any{"$ref": "#/$defs/dur"},
			"b": map[string]any{"$ref": "#/$defs/dur"},
		},
		"$defs": map[string]any{"dur": map[string]any{"type": "string"}},
	}
	if err := auditSchemaSupport(schema); err != nil {
		t.Fatalf("reusing the same $defs entry from independent sibling properties must not be treated as a cycle: %v", err)
	}
}

func TestAuditSchemaSupportAllowsAnnotationKeywords(t *testing.T) {
	schema := map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"$id":     "https://example.test/schema",
		"title":   "example", "description": "example", "$comment": "example",
		"type": "string", "default": "x", "examples": []any{"x"},
		"deprecated": false, "readOnly": false, "writeOnly": false,
	}
	if err := auditSchemaSupport(schema); err != nil {
		t.Fatalf("annotation keywords must not be treated as unsupported: %v", err)
	}
}

func TestAuditSchemaSupportRejectsUnsupportedFormatInUnexercisedBranch(t *testing.T) {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"rarely_set": map[string]any{"type": "string", "format": "email"},
		},
	}
	if err := auditSchemaSupport(schema); err == nil {
		t.Fatal("want an error for a format value validateScalar does not enforce, even under a property no instance exercises")
	}
}

func TestAuditSchemaSupportAcceptsTheEmbeddedSchema(t *testing.T) {
	schema, err := loadSchema()
	if err != nil {
		t.Fatal(err)
	}
	if err := auditSchemaSupport(schema); err != nil {
		t.Fatalf("embedded configuration schema must pass its own support audit: %v", err)
	}
}

func TestValidateScalarRejectsLenientRFC3339Forms(t *testing.T) {
	schema := map[string]any{"type": "string", "format": "date-time"}
	for name, value := range map[string]string{
		"out-of-range offset minute": "2026-01-01T00:00:00+00:60",
		"out-of-range offset hour":   "2026-01-01T00:00:00+24:00",
		"comma fractional separator": "2026-01-01T00:00:00,000Z",
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateScalar(schema, value, "configuration.example"); err == nil {
				t.Fatalf("validateScalar(%q) = nil, want an error: time.Parse(time.RFC3339, ...) accepts this even though it is not valid RFC 3339", value)
			}
		})
	}
	if err := validateScalar(schema, "2026-01-01T00:00:00.5+05:30", "configuration.example"); err != nil {
		t.Fatalf("validateScalar() = %v, want no error for a valid RFC 3339 date-time", err)
	}
}

func TestValidateScalarRejectsUnrepresentableRFC3339Forms(t *testing.T) {
	// RFC 3339 permits a case-insensitive "T"/"Z" and a leap second, but the
	// "expires" value decodes into a *time.Time, which time.Parse parses
	// case-sensitively and which cannot represent a leap second at all,
	// erroring with "second out of range". Accepting these here would let
	// them pass the schema's format check only to fail later, with a worse
	// error, at the typed-config decode.
	schema := map[string]any{"type": "string", "format": "date-time"}
	for name, value := range map[string]string{
		"lowercase T and Z": "2026-01-01t00:00:00z",
		"leap second":       "2016-12-31T23:59:60Z",
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateScalar(schema, value, "configuration.example"); err == nil {
				t.Fatalf("validateScalar(%q) = nil, want an error: this cannot decode into a time.Time", value)
			}
		})
	}
}

func TestValidateScalarRejectsInvalidCalendarDate(t *testing.T) {
	schema := map[string]any{"type": "string", "format": "date-time"}
	for name, value := range map[string]string{
		"February 30th":                "2026-02-30T00:00:00Z",
		"April 31st":                   "2026-04-31T00:00:00Z",
		"February 29th, non-leap year": "2023-02-29T00:00:00Z",
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateScalar(schema, value, "configuration.example"); err == nil {
				t.Fatalf("validateScalar(%q) = nil, want an error: this calendar date does not exist", value)
			}
		})
	}
	if err := validateScalar(schema, "2024-02-29T00:00:00Z", "configuration.example"); err != nil {
		t.Fatalf("validateScalar() = %v, want no error for a valid leap-year date", err)
	}
}

func TestValidateEnforcesConstraintsAlongsideRef(t *testing.T) {
	root := map[string]any{
		"$defs": map[string]any{
			"stringArray": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		},
	}
	schema := map[string]any{"$ref": "#/$defs/stringArray", "minItems": json.Number("1")}
	validator := &schemaValidator{root: root}
	if err := validator.validate(schema, []any{}, "configuration.example"); err == nil {
		t.Fatal("want an error: minItems alongside $ref must still be enforced against the resolved target")
	}
	if err := validator.validate(schema, []any{"x"}, "configuration.example"); err != nil {
		t.Fatalf("validate() = %v, want no error for a value satisfying both $ref and minItems", err)
	}
}
