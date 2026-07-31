package config

import "testing"

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

func TestAuditSchemaSupportAcceptsTheEmbeddedSchema(t *testing.T) {
	schema, err := loadSchema()
	if err != nil {
		t.Fatal(err)
	}
	if err := auditSchemaSupport(schema); err != nil {
		t.Fatalf("embedded configuration schema must pass its own support audit: %v", err)
	}
}
