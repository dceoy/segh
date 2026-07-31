package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	configschema "github.com/dceoy/segh/schema"
)

var loadSchema = sync.OnceValues(func() (map[string]any, error) {
	var schema map[string]any
	decoder := json.NewDecoder(strings.NewReader(configschema.ConfigV4()))
	decoder.UseNumber()
	if err := decoder.Decode(&schema); err != nil {
		return nil, fmt.Errorf("decode embedded configuration schema: %w", err)
	}
	if err := auditSchemaSupport(schema); err != nil {
		return nil, fmt.Errorf("embedded configuration schema uses an unsupported construct: %w", err)
	}
	return schema, nil
})

// supportedSchemaKeywords lists every JSON Schema keyword schemaValidator
// understands, plus the draft 2020-12 annotation keywords that never
// constrain an instance and so are always safe to ignore.
var supportedSchemaKeywords = map[string]bool{
	"$schema": true, "$id": true, "$defs": true,
	"title": true, "description": true, "$comment": true,
	"default": true, "examples": true, "deprecated": true,
	"readOnly": true, "writeOnly": true,

	"$ref": true, "not": true, "type": true, "const": true, "enum": true,
	"properties": true, "additionalProperties": true, "required": true,
	"items": true, "minItems": true, "uniqueItems": true,
	"minLength": true, "pattern": true, "format": true,
	"minimum": true, "maximum": true, "anyOf": true,
}

// auditSchemaSupport walks every schema node reachable through properties,
// $defs, items, not, anyOf, and additionalProperties, independent of any
// configuration instance. schemaValidator implements only a subset of JSON
// Schema, so this fails closed at load time when the embedded schema uses a
// keyword, or a keyword shape, it does not enforce. Without this audit, a
// future schema change could add a constraint that validate silently
// ignores only for instances that happen to exercise the affected branch,
// letting the published schema and runtime validation quietly diverge.
func auditSchemaSupport(schema map[string]any) error {
	for keyword := range schema {
		if !supportedSchemaKeywords[keyword] {
			return fmt.Errorf("schema keyword %q is not supported", keyword)
		}
	}
	if ref, present := schema["$ref"]; present {
		if _, ok := ref.(string); !ok {
			return fmt.Errorf(`schema keyword "$ref" must be a string`)
		}
	}
	if typ, present := schema["type"]; present {
		if _, ok := typ.(string); !ok {
			return fmt.Errorf(`schema keyword "type" must be a string`)
		}
	}
	if not, present := schema["not"]; present {
		object, ok := not.(map[string]any)
		if !ok {
			return fmt.Errorf(`schema keyword "not" must be an object`)
		}
		if err := auditSchemaSupport(object); err != nil {
			return err
		}
	}
	if enum, present := schema["enum"]; present {
		if _, ok := enum.([]any); !ok {
			return fmt.Errorf(`schema keyword "enum" must be an array`)
		}
	}
	if properties, present := schema["properties"]; present {
		object, ok := properties.(map[string]any)
		if !ok {
			return fmt.Errorf(`schema keyword "properties" must be an object`)
		}
		for name, raw := range object {
			propertySchema, ok := raw.(map[string]any)
			if !ok {
				return fmt.Errorf("schema property %q must be an object", name)
			}
			if err := auditSchemaSupport(propertySchema); err != nil {
				return err
			}
		}
	}
	if additional, present := schema["additionalProperties"]; present {
		switch typed := additional.(type) {
		case bool:
		case map[string]any:
			if err := auditSchemaSupport(typed); err != nil {
				return err
			}
		default:
			return fmt.Errorf(`schema keyword "additionalProperties" must be a boolean or an object`)
		}
	}
	if required, present := schema["required"]; present {
		items, ok := required.([]any)
		if !ok {
			return fmt.Errorf(`schema keyword "required" must be an array`)
		}
		for _, item := range items {
			if _, ok := item.(string); !ok {
				return fmt.Errorf(`schema keyword "required" must contain only strings`)
			}
		}
	}
	if items, present := schema["items"]; present {
		object, ok := items.(map[string]any)
		if !ok {
			return fmt.Errorf(`schema keyword "items" must be an object`)
		}
		if err := auditSchemaSupport(object); err != nil {
			return err
		}
	}
	if minItems, present := schema["minItems"]; present {
		if _, ok := integerKeyword(minItems); !ok {
			return fmt.Errorf(`schema keyword "minItems" must be an integer`)
		}
	}
	if uniqueItems, present := schema["uniqueItems"]; present {
		if _, ok := uniqueItems.(bool); !ok {
			return fmt.Errorf(`schema keyword "uniqueItems" must be a boolean`)
		}
	}
	if minLength, present := schema["minLength"]; present {
		if _, ok := integerKeyword(minLength); !ok {
			return fmt.Errorf(`schema keyword "minLength" must be an integer`)
		}
	}
	if pattern, present := schema["pattern"]; present {
		text, ok := pattern.(string)
		if !ok {
			return fmt.Errorf(`schema keyword "pattern" must be a string`)
		}
		if _, err := regexp.Compile(text); err != nil {
			return fmt.Errorf("compile schema pattern: %w", err)
		}
	}
	if format, present := schema["format"]; present {
		if _, ok := format.(string); !ok {
			return fmt.Errorf(`schema keyword "format" must be a string`)
		}
	}
	if minimum, present := schema["minimum"]; present {
		if _, ok := numberKeyword(minimum); !ok {
			return fmt.Errorf(`schema keyword "minimum" must be numeric`)
		}
	}
	if maximum, present := schema["maximum"]; present {
		if _, ok := numberKeyword(maximum); !ok {
			return fmt.Errorf(`schema keyword "maximum" must be numeric`)
		}
	}
	if anyOf, present := schema["anyOf"]; present {
		alternatives, ok := anyOf.([]any)
		if !ok {
			return fmt.Errorf(`schema keyword "anyOf" must be an array`)
		}
		for _, raw := range alternatives {
			alternative, ok := raw.(map[string]any)
			if !ok {
				return fmt.Errorf(`schema keyword "anyOf" must contain only objects`)
			}
			if err := auditSchemaSupport(alternative); err != nil {
				return err
			}
		}
	}
	if defs, present := schema["$defs"]; present {
		object, ok := defs.(map[string]any)
		if !ok {
			return fmt.Errorf(`schema keyword "$defs" must be an object`)
		}
		for name, raw := range object {
			definition, ok := raw.(map[string]any)
			if !ok {
				return fmt.Errorf("schema definition %q must be an object", name)
			}
			if err := auditSchemaSupport(definition); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateConfigDocument(document any) error {
	data, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("convert YAML to JSON-compatible data: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var instance any
	if err := decoder.Decode(&instance); err != nil {
		return fmt.Errorf("decode JSON-compatible configuration: %w", err)
	}
	root, err := loadSchema()
	if err != nil {
		return err
	}
	if err := (&schemaValidator{root: root}).validate(root, instance, "configuration"); err != nil {
		return fmt.Errorf("configuration does not match schema: %w", err)
	}
	return nil
}

// schemaValidator implements only the draft 2020-12 keywords used by the
// embedded segh schema. Keeping this focused avoids a runtime dependency while
// still making the published schema the single structural source of truth.
type schemaValidator struct {
	root map[string]any
}

func (v *schemaValidator) validate(schema map[string]any, value any, location string) error {
	if ref, ok := schema["$ref"].(string); ok {
		resolved, err := v.resolve(ref)
		if err != nil {
			return err
		}
		return v.validate(resolved, value, location)
	}
	if disallowed, ok := schema["not"].(map[string]any); ok && v.validate(disallowed, value, location) == nil {
		return fmt.Errorf("%s matches a disallowed value", location)
	}
	if expected, ok := schema["type"].(string); ok && !matchesSchemaType(expected, value) {
		return fmt.Errorf("%s must be %s", location, expected)
	}
	if expected, ok := schema["const"]; ok && !reflect.DeepEqual(value, expected) {
		return fmt.Errorf("%s must equal %v", location, expected)
	}
	if allowed, ok := schema["enum"].([]any); ok && !containsJSONValue(allowed, value) {
		return fmt.Errorf("%s must be one of %v", location, allowed)
	}
	if err := v.validateObject(schema, value, location); err != nil {
		return err
	}
	if err := v.validateArray(schema, value, location); err != nil {
		return err
	}
	if err := validateScalar(schema, value, location); err != nil {
		return err
	}
	if alternatives, ok := schema["anyOf"].([]any); ok {
		for _, raw := range alternatives {
			alternative, ok := raw.(map[string]any)
			if ok && v.validate(alternative, value, location) == nil {
				return nil
			}
		}
		return fmt.Errorf("%s does not match any allowed schema", location)
	}
	return nil
}

func (v *schemaValidator) validateObject(schema map[string]any, value any, location string) error {
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	properties, _ := schema["properties"].(map[string]any)
	for name, item := range object {
		propertySchema, known := properties[name].(map[string]any)
		if known {
			if err := v.validate(propertySchema, item, location+"."+name); err != nil {
				return err
			}
			continue
		}
		switch additional := schema["additionalProperties"].(type) {
		case bool:
			if !additional {
				return fmt.Errorf("%s.%s is not allowed", location, name)
			}
		case map[string]any:
			if err := v.validate(additional, item, location+"."+name); err != nil {
				return err
			}
		}
	}
	for _, name := range stringsFrom(schema["required"]) {
		if _, present := object[name]; !present {
			return fmt.Errorf("%s.%s is required", location, name)
		}
	}
	return nil
}

func (v *schemaValidator) validateArray(schema map[string]any, value any, location string) error {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	if minimum, ok := integerKeyword(schema["minItems"]); ok && len(items) < minimum {
		return fmt.Errorf("%s must contain at least %d item(s)", location, minimum)
	}
	if unique, _ := schema["uniqueItems"].(bool); unique {
		seen := make(map[string]bool, len(items))
		for _, item := range items {
			encoded, _ := json.Marshal(item)
			key := string(encoded)
			if seen[key] {
				return fmt.Errorf("%s must contain unique items", location)
			}
			seen[key] = true
		}
	}
	if itemSchema, ok := schema["items"].(map[string]any); ok {
		for i, item := range items {
			if err := v.validate(itemSchema, item, fmt.Sprintf("%s[%d]", location, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateScalar(schema map[string]any, value any, location string) error {
	switch typed := value.(type) {
	case string:
		if minimum, ok := integerKeyword(schema["minLength"]); ok && utf8.RuneCountInString(typed) < minimum {
			return fmt.Errorf("%s must contain at least %d character(s)", location, minimum)
		}
		if pattern, ok := schema["pattern"].(string); ok {
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("compile schema pattern for %s: %w", location, err)
			}
			if !compiled.MatchString(typed) {
				return fmt.Errorf("%s does not match the required pattern", location)
			}
		}
		if format, _ := schema["format"].(string); format == "date-time" {
			if _, err := time.Parse(time.RFC3339, typed); err != nil {
				return fmt.Errorf("%s must be an RFC 3339 date-time", location)
			}
		}
	case json.Number:
		number, err := strconv.ParseFloat(string(typed), 64)
		if err != nil {
			return fmt.Errorf("%s must be numeric", location)
		}
		if minimum, ok := numberKeyword(schema["minimum"]); ok && number < minimum {
			return fmt.Errorf("%s must be at least %v", location, minimum)
		}
		if maximum, ok := numberKeyword(schema["maximum"]); ok && number > maximum {
			return fmt.Errorf("%s must be at most %v", location, maximum)
		}
	}
	return nil
}

func (v *schemaValidator) resolve(ref string) (map[string]any, error) {
	if !strings.HasPrefix(ref, "#/") {
		return nil, fmt.Errorf("unsupported schema reference %q", ref)
	}
	var current any = v.root
	for _, segment := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		segment = strings.ReplaceAll(strings.ReplaceAll(segment, "~1", "/"), "~0", "~")
		object, ok := current.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid schema reference %q", ref)
		}
		current, ok = object[segment]
		if !ok {
			return nil, fmt.Errorf("unresolved schema reference %q", ref)
		}
	}
	resolved, ok := current.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema reference %q is not an object", ref)
	}
	return resolved, nil
}

func matchesSchemaType(expected string, value any) bool {
	switch expected {
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "integer":
		number, ok := value.(json.Number)
		if !ok {
			return false
		}
		_, err := strconv.ParseInt(string(number), 10, 64)
		return err == nil
	default:
		return false
	}
}

func containsJSONValue(values []any, target any) bool {
	for _, value := range values {
		if reflect.DeepEqual(value, target) {
			return true
		}
	}
	return false
}

func stringsFrom(value any) []string {
	raw, _ := value.([]any)
	result := make([]string, 0, len(raw))
	for _, item := range raw {
		if text, ok := item.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func integerKeyword(value any) (int, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.Atoi(string(number))
	return parsed, err == nil
}

func numberKeyword(value any) (float64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.ParseFloat(string(number), 64)
	return parsed, err == nil
}
