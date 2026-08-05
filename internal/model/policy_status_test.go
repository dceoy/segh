package model

import (
	"encoding/json"
	"testing"
)

func TestPolicyStatusJSONUsesRetainedValues(t *testing.T) {
	statuses := []PolicyStatus{PolicyPass, PolicyFail, PolicyUnknown, PolicyUnsupported, PolicyExempt}
	data, err := json.Marshal(statuses)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), `["pass","fail","unknown","unsupported","exempt"]`; got != want {
		t.Fatalf("policy statuses = %s, want %s", got, want)
	}
}
