package sarif

import (
	"encoding/json"
	"testing"
)

func TestFindingsPreserveNativeData(t *testing.T) {
	log := Log{
		Version: "2.1.0",
		Runs: []Run{{
			Tool: Tool{Driver: Driver{
				Name:  "Trivy",
				Rules: []Rule{{ID: "AVD-001", Properties: map[string]any{"security-severity": "9.3"}}},
			}},
			Results: []Result{{
				RuleID:  "AVD-001",
				Level:   "error",
				Message: Message{Text: "public storage"},
				Locations: []Location{{PhysicalLocation: PhysicalLocation{
					ArtifactLocation: ArtifactLocation{URI: "infra/main.tf"},
					Region:           Region{StartLine: 7, StartColumn: 3},
				}}},
				PartialFingerprints: map[string]string{"primaryLocationLineHash": "abc"},
			}},
		}},
	}
	findings := Findings(log)
	if len(findings) != 1 {
		t.Fatalf("findings = %d", len(findings))
	}
	got := findings[0]
	if got.Scanner != "trivy" || got.RuleID != "AVD-001" || got.Severity != "critical" || got.URI != "infra/main.tf" || got.Line != 7 {
		t.Fatalf("unexpected finding: %#v", got)
	}
	if got.Fingerprint == "" {
		t.Fatal("missing fingerprint")
	}
}

func TestInjectCategorySetsAutomationDetailsAndPreservesUnknownFields(t *testing.T) {
	input := `{"version":"2.1.0","$schema":"https://example/schema","runs":[` +
		`{"tool":{"driver":{"name":"trivy"}},"results":[],"artifacts":[{"location":{"uri":"a"}}],"properties":{"x":1}},` +
		`{"tool":{"driver":{"name":"trivy"}},"results":[],"automationDetails":{"id":"old"}}` +
		`]}`
	output, err := InjectCategory([]byte(input), "segh/trivy")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema string `json:"$schema"`
		Runs   []struct {
			AutomationDetails struct {
				ID string `json:"id"`
			} `json:"automationDetails"`
			Artifacts  []map[string]any `json:"artifacts"`
			Properties map[string]any   `json:"properties"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(output, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != "https://example/schema" {
		t.Fatalf("unrelated top-level field lost: %#v", doc)
	}
	if len(doc.Runs) != 2 {
		t.Fatalf("runs = %d", len(doc.Runs))
	}
	for i, run := range doc.Runs {
		if run.AutomationDetails.ID != "segh/trivy/" {
			t.Fatalf("run %d automationDetails.id = %q, want segh/trivy/ (trailing slash keeps the whole string as the category)", i, run.AutomationDetails.ID)
		}
	}
	if len(doc.Runs[0].Artifacts) != 1 || doc.Runs[0].Properties["x"] != float64(1) {
		t.Fatalf("unrelated run fields lost: %#v", doc.Runs[0])
	}
}

func TestInjectCategoryRejectsDocumentWithoutRuns(t *testing.T) {
	if _, err := InjectCategory([]byte(`{"version":"2.1.0"}`), "segh/trivy"); err == nil {
		t.Fatal("expected error for SARIF document without runs")
	}
}

func TestFallbackFingerprintStable(t *testing.T) {
	result := Result{RuleID: "rule", Message: Message{Text: "message"}, Level: "warning"}
	log := Log{Version: "2.1.0", Runs: []Run{{Tool: Tool{Driver: Driver{Name: "zizmor"}}, Results: []Result{result}}}}
	first, second := Findings(log), Findings(log)
	if first[0].Fingerprint != second[0].Fingerprint {
		t.Fatal("fallback fingerprint is not stable")
	}
}

func resultAt(rule string, line int) Result {
	return Result{
		RuleID:  rule,
		Message: Message{Text: "issue found"},
		Locations: []Location{{PhysicalLocation: PhysicalLocation{
			ArtifactLocation: ArtifactLocation{URI: "app.py"},
			Region:           Region{StartLine: line},
		}}},
	}
}

func TestFallbackFingerprintIsStableAcrossLineShifts(t *testing.T) {
	before := Log{Version: "2.1.0", Runs: []Run{{Tool: Tool{Driver: Driver{Name: "zizmor"}}, Results: []Result{resultAt("rule", 10)}}}}
	after := Log{Version: "2.1.0", Runs: []Run{{Tool: Tool{Driver: Driver{Name: "zizmor"}}, Results: []Result{resultAt("rule", 25)}}}}
	beforeFindings, afterFindings := Findings(before), Findings(after)
	if beforeFindings[0].Fingerprint != afterFindings[0].Fingerprint {
		t.Fatalf("fingerprint changed across a line shift: %q != %q", beforeFindings[0].Fingerprint, afterFindings[0].Fingerprint)
	}
}

func TestFallbackFingerprintDistinguishesRepeatedOccurrences(t *testing.T) {
	log := Log{Version: "2.1.0", Runs: []Run{{Tool: Tool{Driver: Driver{Name: "zizmor"}}, Results: []Result{
		resultAt("rule", 5), resultAt("rule", 20),
	}}}}
	findings := Findings(log)
	if len(findings) != 2 {
		t.Fatalf("findings = %d", len(findings))
	}
	if findings[0].Fingerprint == findings[1].Fingerprint {
		t.Fatal("two distinct occurrences must not collapse to the same fingerprint")
	}
}

func TestNativeFingerprintDoesNotCollideAcrossRules(t *testing.T) {
	sameNative := func(ruleID string) Result {
		return Result{
			RuleID:              ruleID,
			Message:             Message{Text: "issue"},
			PartialFingerprints: map[string]string{"primaryLocationLineHash": "same"},
		}
	}
	log := Log{Version: "2.1.0", Runs: []Run{{Tool: Tool{Driver: Driver{Name: "trivy"}}, Results: []Result{
		sameNative("rule-a"), sameNative("rule-b"),
	}}}}
	findings := Findings(log)
	if len(findings) != 2 {
		t.Fatalf("findings = %d", len(findings))
	}
	if findings[0].Fingerprint == findings[1].Fingerprint {
		t.Fatal("native fingerprints for different rules must not collide")
	}
}

func TestNativeFingerprintDistinguishesDifferentFiles(t *testing.T) {
	sameNative := func(uri string) Result {
		return Result{
			RuleID:  "rule",
			Message: Message{Text: "issue"},
			Locations: []Location{{PhysicalLocation: PhysicalLocation{
				ArtifactLocation: ArtifactLocation{URI: uri},
			}}},
			PartialFingerprints: map[string]string{"primaryLocationLineHash": "same"},
		}
	}
	log := Log{Version: "2.1.0", Runs: []Run{{Tool: Tool{Driver: Driver{Name: "trivy"}}, Results: []Result{
		sameNative("a.yml"), sameNative("b.yml"),
	}}}}
	findings := Findings(log)
	if len(findings) != 2 {
		t.Fatalf("findings = %d", len(findings))
	}
	if findings[0].Fingerprint == findings[1].Fingerprint {
		t.Fatal("a copied file with the same native fingerprint must not collapse to one fingerprint")
	}
}

func TestNativeFingerprintDistinguishesRepeatedOccurrences(t *testing.T) {
	sameNative := Result{
		RuleID:  "rule",
		Message: Message{Text: "issue"},
		Locations: []Location{{PhysicalLocation: PhysicalLocation{
			ArtifactLocation: ArtifactLocation{URI: "a.yml"},
		}}},
		PartialFingerprints: map[string]string{"primaryLocationLineHash": "same"},
	}
	log := Log{Version: "2.1.0", Runs: []Run{{Tool: Tool{Driver: Driver{Name: "trivy"}}, Results: []Result{
		sameNative, sameNative,
	}}}}
	findings := Findings(log)
	if len(findings) != 2 {
		t.Fatalf("findings = %d", len(findings))
	}
	if findings[0].Fingerprint == findings[1].Fingerprint {
		t.Fatal("a duplicated occurrence at the same location must not collapse to one fingerprint")
	}
}

func TestFallbackFingerprintDistinguishesDifferentFiles(t *testing.T) {
	inFile := func(uri string) Result {
		return Result{
			RuleID:  "rule",
			Message: Message{Text: "issue found"},
			Locations: []Location{{PhysicalLocation: PhysicalLocation{
				ArtifactLocation: ArtifactLocation{URI: uri},
				Region:           Region{StartLine: 10},
			}}},
		}
	}
	log := Log{Version: "2.1.0", Runs: []Run{{Tool: Tool{Driver: Driver{Name: "zizmor"}}, Results: []Result{
		inFile("a.yml"), inFile("b.yml"),
	}}}}
	findings := Findings(log)
	if len(findings) != 2 {
		t.Fatalf("findings = %d", len(findings))
	}
	if findings[0].Fingerprint == findings[1].Fingerprint {
		t.Fatal("the same rule/message finding in two different files must not collapse to one fingerprint")
	}
}

func TestRemapURIsAlignsFingerprintsAcrossRename(t *testing.T) {
	renamed := func(uri string) Result {
		return Result{
			RuleID:  "rule",
			Message: Message{Text: "issue found"},
			Locations: []Location{{PhysicalLocation: PhysicalLocation{
				ArtifactLocation: ArtifactLocation{URI: uri},
				Region:           Region{StartLine: 10},
			}}},
		}
	}
	before := Log{Version: "2.1.0", Runs: []Run{{Tool: Tool{Driver: Driver{Name: "zizmor"}}, Results: []Result{renamed("old.yml")}}}}
	after := Log{Version: "2.1.0", Runs: []Run{{Tool: Tool{Driver: Driver{Name: "zizmor"}}, Results: []Result{renamed("new.yml")}}}}
	beforeFindings := Findings(before)
	if beforeFindings[0].Fingerprint == Findings(after)[0].Fingerprint {
		t.Fatal("fingerprints across a rename must differ without a rename map")
	}
	remapped := RemapURIs(before, map[string]string{"old.yml": "new.yml"})
	remappedFindings := Findings(remapped)
	if remappedFindings[0].URI != "new.yml" {
		t.Fatalf("URI = %q", remappedFindings[0].URI)
	}
	if remappedFindings[0].Fingerprint != Findings(after)[0].Fingerprint {
		t.Fatal("a remapped baseline finding must align with its post-rename counterpart")
	}
}

func TestRemapURIsAlignsNativeFingerprintsAcrossRename(t *testing.T) {
	renamed := func(uri string) Result {
		return Result{
			RuleID:              "rule",
			Message:             Message{Text: "issue found"},
			PartialFingerprints: map[string]string{"primaryLocationLineHash": "same"},
			Locations: []Location{{PhysicalLocation: PhysicalLocation{
				ArtifactLocation: ArtifactLocation{URI: uri},
			}}},
		}
	}
	before := Log{Version: "2.1.0", Runs: []Run{{Tool: Tool{Driver: Driver{Name: "trivy"}}, Results: []Result{renamed("old.yml")}}}}
	after := Log{Version: "2.1.0", Runs: []Run{{Tool: Tool{Driver: Driver{Name: "trivy"}}, Results: []Result{renamed("new.yml")}}}}
	beforeFindings := Findings(before)
	if beforeFindings[0].Fingerprint == Findings(after)[0].Fingerprint {
		t.Fatal("native fingerprints across a rename must differ without a rename map")
	}
	remapped := RemapURIs(before, map[string]string{"old.yml": "new.yml"})
	remappedFindings := Findings(remapped)
	if remappedFindings[0].Fingerprint != Findings(after)[0].Fingerprint {
		t.Fatal("a remapped baseline native fingerprint must align with its post-rename counterpart")
	}
}
