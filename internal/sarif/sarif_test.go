package sarif

import "testing"

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
