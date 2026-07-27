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
