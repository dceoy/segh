package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dceoy/segh/internal/config"
	"github.com/dceoy/segh/internal/model"
	"github.com/dceoy/segh/internal/policy"
)

func TestHelpAndVersionDoNotRequireConfiguration(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"--help"}, "GitHub security governance audit"},
		{[]string{"--version"}, "test-version"},
	} {
		var stdout, stderr bytes.Buffer
		if err := Run(context.Background(), test.args, "test-version", &stdout, &stderr); err != nil {
			t.Fatalf("%v: %v", test.args, err)
		}
		if !strings.Contains(stdout.String(), test.want) {
			t.Fatalf("%v output = %q", test.args, stdout.String())
		}
	}
}

func TestRemovedCommandUsesStableUsageExit(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{"--config", "../../config/organization.yaml", "scan"}, "test", &stdout, &stderr)
	if err == nil || ExitCode(err) != exitUsage || !strings.Contains(err.Error(), `unknown command "scan"`) {
		t.Fatalf("err=%v code=%d", err, ExitCode(err))
	}
}

func TestAuditReturnsIncompleteForIncompletePassingInventory(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	inventory := validInventory(cfg)
	inventory.Complete = false
	inventory.Errors = []model.RunError{{Component: "inventory", Kind: "timeout", Message: "deadline exceeded"}}
	inventoryPath := filepath.Join(dir, "inventory.json")
	writeJSON(t, inventoryPath, inventory)

	var stdout bytes.Buffer
	err := runAudit(cfg, []string{"--inventory", inventoryPath}, &stdout)
	if err == nil || ExitCode(err) != exitIncomplete {
		t.Fatalf("err=%v code=%d", err, ExitCode(err))
	}
	if _, err := os.Stat(filepath.Join(dir, "audit.json")); err != nil {
		t.Fatalf("audit output was not written: %v", err)
	}
}

func TestInventoryRequiresInstallationID(t *testing.T) {
	t.Setenv("SEGH_GITHUB_INSTALLATION_ID", "")
	var stdout bytes.Buffer
	err := runInventory(context.Background(), testConfig(t.TempDir()), nil, &stdout)
	if err == nil || ExitCode(err) != exitAuth ||
		!strings.Contains(err.Error(), "SEGH_GITHUB_INSTALLATION_ID must be a positive integer") {
		t.Fatalf("err = %v, code = %d", err, ExitCode(err))
	}
}

func TestReportUsesConfiguredOutputDirectory(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	inventory := validInventory(cfg)
	audit := validAudit(cfg)
	writeJSON(t, filepath.Join(dir, "inventory.json"), inventory)
	writeJSON(t, filepath.Join(dir, "audit.json"), audit)

	var stdout bytes.Buffer
	if err := runReport(cfg, nil, &stdout); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"report.json", "report.md"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s was not written: %v", name, err)
		}
	}
}

func TestValidateReportArtifactsAcceptsSliceTypedExpectedValueAfterJSONRoundTrip(t *testing.T) {
	// repository.visibility's Expected value is a []string, decoded from JSON
	// into []any on the audit side but left as []string on the freshly
	// evaluated side; the comparison must normalize both before comparing.
	cfg := testConfig(t.TempDir())
	cfg.Policies.Repository.AllowedVisibilities = []string{"public", "internal"}
	inventory := validInventory(cfg)
	audit := policy.New(cfg, time.Now().UTC()).Evaluate(inventory)

	data, err := json.Marshal(audit)
	if err != nil {
		t.Fatal(err)
	}
	var roundTripped model.Audit
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatal(err)
	}
	if err := validateReportArtifacts(inventory, roundTripped, cfg); err != nil {
		t.Fatalf("validateReportArtifacts() = %v, want nil for a legitimate round-tripped audit", err)
	}
}

func TestValidateReportArtifactsRejectsInconsistentInputs(t *testing.T) {
	cfg := testConfig(t.TempDir())
	tests := []struct {
		name   string
		change func(*model.Inventory, *model.Audit)
		want   string
	}{
		{
			name: "inventory schema",
			change: func(inventory *model.Inventory, _ *model.Audit) {
				inventory.SchemaVersion = 0
			},
			want: "unsupported inventory schema version",
		},
		{
			name: "audit schema",
			change: func(_ *model.Inventory, audit *model.Audit) {
				audit.SchemaVersion = 0
			},
			want: "unsupported audit schema version",
		},
		{
			name: "configured organization",
			change: func(inventory *model.Inventory, audit *model.Audit) {
				inventory.Organization = "other"
				audit.Organization = "other"
			},
			want: "does not match configured organization",
		},
		{
			name: "artifact organizations",
			change: func(_ *model.Inventory, audit *model.Audit) {
				audit.Organization = "other"
			},
			want: "does not match inventory organization",
		},
		{
			name: "inventory github host",
			change: func(inventory *model.Inventory, _ *model.Audit) {
				inventory.GitHubHost = "https://github.example.com"
			},
			want: "does not match configured github.web_url",
		},
		{
			name: "inventory records",
			change: func(inventory *model.Inventory, _ *model.Audit) {
				inventory.Selected = 0
			},
			want: "counts do not match its records",
		},
		{
			name: "audit counts",
			change: func(_ *model.Inventory, audit *model.Audit) {
				audit.Results[0].Status = model.PolicyFail
			},
			want: "counts do not match its policy results",
		},
		{
			name: "unknown policy status",
			change: func(_ *model.Inventory, audit *model.Audit) {
				audit.Results[0].Status = "unexpected"
				audit.Counts = map[string]int{"unexpected": 1}
			},
			want: "invalid status",
		},
		{
			name: "missing audit results",
			change: func(_ *model.Inventory, audit *model.Audit) {
				audit.Results = nil
				audit.Counts = map[string]int{}
			},
			want: "results do not match the inventory and configuration",
		},
		{
			// Repository, PolicyID, and Status are unchanged and Counts still
			// balances, so only a full comparison of the re-evaluated result
			// catches tampered evidence/remediation content.
			name: "tampered evidence and remediation",
			change: func(_ *model.Inventory, audit *model.Audit) {
				audit.Results[0].Evidence = "fabricated evidence"
				audit.Results[0].Remediation = "fabricated remediation"
			},
			want: "results do not match the inventory and configuration",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inventory := validInventory(cfg)
			audit := validAudit(cfg)
			test.change(&inventory, &audit)
			err := validateReportArtifacts(inventory, audit, cfg)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected %q error, got %v", test.want, err)
			}
		})
	}
}

func testConfig(outputDirectory string) config.Config {
	cfg := config.Default()
	cfg.Organization = "example"
	cfg.Output.Directory = outputDirectory
	cfg.Policies.Repository.RequireRuleset = true
	return cfg
}

func validInventory(cfg config.Config) model.Inventory {
	return model.Inventory{
		SchemaVersion: model.InventorySchemaVersion,
		Organization:  cfg.Organization,
		GitHubHost:    cfg.GitHub.WebURL,
		GeneratedAt:   time.Now().UTC(),
		Complete:      true,
		Total:         1,
		Selected:      1,
		Repositories: []model.Repository{{
			FullName: "example/repository",
			Ruleset:  model.Observed[bool]{State: model.Available, Value: true},
		}},
	}
}

func validAudit(cfg config.Config) model.Audit {
	return policy.New(cfg, time.Now().UTC()).Evaluate(validInventory(cfg))
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
