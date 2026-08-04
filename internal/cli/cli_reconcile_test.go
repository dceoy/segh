package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/dceoy/segh/internal/model"
)

func TestAuditReconcilesSourceScanEvidenceWithoutCredentials(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "scan-manifest.json")
	writeJSON(t, manifestPath, model.SourceScanManifest{
		SchemaVersion: model.SourceScanSchemaVersion,
		Organization:  "example",
		GitHubHost:    "github.com",
		Enabled:       true,
		Complete:      true,
		Concurrency:   1,
		Repositories:  []model.SourceScanRepository{},
	})
	t.Setenv("GH_TOKEN", "")
	t.Setenv("SEGH_GITHUB_INSTALLATION_ID", "")
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{
		"audit",
		"--reconcile-source-scan",
		"--scan-manifest", manifestPath,
		"--scan-results", filepath.Join(dir, "repository-scans"),
		"--scan-summary-output", filepath.Join(dir, "scan-summary.json"),
		"--scan-markdown-output", filepath.Join(dir, "scan-report.md"),
	}, "test", &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
}
