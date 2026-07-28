package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/dceoy/segh/internal/model"
)

func TestHelpAndVersionDoNotRequireConfiguration(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"--help"}, "Usage:"},
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

func TestScanRunErrorCatchesRunLevelFailuresWithoutFailedResults(t *testing.T) {
	for _, test := range []struct {
		name string
		run  model.ScanRun
	}{
		{
			name: "clone or filter error with no scanner results",
			run: model.ScanRun{
				Selected: 1,
				Errors:   []model.RunError{{Component: "clone", Kind: "runtime", Message: "boom"}},
			},
		},
		{
			name: "total timeout leaves repositories unprocessed",
			run: model.ScanRun{
				Selected:     2,
				Repositories: []model.RepositoryExecution{{Repository: "a/b", Status: "complete"}},
				Errors:       []model.RunError{{Component: "scan", Kind: "total_timeout", Message: "deadline exceeded"}},
			},
		},
		{
			name: "fewer repositories executed than selected",
			run: model.ScanRun{
				Selected:     2,
				Repositories: []model.RepositoryExecution{{Repository: "a/b", Status: "complete"}},
			},
		},
	} {
		if err := scanRunError(test.run); err == nil {
			t.Fatalf("%s: expected error, got nil", test.name)
		}
	}
}

func TestScanRunErrorAcceptsCompleteRuns(t *testing.T) {
	run := model.ScanRun{
		Selected:     1,
		Repositories: []model.RepositoryExecution{{Repository: "a/b", Status: "complete"}},
		Results:      []model.ScannerResult{{Repository: "a/b", Scanner: "trivy", Status: model.ScannerClean}},
	}
	if err := scanRunError(run); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUnknownCommandUsesStableUsageExit(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{"--config", "../../config/pr.yaml", "unknown"}, "test", &stdout, &stderr)
	if err == nil || ExitCode(err) != exitUsage {
		t.Fatalf("err=%v code=%d", err, ExitCode(err))
	}
}
