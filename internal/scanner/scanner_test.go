package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/dceoy/segh/internal/config"
	"github.com/dceoy/segh/internal/model"
)

func TestFilteredTreeRejectsTraversalAndEscapingSymlink(t *testing.T) {
	root := t.TempDir()
	if _, cleanup, err := filteredTree(root, []string{"../secret"}); err == nil {
		cleanup()
		t.Fatal("expected traversal rejection")
	}
	if runtime.GOOS != "windows" {
		outside := filepath.Join(t.TempDir(), "outside")
		if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
			t.Fatal(err)
		}
		if _, cleanup, err := filteredTree(root, []string{"link"}); err == nil {
			cleanup()
			t.Fatal("expected symlink escape rejection")
		}
	}
}

func TestFilteredTreeCopiesOnlySelectedRegularFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "infra"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "infra", "main.tf"), []byte("resource {}"), 0o600); err != nil {
		t.Fatal(err)
	}
	filtered, cleanup, err := filteredTree(root, []string{"infra/main.tf", "deleted.tf"})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, err := os.Stat(filepath.Join(filtered, "infra", "main.tf")); err != nil {
		t.Fatal(err)
	}
}

func TestFixedCommandsDisableOverlappingTrivyScanners(t *testing.T) {
	cfg := config.Default()
	cfg.Scanners.Trivy.Exclude = []string{"vendor/**"}
	cfg.Scanners.Semgrep.Rules = []string{"rules/org.yml"}
	service := Service{cfg: cfg}
	_, args, _ := service.command("trivy", model.Repository{}, "/target", "/result")
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--scanners misconfig") || strings.Contains(joined, "secret") || strings.Contains(joined, "vuln") {
		t.Fatalf("unsafe Trivy command: %v", args)
	}
	_, scorecardArgs, _ := service.command("scorecard", model.Repository{FullName: "org/repo"}, "/target", "/result.json")
	if !strings.Contains(strings.Join(scorecardArgs, " "), "--format json") {
		t.Fatalf("Scorecard must retain native JSON: %v", scorecardArgs)
	}
}

func TestCountScorecardIndividualChecks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scorecard.json")
	data, err := json.Marshal(map[string]any{
		"score":  7.5,
		"checks": []map[string]any{{"name": "Pinned-Dependencies", "score": 8}, {"name": "License", "score": 10}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	count, err := countFindings("scorecard", path)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("individual check findings = %d", count)
	}
}

func TestValidateCloneURLBindsHostAndRepository(t *testing.T) {
	cfg := config.Default()
	cfg.GitHub.WebURL = "https://github.example"
	service := Service{cfg: cfg}
	repo := model.Repository{FullName: "org/repo", CloneURL: "https://github.example/org/repo.git"}
	if err := service.validateCloneURL(repo); err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{
		"https://evil.example/org/repo.git",
		"https://token@github.example/org/repo.git",
		"https://github.example/other/repo.git",
		"https://github.example/org/repo.git?x=1",
	} {
		repo.CloneURL = unsafe
		if err := service.validateCloneURL(repo); err == nil {
			t.Fatalf("accepted unsafe clone URL %q", unsafe)
		}
	}
}

func TestResourceLimitsFailClosedOffLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("non-Linux behavior")
	}
	_, _, err := applyResourceLimits("tool", nil, definition{cpuSeconds: 1})
	if err == nil {
		t.Fatal("expected unsupported resource-limit error")
	}
}

func TestEmptyTokenNotRequiredForDryRun(t *testing.T) {
	cfg := config.Default()
	cfg.Organization = "org"
	cfg.Execution.DryRun = true
	cfg.Execution.TotalTimeout = time.Second
	cfg.Execution.RepositoryTimeout = time.Second
	cfg.Scanners.Zizmor.Enabled = true
	cfg.Scanners.Zizmor.Version = "1"
	service := New(cfg, tokenStub{}, nil)
	run := service.Run(context.Background(), []Target{{Repository: model.Repository{FullName: "org/repo"}}}, "digest", "run")
	planned := 0
	for _, result := range run.Results {
		if result.Status == model.ScannerPlanned {
			planned++
		}
	}
	if len(run.Results) != 4 || planned != 1 {
		t.Fatalf("unexpected dry run: %#v", run.Results)
	}
}

type tokenStub struct{}

func (tokenStub) Token(context.Context) (string, error) { return "", nil }
