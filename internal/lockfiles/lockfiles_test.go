package lockfiles

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/dceoy/segh/internal/config"
	"github.com/dceoy/segh/internal/model"
)

type fakeAPI struct {
	tree      []treeEntry
	truncated bool
	treeErr   error
	files     map[string]string
}

func (f *fakeAPI) Get(_ context.Context, apiPath string, out any) error {
	switch {
	case strings.Contains(apiPath, "/git/trees/"):
		if f.treeErr != nil {
			return f.treeErr
		}
		return marshalInto(struct {
			Tree      []treeEntry `json:"tree"`
			Truncated bool        `json:"truncated"`
		}{Tree: f.tree, Truncated: f.truncated}, out)
	case strings.Contains(apiPath, "/contents/"):
		rest := strings.SplitN(apiPath, "/contents/", 2)[1]
		filePath := strings.SplitN(rest, "?ref=", 2)[0]
		content, ok := f.files[filePath]
		if !ok {
			return fmt.Errorf("404: %s not found", filePath)
		}
		return marshalInto(struct {
			Encoding string `json:"encoding"`
			Content  string `json:"content"`
		}{Encoding: "base64", Content: base64.StdEncoding.EncodeToString([]byte(content))}, out)
	default:
		return fmt.Errorf("unexpected path %s", apiPath)
	}
}

func marshalInto(v, out any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func blobs(paths ...string) []treeEntry {
	entries := make([]treeEntry, 0, len(paths))
	for _, p := range paths {
		entries = append(entries, treeEntry{Path: p, Type: "blob"})
	}
	return entries
}

func enabledConfig() config.Config {
	cfg := config.Default()
	enabled := true
	cfg.Policies.Dependencies.LockFiles = &enabled
	cfg.Inventory.Concurrency = 2
	return cfg
}

func repo(fullName string) model.Repository {
	return model.Repository{FullName: fullName, DefaultBranch: "main"}
}

func inventoryOf(repos ...model.Repository) model.Inventory {
	return model.Inventory{Repositories: repos}
}

func TestRunReturnsNilWithoutAnyCallWhenDisabled(t *testing.T) {
	cfg := config.Default() // LockFiles is nil (disabled) by default.
	api := &fakeAPI{tree: blobs("package.json"), files: map[string]string{"package.json": `{"dependencies":{"left-pad":"1.0.0"}}`}}
	results := New(cfg, api).Run(context.Background(), inventoryOf(repo("example/repo")))
	if results != nil {
		t.Fatalf("Run() = %v, want nil when lock_files is disabled", results)
	}
}

func TestRunDetectsMissingNPMLockFile(t *testing.T) {
	api := &fakeAPI{
		tree:  blobs("package.json"),
		files: map[string]string{"package.json": `{"name":"app","dependencies":{"left-pad":"1.0.0"}}`},
	}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/app")))
	if len(results) != 1 {
		t.Fatalf("Run() returned %d results, want 1: %#v", len(results), results)
	}
	result := results[0]
	if result.PolicyID != "dependencies.lock_file" || result.Status != model.PolicyWarning {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.Evidence != "package.json" {
		t.Fatalf("Evidence = %q, want package.json", result.Evidence)
	}
	if !strings.Contains(result.Remediation, "npm install --package-lock-only") {
		t.Fatalf("Remediation = %q, want the inferred npm command", result.Remediation)
	}
}

func TestRunSkipsWhenLockFileIsBesideTheManifest(t *testing.T) {
	api := &fakeAPI{
		tree: blobs("package.json", "package-lock.json"),
		files: map[string]string{
			"package.json": `{"dependencies":{"left-pad":"1.0.0"}}`,
		},
	}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/app")))
	if len(results) != 0 {
		t.Fatalf("Run() = %#v, want no findings when the lock file is present", results)
	}
}

func TestRunRecognizesAlternativeLockFiles(t *testing.T) {
	for _, lock := range []string{"npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"} {
		t.Run(lock, func(t *testing.T) {
			api := &fakeAPI{
				tree:  blobs("package.json", lock),
				files: map[string]string{"package.json": `{"dependencies":{"left-pad":"1.0.0"}}`},
			}
			results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/app")))
			if len(results) != 0 {
				t.Fatalf("Run() = %#v, want no findings when %s covers the manifest", results, lock)
			}
		})
	}
}

func TestRunSkipsManifestsWithoutDeclaredDependencies(t *testing.T) {
	api := &fakeAPI{
		tree:  blobs("package.json"),
		files: map[string]string{"package.json": `{"name":"app"}`},
	}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/app")))
	if len(results) != 0 {
		t.Fatalf("Run() = %#v, want no findings for a manifest without dependencies", results)
	}
}

func TestRunHandlesWorkspaceRootLockFileWithoutDuplicateFindings(t *testing.T) {
	api := &fakeAPI{
		tree: blobs(
			"package.json",
			"packages/a/package.json",
			"packages/b/package.json",
			"pnpm-lock.yaml",
		),
		files: map[string]string{
			"package.json":            `{"dependencies":{"left-pad":"1.0.0"}}`,
			"packages/a/package.json": `{"dependencies":{"left-pad":"1.0.0"}}`,
			"packages/b/package.json": `{"devDependencies":{"jest":"29.0.0"}}`,
		},
	}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/monorepo")))
	if len(results) != 0 {
		t.Fatalf("Run() = %#v, want no findings when a workspace-root lock file covers every manifest", results)
	}
}

func TestRunReportsEachUncoveredWorkspaceManifestSeparately(t *testing.T) {
	api := &fakeAPI{
		tree: blobs(
			"packages/a/package.json",
			"packages/b/package.json",
		),
		files: map[string]string{
			"packages/a/package.json": `{"dependencies":{"left-pad":"1.0.0"}}`,
			"packages/b/package.json": `{"dependencies":{"chalk":"5.0.0"}}`,
		},
	}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/monorepo")))
	if len(results) != 2 {
		t.Fatalf("Run() returned %d results, want 2: %#v", len(results), results)
	}
	if results[0].Evidence != "packages/a/package.json" || results[1].Evidence != "packages/b/package.json" {
		t.Fatalf("unexpected evidence ordering: %#v", results)
	}
}

func TestRunIgnoresManifestsUnderVendoredDirectories(t *testing.T) {
	api := &fakeAPI{
		tree: blobs("node_modules/left-pad/package.json"),
		files: map[string]string{
			"node_modules/left-pad/package.json": `{"dependencies":{"foo":"1.0.0"}}`,
		},
	}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/app")))
	if len(results) != 0 {
		t.Fatalf("Run() = %#v, want no findings for a manifest under node_modules", results)
	}
}

func TestInferNodePackageManagerFromPackageManagerField(t *testing.T) {
	api := &fakeAPI{
		tree:  blobs("package.json"),
		files: map[string]string{"package.json": `{"packageManager":"pnpm@8.6.0","dependencies":{"left-pad":"1.0.0"}}`},
	}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/app")))
	if len(results) != 1 || !strings.Contains(results[0].Remediation, "pnpm install --lockfile-only") {
		t.Fatalf("unexpected result: %#v", results)
	}
}

func TestInferNodePackageManagerFromWorkspaceConfigFile(t *testing.T) {
	api := &fakeAPI{
		tree:  blobs("package.json", ".yarnrc.yml"),
		files: map[string]string{"package.json": `{"dependencies":{"left-pad":"1.0.0"}}`},
	}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/app")))
	if len(results) != 1 || !strings.Contains(results[0].Remediation, "yarn install") {
		t.Fatalf("unexpected result: %#v", results)
	}
}

func TestRunInfersPoetryForPyprojectToml(t *testing.T) {
	api := &fakeAPI{
		tree: blobs("pyproject.toml"),
		files: map[string]string{
			"pyproject.toml": "[tool.poetry]\nname = \"app\"\n\n[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"^2.31\"\n",
		},
	}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/pyapp")))
	if len(results) != 1 {
		t.Fatalf("Run() returned %d results, want 1: %#v", len(results), results)
	}
	if results[0].Status != model.PolicyNotice || !strings.Contains(results[0].Remediation, "poetry lock") {
		t.Fatalf("unexpected result: %#v", results[0])
	}
}

func TestRunSkipsPyprojectWithOnlyPythonVersionConstraint(t *testing.T) {
	api := &fakeAPI{
		tree: blobs("pyproject.toml"),
		files: map[string]string{
			"pyproject.toml": "[tool.poetry]\nname = \"app\"\n\n[tool.poetry.dependencies]\npython = \"^3.11\"\n",
		},
	}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/pyapp")))
	if len(results) != 0 {
		t.Fatalf("Run() = %#v, want no findings for python-only poetry dependencies", results)
	}
}

func TestRunDetectsPEP621DependenciesArray(t *testing.T) {
	api := &fakeAPI{
		tree: blobs("pyproject.toml"),
		files: map[string]string{
			"pyproject.toml": "[project]\nname = \"app\"\ndependencies = [\n  \"requests>=2.31\",\n]\n",
		},
	}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/pyapp")))
	if len(results) != 1 || !strings.Contains(results[0].Remediation, "uv lock") {
		t.Fatalf("unexpected result: %#v", results)
	}
}

func TestRunGoModWarnsWhenMainPackagePresent(t *testing.T) {
	api := &fakeAPI{
		tree: blobs("go.mod", "cmd/app/main.go"),
		files: map[string]string{
			"go.mod": "module example.com/app\n\ngo 1.23\n\nrequire github.com/example/dep v1.0.0\n",
		},
	}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/goapp")))
	if len(results) != 1 || results[0].Status != model.PolicyWarning {
		t.Fatalf("unexpected result: %#v", results)
	}
}

func TestRunGoModNoticesWhenNoMainPackage(t *testing.T) {
	api := &fakeAPI{
		tree: blobs("go.mod", "lib.go"),
		files: map[string]string{
			"go.mod": "module example.com/lib\n\ngo 1.23\n\nrequire (\n\tgithub.com/example/dep v1.0.0\n)\n",
		},
	}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/golib")))
	if len(results) != 1 || results[0].Status != model.PolicyNotice {
		t.Fatalf("unexpected result: %#v", results)
	}
}

func TestRunSkipsGoModWithoutRequireDirectives(t *testing.T) {
	api := &fakeAPI{
		tree:  blobs("go.mod"),
		files: map[string]string{"go.mod": "module example.com/app\n\ngo 1.23\n"},
	}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/goapp")))
	if len(results) != 0 {
		t.Fatalf("Run() = %#v, want no findings for a go.mod without require directives", results)
	}
}

func TestRunComposerNoticesWhenTypeIsLibrary(t *testing.T) {
	api := &fakeAPI{
		tree: blobs("composer.json"),
		files: map[string]string{
			"composer.json": `{"type":"library","require":{"php":"^8.1","monolog/monolog":"^3.0"}}`,
		},
	}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/phplib")))
	if len(results) != 1 || results[0].Status != model.PolicyNotice {
		t.Fatalf("unexpected result: %#v", results)
	}
}

func TestRunComposerWarnsWithoutLibraryType(t *testing.T) {
	api := &fakeAPI{
		tree: blobs("composer.json"),
		files: map[string]string{
			"composer.json": `{"require":{"php":"^8.1","monolog/monolog":"^3.0"}}`,
		},
	}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/phpapp")))
	if len(results) != 1 || results[0].Status != model.PolicyWarning {
		t.Fatalf("unexpected result: %#v", results)
	}
}

func TestRunSkipsComposerWithOnlyPHPConstraint(t *testing.T) {
	api := &fakeAPI{
		tree:  blobs("composer.json"),
		files: map[string]string{"composer.json": `{"require":{"php":"^8.1"}}`},
	}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/phpapp")))
	if len(results) != 0 {
		t.Fatalf("Run() = %#v, want no findings when require only constrains the php version", results)
	}
}

func TestRunDetectsCargoDependencies(t *testing.T) {
	api := &fakeAPI{
		tree: blobs("Cargo.toml"),
		files: map[string]string{
			"Cargo.toml": "[package]\nname = \"app\"\n\n[dependencies]\nserde = \"1\"\n",
		},
	}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/rustcrate")))
	if len(results) != 1 || results[0].Status != model.PolicyNotice {
		t.Fatalf("unexpected result: %#v", results)
	}
}

func TestRunDetectsPipfileDependencies(t *testing.T) {
	api := &fakeAPI{
		tree: blobs("Pipfile"),
		files: map[string]string{
			"Pipfile": "[packages]\nrequests = \"*\"\n",
		},
	}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/pipenvapp")))
	if len(results) != 1 || results[0].Status != model.PolicyWarning {
		t.Fatalf("unexpected result: %#v", results)
	}
}

func TestRunDetectsGemfileDependencies(t *testing.T) {
	api := &fakeAPI{
		tree: blobs("Gemfile"),
		files: map[string]string{
			"Gemfile": "source 'https://rubygems.org'\ngem 'rails'\n",
		},
	}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/rubyapp")))
	if len(results) != 1 || results[0].Status != model.PolicyWarning {
		t.Fatalf("unexpected result: %#v", results)
	}
}

func TestRunDetectsMixDependencies(t *testing.T) {
	api := &fakeAPI{
		tree: blobs("mix.exs"),
		files: map[string]string{
			"mix.exs": "defmodule App.MixProject do\n  use Mix.Project\n\n  defp deps do\n    [\n      {:jason, \"~> 1.4\"}\n    ]\n  end\nend\n",
		},
	}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/elixirapp")))
	if len(results) != 1 || results[0].Status != model.PolicyWarning {
		t.Fatalf("unexpected result: %#v", results)
	}
}

func TestRunSkipsMixWithoutDependencies(t *testing.T) {
	api := &fakeAPI{
		tree: blobs("mix.exs"),
		files: map[string]string{
			"mix.exs": "defmodule App.MixProject do\n  use Mix.Project\n\n  defp deps do\n    []\n  end\nend\n",
		},
	}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/elixirapp")))
	if len(results) != 0 {
		t.Fatalf("Run() = %#v, want no findings for an empty deps list", results)
	}
}

func TestRunDetectsPubspecDependencies(t *testing.T) {
	api := &fakeAPI{
		tree: blobs("pubspec.yaml"),
		files: map[string]string{
			"pubspec.yaml": "name: app\ndependencies:\n  http: ^1.0.0\n",
		},
	}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/dartapp")))
	if len(results) != 1 || results[0].Status != model.PolicyWarning {
		t.Fatalf("unexpected result: %#v", results)
	}
}

func TestRunDetectsTerraformProviders(t *testing.T) {
	api := &fakeAPI{
		tree: blobs("infra/main.tf", "infra/versions.tf"),
		files: map[string]string{
			"infra/main.tf":     "resource \"aws_s3_bucket\" \"example\" {}\n",
			"infra/versions.tf": "terraform {\n  required_providers {\n    aws = {\n      source  = \"hashicorp/aws\"\n      version = \"~> 5.0\"\n    }\n  }\n}\n",
		},
	}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/infra")))
	if len(results) != 1 {
		t.Fatalf("Run() returned %d results, want 1 (one per directory, not per file): %#v", len(results), results)
	}
	if results[0].Evidence != "infra" {
		t.Fatalf("Evidence = %q, want the directory infra", results[0].Evidence)
	}
}

func TestRunSkipsTerraformWithoutRequiredProviders(t *testing.T) {
	api := &fakeAPI{
		tree: blobs("infra/main.tf"),
		files: map[string]string{
			"infra/main.tf": "resource \"aws_s3_bucket\" \"example\" {}\n",
		},
	}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/infra")))
	if len(results) != 0 {
		t.Fatalf("Run() = %#v, want no findings without a required_providers block", results)
	}
}

func TestRunDetectsFlakeInputs(t *testing.T) {
	api := &fakeAPI{
		tree: blobs("flake.nix"),
		files: map[string]string{
			"flake.nix": "{\n  inputs = {\n    nixpkgs.url = \"github:NixOS/nixpkgs\";\n  };\n}\n",
		},
	}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/nixflake")))
	if len(results) != 1 || results[0].Status != model.PolicyWarning {
		t.Fatalf("unexpected result: %#v", results)
	}
}

func TestRunReportsTruncatedTreeAsNotice(t *testing.T) {
	api := &fakeAPI{truncated: true}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/huge")))
	if len(results) != 1 || results[0].Status != model.PolicyNotice {
		t.Fatalf("unexpected result: %#v", results)
	}
	if !strings.Contains(fmt.Sprint(results[0].Observed), "truncated") {
		t.Fatalf("Observed = %v, want a mention of truncation", results[0].Observed)
	}
}

func TestRunReportsTreeFetchFailureAsNotice(t *testing.T) {
	api := &fakeAPI{treeErr: fmt.Errorf("500: internal error")}
	results := New(enabledConfig(), api).Run(context.Background(), inventoryOf(repo("example/broken")))
	if len(results) != 1 || results[0].Status != model.PolicyNotice {
		t.Fatalf("unexpected result: %#v", results)
	}
}
