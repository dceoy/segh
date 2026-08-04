// Package lockfiles detects a dependency manifest committed without its
// corresponding lock or checksum file, using only read-only GitHub API
// calls (a recursive tree listing and, for matched manifests, their file
// content) against each repository's default branch. It never checks out,
// executes, or installs anything from the target repository.
package lockfiles

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/dceoy/segh/internal/config"
	"github.com/dceoy/segh/internal/model"
	"gopkg.in/yaml.v3"
)

const policyID = "dependencies.lock_file"

// API is the subset of the GitHub client Checker needs: a single GET that
// decodes a JSON response, matching internal/github.Client's Get method.
type API interface {
	Get(ctx context.Context, apiPath string, out any) error
}

type Checker struct {
	cfg    config.Config
	client API
}

func New(cfg config.Config, client API) *Checker {
	return &Checker{cfg: cfg, client: client}
}

// Run reports one PolicyResult per manifest found without a covering lock
// file among repo.FullName's default branch, for every repository in
// inventory. It returns nil without making any API call when
// policies.dependencies.lock_files is not enabled.
func (c *Checker) Run(ctx context.Context, inventory model.Inventory) []model.PolicyResult {
	if c.cfg.Policies.Dependencies.LockFiles == nil || !*c.cfg.Policies.Dependencies.LockFiles {
		return nil
	}
	concurrency := c.cfg.Inventory.Concurrency
	if concurrency < 1 {
		concurrency = 1
	}
	jobs := make(chan model.Repository)
	results := make(chan []model.PolicyResult, len(inventory.Repositories))
	var workers sync.WaitGroup
	for range concurrency {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for repo := range jobs {
				results <- c.repository(ctx, repo)
			}
		}()
	}
	go func() {
		defer close(results)
		for _, repo := range inventory.Repositories {
			select {
			case <-ctx.Done():
				close(jobs)
				workers.Wait()
				return
			case jobs <- repo:
			}
		}
		close(jobs)
		workers.Wait()
	}()

	var all []model.PolicyResult
	for batch := range results {
		all = append(all, batch...)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Repository != all[j].Repository {
			return all[i].Repository < all[j].Repository
		}
		return all[i].Evidence < all[j].Evidence
	})
	return all
}

type treeEntry struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

func (c *Checker) repository(ctx context.Context, repo model.Repository) []model.PolicyResult {
	base := repoBase(repo.FullName)
	var tree struct {
		Tree      []treeEntry `json:"tree"`
		Truncated bool        `json:"truncated"`
	}
	apiPath := base + "/git/trees/" + url.PathEscape(repo.DefaultBranch) + "?recursive=1"
	if err := c.client.Get(ctx, apiPath, &tree); err != nil {
		return []model.PolicyResult{incompleteResult(repo, "fetch repository tree: "+err.Error())}
	}
	if tree.Truncated {
		return []model.PolicyResult{incompleteResult(repo, "repository tree response was truncated; too large to evaluate completely")}
	}

	files := make(map[string]bool, len(tree.Tree))
	var paths []string
	for _, entry := range tree.Tree {
		if entry.Type != "blob" {
			continue
		}
		files[entry.Path] = true
		paths = append(paths, entry.Path)
	}

	var findings []model.PolicyResult
	for _, eco := range ecosystems {
		for _, match := range eco.findManifests(paths) {
			if lockFileCovered(match.searchDir, eco.lockCandidates, files) {
				continue
			}
			contents := c.fetchContents(ctx, base, repo.DefaultBranch, match.sources)
			if !eco.hasDependencies(contents) {
				continue
			}
			severity, command, rationale := eco.classify(contents, files, match.path)
			findings = append(findings, model.PolicyResult{
				Repository:  repo.FullName,
				PolicyID:    policyID,
				Status:      severity,
				Severity:    string(severity),
				Observed:    match.path,
				Expected:    strings.Join(eco.lockCandidates, " or "),
				Evidence:    match.path,
				Remediation: lockRemediation(eco, command, rationale),
			})
		}
	}
	return findings
}

func incompleteResult(repo model.Repository, message string) model.PolicyResult {
	return model.PolicyResult{
		Repository:  repo.FullName,
		PolicyID:    policyID,
		Status:      model.PolicyNotice,
		Severity:    string(model.PolicyNotice),
		Observed:    message,
		Expected:    "a complete repository file tree",
		Evidence:    "git/trees",
		Remediation: "Lock-file detection could not evaluate this repository automatically; review dependency manifests manually.",
	}
}

func lockRemediation(eco ecosystemSpec, command, rationale string) string {
	message := fmt.Sprintf("Commit a lock/checksum file for %s (expected one of: %s).",
		eco.label, strings.Join(eco.lockCandidates, ", "))
	if command != "" {
		message += " Suggested command: `" + command + "`."
	}
	if rationale != "" {
		message += " (" + rationale + ")"
	}
	return message
}

type fetchedContent struct {
	path string
	data []byte
}

func (c *Checker) fetchContents(ctx context.Context, base, branch string, sources []string) []fetchedContent {
	var out []fetchedContent
	for _, src := range sources {
		var response struct {
			Encoding string `json:"encoding"`
			Content  string `json:"content"`
		}
		apiPath := base + "/contents/" + src + "?ref=" + url.PathEscape(branch)
		if err := c.client.Get(ctx, apiPath, &response); err != nil {
			continue
		}
		if response.Encoding != "base64" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(response.Content, "\n", ""))
		if err != nil {
			continue
		}
		out = append(out, fetchedContent{path: src, data: decoded})
	}
	return out
}

func repoBase(fullName string) string {
	owner, name, ok := strings.Cut(fullName, "/")
	if !ok {
		return "/repos/" + url.PathEscape(fullName)
	}
	return "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name)
}

// manifestMatch is one manifest (or, for Terraform, one directory of *.tf
// files) found in a repository's tree.
type manifestMatch struct {
	path      string   // the path reported to the operator
	searchDir string   // directory the lock-file ancestor search starts from
	sources   []string // file(s) fetched to decide hasDependencies/classify
}

type ecosystemSpec struct {
	id              string
	label           string
	lockCandidates  []string
	findManifests   func(paths []string) []manifestMatch
	hasDependencies func(files []fetchedContent) bool
	classify        func(files []fetchedContent, tree map[string]bool, manifestPath string) (model.PolicyStatus, string, string)
}

// excludedSegments are path segments that hold vendored, fetched, or
// generated dependency trees rather than the repository's own manifests. A
// manifest found under one of these is never a real, first-party manifest.
var excludedSegments = map[string]bool{
	"node_modules":     true,
	"vendor":           true,
	"deps":             true,
	"_build":           true,
	".terraform":       true,
	".dart_tool":       true,
	"bower_components": true,
}

func hasExcludedSegment(p string) bool {
	for _, segment := range strings.Split(p, "/") {
		if excludedSegments[segment] {
			return true
		}
	}
	return false
}

func manifestsNamed(name string) func([]string) []manifestMatch {
	return func(paths []string) []manifestMatch {
		var matches []manifestMatch
		for _, p := range paths {
			if hasExcludedSegment(p) {
				continue
			}
			if path.Base(p) == name {
				matches = append(matches, manifestMatch{path: p, searchDir: path.Dir(p), sources: []string{p}})
			}
		}
		return matches
	}
}

func manifestsForTerraform(paths []string) []manifestMatch {
	byDir := map[string][]string{}
	for _, p := range paths {
		if hasExcludedSegment(p) {
			continue
		}
		if strings.HasSuffix(p, ".tf") {
			dir := path.Dir(p)
			byDir[dir] = append(byDir[dir], p)
		}
	}
	var matches []manifestMatch
	for dir, sources := range byDir {
		sort.Strings(sources)
		matches = append(matches, manifestMatch{path: dir, searchDir: dir, sources: sources})
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].path < matches[j].path })
	return matches
}

// lockFileCovered reports whether any of candidates exists beside searchDir
// or at any of its ancestor directories up to the repository root, matching
// both a manifest-local lock file and one shared by a workspace/monorepo
// root.
func lockFileCovered(searchDir string, candidates []string, files map[string]bool) bool {
	dir := searchDir
	for {
		for _, candidate := range candidates {
			if files[joinPath(dir, candidate)] {
				return true
			}
		}
		if dir == "." {
			return false
		}
		dir = path.Dir(dir)
	}
}

func joinPath(dir, name string) string {
	if dir == "." {
		return name
	}
	return dir + "/" + name
}

func ancestorDirs(dir string) []string {
	var dirs []string
	for {
		dirs = append(dirs, dir)
		if dir == "." {
			return dirs
		}
		dir = path.Dir(dir)
	}
}

func soleContent(files []fetchedContent) []byte {
	if len(files) == 0 {
		return nil
	}
	return files[0].data
}

// tomlSection returns the raw text of a TOML table body (everything after
// "[table]" up to the next line that opens another table), using a
// deliberately narrow scanner rather than a general TOML parser: it is only
// asked whether a small, known set of dependency-bearing tables is present
// and non-empty, not to fully parse an arbitrary document.
func tomlSection(data []byte, table string) (string, bool) {
	header := "[" + table + "]"
	text := string(data)
	idx := strings.Index(text, header)
	if idx == -1 {
		return "", false
	}
	rest := text[idx+len(header):]
	if loc := tomlHeaderPattern.FindStringIndex(rest); loc != nil {
		return rest[:loc[0]], true
	}
	return rest, true
}

var tomlHeaderPattern = regexp.MustCompile(`(?m)^\s*\[`)

// tomlSectionKeyCount counts non-blank, non-comment "key = value" lines in
// section, excluding any key named in ignore (for example "python", which
// pyproject.toml's [tool.poetry.dependencies] always carries alongside real
// dependencies).
func tomlSectionKeyCount(section string, ignore ...string) int {
	ignored := make(map[string]bool, len(ignore))
	for _, key := range ignore {
		ignored[key] = true
	}
	count := 0
	for _, line := range strings.Split(section, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, _, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		key = strings.Trim(strings.TrimSpace(key), `"'`)
		if ignored[key] {
			continue
		}
		count++
	}
	return count
}

// tomlArrayNonEmpty reports whether table contains "key = [...]" with at
// least one entry inside the brackets, whether the array is written on one
// line or spans several.
func tomlArrayNonEmpty(data []byte, table, key string) bool {
	section, ok := tomlSection(data, table)
	if !ok {
		return false
	}
	keyPattern := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(key) + `\s*=`)
	loc := keyPattern.FindStringIndex(section)
	if loc == nil {
		return false
	}
	rest := section[loc[1]:]
	start := strings.IndexByte(rest, '[')
	if start == -1 {
		return false
	}
	end := strings.IndexByte(rest[start:], ']')
	if end == -1 {
		return false
	}
	return strings.TrimSpace(rest[start+1:start+end]) != ""
}

// braceBlockNonEmpty finds the first "{...}" block following keyword (using
// balanced-brace matching so a nested block does not close it early) and
// reports whether it contains any non-blank, non-comment line.
func braceBlockNonEmpty(text, keyword string) bool {
	idx := strings.Index(text, keyword)
	if idx == -1 {
		return false
	}
	rest := text[idx+len(keyword):]
	start := strings.IndexByte(rest, '{')
	if start == -1 {
		return false
	}
	depth := 0
	for i := start; i < len(rest); i++ {
		switch rest[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return hasNonCommentContent(rest[start+1 : i])
			}
		}
	}
	return false
}

func hasNonCommentContent(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		return true
	}
	return false
}

// --- npm/Node.js ---

func npmHasDependencies(files []fetchedContent) bool {
	var manifest struct {
		Dependencies         map[string]json.RawMessage `json:"dependencies"`
		DevDependencies      map[string]json.RawMessage `json:"devDependencies"`
		PeerDependencies     map[string]json.RawMessage `json:"peerDependencies"`
		OptionalDependencies map[string]json.RawMessage `json:"optionalDependencies"`
	}
	if json.Unmarshal(soleContent(files), &manifest) != nil {
		return false
	}
	return len(manifest.Dependencies) > 0 || len(manifest.DevDependencies) > 0 ||
		len(manifest.PeerDependencies) > 0 || len(manifest.OptionalDependencies) > 0
}

func classifyNPM(files []fetchedContent, tree map[string]bool, manifestPath string) (model.PolicyStatus, string, string) {
	manager := inferNodePackageManager(files, tree, path.Dir(manifestPath))
	command := map[string]string{
		"npm":  "npm install --package-lock-only",
		"yarn": "yarn install",
		"pnpm": "pnpm install --lockfile-only",
		"bun":  "bun install",
	}[manager]
	return model.PolicyWarning, command, "inferred package manager: " + manager
}

func inferNodePackageManager(files []fetchedContent, tree map[string]bool, dir string) string {
	if data := soleContent(files); data != nil {
		var manifest struct {
			PackageManager string `json:"packageManager"`
		}
		if json.Unmarshal(data, &manifest) == nil {
			switch {
			case strings.HasPrefix(manifest.PackageManager, "pnpm@"):
				return "pnpm"
			case strings.HasPrefix(manifest.PackageManager, "yarn@"):
				return "yarn"
			case strings.HasPrefix(manifest.PackageManager, "bun@"):
				return "bun"
			case strings.HasPrefix(manifest.PackageManager, "npm@"):
				return "npm"
			}
		}
	}
	for _, ancestor := range ancestorDirs(dir) {
		switch {
		case tree[joinPath(ancestor, "pnpm-workspace.yaml")]:
			return "pnpm"
		case tree[joinPath(ancestor, ".yarnrc.yml")], tree[joinPath(ancestor, ".yarnrc")]:
			return "yarn"
		case tree[joinPath(ancestor, "bunfig.toml")]:
			return "bun"
		}
	}
	return "npm"
}

// --- Python (pyproject.toml) ---

func pyprojectHasDependencies(files []fetchedContent) bool {
	data := soleContent(files)
	if data == nil {
		return false
	}
	if tomlArrayNonEmpty(data, "project", "dependencies") {
		return true
	}
	section, ok := tomlSection(data, "tool.poetry.dependencies")
	return ok && tomlSectionKeyCount(section, "python") > 0
}

func classifyPyproject(files []fetchedContent, _ map[string]bool, _ string) (model.PolicyStatus, string, string) {
	data := soleContent(files)
	if _, ok := tomlSection(data, "tool.poetry"); ok {
		return model.PolicyNotice, "poetry lock", "inferred tool: poetry"
	}
	if _, ok := tomlSection(data, "tool.pdm"); ok {
		return model.PolicyNotice, "pdm lock", "inferred tool: pdm"
	}
	return model.PolicyNotice, "uv lock", "inferred tool: uv (default for a PEP 621 project)"
}

// --- Pipenv ---

func pipfileHasDependencies(files []fetchedContent) bool {
	data := soleContent(files)
	if data == nil {
		return false
	}
	for _, table := range []string{"packages", "dev-packages"} {
		if section, ok := tomlSection(data, table); ok && tomlSectionKeyCount(section) > 0 {
			return true
		}
	}
	return false
}

func classifyPipfile(_ []fetchedContent, _ map[string]bool, _ string) (model.PolicyStatus, string, string) {
	return model.PolicyWarning, "pipenv lock", "Pipfile-managed projects are almost always applications"
}

// --- Cargo/Rust ---

func cargoHasDependencies(files []fetchedContent) bool {
	data := soleContent(files)
	if data == nil {
		return false
	}
	for _, table := range []string{"dependencies", "dev-dependencies", "build-dependencies"} {
		if section, ok := tomlSection(data, table); ok && tomlSectionKeyCount(section) > 0 {
			return true
		}
	}
	return false
}

func classifyCargo(_ []fetchedContent, _ map[string]bool, _ string) (model.PolicyStatus, string, string) {
	return model.PolicyNotice, "cargo generate-lockfile", "Cargo.lock is optional for a published library per Cargo's own guidance"
}

// --- Go modules ---

var goRequireLinePattern = regexp.MustCompile(`(?m)^require\s+\S+\s+\S+`)

func goModHasDependencies(files []fetchedContent) bool {
	data := soleContent(files)
	if data == nil {
		return false
	}
	text := string(data)
	if goRequireLinePattern.MatchString(text) {
		return true
	}
	idx := strings.Index(text, "require (")
	if idx == -1 {
		return false
	}
	rest := text[idx+len("require ("):]
	end := strings.Index(rest, ")")
	if end == -1 {
		return false
	}
	return hasNonCommentContent(strings.ReplaceAll(rest[:end], "//", "#"))
}

func classifyGoMod(_ []fetchedContent, tree map[string]bool, manifestPath string) (model.PolicyStatus, string, string) {
	if hasGoMainPackage(tree, path.Dir(manifestPath)) {
		return model.PolicyWarning, "go mod tidy", "a main.go was found under the module root"
	}
	return model.PolicyNotice, "go mod tidy", "no main.go was found under the module root; likely a library module"
}

func hasGoMainPackage(tree map[string]bool, root string) bool {
	prefix := ""
	if root != "." {
		prefix = root + "/"
	}
	for p := range tree {
		if strings.HasPrefix(p, prefix) && path.Base(p) == "main.go" {
			return true
		}
	}
	return false
}

// --- Bundler/Ruby ---

var gemfileGemPattern = regexp.MustCompile(`(?m)^\s*gem\s+['"]`)

func gemfileHasDependencies(files []fetchedContent) bool {
	data := soleContent(files)
	return data != nil && gemfileGemPattern.Match(data)
}

func classifyGemfile(_ []fetchedContent, _ map[string]bool, _ string) (model.PolicyStatus, string, string) {
	return model.PolicyWarning, "bundle lock", "Gemfile-managed projects are typically applications; a published gem library uses a .gemspec instead"
}

// --- Composer/PHP ---

func composerHasDependencies(files []fetchedContent) bool {
	data := soleContent(files)
	if data == nil {
		return false
	}
	var manifest struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if json.Unmarshal(data, &manifest) != nil {
		return false
	}
	delete(manifest.Require, "php")
	return len(manifest.Require) > 0 || len(manifest.RequireDev) > 0
}

func classifyComposer(files []fetchedContent, _ map[string]bool, _ string) (model.PolicyStatus, string, string) {
	data := soleContent(files)
	var manifest struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(data, &manifest) == nil && manifest.Type == "library" {
		return model.PolicyNotice, "composer update --lock", `composer.json declares "type": "library"`
	}
	return model.PolicyWarning, "composer update --lock", "no library type declared"
}

// --- Mix/Elixir ---

var mixDepsTuplePattern = regexp.MustCompile(`\{\s*:\w`)

func mixHasDependencies(files []fetchedContent) bool {
	data := soleContent(files)
	if data == nil {
		return false
	}
	text := string(data)
	idx := strings.Index(text, "deps do")
	if idx == -1 {
		return false
	}
	body := text[idx+len("deps do"):]
	if boundary := nextFunctionBoundary(body); boundary != -1 {
		body = body[:boundary]
	}
	return mixDepsTuplePattern.MatchString(body)
}

func nextFunctionBoundary(text string) int {
	for _, marker := range []string{"\n  def ", "\n  defp ", "\ndef ", "\ndefp "} {
		if idx := strings.Index(text, marker); idx != -1 {
			return idx
		}
	}
	return -1
}

func classifyMix(_ []fetchedContent, _ map[string]bool, _ string) (model.PolicyStatus, string, string) {
	return model.PolicyWarning, "mix deps.get", "Mix projects are treated as applications by default"
}

// --- Pub/Dart ---

func pubspecHasDependencies(files []fetchedContent) bool {
	data := soleContent(files)
	if data == nil {
		return false
	}
	var manifest struct {
		Dependencies    map[string]any `yaml:"dependencies"`
		DevDependencies map[string]any `yaml:"dev_dependencies"`
	}
	if yaml.Unmarshal(data, &manifest) != nil {
		return false
	}
	return len(manifest.Dependencies) > 0 || len(manifest.DevDependencies) > 0
}

func classifyPubspec(_ []fetchedContent, _ map[string]bool, _ string) (model.PolicyStatus, string, string) {
	return model.PolicyWarning, "dart pub get", "Dart/Flutter projects are treated as applications by default"
}

// --- Terraform ---

func terraformHasDependencies(files []fetchedContent) bool {
	var combined strings.Builder
	for _, f := range files {
		combined.Write(f.data)
		combined.WriteByte('\n')
	}
	return braceBlockNonEmpty(combined.String(), "required_providers")
}

func classifyTerraform(_ []fetchedContent, _ map[string]bool, _ string) (model.PolicyStatus, string, string) {
	return model.PolicyWarning, "terraform init", "declares one or more required providers"
}

// --- Nix flakes ---

func flakeHasDependencies(files []fetchedContent) bool {
	data := soleContent(files)
	return data != nil && braceBlockNonEmpty(string(data), "inputs")
}

func classifyFlake(_ []fetchedContent, _ map[string]bool, _ string) (model.PolicyStatus, string, string) {
	return model.PolicyWarning, "nix flake lock", "declares one or more flake inputs"
}

// ecosystems is the data-driven manifest-to-lock mapping. Severity defaults
// reflect a repository-population heuristic, not a per-repository fact:
// ecosystems whose primary use in practice is a deployable application
// default to "warning", and ecosystems whose primary convention is a
// published, reusable package default to "notice". Two ecosystems refine
// that default using a signal the manifest itself provides (composer.json's
// "type" field, and whether a Go module has a main package).
var ecosystems = []ecosystemSpec{
	{
		id:              "npm",
		label:           "npm/Node.js",
		lockCandidates:  []string{"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"},
		findManifests:   manifestsNamed("package.json"),
		hasDependencies: npmHasDependencies,
		classify:        classifyNPM,
	},
	{
		id:              "pyproject",
		label:           "Python (pyproject.toml)",
		lockCandidates:  []string{"uv.lock", "poetry.lock", "pdm.lock"},
		findManifests:   manifestsNamed("pyproject.toml"),
		hasDependencies: pyprojectHasDependencies,
		classify:        classifyPyproject,
	},
	{
		id:              "pipenv",
		label:           "Pipenv",
		lockCandidates:  []string{"Pipfile.lock"},
		findManifests:   manifestsNamed("Pipfile"),
		hasDependencies: pipfileHasDependencies,
		classify:        classifyPipfile,
	},
	{
		id:              "cargo",
		label:           "Cargo/Rust",
		lockCandidates:  []string{"Cargo.lock"},
		findManifests:   manifestsNamed("Cargo.toml"),
		hasDependencies: cargoHasDependencies,
		classify:        classifyCargo,
	},
	{
		id:              "go",
		label:           "Go modules",
		lockCandidates:  []string{"go.sum"},
		findManifests:   manifestsNamed("go.mod"),
		hasDependencies: goModHasDependencies,
		classify:        classifyGoMod,
	},
	{
		id:              "bundler",
		label:           "Bundler/Ruby",
		lockCandidates:  []string{"Gemfile.lock"},
		findManifests:   manifestsNamed("Gemfile"),
		hasDependencies: gemfileHasDependencies,
		classify:        classifyGemfile,
	},
	{
		id:              "composer",
		label:           "Composer/PHP",
		lockCandidates:  []string{"composer.lock"},
		findManifests:   manifestsNamed("composer.json"),
		hasDependencies: composerHasDependencies,
		classify:        classifyComposer,
	},
	{
		id:              "mix",
		label:           "Mix/Elixir",
		lockCandidates:  []string{"mix.lock"},
		findManifests:   manifestsNamed("mix.exs"),
		hasDependencies: mixHasDependencies,
		classify:        classifyMix,
	},
	{
		id:              "pub",
		label:           "Pub/Dart",
		lockCandidates:  []string{"pubspec.lock"},
		findManifests:   manifestsNamed("pubspec.yaml"),
		hasDependencies: pubspecHasDependencies,
		classify:        classifyPubspec,
	},
	{
		id:              "terraform",
		label:           "Terraform",
		lockCandidates:  []string{".terraform.lock.hcl"},
		findManifests:   manifestsForTerraform,
		hasDependencies: terraformHasDependencies,
		classify:        classifyTerraform,
	},
	{
		id:              "nix",
		label:           "Nix flakes",
		lockCandidates:  []string{"flake.lock"},
		findManifests:   manifestsNamed("flake.nix"),
		hasDependencies: flakeHasDependencies,
		classify:        classifyFlake,
	},
}
