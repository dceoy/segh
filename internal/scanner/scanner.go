package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dceoy/segh/internal/config"
	gh "github.com/dceoy/segh/internal/github"
	"github.com/dceoy/segh/internal/logging"
	"github.com/dceoy/segh/internal/model"
	"github.com/dceoy/segh/internal/sarif"
)

type Target struct {
	Repository model.Repository
	Path       string
	Files      []string
}

type Service struct {
	cfg       config.Config
	tokens    gh.TokenProvider
	log       *logging.Logger
	versionMu sync.Mutex
	verified  map[string]error
	resolved  map[string]string
	// toolHome is a single persistent HOME shared by every scanner invocation across
	// the whole Run(), set once before workers start and read-only thereafter. Earlier,
	// each invocation got its own throwaway HOME, so the Aqua-managed scanner binary had
	// to be lazily installed on every single call instead of once; that install then ran
	// inside the prlimit-wrapped, resource-limited execution and could exceed the fsize
	// cap. Sharing one HOME lets the unconstrained verifyVersion call install the binary
	// once, so later resource-limited runs find it already present.
	toolHome string
}

type definition struct {
	name       string
	version    string
	timeout    time.Duration
	cpuSeconds int
	memoryMB   int
	enabled    bool
}

func New(cfg config.Config, tokens gh.TokenProvider, log *logging.Logger) *Service {
	return &Service{cfg: cfg, tokens: tokens, log: log, verified: map[string]error{}, resolved: map[string]string{}}
}

func (s *Service) Run(ctx context.Context, targets []Target, configDigest, runID string) model.ScanRun {
	run := model.ScanRun{
		SchemaVersion: model.ScanSchemaVersion,
		RunID:         runID,
		ConfigDigest:  configDigest,
		StartedAt:     time.Now().UTC(),
		Selected:      len(targets),
	}
	toolHome, err := os.MkdirTemp("", "segh-tools-*")
	if err != nil {
		run.Errors = append(run.Errors, model.RunError{Component: "scan", Kind: "runtime", Message: "create scanner tool directory"})
		run.FinishedAt = time.Now().UTC()
		return run
	}
	defer func() { _ = os.RemoveAll(toolHome) }()
	s.toolHome = toolHome
	totalCtx, cancel := context.WithTimeout(ctx, s.cfg.Execution.TotalTimeout)
	defer cancel()
	type result struct {
		items     []model.ScannerResult
		errs      []model.RunError
		execution model.RepositoryExecution
	}
	type job struct {
		target   Target
		queuedAt time.Time
	}
	jobs := make(chan job)
	results := make(chan result, len(targets))
	var workers sync.WaitGroup
	for range s.cfg.Execution.Concurrency {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for item := range jobs {
				started := time.Now().UTC()
				items, errs, commitSHA := s.scanRepository(totalCtx, item.target)
				finished := time.Now().UTC()
				status := "complete"
				if len(errs) > 0 {
					status = "partial"
				}
				results <- result{
					items: items, errs: errs,
					execution: model.RepositoryExecution{
						Repository: item.target.Repository.FullName,
						QueuedAt:   item.queuedAt, StartedAt: started, FinishedAt: finished,
						QueueMS:    started.Sub(item.queuedAt).Milliseconds(),
						DurationMS: finished.Sub(started).Milliseconds(), Status: status,
						CommitSHA: commitSHA,
					},
				}
			}
		}()
	}
	go func() {
		defer close(results)
		for _, target := range targets {
			queuedAt := time.Now().UTC()
			select {
			case <-totalCtx.Done():
				close(jobs)
				workers.Wait()
				return
			case jobs <- job{target: target, queuedAt: queuedAt}:
			}
		}
		close(jobs)
		workers.Wait()
	}()
	for result := range results {
		run.Results = append(run.Results, result.items...)
		run.Errors = append(run.Errors, result.errs...)
		run.Repositories = append(run.Repositories, result.execution)
	}
	if err := totalCtx.Err(); err != nil {
		run.Errors = append(run.Errors, model.RunError{Component: "scan", Kind: "total_timeout", Message: err.Error()})
	}
	sort.Slice(run.Results, func(i, j int) bool {
		if run.Results[i].Repository != run.Results[j].Repository {
			return run.Results[i].Repository < run.Results[j].Repository
		}
		return run.Results[i].Scanner < run.Results[j].Scanner
	})
	sort.Slice(run.Repositories, func(i, j int) bool {
		return run.Repositories[i].Repository < run.Repositories[j].Repository
	})
	run.FinishedAt = time.Now().UTC()
	return run
}

func (s *Service) scanRepository(ctx context.Context, target Target) ([]model.ScannerResult, []model.RunError, string) {
	repository := target.Repository.FullName
	repoCtx, cancel := context.WithTimeout(ctx, s.cfg.Execution.RepositoryTimeout)
	defer cancel()
	workPath := target.Path
	var cleanup func()
	var commitSHA string
	if workPath == "" && !s.cfg.Execution.DryRun {
		var err error
		workPath, cleanup, commitSHA, err = s.clone(repoCtx, target.Repository)
		if err != nil {
			return nil, []model.RunError{{Repository: repository, Component: "clone", Kind: "runtime", Message: err.Error()}}, ""
		}
		defer cleanup()
	}
	if len(target.Files) > 0 && !s.cfg.Execution.DryRun {
		filtered, filteredCleanup, err := filteredTree(workPath, target.Files)
		if err != nil {
			return nil, []model.RunError{{Repository: repository, Component: "filter", Kind: "untrusted_path", Message: err.Error()}}, ""
		}
		defer filteredCleanup()
		workPath = filtered
	}
	definitions := s.definitions()
	results := make([]model.ScannerResult, 0, len(definitions))
	for _, scanner := range definitions {
		if !scanner.enabled || !supported(scanner.name, workPath, s.cfg.Execution.DryRun) {
			results = append(results, model.ScannerResult{
				Repository: repository, Scanner: scanner.name, Version: scanner.version, Status: model.ScannerSkipped,
			})
			continue
		}
		if s.cfg.Execution.DryRun {
			results = append(results, model.ScannerResult{
				Repository: repository, Scanner: scanner.name, Version: scanner.version, Status: model.ScannerPlanned,
			})
			continue
		}
		results = append(results, s.execute(repoCtx, target.Repository, workPath, scanner))
	}
	var errs []model.RunError
	for _, result := range results {
		if result.Status == model.ScannerFailed {
			errs = append(errs, model.RunError{
				Repository: repository, Component: result.Scanner, Kind: "scanner", Message: result.Error,
			})
		}
	}
	return results, errs, commitSHA
}

func (s *Service) definitions() []definition {
	return []definition{
		fromConfig("zizmor", s.cfg.Scanners.Zizmor),
		fromConfig("trivy", s.cfg.Scanners.Trivy),
		fromConfig("scorecard", s.cfg.Scanners.Scorecard),
		fromConfig("semgrep", s.cfg.Scanners.Semgrep.Scanner),
	}
}

func (s *Service) execute(parent context.Context, repo model.Repository, workPath string, scanner definition) model.ScannerResult {
	started := time.Now().UTC()
	result := model.ScannerResult{
		Repository: repo.FullName, Scanner: scanner.name, Version: scanner.version, StartedAt: started,
	}
	dir := filepath.Join(s.cfg.Output.Directory, "sarif", artifactName(repo.FullName))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		result.Status, result.Error = model.ScannerFailed, "create scanner output directory"
		return result
	}
	extension := ".sarif"
	if scanner.name == "scorecard" {
		extension = ".json"
	}
	result.ResultPath = filepath.Join(dir, scanner.name+extension)
	result.DiagnosticPath = filepath.Join(dir, scanner.name+".log")
	absoluteResultPath, err := filepath.Abs(result.ResultPath)
	if err != nil {
		result.Status, result.Error = model.ScannerFailed, "resolve scanner output path"
		return result
	}
	absoluteDiagnosticPath, err := filepath.Abs(result.DiagnosticPath)
	if err != nil {
		result.Status, result.Error = model.ScannerFailed, "resolve scanner diagnostic path"
		return result
	}
	ctx, cancel := context.WithTimeout(parent, scanner.timeout)
	defer cancel()
	if err := s.verifyVersion(ctx, scanner); err != nil {
		result.Status, result.Error = model.ScannerFailed, err.Error()
		return result
	}
	_, args, stdoutToSARIF := s.command(scanner.name, repo, workPath, absoluteResultPath)
	// Resolve the real installed binary now that verifyVersion (above) has already
	// completed any lazy install unconstrained by resource limits, so the resource-limited
	// execution below never has to install anything itself.
	command, resolveErr := s.resolveExecutable(ctx, scanner)
	if resolveErr != nil {
		result.Status, result.Error = model.ScannerFailed, resolveErr.Error()
		return result
	}
	diagnostic, err := os.OpenFile(absoluteDiagnosticPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- derived beneath the configured output directory.
	if err != nil {
		result.Status, result.Error = model.ScannerFailed, "create scanner diagnostic output"
		return result
	}
	defer func() { _ = diagnostic.Close() }()
	command, args, limitErr := applyResourceLimits(command, args, scanner)
	if limitErr != nil {
		result.Status, result.Error = model.ScannerFailed, limitErr.Error()
		return result
	}
	cmd := exec.CommandContext(ctx, command, args...) // #nosec G204 -- command is a closed internal enum and arguments are passed without a shell.
	cmd.Dir = s.cfg.SourceDir
	cmd.Env = toolEnvironment(s.toolHome)
	if scanner.name == "scorecard" {
		token, tokenErr := s.tokens.Token(ctx)
		if tokenErr != nil {
			result.Status, result.Error = model.ScannerFailed, "obtain read-only token for Scorecard"
			return result
		}
		host, hostErr := scorecardHost(s.cfg.GitHub.WebURL)
		if hostErr != nil {
			result.Status, result.Error = model.ScannerFailed, hostErr.Error()
			return result
		}
		cmd.Env = append(cmd.Env, "GITHUB_AUTH_TOKEN="+token)
		if host != "" {
			cmd.Env = append(cmd.Env, "GH_HOST="+host)
		}
	}
	cmd.Stderr = &limitedWriter{writer: diagnostic, remaining: 10 << 20}
	var sarifOutput *os.File
	if stdoutToSARIF {
		sarifOutput, err = os.OpenFile(absoluteResultPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- derived beneath the configured output directory.
		if err != nil {
			result.Status, result.Error = model.ScannerFailed, "create SARIF output"
			return result
		}
		cmd.Stdout = sarifOutput
	} else {
		cmd.Stdout = &limitedWriter{writer: diagnostic, remaining: 10 << 20}
	}
	err = cmd.Run()
	if sarifOutput != nil {
		if closeErr := sarifOutput.Close(); err == nil {
			err = closeErr
		}
	}
	result.DurationMS = time.Since(started).Milliseconds()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		result.Status, result.Error = model.ScannerFailed, "scanner timeout"
		return result
	}
	findings, parseErr := countFindings(scanner.name, absoluteResultPath)
	if parseErr != nil {
		result.Status = model.ScannerFailed
		if err != nil {
			result.Error = "scanner failed and did not produce valid structured output"
		} else {
			result.Error = parseErr.Error()
		}
		return result
	}
	result.Findings = findings
	if err != nil && !acceptedFindingExit(scanner.name, err) {
		result.Status, result.Error = model.ScannerFailed, exitDescription(err)
		return result
	}
	if findings > 0 {
		result.Status = model.ScannerFindings
	} else {
		result.Status = model.ScannerClean
	}
	return result
}

func (s *Service) verifyVersion(ctx context.Context, scanner definition) error {
	s.versionMu.Lock()
	defer s.versionMu.Unlock()
	key := scanner.name + "@" + scanner.version
	if err, exists := s.verified[key]; exists {
		return err
	}
	err := verifyVersion(ctx, scanner, s.cfg.SourceDir, s.toolHome)
	s.verified[key] = err
	return err
}

// resolveExecutable returns the absolute path of the already-installed scanner binary,
// bypassing any Aqua proxy shim for the resource-limited execution that follows. It is
// cached per scanner name and must only be called after verifyVersion has installed it.
func (s *Service) resolveExecutable(ctx context.Context, scanner definition) (string, error) {
	s.versionMu.Lock()
	defer s.versionMu.Unlock()
	if path, exists := s.resolved[scanner.name]; exists {
		return path, nil
	}
	path, err := resolveExecutable(ctx, scanner.name, s.cfg.SourceDir, s.toolHome)
	if err != nil {
		return "", err
	}
	s.resolved[scanner.name] = path
	return path, nil
}

func (s *Service) command(name string, repo model.Repository, workPath, resultPath string) (string, []string, bool) {
	switch name {
	case "zizmor":
		return "zizmor", []string{"--offline", "--no-config", "--strict-collection", "--format=sarif", workPath}, true
	case "trivy":
		args := []string{
			"fs", "--scanners", "misconfig", "--format", "sarif", "--output", resultPath,
			"--skip-dirs", ".git", "--skip-check-update", "--skip-version-check", "--offline-scan",
		}
		for _, exclude := range s.cfg.Scanners.Trivy.Exclude {
			args = append(args, "--skip-files", exclude)
		}
		return "trivy", append(args, workPath), false
	case "scorecard":
		return "scorecard", []string{"--repo", repo.FullName, "--format", "json", "--output", resultPath, "--show-details"}, false
	case "semgrep":
		args := []string{"scan", "--metrics=off", "--disable-version-check", "--sarif-output", resultPath}
		for _, rule := range s.cfg.Scanners.Semgrep.Rules {
			args = append(args, "--config", rule)
		}
		for _, exclude := range s.cfg.Scanners.Semgrep.Exclude {
			args = append(args, "--exclude", exclude)
		}
		return "semgrep", append(args, workPath), false
	default:
		panic("unknown scanner")
	}
}

func countFindings(scannerName, path string) (int, error) {
	if scannerName != "scorecard" {
		return sarif.CountFile(path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("stat Scorecard JSON: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > 50<<20 {
		return 0, fmt.Errorf("scorecard JSON exceeds 50 MiB")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- fixed, regular, size-bounded Scorecard output path.
	if err != nil {
		return 0, fmt.Errorf("read Scorecard JSON: %w", err)
	}
	var result struct {
		Checks []struct {
			Score int `json:"score"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return 0, fmt.Errorf("decode Scorecard JSON: %w", err)
	}
	findings := 0
	for _, check := range result.Checks {
		if check.Score < 10 {
			findings++
		}
	}
	return findings, nil
}

// clone checks out repo's default branch and returns the worktree path, a cleanup
// function, and the commit SHA actually checked out (resolved after clone, since
// DefaultBranch is a moving ref that may have advanced past the inventory's recorded
// default-branch SHA between inventory time and clone time). Callers must publish
// findings against this resolved SHA, not any earlier-observed one, so that SARIF
// uploads are never attributed to a commit other than the one that was scanned.
func (s *Service) clone(ctx context.Context, repo model.Repository) (string, func(), string, error) {
	if err := s.validateCloneURL(repo); err != nil {
		return "", nil, "", err
	}
	root, err := os.MkdirTemp("", "segh-repository-*")
	if err != nil {
		return "", nil, "", fmt.Errorf("create repository worktree: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(root) }
	destination := filepath.Join(root, "source")
	token, err := s.tokens.Token(ctx)
	if err != nil {
		cleanup()
		return "", nil, "", err
	}
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth=1", "--single-branch", "--no-tags", "--branch", repo.DefaultBranch, "--", repo.CloneURL, destination) // #nosec G204 -- URL is bound to the configured GitHub host/repository and no shell is used.
	cmd.Env = append(safeBaseEnvironment(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=http.extraHeader",
		"GIT_CONFIG_VALUE_0=Authorization: Bearer "+token,
	)
	output, err := limitedCombinedOutput(cmd, 1<<20)
	if err != nil {
		cleanup()
		return "", nil, "", fmt.Errorf("clone failed: %s", sanitizeDiagnostic(output))
	}
	commitSHA, err := resolveHeadSHA(ctx, destination)
	if err != nil {
		cleanup()
		return "", nil, "", err
	}
	return destination, cleanup, commitSHA, nil
}

var fullSHAPattern = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// resolveHeadSHA returns the full commit SHA checked out at worktree. stdout and stderr
// are captured separately, since a stray git advice/warning line on stderr must not be
// parsed as part of the SHA.
func resolveHeadSHA(ctx context.Context, worktree string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", worktree, "rev-parse", "HEAD") // #nosec G204 -- worktree is a path segh itself created via os.MkdirTemp.
	cmd.Env = safeBaseEnvironment()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{writer: &stdout, remaining: 4096}
	cmd.Stderr = &limitedWriter{writer: &stderr, remaining: 4096}
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("resolve scanned commit SHA: %s", sanitizeDiagnostic(stderr.String()))
	}
	sha := strings.TrimSpace(stdout.String())
	if !fullSHAPattern.MatchString(sha) {
		return "", fmt.Errorf("resolve scanned commit SHA: unexpected git output")
	}
	return sha, nil
}

// scorecardHost derives the GH_HOST value Scorecard expects (a bare host, no scheme or
// trailing slash) from the configured GitHub web URL, for GitHub Enterprise Server hosts;
// GITHUB_API_URL/GITHUB_SERVER_URL are not recognized by Scorecard. It returns "" for the
// default github.com host so callers leave GH_HOST unset on the common path rather than
// exercising Scorecard's Enterprise-host handling for a host that needs none of it.
func scorecardHost(webURL string) (string, error) {
	parsed, err := url.Parse(webURL)
	if err != nil || parsed.Host == "" {
		return "", fmt.Errorf("resolve GitHub host for Scorecard")
	}
	if strings.EqualFold(parsed.Host, "github.com") {
		return "", nil
	}
	return parsed.Host, nil
}

func (s *Service) validateCloneURL(repo model.Repository) error {
	cloneURL, err := url.Parse(repo.CloneURL)
	if err != nil || cloneURL.Scheme != "https" || cloneURL.User != nil || cloneURL.RawQuery != "" || cloneURL.Fragment != "" {
		return fmt.Errorf("refusing invalid or non-HTTPS clone URL")
	}
	webURL, err := url.Parse(s.cfg.GitHub.WebURL)
	if err != nil || !strings.EqualFold(cloneURL.Host, webURL.Host) {
		return fmt.Errorf("clone URL host does not match configured GitHub host")
	}
	expected := "/" + repo.FullName
	if cloneURL.EscapedPath() != expected && cloneURL.EscapedPath() != expected+".git" {
		return fmt.Errorf("clone URL path does not match target repository")
	}
	return nil
}

func filteredTree(root string, files []string) (string, func(), error) {
	temp, err := os.MkdirTemp("", "segh-changed-files-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(temp) }
	cleanRoot, err := filepath.Abs(root)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	files, err = includeLocalActionDefinitions(cleanRoot, files)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	for _, candidate := range files {
		if filepath.IsAbs(candidate) {
			cleanup()
			return "", nil, fmt.Errorf("absolute changed-file path rejected")
		}
		clean := filepath.Clean(filepath.FromSlash(candidate))
		if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			cleanup()
			return "", nil, fmt.Errorf("changed-file path escapes repository")
		}
		source := filepath.Join(cleanRoot, clean)
		resolved, err := filepath.EvalSymlinks(source)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			cleanup()
			return "", nil, fmt.Errorf("resolve changed-file path: %w", err)
		}
		relative, err := filepath.Rel(cleanRoot, resolved)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			cleanup()
			return "", nil, fmt.Errorf("changed-file symlink escapes repository")
		}
		info, err := os.Stat(resolved)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			cleanup()
			return "", nil, fmt.Errorf("stat changed-file path: %w", err)
		}
		if info.IsDir() {
			// An unpopulated submodule gitlink surfaces here as an empty directory, not missing content.
			continue
		}
		if !info.Mode().IsRegular() || info.Size() > 10<<20 {
			cleanup()
			return "", nil, fmt.Errorf("changed-file %q exceeds the size limit or is not a regular file", clean)
		}
		destination := filepath.Join(temp, clean)
		if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
			cleanup()
			return "", nil, err
		}
		if err := copyFile(resolved, destination, info.Mode().Perm()&0o600); err != nil {
			cleanup()
			return "", nil, err
		}
	}
	return temp, cleanup, nil
}

// includeLocalActionDefinitions keeps repository-local composite actions available to
// scanners even when a changed workflow starts referring to an otherwise unchanged
// action outside .github. All action manifests are included so transitive ./... action
// references remain resolvable without copying the repository's other unchanged files.
func includeLocalActionDefinitions(root string, files []string) ([]string, error) {
	const maxFilteredFiles = 10_000
	included := make(map[string]bool, len(files))
	result := make([]string, 0, len(files))
	for _, file := range files {
		if !included[file] {
			included[file] = true
			result = append(result, file)
		}
	}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() != "action.yml" && entry.Name() != "action.yaml" {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if included[relative] {
			return nil
		}
		if len(result) >= maxFilteredFiles {
			return fmt.Errorf("changed-file and local-action set exceeds %d files", maxFilteredFiles)
		}
		included[relative] = true
		result = append(result, relative)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("discover local action definitions: %w", err)
	}
	return result, nil
}

func copyFile(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source) // #nosec G304 -- source is resolved and proven inside the repository root.
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode) // #nosec G304 -- destination is inside a unique temporary tree.
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, io.LimitReader(input, 10<<20))
	closeErr := output.Close()
	return errors.Join(copyErr, closeErr)
}

func supported(name, root string, dryRun bool) bool {
	if dryRun || name == "scorecard" || name == "semgrep" {
		return true
	}
	found := false
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || found {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		relative, _ := filepath.Rel(root, path)
		base := strings.ToLower(entry.Name())
		switch name {
		case "zizmor":
			found = strings.HasPrefix(filepath.ToSlash(relative), ".github/") &&
				(strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml"))
		case "trivy":
			found = base == "dockerfile" || strings.HasSuffix(base, ".tf") ||
				strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml") ||
				strings.HasSuffix(base, ".json")
		}
		return nil
	})
	return found
}

func scannerEnvironment() []string {
	return append(safeBaseEnvironment(),
		"NO_COLOR=1",
		"SEMGREP_SEND_METRICS=off",
		"SEMGREP_ENABLE_VERSION_CHECK=0",
	)
}

func safeBaseEnvironment() []string {
	keys := []string{
		"PATH", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "SSL_CERT_FILE", "SSL_CERT_DIR",
		"AQUA_ROOT_DIR", "AQUA_CONFIG",
	}
	env := make([]string, 0, len(keys)+2)
	for _, key := range keys {
		if value, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+value)
		}
	}
	if runtime.GOOS != "windows" {
		env = append(env, "LANG=C.UTF-8")
	}
	return env
}

func acceptedFindingExit(scanner string, err error) bool {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return false
	}
	code := exitErr.ExitCode()
	switch scanner {
	case "zizmor":
		return slices.Contains([]int{1, 10}, code)
	case "semgrep":
		return code == 1
	default:
		return false
	}
}

func exitDescription(err error) string {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return fmt.Sprintf("scanner exited with status %d", exitErr.ExitCode())
	}
	return "scanner execution failed"
}

func scannerTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return 10 * time.Minute
	}
	return timeout
}

func fromConfig(name string, cfg config.Scanner) definition {
	return definition{
		name: name, version: cfg.Version, timeout: scannerTimeout(cfg.Timeout),
		cpuSeconds: cfg.CPUSeconds, memoryMB: cfg.MemoryMB, enabled: cfg.Enabled,
	}
}

// verifyVersion runs the scanner's own --version/version check in the shared, persistent
// toolHome, never under prlimit. For an Aqua-managed scanner this is what actually
// performs the lazy install, so it must have room to write the full binary: unlike the
// resource-limited scan execution later, nothing here is fsize/cpu/memory constrained.
func verifyVersion(ctx context.Context, scanner definition, workingDirectory, toolHome string) error {
	var args []string
	if scanner.name == "scorecard" {
		args = []string{"version"}
	} else {
		args = []string{"--version"}
	}
	cmd := exec.CommandContext(ctx, scanner.name, args...) // #nosec G204 -- scanner name is a closed internal enum.
	cmd.Dir = workingDirectory
	cmd.Env = toolEnvironment(toolHome)
	output, err := limitedCombinedOutput(cmd, 64<<10)
	if err != nil {
		return fmt.Errorf("verify %s version: command failed", scanner.name)
	}
	expected := strings.TrimPrefix(strings.ToLower(scanner.version), "v")
	if !strings.Contains(strings.ToLower(output), expected) {
		return fmt.Errorf("%s version does not match configured immutable version %s", scanner.name, scanner.version)
	}
	return nil
}

// resolveExecutable returns the absolute path of the installed scanner binary. When the
// scanner is managed by Aqua (present in this CI environment), "aqua which <name>" is
// used so the resource-limited execution can invoke the real binary directly instead of
// going back through Aqua's proxy shim. Outside an Aqua-managed environment (e.g. local
// development), the scanner name is returned unchanged and resolved from PATH as before.
func resolveExecutable(ctx context.Context, name, workingDirectory, toolHome string) (string, error) {
	if !commandAvailable("aqua") {
		return name, nil
	}
	cmd := exec.CommandContext(ctx, "aqua", "which", name) // #nosec G204 -- name is a closed internal enum.
	cmd.Dir = workingDirectory
	cmd.Env = toolEnvironment(toolHome)
	output, err := limitedCombinedOutput(cmd, 4<<10)
	if err != nil {
		return "", fmt.Errorf("resolve %s executable path: %s", name, sanitizeDiagnostic(output))
	}
	resolved := strings.TrimSpace(output)
	if resolved == "" {
		return "", fmt.Errorf("aqua did not resolve an executable path for %s", name)
	}
	// "aqua which" computes the expected install path from registry metadata; it does
	// not itself verify the file exists. Fall back to PATH resolution rather than handing
	// exec a path that may not be there, which would otherwise surface as an opaque exec
	// failure indistinguishable from a real scan failure.
	if !existingFile(resolved) {
		return name, nil
	}
	return resolved, nil
}

func commandAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func existingFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func toolEnvironment(toolHome string) []string {
	if toolHome == "" {
		return scannerEnvironment()
	}
	return append(scannerEnvironment(),
		"HOME="+toolHome,
		"XDG_CACHE_HOME="+filepath.Join(toolHome, "cache"),
		"XDG_DATA_HOME="+filepath.Join(toolHome, "data"),
	)
}

func applyResourceLimits(command string, args []string, scanner definition) (string, []string, error) {
	if scanner.cpuSeconds == 0 && scanner.memoryMB == 0 {
		return command, args, nil
	}
	if runtime.GOOS != "linux" {
		return "", nil, fmt.Errorf("scanner resource limits require Linux")
	}
	if _, err := exec.LookPath("prlimit"); err != nil {
		return "", nil, fmt.Errorf("scanner resource limits require prlimit")
	}
	limits := make([]string, 0, 4+len(args))
	if scanner.cpuSeconds > 0 {
		limits = append(limits, fmt.Sprintf("--cpu=%d", scanner.cpuSeconds))
	}
	if scanner.memoryMB > 0 {
		limits = append(limits, fmt.Sprintf("--as=%d", int64(scanner.memoryMB)*1024*1024))
	}
	limits = append(limits, fmt.Sprintf("--fsize=%d", int64(64<<20)))
	limits = append(limits, "--", command)
	limits = append(limits, args...)
	return "prlimit", limits, nil
}

func artifactName(repository string) string {
	sum := sha256.Sum256([]byte(repository))
	name := strings.NewReplacer("/", "-", "\\", "-", ":", "-").Replace(repository)
	name = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '-'
	}, name)
	if len(name) > 80 {
		name = name[:80]
	}
	return name + "-" + hex.EncodeToString(sum[:4])
}

func limitedCombinedOutput(cmd *exec.Cmd, limit int64) (string, error) {
	var buffer bytes.Buffer
	writer := &limitedWriter{writer: &buffer, remaining: limit}
	cmd.Stdout, cmd.Stderr = writer, writer
	err := cmd.Run()
	return buffer.String(), err
}

func sanitizeDiagnostic(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	if len(value) > 512 {
		value = value[:512]
	}
	return value
}

type limitedWriter struct {
	writer    io.Writer
	remaining int64
}

func (w *limitedWriter) Write(data []byte) (int, error) {
	original := len(data)
	if w.remaining <= 0 {
		return original, nil
	}
	if int64(len(data)) > w.remaining {
		data = data[:w.remaining]
	}
	written, err := w.writer.Write(data)
	w.remaining -= int64(written)
	if err != nil {
		return written, err
	}
	return original, nil
}
