package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dceoy/segh/internal/batch"
	"github.com/dceoy/segh/internal/config"
	"github.com/dceoy/segh/internal/gate"
	gh "github.com/dceoy/segh/internal/github"
	"github.com/dceoy/segh/internal/logging"
	"github.com/dceoy/segh/internal/merge"
	"github.com/dceoy/segh/internal/model"
	"github.com/dceoy/segh/internal/output"
	"github.com/dceoy/segh/internal/policy"
	"github.com/dceoy/segh/internal/publication"
	"github.com/dceoy/segh/internal/report"
	"github.com/dceoy/segh/internal/scanner"
)

const (
	exitSuccess    = 0
	exitFindings   = 1
	exitUsage      = 2
	exitAuth       = 3
	exitIncomplete = 4
	exitRuntime    = 5
)

type commandError struct {
	code int
	err  error
}

func (e *commandError) Error() string { return e.err.Error() }
func (e *commandError) Unwrap() error { return e.err }

type globals struct {
	configPath string
	webURL     string
	apiURL     string
	graphqlURL string
}

func Run(ctx context.Context, args []string, version string, stdout, stderr io.Writer) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		printHelp(stdout, version)
		return nil
	}
	if len(args) == 1 && (args[0] == "--version" || args[0] == "version") {
		writef(stdout, "%s\n", version)
		return nil
	}
	global := flag.NewFlagSet("segh", flag.ContinueOnError)
	global.SetOutput(stderr)
	options := globals{}
	global.StringVar(&options.configPath, "config", "segh.yaml", "path to strict versioned configuration")
	global.StringVar(&options.webURL, "github-web-url", "", "override GitHub web URL")
	global.StringVar(&options.apiURL, "github-api-url", "", "override GitHub REST API URL")
	global.StringVar(&options.graphqlURL, "github-graphql-url", "", "override GitHub GraphQL API URL")
	global.Usage = func() { printHelp(stdout, version) }
	if err := global.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return usageError(err)
	}
	remaining := global.Args()
	if len(remaining) == 0 {
		printHelp(stdout, version)
		return nil
	}
	command := remaining[0]
	if command == "help" || command == "--help" || command == "-h" {
		printHelp(stdout, version)
		return nil
	}
	if command == "version" || command == "--version" {
		writef(stdout, "%s\n", version)
		return nil
	}

	cfg, raw, err := config.Load(options.configPath)
	if err != nil {
		return usageError(err)
	}
	if options.webURL != "" {
		cfg.GitHub.WebURL = options.webURL
	}
	if options.apiURL != "" {
		cfg.GitHub.APIURL = options.apiURL
	}
	if options.graphqlURL != "" {
		cfg.GitHub.GraphQLURL = options.graphqlURL
	}
	if err := cfg.Validate(filepath.Dir(options.configPath)); err != nil {
		return usageError(err)
	}
	log := logging.New(stderr)
	commandArgs := remaining[1:]
	switch command {
	case "validate":
		writef(stdout, "configuration is valid\n")
		return nil
	case "inventory":
		return runInventory(ctx, cfg, commandArgs, stdout, log)
	case "audit":
		return runAudit(cfg, commandArgs, stdout)
	case "scan":
		return runScan(ctx, cfg, raw, commandArgs, stdout, log)
	case "batch":
		return runBatch(commandArgs, stdout)
	case "merge":
		return runMerge(commandArgs, stdout)
	case "publish":
		return runPublish(ctx, cfg, commandArgs, stdout, log)
	case "report":
		return runReport(commandArgs, stdout)
	case "remediate":
		return runRemediate(commandArgs, stdout)
	case "pr-gate":
		return runGate(cfg, commandArgs, stdout)
	default:
		return usageError(fmt.Errorf("unknown command %q", command))
	}
}

func ExitCode(err error) int {
	if err == nil {
		return exitSuccess
	}
	var commandErr *commandError
	if errors.As(err, &commandErr) {
		return commandErr.code
	}
	return exitRuntime
}

func runInventory(ctx context.Context, cfg config.Config, args []string, stdout io.Writer, log *logging.Logger) error {
	flags := commandFlags("inventory")
	outputPath := flags.String("output", filepath.Join(cfg.Output.Directory, "inventory.json"), "inventory JSON output")
	if err := flags.Parse(args); err != nil {
		return usageError(err)
	}
	if flags.NArg() != 0 {
		return usageError(fmt.Errorf("inventory does not accept positional arguments"))
	}
	_, client, err := githubClient(cfg, log)
	if err != nil {
		return authError(err)
	}
	inventory, runErr := gh.NewInventoryService(cfg, client, log).Run(ctx)
	if err := output.JSON(*outputPath, inventory); err != nil {
		return runtimeError(err)
	}
	if cfg.Output.JSONL {
		if err := output.JSONL(strings.TrimSuffix(*outputPath, filepath.Ext(*outputPath))+".jsonl", inventory.Repositories); err != nil {
			return runtimeError(err)
		}
	}
	writef(stdout, "wrote %d repositories to %s\n", len(inventory.Repositories), *outputPath)
	if runErr != nil || !inventory.Complete {
		var apiErr *gh.APIError
		if errors.As(runErr, &apiErr) && (apiErr.StatusCode == 401 || apiErr.StatusCode == 403) {
			return authError(fmt.Errorf("inventory authentication or permission failure"))
		}
		return incompleteError(fmt.Errorf("inventory is incomplete"))
	}
	return nil
}

func runAudit(cfg config.Config, args []string, stdout io.Writer) error {
	flags := commandFlags("audit")
	inputPath := flags.String("inventory", filepath.Join(cfg.Output.Directory, "inventory.json"), "inventory JSON input")
	outputPath := flags.String("output", filepath.Join(cfg.Output.Directory, "audit.json"), "audit JSON output")
	markdownPath := flags.String("markdown", filepath.Join(cfg.Output.Directory, "audit.md"), "Markdown summary output")
	if err := flags.Parse(args); err != nil {
		return usageError(err)
	}
	var inventory model.Inventory
	if err := readJSON(*inputPath, &inventory); err != nil {
		return runtimeError(err)
	}
	if inventory.SchemaVersion != model.InventorySchemaVersion {
		return usageError(fmt.Errorf("unsupported inventory schema version %d", inventory.SchemaVersion))
	}
	audit := policy.New(cfg, time.Now()).Evaluate(inventory)
	if err := output.JSON(*outputPath, audit); err != nil {
		return runtimeError(err)
	}
	if cfg.Output.JSONL {
		if err := output.JSONL(strings.TrimSuffix(*outputPath, filepath.Ext(*outputPath))+".jsonl", audit.Results); err != nil {
			return runtimeError(err)
		}
	}
	consolidated := report.Build(&inventory, &audit, nil, nil, -1)
	if err := output.Text(*markdownPath, report.Markdown(consolidated)); err != nil {
		return runtimeError(err)
	}
	writef(stdout, "wrote %d policy results to %s\n", len(audit.Results), *outputPath)
	if policy.Violations(audit) {
		return findingsError(fmt.Errorf("policy violations found"))
	}
	if policy.Partial(audit) {
		return incompleteError(fmt.Errorf("policy coverage is incomplete"))
	}
	return nil
}

func runScan(ctx context.Context, cfg config.Config, raw []byte, args []string, stdout io.Writer, log *logging.Logger) error {
	flags := commandFlags("scan")
	inventoryPath := flags.String("inventory", "", "inventory JSON containing repositories to scan")
	repository := flags.String("repository", "", "target owner/repository for a local scan")
	localPath := flags.String("path", "", "existing repository path; omitted to clone inventory targets")
	changedFileList := flags.String("changed-file-list", "", "newline-delimited changed repository-relative paths")
	changedFileList0 := flags.String("changed-file-list0", "", "NUL-delimited changed repository-relative paths")
	outputPath := flags.String("output", filepath.Join(cfg.Output.Directory, "scan.json"), "scan result JSON output")
	outputDir := flags.String("output-directory", cfg.Output.Directory, "scanner artifact output directory")
	runID := flags.String("run-id", defaultRunID(), "stable run identifier")
	dryRun := flags.Bool("dry-run", cfg.Execution.DryRun, "plan without cloning or running scanners")
	if err := flags.Parse(args); err != nil {
		return usageError(err)
	}
	cfg.Execution.DryRun = *dryRun
	cfg.Output.Directory = *outputDir
	var targets []scanner.Target
	if *inventoryPath != "" {
		var inventory model.Inventory
		if err := readJSON(*inventoryPath, &inventory); err != nil {
			return runtimeError(err)
		}
		for _, repo := range inventory.Repositories {
			targets = append(targets, scanner.Target{Repository: repo})
		}
	} else {
		if *localPath == "" {
			return usageError(fmt.Errorf("scan requires --inventory or --path"))
		}
		absolute, err := filepath.Abs(*localPath)
		if err != nil {
			return usageError(err)
		}
		info, err := os.Stat(absolute)
		if err != nil || !info.IsDir() {
			return usageError(fmt.Errorf("--path must be an existing directory"))
		}
		name := *repository
		if name == "" {
			name = cfg.Organization + "/" + filepath.Base(absolute)
		}
		repo := model.Repository{
			FullName: name, HTMLURL: strings.TrimRight(cfg.GitHub.WebURL, "/") + "/" + name,
			DefaultBranch: "HEAD",
		}
		targets = append(targets, scanner.Target{Repository: repo, Path: absolute})
	}
	if *changedFileList != "" && *changedFileList0 != "" {
		return usageError(fmt.Errorf("use only one of --changed-file-list and --changed-file-list0"))
	}
	if *changedFileList != "" || *changedFileList0 != "" {
		if len(targets) != 1 {
			return usageError(fmt.Errorf("changed-file lists require a single local target"))
		}
		listPath, separator := *changedFileList, "\n"
		if *changedFileList0 != "" {
			listPath, separator = *changedFileList0, "\x00"
		}
		files, err := readList(listPath, separator, 10_000)
		if err != nil {
			return usageError(err)
		}
		targets[0].Files = files
	}
	var tokens gh.TokenProvider = emptyToken{}
	if requiresAuth(targets, cfg) {
		auth, err := gh.NewAuth(cfg, log)
		if err != nil {
			return authError(err)
		}
		tokens = auth
	}
	scanRun := scanner.New(cfg, tokens, log).Run(ctx, targets, config.Digest(raw), *runID)
	if err := output.JSON(*outputPath, scanRun); err != nil {
		return runtimeError(err)
	}
	if cfg.Output.JSONL {
		if err := output.JSONL(strings.TrimSuffix(*outputPath, filepath.Ext(*outputPath))+".jsonl", scanRun.Results); err != nil {
			return runtimeError(err)
		}
	}
	writef(stdout, "wrote %d scanner results to %s\n", len(scanRun.Results), *outputPath)
	if err := scanRunError(scanRun); err != nil {
		return runtimeError(err)
	}
	if hasScannerStatus(scanRun, model.ScannerFindings) {
		return findingsError(fmt.Errorf("scanner findings found"))
	}
	return nil
}

func runBatch(args []string, stdout io.Writer) error {
	flags := commandFlags("batch")
	inventoryPath := flags.String("inventory", "segh-results/inventory.json", "inventory JSON input")
	outputDir := flags.String("output-directory", "segh-results/batches", "batch output directory")
	matrixPath := flags.String("matrix", "segh-results/batches/matrix.json", "matrix JSON output")
	size := flags.Int("size", 25, "repositories per deterministic batch")
	var repositories stringList
	flags.Var(&repositories, "repository", "exact repository to include (repeatable)")
	if err := flags.Parse(args); err != nil {
		return usageError(err)
	}
	var inventory model.Inventory
	if err := readJSON(*inventoryPath, &inventory); err != nil {
		return runtimeError(err)
	}
	matrix, err := batch.Write(inventory, *size, repositories, *outputDir)
	if err != nil {
		return usageError(err)
	}
	if err := output.JSON(*matrixPath, matrix); err != nil {
		return runtimeError(err)
	}
	writef(stdout, "wrote %d deterministic batches to %s\n", len(matrix.Include), *outputDir)
	return nil
}

func runMerge(args []string, stdout io.Writer) error {
	flags := commandFlags("merge")
	var scanPaths stringList
	flags.Var(&scanPaths, "scan", "scan JSON file or directory (repeatable)")
	outputPath := flags.String("output", "segh-results/scan-merged.json", "merged scan JSON output")
	if err := flags.Parse(args); err != nil {
		return usageError(err)
	}
	if len(scanPaths) == 0 {
		return usageError(fmt.Errorf("merge requires at least one --scan"))
	}
	paths, err := expandNamedFiles(scanPaths, "scan.json")
	if err != nil {
		return runtimeError(err)
	}
	var runs []model.ScanRun
	for _, path := range paths {
		var run model.ScanRun
		if err := readJSON(path, &run); err != nil {
			return runtimeError(err)
		}
		runs = append(runs, run)
	}
	merged, err := merge.Scans(runs)
	if err != nil {
		return usageError(err)
	}
	if err := output.JSON(*outputPath, merged); err != nil {
		return runtimeError(err)
	}
	writef(stdout, "merged %d scan runs into %s\n", len(runs), *outputPath)
	return nil
}

func runPublish(ctx context.Context, cfg config.Config, args []string, stdout io.Writer, log *logging.Logger) error {
	flags := commandFlags("publish")
	scanPath := flags.String("scan", filepath.Join(cfg.Output.Directory, "scan.json"), "scan result JSON input")
	inventoryPath := flags.String("inventory", "", "inventory input for per-repository SHA/ref publication")
	commitSHA := flags.String("commit-sha", "", "full target commit SHA")
	ref := flags.String("ref", "", "full target ref")
	outputPath := flags.String("output", filepath.Join(cfg.Output.Directory, "publications.json"), "publication JSON output")
	if err := flags.Parse(args); err != nil {
		return usageError(err)
	}
	if *inventoryPath == "" && (*commitSHA == "" || *ref == "") {
		return usageError(fmt.Errorf("publish requires --inventory or both --commit-sha and --ref"))
	}
	var scanRun model.ScanRun
	if err := readJSON(*scanPath, &scanRun); err != nil {
		return runtimeError(err)
	}
	if !cfg.Publication.Enabled {
		publications := retainedPublications(scanRun, cfg, *commitSHA, *ref)
		if err := output.JSON(*outputPath, publications); err != nil {
			return runtimeError(err)
		}
		writef(stdout, "SARIF publication is disabled; results are retained locally\n")
		return nil
	}
	_, client, err := githubClient(cfg, log)
	if err != nil {
		return authError(err)
	}
	publisher := publication.New(client, cfg.Publication.PollTimeout)
	inventoryRepos := map[string]model.Repository{}
	if *inventoryPath != "" {
		var inventory model.Inventory
		if err := readJSON(*inventoryPath, &inventory); err != nil {
			return runtimeError(err)
		}
		for _, repository := range inventory.Repositories {
			inventoryRepos[repository.FullName] = repository
		}
	}
	var publications []model.Publication
	for _, result := range scanRun.Results {
		if result.ResultPath == "" || !strings.EqualFold(filepath.Ext(result.ResultPath), ".sarif") ||
			result.Status == model.ScannerFailed || result.Status == model.ScannerSkipped || result.Status == model.ScannerPlanned {
			continue
		}
		category := cfg.Publication.CategoryPrefix + "/" + result.Scanner
		targetSHA, targetRef := *commitSHA, *ref
		if *inventoryPath != "" {
			repository, exists := inventoryRepos[result.Repository]
			if !exists || repository.DefaultBranchSHA.State != model.Available {
				publications = append(publications, model.Publication{
					Repository: result.Repository, Scanner: result.Scanner, Category: category,
					Status: model.PublicationRejected, Error: "inventory lacks a known default-branch SHA",
				})
				continue
			}
			targetSHA = repository.DefaultBranchSHA.Value
			targetRef = "refs/heads/" + repository.DefaultBranch
		}
		sarifPath, pathErr := secureArtifactPath(cfg.Output.Directory, result.ResultPath)
		if pathErr != nil {
			publications = append(publications, model.Publication{
				Repository: result.Repository, Scanner: result.Scanner, Category: category,
				CommitSHA: targetSHA, Ref: targetRef, Status: model.PublicationRejected,
				Error: "SARIF result path is outside the configured output directory",
			})
			continue
		}
		publications = append(publications, publisher.Upload(ctx, result.Repository, result.Scanner, category, targetSHA, targetRef, sarifPath))
	}
	if err := output.JSON(*outputPath, publications); err != nil {
		return runtimeError(err)
	}
	writef(stdout, "wrote %d publication results to %s\n", len(publications), *outputPath)
	for _, item := range publications {
		if item.Status == model.PublicationRejected {
			return authError(fmt.Errorf("one or more SARIF uploads were rejected"))
		}
		if item.Status == model.PublicationFailed || item.Status == model.PublicationUnsupported {
			return incompleteError(fmt.Errorf("one or more SARIF uploads were not completed"))
		}
	}
	return nil
}

func runReport(args []string, stdout io.Writer) error {
	flags := commandFlags("report")
	inventoryPath := flags.String("inventory", "", "inventory JSON input")
	auditPath := flags.String("audit", "", "audit JSON input")
	scanPath := flags.String("scan", "", "scan JSON input")
	expectedRepositories := flags.Int("expected-repositories", -1, "number of distinct repositories the scan stage was expected to cover; marks coverage partial when the scan is missing or covers fewer (-1 disables this check)")
	previousScanPath := flags.String("previous-scan", "", "optional prior scan JSON for trend input")
	var publicationPaths stringList
	flags.Var(&publicationPaths, "publications", "publication JSON file or directory (repeatable)")
	outputPath := flags.String("output", "segh-results/report.json", "consolidated JSON output")
	markdownPath := flags.String("markdown", "segh-results/report.md", "Markdown output")
	if err := flags.Parse(args); err != nil {
		return usageError(err)
	}
	var inventory *model.Inventory
	var audit *model.Audit
	var scanRun *model.ScanRun
	var publications []model.Publication
	if *inventoryPath != "" {
		inventory = &model.Inventory{}
		if err := readJSON(*inventoryPath, inventory); err != nil {
			return runtimeError(err)
		}
	}
	if *auditPath != "" {
		audit = &model.Audit{}
		if err := readJSON(*auditPath, audit); err != nil {
			return runtimeError(err)
		}
	}
	if *scanPath != "" {
		scanRun = &model.ScanRun{}
		if err := readJSON(*scanPath, scanRun); err != nil {
			return runtimeError(err)
		}
	}
	if len(publicationPaths) > 0 {
		paths, err := expandNamedFiles(publicationPaths, "publications.json")
		if err != nil {
			return runtimeError(err)
		}
		for _, path := range paths {
			var batch []model.Publication
			if err := readJSON(path, &batch); err != nil {
				return runtimeError(err)
			}
			publications = append(publications, batch...)
		}
	}
	result := report.Build(inventory, audit, scanRun, publications, *expectedRepositories)
	if *previousScanPath != "" {
		var previous model.ScanRun
		if err := readJSON(*previousScanPath, &previous); err != nil {
			return runtimeError(err)
		}
		report.AddTrend(&result, previous)
	}
	if err := output.JSON(*outputPath, result); err != nil {
		return runtimeError(err)
	}
	if err := output.Text(*markdownPath, report.Markdown(result)); err != nil {
		return runtimeError(err)
	}
	writef(stdout, "wrote consolidated report to %s and %s\n", *outputPath, *markdownPath)
	return nil
}

func runRemediate(args []string, stdout io.Writer) error {
	flags := commandFlags("remediate")
	auditPath := flags.String("audit", "segh-results/audit.json", "audit JSON input")
	outputPath := flags.String("output", "segh-results/remediation.md", "remediation plan output")
	if err := flags.Parse(args); err != nil {
		return usageError(err)
	}
	var audit model.Audit
	if err := readJSON(*auditPath, &audit); err != nil {
		return runtimeError(err)
	}
	var builder strings.Builder
	builder.WriteString("# segh remediation plan\n\n")
	builder.WriteString("This is guidance only. `segh` does not mutate repository or organization settings.\n\n")
	groups := map[string][]model.PolicyResult{}
	for _, result := range audit.Results {
		if result.Status == model.PolicyFail {
			groups[policy.RemediationClass(result.PolicyID)] = append(groups[policy.RemediationClass(result.PolicyID)], result)
		}
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(&builder, "## %s\n\n", key)
		for _, result := range groups[key] {
			fmt.Fprintf(&builder, "- `%s` / `%s`: %s\n", result.Repository, result.PolicyID, result.Remediation)
		}
		builder.WriteByte('\n')
	}
	if len(keys) == 0 {
		builder.WriteString("No unsuppressed policy violations require remediation.\n")
	}
	if err := output.Text(*outputPath, builder.String()); err != nil {
		return runtimeError(err)
	}
	writef(stdout, "wrote remediation plan to %s\n", *outputPath)
	return nil
}

func runGate(cfg config.Config, args []string, stdout io.Writer) error {
	flags := commandFlags("pr-gate")
	var current, baseline stringList
	flags.Var(&current, "current", "current SARIF file or directory (repeatable)")
	flags.Var(&baseline, "baseline", "baseline SARIF file or directory (repeatable)")
	renameMap0 := flags.String("rename-map0", "", "NUL-delimited old-path/new-path pairs to align renamed baseline findings")
	outputPath := flags.String("output", filepath.Join(cfg.Output.Directory, "pr-gate.json"), "gate JSON output")
	markdownPath := flags.String("markdown", filepath.Join(cfg.Output.Directory, "pr-gate.md"), "gate Markdown output")
	annotations := flags.Bool("annotations", false, "emit escaped GitHub workflow commands")
	if err := flags.Parse(args); err != nil {
		return usageError(err)
	}
	if len(current) == 0 {
		return usageError(fmt.Errorf("pr-gate requires at least one --current path"))
	}
	renames, err := readRenameMap(*renameMap0)
	if err != nil {
		return usageError(err)
	}
	result, err := gate.Compare(current, baseline, cfg.PullRequest, renames)
	if err != nil {
		return runtimeError(err)
	}
	if err := output.JSON(*outputPath, result); err != nil {
		return runtimeError(err)
	}
	if err := output.Text(*markdownPath, gate.Markdown(result)); err != nil {
		return runtimeError(err)
	}
	if *annotations {
		for _, annotation := range gate.Annotations(result) {
			writef(stdout, "%s\n", annotation)
		}
	}
	writef(stdout, "new=%d blocking=%d report_only=%t\n", len(result.NewFindings), len(result.BlockingFindings), result.ReportOnly)
	if result.Failed() {
		return findingsError(fmt.Errorf("new blocking security findings found"))
	}
	return nil
}

func githubClient(cfg config.Config, log *logging.Logger) (*gh.Auth, *gh.Client, error) {
	auth, err := gh.NewAuth(cfg, log)
	if err != nil {
		return nil, nil, err
	}
	client, err := gh.NewClient(cfg, auth, log)
	return auth, client, err
}

type emptyToken struct{}

func (emptyToken) Token(context.Context) (string, error) { return "", nil }

func requiresAuth(targets []scanner.Target, cfg config.Config) bool {
	if cfg.Execution.DryRun {
		return false
	}
	if cfg.Scanners.Scorecard.Enabled {
		return true
	}
	for _, target := range targets {
		if target.Path == "" {
			return true
		}
	}
	return false
}

func retainedPublications(scanRun model.ScanRun, cfg config.Config, sha, ref string) []model.Publication {
	var results []model.Publication
	for _, item := range scanRun.Results {
		if item.ResultPath == "" || !strings.EqualFold(filepath.Ext(item.ResultPath), ".sarif") {
			continue
		}
		results = append(results, model.Publication{
			Repository: item.Repository, Scanner: item.Scanner,
			Category:  cfg.Publication.CategoryPrefix + "/" + item.Scanner,
			CommitSHA: sha, Ref: ref, Status: model.PublicationRetained,
		})
	}
	return results
}

func hasScannerStatus(run model.ScanRun, status model.ScannerStatus) bool {
	for _, result := range run.Results {
		if result.Status == status {
			return true
		}
	}
	return false
}

// scanRunError reports a runtime failure whenever the scan did not fully complete,
// even when no individual ScannerResult carries a failed status: a clone/filter
// error or a total-timeout can abort a repository before any scanner runs.
func scanRunError(run model.ScanRun) error {
	if hasScannerStatus(run, model.ScannerFailed) {
		return fmt.Errorf("one or more scanners failed")
	}
	if len(run.Errors) > 0 {
		return fmt.Errorf("one or more repositories were not fully scanned")
	}
	if len(run.Repositories) < run.Selected {
		return fmt.Errorf("scan run is incomplete: %d of %d selected repositories were scanned", len(run.Repositories), run.Selected)
	}
	return nil
}

func readJSON(path string, value any) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() > 100<<20 {
		return fmt.Errorf("%s must be a regular JSON file no larger than 100 MiB", path)
	}
	file, err := os.Open(path) // #nosec G304 -- command inputs explicitly select normalized JSON artifacts.
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	decoder := json.NewDecoder(io.LimitReader(file, 100<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("decode %s: trailing data", path)
	}
	return nil
}

// readRenameMap parses a NUL-delimited old-path,new-path,old-path,new-path,... list, as
// emitted by a caller workflow that already detected renames via "git diff --name-status
// -M -z", into a map of old path to new path.
func readRenameMap(path string) (map[string]string, error) {
	if path == "" {
		return nil, nil
	}
	entries, err := readList(path, "\x00", 20_000)
	if err != nil {
		return nil, err
	}
	if len(entries)%2 != 0 {
		return nil, fmt.Errorf("rename map must contain old/new path pairs, got %d entries", len(entries))
	}
	renames := make(map[string]string, len(entries)/2)
	for i := 0; i < len(entries); i += 2 {
		renames[entries[i]] = entries[i+1]
	}
	return renames, nil
}

func readList(path, separator string, limit int) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 5<<20 {
		return nil, fmt.Errorf("%s exceeds 5 MiB", path)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- the CLI operator selected a regular, size-bounded list.
	if err != nil {
		return nil, err
	}
	var values []string
	value := string(data)
	if separator == "\n" {
		value = strings.ReplaceAll(value, "\r\n", "\n")
	}
	for _, line := range strings.Split(value, separator) {
		if line == "" {
			continue
		}
		values = append(values, line)
		if len(values) > limit {
			return nil, fmt.Errorf("%s exceeds %d entries", path, limit)
		}
	}
	return values, nil
}

func secureArtifactPath(root, candidate string) (string, error) {
	if candidate == "" {
		return "", fmt.Errorf("empty artifact path")
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	absoluteCandidate, err := filepath.Abs(candidate)
	if err != nil {
		return "", err
	}
	resolvedRoot, err := filepath.EvalSymlinks(absoluteRoot)
	if err != nil {
		return "", err
	}
	resolvedCandidate, err := filepath.EvalSymlinks(absoluteCandidate)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(resolvedRoot, resolvedCandidate)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("artifact path escapes configured output directory")
	}
	info, err := os.Stat(resolvedCandidate)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("artifact path is not a regular file")
	}
	return resolvedCandidate, nil
}

func expandNamedFiles(paths []string, filename string) ([]string, error) {
	var expanded []string
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			expanded = append(expanded, path)
			continue
		}
		err = filepath.WalkDir(path, func(current string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !entry.IsDir() && entry.Name() == filename {
				expanded = append(expanded, current)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(expanded)
	if len(expanded) == 0 {
		return nil, fmt.Errorf("no %s files found", filename)
	}
	return expanded, nil
}

func commandFlags(name string) *flag.FlagSet {
	flags := flag.NewFlagSet("segh "+name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	return flags
}

func printHelp(out io.Writer, version string) {
	writef(out, `segh %s - SecOps toolkit for GitHub

Usage:
  segh [global options] <command> [options]

Commands:
  validate     Strictly validate segh.yaml
  inventory    Enumerate and classify organization repositories
  audit        Evaluate inventory against expected-state policy
  scan         Run fixed security scanner adapters
  batch        Split an inventory into deterministic matrix batches
  merge        Merge isolated batch scan results
  publish      Upload scanner SARIF to target repositories
  report       Build deterministic JSON and Markdown reports
  remediate    Generate non-mutating remediation guidance
  pr-gate      Compare SARIF with a baseline and gate new findings
  version      Print the build version

Global options:
  --config PATH                 Configuration file (default segh.yaml)
  --github-web-url URL          GitHub Enterprise web URL override
  --github-api-url URL          GitHub Enterprise REST URL override
  --github-graphql-url URL      GitHub Enterprise GraphQL URL override

Exit codes:
  0 success
  1 policy violations or blocking findings
  2 invalid arguments or configuration
  3 authentication or permission failure
  4 partial/unsupported coverage
  5 scanner or runtime failure
`, version)
}

func writef(out io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(out, format, args...)
}

func defaultRunID() string {
	if value := os.Getenv("GITHUB_RUN_ID"); value != "" {
		return value
	}
	return time.Now().UTC().Format("20060102T150405Z")
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func usageError(err error) error      { return &commandError{code: exitUsage, err: err} }
func authError(err error) error       { return &commandError{code: exitAuth, err: err} }
func findingsError(err error) error   { return &commandError{code: exitFindings, err: err} }
func incompleteError(err error) error { return &commandError{code: exitIncomplete, err: err} }
func runtimeError(err error) error    { return &commandError{code: exitRuntime, err: err} }
