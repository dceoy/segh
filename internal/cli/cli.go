package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/dceoy/segh/internal/config"
	gh "github.com/dceoy/segh/internal/github"
	"github.com/dceoy/segh/internal/model"
	"github.com/dceoy/segh/internal/output"
	"github.com/dceoy/segh/internal/policy"
	"github.com/dceoy/segh/internal/report"
	"github.com/dceoy/segh/internal/sourcescan"
)

const (
	exitSuccess    = 0
	exitFindings   = 1
	exitUsage      = 2
	exitAuth       = 3
	exitIncomplete = 4
	exitRuntime    = 5

	defaultInventoryOutput    = "segh-results/inventory.json"
	defaultAuditOutput        = "segh-results/audit.json"
	defaultMarkdownOutput     = "segh-results/report.md"
	defaultScanManifestOutput = "segh-results/scan-manifest.json"
	defaultScanSummaryOutput  = "segh-results/scan-summary.json"
	defaultScanMarkdownOutput = "segh-results/scan-report.md"
)

var newGitHubAPI = func() (gh.API, error) {
	return gh.NewClient()
}

type commandError struct {
	code int
	err  error
}

func (e *commandError) Error() string { return e.err.Error() }
func (e *commandError) Unwrap() error { return e.err }

func Run(ctx context.Context, args []string, version string, stdout, stderr io.Writer) error {
	if len(args) == 0 || len(args) == 1 && slicesHelp(args[0]) {
		printHelp(stdout, version)
		return nil
	}
	if len(args) == 1 && slicesVersion(args[0]) {
		writef(stdout, "%s\n", version)
		return nil
	}
	switch args[0] {
	case "audit":
		return runAudit(ctx, args[1:], stdout, stderr)
	case "scan-plan":
		return runScanPlan(ctx, args[1:], stdout, stderr)
	case "scan-summary":
		return runScanSummary(args[1:], stdout, stderr)
	default:
		return usageError(fmt.Errorf("unknown command %q", args[0]))
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

func runAudit(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("segh audit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "segh.yaml", "path to strict version 5 configuration")
	validateOnly := flags.Bool("validate-only", false, "validate configuration without GitHub credentials")
	inventoryPath := flags.String("inventory-output", defaultInventoryOutput, "inventory JSON output")
	auditPath := flags.String("audit-output", defaultAuditOutput, "audit JSON output")
	markdownPath := flags.String("markdown-output", defaultMarkdownOutput, "Markdown output")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return usageError(err)
	}
	if flags.NArg() != 0 {
		return usageError(fmt.Errorf("audit does not accept positional arguments"))
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return usageError(err)
	}
	if *validateOnly {
		writef(stdout, "configuration is valid\n")
		return nil
	}
	if *inventoryPath == "" || *auditPath == "" || *markdownPath == "" {
		return usageError(fmt.Errorf("output paths must not be empty"))
	}
	cleanInventoryPath := filepath.Clean(*inventoryPath)
	cleanAuditPath := filepath.Clean(*auditPath)
	cleanMarkdownPath := filepath.Clean(*markdownPath)
	if cleanInventoryPath == cleanAuditPath || cleanInventoryPath == cleanMarkdownPath ||
		cleanAuditPath == cleanMarkdownPath {
		return usageError(fmt.Errorf("output paths must be distinct"))
	}

	installationID, err := strconv.ParseInt(os.Getenv("SEGH_GITHUB_INSTALLATION_ID"), 10, 64)
	if err != nil || installationID <= 0 {
		return authError(fmt.Errorf("SEGH_GITHUB_INSTALLATION_ID must be a positive integer"))
	}
	client, err := newGitHubAPI()
	if err != nil {
		return authError(err)
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.Inventory.Timeout))
	defer cancel()

	inventory, runErr := gh.NewInventoryService(cfg, client, installationID).Run(ctx)
	audit := policy.New(cfg, time.Now()).Evaluate(inventory)
	markdown := report.Markdown(inventory, audit)
	if err := errors.Join(
		output.JSON(*inventoryPath, inventory),
		output.JSON(*auditPath, audit),
		output.Text(*markdownPath, markdown),
	); err != nil {
		return runtimeError(err)
	}
	writef(stdout, "wrote inventory, audit, and Markdown evidence to %s, %s, and %s\n",
		*inventoryPath, *auditPath, *markdownPath)

	var apiErr *gh.APIError
	if errors.As(runErr, &apiErr) && (apiErr.StatusCode == 401 || apiErr.StatusCode == 403) {
		return authError(fmt.Errorf("inventory authentication or permission failure"))
	}
	if runErr != nil || audit.Coverage != "complete" {
		return incompleteError(fmt.Errorf("audit coverage is incomplete"))
	}
	if policy.Violations(audit) {
		return findingsError(fmt.Errorf("policy violations found"))
	}
	return nil
}

func runScanPlan(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("segh scan-plan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "segh.yaml", "path to strict version 5 configuration")
	inventoryPath := flags.String("inventory", defaultInventoryOutput, "governance inventory JSON")
	manifestPath := flags.String("manifest-output", defaultScanManifestOutput, "source scan manifest JSON")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return usageError(err)
	}
	if flags.NArg() != 0 || *inventoryPath == "" || *manifestPath == "" {
		return usageError(fmt.Errorf("scan-plan requires non-empty paths and accepts no positional arguments"))
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return usageError(err)
	}
	var inventory model.Inventory
	if err := sourcescan.ReadJSON(*inventoryPath, &inventory); err != nil {
		return runtimeError(fmt.Errorf("read inventory: %w", err))
	}
	client, err := newGitHubAPI()
	if err != nil {
		return authError(err)
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.Inventory.Timeout))
	defer cancel()
	manifest, planErr := sourcescan.NewPlanner(cfg, client).Run(ctx, inventory)
	if err := output.JSON(*manifestPath, manifest); err != nil {
		return runtimeError(err)
	}
	writef(stdout, "wrote source scan manifest to %s\n", *manifestPath)
	if planErr != nil {
		switch classifyPlanFailure(planErr) {
		case exitAuth:
			return authError(fmt.Errorf("source scan planning authentication or permission failure"))
		case exitRuntime:
			return runtimeError(planErr)
		default:
			return incompleteError(planErr)
		}
	}
	return nil
}

// classifyPlanFailure inspects every *gh.APIError reachable anywhere in
// planErr's error tree (which may join one failure per repository whose
// commit resolution failed) and picks the most specific applicable exit
// class: an authentication/permission failure on any repository takes
// precedence, a repository-not-found or unprocessable-ref failure is an
// unresolved coverage gap, and anything else backed by a GitHub API error
// (5xx, a transport failure, or a malformed response, all surfaced as a
// status-0 APIError) is a planner runtime failure. When the tree carries no
// APIError at all (for example, an overall planning timeout or a bounded
// matrix-size truncation with no individual commit-resolution failures),
// the failure is reported as unresolved coverage, matching prior behavior.
func classifyPlanFailure(err error) int {
	apiErrs := collectAPIErrors(err)
	for _, apiErr := range apiErrs {
		if apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden {
			return exitAuth
		}
	}
	for _, apiErr := range apiErrs {
		if apiErr.StatusCode != http.StatusNotFound && apiErr.StatusCode != http.StatusUnprocessableEntity {
			return exitRuntime
		}
	}
	return exitIncomplete
}

// collectAPIErrors walks err (descending through any errors.Join tree) and
// returns every *gh.APIError found. A branch that carries no APIError
// (a plain sentinel message, for instance) contributes nothing.
func collectAPIErrors(err error) []*gh.APIError {
	if err == nil {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var apiErrs []*gh.APIError
		for _, sub := range joined.Unwrap() {
			apiErrs = append(apiErrs, collectAPIErrors(sub)...)
		}
		return apiErrs
	}
	var apiErr *gh.APIError
	if errors.As(err, &apiErr) {
		return []*gh.APIError{apiErr}
	}
	return nil
}

func runScanSummary(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("segh scan-summary", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", defaultScanManifestOutput, "source scan manifest JSON")
	resultsDirectory := flags.String("results", "repository-scans", "repository scan evidence directory")
	summaryPath := flags.String("summary-output", defaultScanSummaryOutput, "source scan summary JSON")
	markdownPath := flags.String("markdown-output", defaultScanMarkdownOutput, "bounded source scan Markdown")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return usageError(err)
	}
	if flags.NArg() != 0 || *manifestPath == "" || *resultsDirectory == "" || *summaryPath == "" || *markdownPath == "" {
		return usageError(fmt.Errorf("scan-summary requires non-empty paths and accepts no positional arguments"))
	}
	var manifest model.SourceScanManifest
	if err := sourcescan.ReadJSON(*manifestPath, &manifest); err != nil {
		return runtimeError(fmt.Errorf("read scan manifest: %w", err))
	}
	summary, summarizeErr := sourcescan.Summarize(manifest, *resultsDirectory, time.Now())
	if err := errors.Join(output.JSON(*summaryPath, summary), output.Text(*markdownPath, sourcescan.Markdown(summary))); err != nil {
		return runtimeError(err)
	}
	writef(stdout, "wrote source scan summary to %s and %s\n", *summaryPath, *markdownPath)
	if summarizeErr != nil || summary.Counts.Errors > 0 {
		return runtimeError(fmt.Errorf("source scan runtime errors found"))
	}
	if !summary.Complete || summary.Counts.Incomplete > 0 {
		return incompleteError(fmt.Errorf("source scan coverage is incomplete"))
	}
	if summary.Counts.Findings > 0 {
		return findingsError(fmt.Errorf("source scan findings found"))
	}
	return nil
}

func printHelp(out io.Writer, version string) {
	writef(out, `segh %s - GitHub security governance audit

Usage:
  segh audit [options]

Commands:
  audit        Validate configuration, inventory controls, evaluate policy, and write evidence
  scan-plan    Resolve selected default branches to immutable commit SHAs
  scan-summary Validate and aggregate separate repository scan evidence
  version      Print the build version

Audit options:
  --config PATH             Configuration file (default segh.yaml)
  --validate-only           Validate configuration without GitHub credentials
  --inventory-output PATH   Inventory JSON (default segh-results/inventory.json)
  --audit-output PATH       Canonical policy JSON (default segh-results/audit.json)
  --markdown-output PATH    Operator report (default segh-results/report.md)

Host selection:
  Set GH_HOST for GHE.com or GitHub Enterprise Server; the default is github.com.

Authentication:
  Supply GH_TOKEN and SEGH_GITHUB_INSTALLATION_ID from the same App-token issuer.

Exit codes:
  0 success
  1 policy violations
  2 invalid arguments or configuration
  3 authentication or permission failure
  4 partial or unsupported coverage
  5 runtime failure
`, version)
}

func slicesHelp(value string) bool {
	return value == "--help" || value == "-h" || value == "help"
}

func slicesVersion(value string) bool {
	return value == "--version" || value == "version"
}

func writef(out io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(out, format, args...)
}

func usageError(err error) error      { return &commandError{code: exitUsage, err: err} }
func authError(err error) error       { return &commandError{code: exitAuth, err: err} }
func findingsError(err error) error   { return &commandError{code: exitFindings, err: err} }
func incompleteError(err error) error { return &commandError{code: exitIncomplete, err: err} }
func runtimeError(err error) error    { return &commandError{code: exitRuntime, err: err} }
