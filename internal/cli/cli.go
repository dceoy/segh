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

	authenticatedAuditTimeout = 50 * time.Minute
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
	if len(args) == 0 {
		printHelp(stdout, version)
		return nil
	}
	if len(args) == 1 {
		switch args[0] {
		case "--help", "-h", "help":
			printHelp(stdout, version)
			return nil
		case "--version", "version":
			writef(stdout, "%s\n", version)
			return nil
		}
	}
	if args[0] != "audit" {
		return usageError(fmt.Errorf("unknown command %q", args[0]))
	}
	return runAudit(ctx, args[1:], stdout, stderr)
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
	scanManifestPath := flags.String("scan-manifest", defaultScanManifestOutput, "source scan manifest JSON")
	reconcileSourceScan := flags.Bool("reconcile-source-scan", false, "reconcile repository source scan evidence")
	scanResultsDirectory := flags.String("scan-results", "repository-scans", "repository source scan evidence directory")
	scanSummaryPath := flags.String("scan-summary-output", defaultScanSummaryOutput, "source scan summary JSON")
	scanMarkdownPath := flags.String("scan-markdown-output", defaultScanMarkdownOutput, "bounded source scan Markdown")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return usageError(err)
	}
	if flags.NArg() != 0 {
		return usageError(fmt.Errorf("audit does not accept positional arguments"))
	}
	if *reconcileSourceScan {
		if *validateOnly {
			return usageError(fmt.Errorf("--validate-only cannot be combined with --reconcile-source-scan"))
		}
		return runSourceScanReconciliation(
			*scanManifestPath, *scanResultsDirectory, *scanSummaryPath, *scanMarkdownPath, stdout,
		)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return usageError(err)
	}
	if *validateOnly {
		writef(stdout, "configuration is valid\n")
		return nil
	}
	if *inventoryPath == "" || *auditPath == "" || *markdownPath == "" ||
		cfg.SourceScan.Enabled && *scanManifestPath == "" {
		return usageError(fmt.Errorf("output paths must not be empty"))
	}
	paths := []string{filepath.Clean(*inventoryPath), filepath.Clean(*auditPath), filepath.Clean(*markdownPath)}
	if cfg.SourceScan.Enabled {
		paths = append(paths, filepath.Clean(*scanManifestPath))
	}
	for i := range paths {
		for j := i + 1; j < len(paths); j++ {
			if paths[i] == paths[j] {
				return usageError(fmt.Errorf("output paths must be distinct"))
			}
		}
	}

	installationID, err := strconv.ParseInt(os.Getenv("SEGH_GITHUB_INSTALLATION_ID"), 10, 64)
	if err != nil || installationID <= 0 {
		return authError(fmt.Errorf("SEGH_GITHUB_INSTALLATION_ID must be a positive integer"))
	}
	client, err := newGitHubAPI()
	if err != nil {
		return authError(err)
	}

	authenticatedCtx, cancelAuthenticated := context.WithTimeout(ctx, authenticatedAuditTimeout)
	defer cancelAuthenticated()

	inventoryCtx, cancelInventory := context.WithTimeout(authenticatedCtx, time.Duration(cfg.Inventory.Timeout))
	inventory, inventoryErr := gh.NewInventoryService(cfg, client, installationID).Run(inventoryCtx)
	audit := policy.New(cfg, time.Now()).Evaluate(inventory)
	cancelInventory()
	markdown := report.Markdown(inventory, audit)

	var manifest model.SourceScanManifest
	var planErr error
	if cfg.SourceScan.Enabled {
		planCtx, cancelPlan := context.WithTimeout(authenticatedCtx, time.Duration(cfg.Inventory.Timeout))
		manifest, planErr = sourcescan.NewPlanner(cfg, client).Run(planCtx, inventory)
		cancelPlan()
	}
	writeErr := errors.Join(
		output.JSON(*inventoryPath, inventory),
		output.JSON(*auditPath, audit),
		output.Text(*markdownPath, markdown),
	)
	if cfg.SourceScan.Enabled {
		writeErr = errors.Join(writeErr, output.JSON(*scanManifestPath, manifest))
	}
	if writeErr != nil {
		return runtimeError(writeErr)
	}
	if cfg.SourceScan.Enabled {
		writef(stdout, "wrote governance evidence to %s, %s, and %s and source scan manifest to %s\n",
			*inventoryPath, *auditPath, *markdownPath, *scanManifestPath)
	} else {
		writef(stdout, "wrote inventory, audit, and Markdown evidence to %s, %s, and %s\n",
			*inventoryPath, *auditPath, *markdownPath)
	}

	if authenticationFailure(inventoryErr) || authenticationFailure(planErr) {
		return authError(fmt.Errorf("audit authentication or permission failure"))
	}
	if planErr != nil && isRuntimePlanFailure(planErr) {
		return runtimeError(planErr)
	}
	if inventoryErr != nil || planErr != nil || audit.Coverage != "complete" {
		return incompleteError(fmt.Errorf("audit coverage is incomplete"))
	}
	if policy.Violations(audit) {
		return findingsError(fmt.Errorf("policy violations found"))
	}
	return nil
}

func runSourceScanReconciliation(manifestPath, resultsDirectory, summaryPath, markdownPath string, stdout io.Writer) error {
	if manifestPath == "" || resultsDirectory == "" || summaryPath == "" || markdownPath == "" {
		return usageError(fmt.Errorf("source scan reconciliation requires non-empty paths"))
	}
	paths := []string{filepath.Clean(manifestPath), filepath.Clean(summaryPath), filepath.Clean(markdownPath)}
	for i := range paths {
		for j := i + 1; j < len(paths); j++ {
			if paths[i] == paths[j] {
				return usageError(fmt.Errorf("source scan evidence paths must be distinct"))
			}
		}
	}
	var manifest model.SourceScanManifest
	if err := sourcescan.ReadJSON(manifestPath, &manifest); err != nil {
		return runtimeError(fmt.Errorf("read scan manifest: %w", err))
	}
	summary, summarizeErr := sourcescan.Summarize(manifest, resultsDirectory, time.Now())
	if err := errors.Join(output.JSON(summaryPath, summary), output.Text(markdownPath, sourcescan.Markdown(summary))); err != nil {
		return runtimeError(err)
	}
	writef(stdout, "wrote source scan summary to %s and %s\n", summaryPath, markdownPath)
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

func authenticationFailure(err error) bool {
	for _, apiErr := range collectAPIErrors(err) {
		if apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden {
			return true
		}
	}
	return false
}

func isRuntimePlanFailure(err error) bool {
	for _, apiErr := range collectAPIErrors(err) {
		switch apiErr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusUnprocessableEntity:
			continue
		default:
			return true
		}
	}
	return false
}

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

func printHelp(out io.Writer, version string) {
	writef(out, `segh %s - GitHub security governance audit

Usage:
  segh audit --config segh.yaml [options]

Options:
  --config PATH             Configuration file (default segh.yaml)
  --validate-only           Validate configuration without GitHub credentials
  --inventory-output PATH   Inventory JSON (default segh-results/inventory.json)
  --audit-output PATH       Canonical policy JSON (default segh-results/audit.json)
  --markdown-output PATH    Operator report (default segh-results/report.md)

When source scanning is enabled, the same audit execution also writes an
immutable source-scan manifest. The control workflow later reconciles the
identity-bound repository artifacts through the audit command.

Platform:
  GitHub.com is the only supported runtime platform.

Authentication:
  Supply GH_TOKEN and SEGH_GITHUB_INSTALLATION_ID from the same App-token issuer.

Exit codes:
  0 success
  1 policy or source-scan findings
  2 invalid arguments or configuration
  3 authentication or permission failure
  4 incomplete coverage
  5 runtime failure

"segh version" prints the build version.
`, version)
}

func writef(out io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(out, format, args...)
}

func usageError(err error) error      { return &commandError{code: exitUsage, err: err} }
func authError(err error) error       { return &commandError{code: exitAuth, err: err} }
func findingsError(err error) error   { return &commandError{code: exitFindings, err: err} }
func incompleteError(err error) error { return &commandError{code: exitIncomplete, err: err} }
func runtimeError(err error) error    { return &commandError{code: exitRuntime, err: err} }
