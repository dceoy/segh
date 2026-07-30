package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
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
)

const (
	exitSuccess    = 0
	exitFindings   = 1
	exitUsage      = 2
	exitAuth       = 3
	exitIncomplete = 4
	exitRuntime    = 5

	defaultInventoryOutput = "segh-results/inventory.json"
	defaultAuditOutput     = "segh-results/audit.json"
	defaultMarkdownOutput  = "segh-results/report.md"
)

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
	configPath := flags.String("config", "segh.yaml", "path to strict version 3 configuration")
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
	client, err := gh.NewClient()
	if err != nil {
		return authError(err)
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.Inventory.Timeout))
	defer cancel()

	inventory, runErr := gh.NewInventoryService(cfg, client, installationID).Run(ctx)
	audit := policy.New(cfg, time.Now()).Evaluate(inventory)
	if err := validateArtifacts(inventory, audit, cfg, client.Hostname()); err != nil {
		return runtimeError(fmt.Errorf("validate generated evidence: %w", err))
	}
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

func validateArtifacts(
	inventory model.Inventory, audit model.Audit, cfg config.Config, githubHost string,
) error {
	if err := validateInventory(inventory, cfg, githubHost); err != nil {
		return err
	}
	if err := validateAudit(inventory, audit); err != nil {
		return err
	}
	expected := policy.New(cfg, audit.GeneratedAt).Evaluate(inventory)
	equal, err := canonicalJSONEqual(audit, expected)
	if err != nil {
		return fmt.Errorf("compare audit result: %w", err)
	}
	if !equal {
		return fmt.Errorf("audit does not match the inventory and configuration")
	}
	return nil
}

func validateInventory(inventory model.Inventory, cfg config.Config, githubHost string) error {
	if inventory.SchemaVersion != model.SchemaVersion {
		return fmt.Errorf("unsupported inventory schema version %d", inventory.SchemaVersion)
	}
	if inventory.Organization != cfg.Organization {
		return fmt.Errorf("inventory organization %q does not match configured organization %q",
			inventory.Organization, cfg.Organization)
	}
	if inventory.GitHubHost == "" || inventory.GeneratedAt.IsZero() {
		return fmt.Errorf("inventory is missing required metadata")
	}
	if inventory.GitHubHost != githubHost {
		return fmt.Errorf("inventory github_host %q does not match effective GitHub host %q",
			inventory.GitHubHost, githubHost)
	}
	if inventory.Total < 0 || inventory.Selected < 0 || inventory.Excluded < 0 {
		return fmt.Errorf("inventory repository counts must not be negative")
	}
	if inventory.Selected != len(inventory.Repositories) || inventory.Excluded != len(inventory.Exclusions) {
		return fmt.Errorf("inventory repository counts do not match its records")
	}
	observed := inventory.Selected + inventory.Excluded
	if observed > inventory.Total || inventory.Complete && observed != inventory.Total {
		return fmt.Errorf("inventory total does not match its selected and excluded repositories")
	}
	if inventory.Complete && len(inventory.Errors) > 0 {
		return fmt.Errorf("complete inventory must not contain collection errors")
	}
	return nil
}

func validateAudit(inventory model.Inventory, audit model.Audit) error {
	if audit.SchemaVersion != model.SchemaVersion {
		return fmt.Errorf("unsupported audit schema version %d", audit.SchemaVersion)
	}
	if audit.Organization != inventory.Organization {
		return fmt.Errorf("audit organization %q does not match inventory organization %q",
			audit.Organization, inventory.Organization)
	}
	if audit.GeneratedAt.IsZero() || audit.PolicyCounts == nil {
		return fmt.Errorf("audit is missing required metadata")
	}
	if audit.GeneratedAt.Before(inventory.GeneratedAt) {
		return fmt.Errorf("audit generated_at %s predates inventory generated_at %s",
			audit.GeneratedAt.UTC().Format(time.RFC3339Nano),
			inventory.GeneratedAt.UTC().Format(time.RFC3339Nano))
	}
	wantRepositoryCounts := model.RepositoryCounts{
		Total: inventory.Total, Selected: inventory.Selected, Excluded: inventory.Excluded,
	}
	if audit.RepositoryCounts != wantRepositoryCounts {
		return fmt.Errorf("audit repository counts do not match inventory")
	}
	if audit.Coverage != "complete" && audit.Coverage != "partial" {
		return fmt.Errorf("audit has invalid coverage %q", audit.Coverage)
	}
	counts := map[string]int{}
	for i, result := range audit.Results {
		switch result.Status {
		case model.PolicyPass, model.PolicyFail, model.PolicyUnknown, model.PolicyUnsupported, model.PolicyExempt:
		default:
			return fmt.Errorf("audit result %d has invalid status %q", i, result.Status)
		}
		if result.PolicyID == "" {
			return fmt.Errorf("audit result %d is missing a policy ID", i)
		}
		counts[string(result.Status)]++
	}
	if !maps.Equal(counts, audit.PolicyCounts) {
		return fmt.Errorf("audit policy counts do not match its results")
	}
	return nil
}

func canonicalJSONEqual(left, right any) (bool, error) {
	leftJSON, err := json.Marshal(left)
	if err != nil {
		return false, fmt.Errorf("encode left value: %w", err)
	}
	rightJSON, err := json.Marshal(right)
	if err != nil {
		return false, fmt.Errorf("encode right value: %w", err)
	}
	return bytes.Equal(leftJSON, rightJSON), nil
}

func printHelp(out io.Writer, version string) {
	writef(out, `segh %s - GitHub security governance audit

Usage:
  segh audit [options]

Commands:
  audit        Validate configuration, inventory controls, evaluate policy, and write evidence
  version      Print the build version

Audit options:
  --config PATH             Configuration file (default segh.yaml)
  --validate-only           Validate configuration without GitHub credentials
  --inventory-output PATH   Inventory JSON (default segh-results/inventory.json)
  --audit-output PATH       Canonical policy JSON (default segh-results/audit.json)
  --markdown-output PATH    Operator report (default segh-results/report.md)

Host selection:
  Set GH_HOST for GitHub Enterprise Server; the default is github.com.

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
