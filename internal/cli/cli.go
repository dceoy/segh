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
)

type commandError struct {
	code int
	err  error
}

func (e *commandError) Error() string { return e.err.Error() }
func (e *commandError) Unwrap() error { return e.err }

func Run(ctx context.Context, args []string, version string, stdout, stderr io.Writer) error {
	if len(args) == 1 && slicesHelp(args[0]) {
		printHelp(stdout, version)
		return nil
	}
	if len(args) == 1 && slicesVersion(args[0]) {
		writef(stdout, "%s\n", version)
		return nil
	}

	global := flag.NewFlagSet("segh", flag.ContinueOnError)
	global.SetOutput(stderr)
	configPath := global.String("config", "segh.yaml", "path to strict versioned configuration")
	webURL := global.String("github-web-url", "", "override GitHub web URL")
	global.Usage = func() { printHelp(stdout, version) }
	if err := global.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return usageError(err)
	}
	remaining := global.Args()
	if len(remaining) == 0 || slicesHelp(remaining[0]) {
		printHelp(stdout, version)
		return nil
	}
	if slicesVersion(remaining[0]) {
		writef(stdout, "%s\n", version)
		return nil
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return usageError(err)
	}
	if *webURL != "" {
		cfg.GitHub.WebURL = *webURL
		if err := cfg.Validate(); err != nil {
			return usageError(err)
		}
	}
	commandArgs := remaining[1:]
	switch remaining[0] {
	case "validate":
		if len(commandArgs) != 0 {
			return usageError(fmt.Errorf("validate does not accept arguments"))
		}
		writef(stdout, "configuration is valid\n")
		return nil
	case "inventory":
		return runInventory(ctx, cfg, commandArgs, stdout)
	case "audit":
		return runAudit(cfg, commandArgs, stdout)
	case "report":
		return runReport(cfg, commandArgs, stdout)
	default:
		return usageError(fmt.Errorf("unknown command %q", remaining[0]))
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

func runInventory(ctx context.Context, cfg config.Config, args []string, stdout io.Writer) error {
	flags := commandFlags("inventory")
	outputPath := flags.String("output", filepath.Join(cfg.Output.Directory, "inventory.json"), "inventory JSON output")
	if err := flags.Parse(args); err != nil {
		return usageError(err)
	}
	if flags.NArg() != 0 {
		return usageError(fmt.Errorf("inventory does not accept positional arguments"))
	}
	installationID, err := strconv.ParseInt(os.Getenv("SEGH_GITHUB_INSTALLATION_ID"), 10, 64)
	if err != nil || installationID <= 0 {
		return authError(fmt.Errorf("SEGH_GITHUB_INSTALLATION_ID must be a positive integer"))
	}
	client, err := gh.NewClient(cfg)
	if err != nil {
		return authError(err)
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.Inventory.Timeout))
	defer cancel()
	inventory, runErr := gh.NewInventoryService(cfg, client, installationID).Run(ctx)
	if err := output.JSON(*outputPath, inventory); err != nil {
		return runtimeError(err)
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
	if err := flags.Parse(args); err != nil {
		return usageError(err)
	}
	if flags.NArg() != 0 {
		return usageError(fmt.Errorf("audit does not accept positional arguments"))
	}
	var inventory model.Inventory
	if err := readJSON(*inputPath, &inventory); err != nil {
		return runtimeError(err)
	}
	if err := validateInventory(inventory, cfg); err != nil {
		return usageError(err)
	}
	audit := policy.New(cfg, time.Now()).Evaluate(inventory)
	if err := output.JSON(*outputPath, audit); err != nil {
		return runtimeError(err)
	}
	writef(stdout, "wrote %d policy results to %s\n", len(audit.Results), *outputPath)
	if policy.Violations(audit) {
		return findingsError(fmt.Errorf("policy violations found"))
	}
	if !inventory.Complete || policy.Partial(audit) {
		return incompleteError(fmt.Errorf("policy coverage is incomplete"))
	}
	return nil
}

func runReport(cfg config.Config, args []string, stdout io.Writer) error {
	flags := commandFlags("report")
	inventoryPath := flags.String("inventory", filepath.Join(cfg.Output.Directory, "inventory.json"), "inventory JSON input")
	auditPath := flags.String("audit", filepath.Join(cfg.Output.Directory, "audit.json"), "audit JSON input")
	outputPath := flags.String("output", filepath.Join(cfg.Output.Directory, "report.json"), "consolidated JSON output")
	markdownPath := flags.String("markdown", filepath.Join(cfg.Output.Directory, "report.md"), "Markdown output")
	if err := flags.Parse(args); err != nil {
		return usageError(err)
	}
	if flags.NArg() != 0 {
		return usageError(fmt.Errorf("report does not accept positional arguments"))
	}
	var inventory model.Inventory
	if err := readJSON(*inventoryPath, &inventory); err != nil {
		return runtimeError(err)
	}
	var audit model.Audit
	if err := readJSON(*auditPath, &audit); err != nil {
		return runtimeError(err)
	}
	if err := validateReportArtifacts(inventory, audit, cfg); err != nil {
		return usageError(err)
	}
	result := report.Build(&inventory, &audit)
	if err := output.JSON(*outputPath, result); err != nil {
		return runtimeError(err)
	}
	if err := output.Text(*markdownPath, report.Markdown(result)); err != nil {
		return runtimeError(err)
	}
	writef(stdout, "wrote consolidated report to %s and %s\n", *outputPath, *markdownPath)
	if result.Summary.Coverage != "complete" {
		return incompleteError(fmt.Errorf("report coverage is incomplete"))
	}
	if policy.Violations(audit) {
		return findingsError(fmt.Errorf("policy violations found"))
	}
	return nil
}

func validateInventory(inventory model.Inventory, cfg config.Config) error {
	if inventory.SchemaVersion != model.InventorySchemaVersion {
		return fmt.Errorf("unsupported inventory schema version %d", inventory.SchemaVersion)
	}
	if inventory.Organization != cfg.Organization {
		return fmt.Errorf("inventory organization %q does not match configured organization %q", inventory.Organization, cfg.Organization)
	}
	if inventory.GitHubHost == "" || inventory.GeneratedAt.IsZero() {
		return fmt.Errorf("inventory is missing required metadata")
	}
	if inventory.GitHubHost != cfg.GitHub.WebURL {
		return fmt.Errorf("inventory github_host %q does not match configured github.web_url %q", inventory.GitHubHost, cfg.GitHub.WebURL)
	}
	if inventory.Total < 0 || inventory.Selected < 0 || inventory.Excluded < 0 {
		return fmt.Errorf("inventory repository counts must not be negative")
	}
	if inventory.Selected != len(inventory.Repositories) || inventory.Excluded != len(inventory.Exclusions) {
		return fmt.Errorf("inventory repository counts do not match its records")
	}
	observed := inventory.Selected + inventory.Excluded
	if observed > inventory.Total || (inventory.Complete && observed != inventory.Total) {
		return fmt.Errorf("inventory total does not match its selected and excluded repositories")
	}
	if inventory.Complete && len(inventory.Errors) > 0 {
		return fmt.Errorf("complete inventory must not contain collection errors")
	}
	return nil
}

func validateReportArtifacts(inventory model.Inventory, audit model.Audit, cfg config.Config) error {
	if err := validateInventory(inventory, cfg); err != nil {
		return err
	}
	if err := validateAudit(inventory, audit); err != nil {
		return err
	}
	expected := policy.New(cfg, audit.GeneratedAt).Evaluate(inventory)
	equal, err := canonicalJSONEqual(audit.Results, expected.Results)
	if err != nil {
		return fmt.Errorf("compare audit results: %w", err)
	}
	if !equal {
		return fmt.Errorf("audit results do not match the inventory and configuration")
	}
	return nil
}

func validateAudit(inventory model.Inventory, audit model.Audit) error {
	if audit.SchemaVersion != model.PolicySchemaVersion {
		return fmt.Errorf("unsupported audit schema version %d", audit.SchemaVersion)
	}
	if audit.Organization != inventory.Organization {
		return fmt.Errorf("audit organization %q does not match inventory organization %q", audit.Organization, inventory.Organization)
	}
	if audit.GeneratedAt.IsZero() || audit.Counts == nil {
		return fmt.Errorf("audit is missing required metadata")
	}
	if audit.GeneratedAt.Before(inventory.GeneratedAt) {
		return fmt.Errorf(
			"audit generated_at %s predates inventory generated_at %s",
			audit.GeneratedAt.UTC().Format(time.RFC3339Nano),
			inventory.GeneratedAt.UTC().Format(time.RFC3339Nano),
		)
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
	if !maps.Equal(counts, audit.Counts) {
		return fmt.Errorf("audit counts do not match its policy results")
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

func readJSON(path string, value any) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() > 100<<20 {
		return fmt.Errorf("%s must be a regular JSON file no larger than 100 MiB", path)
	}
	file, err := os.Open(path) // #nosec G304 -- the CLI operator explicitly selects a bounded JSON artifact.
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

func commandFlags(name string) *flag.FlagSet {
	flags := flag.NewFlagSet("segh "+name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	return flags
}

func printHelp(out io.Writer, version string) {
	writef(out, `segh %s - GitHub security governance audit

Usage:
  segh [global options] <command> [options]

Commands:
  validate     Strictly validate segh.yaml
  inventory    Assess GitHub-native control coverage
  audit        Evaluate inventory against explicit policy
  report       Build deterministic JSON and Markdown reports
  version      Print the build version

Global options:
  --config PATH                 Configuration file (default segh.yaml)
  --github-web-url URL          GitHub Enterprise web URL override

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
