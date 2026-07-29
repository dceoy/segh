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
		return runReport(commandArgs, stdout)
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
	client, err := gh.NewClient(cfg)
	if err != nil {
		return authError(err)
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Inventory.Timeout)
	defer cancel()
	inventory, runErr := gh.NewInventoryService(cfg, client).Run(ctx)
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
	if inventory.SchemaVersion != model.InventorySchemaVersion {
		return usageError(fmt.Errorf("unsupported inventory schema version %d", inventory.SchemaVersion))
	}
	audit := policy.New(cfg, time.Now()).Evaluate(inventory)
	if err := output.JSON(*outputPath, audit); err != nil {
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

func runReport(args []string, stdout io.Writer) error {
	flags := commandFlags("report")
	inventoryPath := flags.String("inventory", "segh-results/inventory.json", "inventory JSON input")
	auditPath := flags.String("audit", "segh-results/audit.json", "audit JSON input")
	outputPath := flags.String("output", "segh-results/report.json", "consolidated JSON output")
	markdownPath := flags.String("markdown", "segh-results/report.md", "Markdown output")
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
  Supply GH_TOKEN. In Actions, generate it with actions/create-github-app-token.

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
