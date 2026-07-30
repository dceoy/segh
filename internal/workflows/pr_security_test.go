// Package workflows pins structural properties of the security-critical
// GitHub Actions workflows that a pull request could otherwise silently
// weaken, since GitHub Actions has no runtime to exercise those properties
// against.
package workflows

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	prSecurityWorkflowPath     = "../../.github/workflows/pr-security.yml"
	prSecuritySelfWorkflowPath = "../../.github/workflows/pr-security-self.yml"
	shellcheckrcPath           = "../../.github/security/shellcheckrc"
)

type prSecurityStep struct {
	Name string            `yaml:"name"`
	With map[string]any    `yaml:"with"`
	Env  map[string]string `yaml:"env"`
	Run  string            `yaml:"run"`
}

type prSecurityJob struct {
	If          string            `yaml:"if"`
	Permissions map[string]string `yaml:"permissions"`
	Steps       []prSecurityStep  `yaml:"steps"`
}

type prSecurityWorkflow struct {
	On   map[string]any           `yaml:"on"`
	Jobs map[string]prSecurityJob `yaml:"jobs"`
}

func loadPRSecurityWorkflow(t *testing.T) prSecurityWorkflow {
	t.Helper()
	data, err := os.ReadFile(prSecurityWorkflowPath)
	if err != nil {
		t.Fatalf("read %s: %v", prSecurityWorkflowPath, err)
	}
	var workflow prSecurityWorkflow
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("parse %s: %v", prSecurityWorkflowPath, err)
	}
	return workflow
}

func loadPRSecuritySelfWorkflow(t *testing.T) prSecurityWorkflow {
	t.Helper()
	data, err := os.ReadFile(prSecuritySelfWorkflowPath)
	if err != nil {
		t.Fatalf("read %s: %v", prSecuritySelfWorkflowPath, err)
	}
	var workflow prSecurityWorkflow
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("parse %s: %v", prSecuritySelfWorkflowPath, err)
	}
	return workflow
}

func stepNames(steps []prSecurityStep) []string {
	names := make([]string, len(steps))
	for i, step := range steps {
		names[i] = step.Name
	}
	return names
}

// TestPRSecurityWorkflowDoesNotTriggerOnPullRequestTarget pins that
// pr-security.yml no longer declares pull_request_target. Declaring both
// pull_request and pull_request_target in one workflow file made every
// ordinary pull_request run on the source repository emit a skipped
// scan-self job on the pull request's own head commit; a skipped job
// satisfies a required check trivially, so requiring "scan-self" (or the
// documented "scan") could be satisfied without the trusted scan ever
// running against that commit. Splitting the trigger into
// pr-security-self.yml removes that skippable job entirely.
func TestPRSecurityWorkflowDoesNotTriggerOnPullRequestTarget(t *testing.T) {
	workflow := loadPRSecurityWorkflow(t)
	if _, ok := workflow.On["pull_request"]; !ok {
		t.Error("on: is missing trigger \"pull_request\"")
	}
	if _, ok := workflow.On["pull_request_target"]; ok {
		t.Error("on: still declares \"pull_request_target\"; this would reintroduce a skipped scan-self job on pull_request runs")
	}
	if _, ok := workflow.Jobs["scan-self"]; ok {
		t.Error("jobs.scan-self should live in pr-security-self.yml, not pr-security.yml")
	}
}

// TestPRSecuritySelfWorkflowTriggersOnlyOnPullRequestTarget pins that
// pr-security-self.yml's only trigger is pull_request_target, so it is
// sourced from the base branch (a pull request cannot weaken it) and never
// also runs under an ordinary pull_request event on the source repository.
func TestPRSecuritySelfWorkflowTriggersOnlyOnPullRequestTarget(t *testing.T) {
	workflow := loadPRSecuritySelfWorkflow(t)
	if _, ok := workflow.On["pull_request_target"]; !ok {
		t.Error("on: is missing trigger \"pull_request_target\"")
	}
	if _, ok := workflow.On["pull_request"]; ok {
		t.Error("on: still declares \"pull_request\"; scan-self would then run twice and re-emit a skippable head-commit job")
	}
}

// TestPRSecurityScanSelfGatedToSourceRepository pins that scan-self only
// runs for the source repository.
func TestPRSecurityScanSelfGatedToSourceRepository(t *testing.T) {
	workflow := loadPRSecuritySelfWorkflow(t)
	job, ok := workflow.Jobs["scan-self"]
	if !ok {
		t.Fatal("jobs.scan-self is missing")
	}
	if !strings.Contains(job.If, "github.repository == 'dceoy/segh'") {
		t.Errorf("jobs.scan-self.if = %q, want it to contain %q", job.If, "github.repository == 'dceoy/segh'")
	}
}

// TestPRSecurityPublishSelfCheckReportsOnHeadSHA pins that a separate
// publish-self-check job, not scan-self itself, explicitly publishes a
// check run pinned to the pull request's head SHA. GITHUB_SHA (and the
// check run GitHub Actions creates automatically for scan-self) resolves to
// the base branch's commit under pull_request_target, not the pull
// request's head, so a required check would evaluate against the wrong
// commit unless this job explicitly reports against
// github.event.pull_request.head.sha itself. checks:write is granted to
// neither job's ambient token: publish-self-check mints a dedicated GitHub
// App token for that instead (see
// TestPRSecurityPublishSelfCheckUsesDedicatedAppToken), so scan-self, which
// checks out and scans untrusted pull-request content, never has it either.
func TestPRSecurityPublishSelfCheckReportsOnHeadSHA(t *testing.T) {
	workflow := loadPRSecuritySelfWorkflow(t)
	scanSelf, ok := workflow.Jobs["scan-self"]
	if !ok {
		t.Fatal("jobs.scan-self is missing")
	}
	if _, hasChecks := scanSelf.Permissions["checks"]; hasChecks {
		t.Errorf("jobs.scan-self.permissions.checks = %q, want it unset: checks:write must not be granted to the job scanning untrusted pull-request content", scanSelf.Permissions["checks"])
	}
	job, ok := workflow.Jobs["publish-self-check"]
	if !ok {
		t.Fatal("jobs.publish-self-check is missing")
	}
	if _, hasChecks := job.Permissions["checks"]; hasChecks {
		t.Errorf("jobs.publish-self-check.permissions.checks = %q, want it unset: the ambient token no longer publishes the check, a dedicated GitHub App token does", job.Permissions["checks"])
	}
	if !strings.Contains(job.If, "needs.scan-self.result") {
		t.Errorf("jobs.publish-self-check.if = %q, want it to depend on needs.scan-self.result", job.If)
	}
	step, ok := findStep(job.Steps, "Publish the gate result on the pull request's head commit")
	if !ok {
		t.Fatal("jobs.publish-self-check is missing step \"Publish the gate result on the pull request's head commit\"")
	}
	if step.Run == "" {
		t.Fatal("jobs.publish-self-check step is missing a run script")
	}
	if !strings.Contains(step.Run, "github.event.pull_request.head.sha") {
		t.Error("jobs.publish-self-check does not reference github.event.pull_request.head.sha")
	}
}

// TestPRSecurityPublishSelfCheckUsesDedicatedAppToken pins that
// publish-self-check authenticates with a token minted from a dedicated
// GitHub App, not github.token. github.token's identity is the shared
// default "GitHub Actions" App available to every workflow in the
// repository, including one an ordinary same-repository pull request could
// add; publishing with it would let such a pull request forge this check's
// result on its own head SHA.
func TestPRSecurityPublishSelfCheckUsesDedicatedAppToken(t *testing.T) {
	job, ok := loadPRSecuritySelfWorkflow(t).Jobs["publish-self-check"]
	if !ok {
		t.Fatal("jobs.publish-self-check is missing")
	}
	step, ok := findStep(job.Steps, "Publish the gate result on the pull request's head commit")
	if !ok {
		t.Fatal("jobs.publish-self-check is missing step \"Publish the gate result on the pull request's head commit\"")
	}
	token := step.Env["GH_TOKEN"]
	if token == "" {
		t.Fatal("jobs.publish-self-check publish step is missing env.GH_TOKEN")
	}
	if strings.Contains(token, "github.token") {
		t.Errorf("jobs.publish-self-check publish step env.GH_TOKEN = %q, must not use github.token", token)
	}
	if !strings.Contains(token, "steps.app-token.outputs.token") {
		t.Errorf("jobs.publish-self-check publish step env.GH_TOKEN = %q, want it to use the minted App token", token)
	}
}

// ignoredCheckoutWithKeys lists, per step name, the "with" inputs that are
// intentionally different between scan (which checks out another
// repository's trusted config and pull request under pull_request) and
// scan-self (which checks out this repository's own base commit and pull
// request under pull_request_target): the trusted-config checkout's
// source/ref, and scan-self's required fork-checkout opt-in.
var ignoredCheckoutWithKeys = map[string][]string{
	"Check out trusted scanner configuration": {"repository", "ref"},
	"Check out pull request":                  {"allow-unsafe-pr-checkout"},
}

func readPRSecurityWorkflowFile(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(prSecurityWorkflowPath)
	if err != nil {
		t.Fatalf("read %s: %v", prSecurityWorkflowPath, err)
	}
	return data
}

func readPRSecuritySelfWorkflowFile(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(prSecuritySelfWorkflowPath)
	if err != nil {
		t.Fatalf("read %s: %v", prSecuritySelfWorkflowPath, err)
	}
	return data
}

// rawJobSteps decodes a job's steps as untyped maps rather than through
// prSecurityStep, so comparison below is not limited to the handful of
// fields prSecurityStep happens to declare: any field on any step,
// including ones added after this test is written, is compared.
func rawJobSteps(t *testing.T, data []byte, job string) []map[string]any {
	t.Helper()
	var document map[string]any
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("parse workflow: %v", err)
	}
	jobs, ok := document["jobs"].(map[string]any)
	if !ok {
		t.Fatal("jobs is missing or not a mapping")
	}
	jobRaw, ok := jobs[job].(map[string]any)
	if !ok {
		t.Fatalf("jobs.%s is missing or not a mapping", job)
	}
	stepsRaw, ok := jobRaw["steps"].([]any)
	if !ok {
		t.Fatalf("jobs.%s.steps is missing or not a sequence", job)
	}
	steps := make([]map[string]any, len(stepsRaw))
	for i, item := range stepsRaw {
		step, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("jobs.%s.steps[%d] is not a mapping", job, i)
		}
		steps[i] = step
	}
	return steps
}

// normalizedRawStep returns a copy of step with the given keys removed from
// its "with" mapping, leaving every other field, including ones not named
// here, untouched for comparison.
func normalizedRawStep(step map[string]any, ignoredWithKeys []string) map[string]any {
	normalized := make(map[string]any, len(step))
	for key, value := range step {
		normalized[key] = value
	}
	with, ok := normalized["with"].(map[string]any)
	if !ok || len(ignoredWithKeys) == 0 {
		return normalized
	}
	normalizedWith := make(map[string]any, len(with))
	for key, value := range with {
		normalizedWith[key] = value
	}
	for _, key := range ignoredWithKeys {
		delete(normalizedWith, key)
	}
	normalized["with"] = normalizedWith
	return normalized
}

// TestPRSecurityScanAndScanSelfStepsStayInSync pins that scan and scan-self
// run the same scanner and enforcement steps. A pull request cannot edit
// scan-self's own definition, but nothing stops a future change from
// updating scan's gate logic while forgetting scan-self's, silently
// reopening the enforcement gap scan-self exists to close. The comparison
// covers every field of every step (uses, with, env, run, if,
// working-directory, continue-on-error, and so on) except the checkout
// inputs in ignoredCheckoutWithKeys, which are intentionally different.
func TestPRSecurityScanAndScanSelfStepsStayInSync(t *testing.T) {
	scan, ok := loadPRSecurityWorkflow(t).Jobs["scan"]
	if !ok {
		t.Fatal("jobs.scan is missing")
	}
	scanSelf, ok := loadPRSecuritySelfWorkflow(t).Jobs["scan-self"]
	if !ok {
		t.Fatal("jobs.scan-self is missing")
	}
	scanSteps, scanSelfSteps := stepNames(scan.Steps), stepNames(scanSelf.Steps)
	if !reflect.DeepEqual(scanSteps, scanSelfSteps) {
		t.Fatalf("jobs.scan and jobs.scan-self steps diverged:\nscan:      %v\nscan-self: %v", scanSteps, scanSelfSteps)
	}
	for _, want := range []string{
		"Run zizmor gate",
		"Run actionlint and embedded ShellCheck gate",
		"Run standalone ShellCheck gate",
		"Run Checkov infrastructure-as-code gate",
		"Run Trivy vulnerability gate",
		"Run Trivy secret gate",
		"Enforce scanner gates",
	} {
		if !slicesContains(scanSelfSteps, want) {
			t.Errorf("jobs.scan-self is missing step %q", want)
		}
	}
	scanRawSteps := rawJobSteps(t, readPRSecurityWorkflowFile(t), "scan")
	scanSelfRawSteps := rawJobSteps(t, readPRSecuritySelfWorkflowFile(t), "scan-self")
	if len(scanRawSteps) != len(scanSelfRawSteps) {
		t.Fatalf("jobs.scan has %d steps, jobs.scan-self has %d", len(scanRawSteps), len(scanSelfRawSteps))
	}
	for i, name := range scanSteps {
		ignoredWithKeys := ignoredCheckoutWithKeys[name]
		normalizedScan := normalizedRawStep(scanRawSteps[i], ignoredWithKeys)
		normalizedScanSelf := normalizedRawStep(scanSelfRawSteps[i], ignoredWithKeys)
		if !reflect.DeepEqual(normalizedScan, normalizedScanSelf) {
			t.Errorf(
				"step %q diverged between jobs.scan and jobs.scan-self beyond the intentional checkout differences:\nscan:      %+v\nscan-self: %+v",
				name, normalizedScan, normalizedScanSelf,
			)
		}
	}
}

// TestPRSecurityUsesDedicatedScannerOwnership pins the hard scanner cutovers:
// Checkov owns infrastructure-as-code, actionlint owns workflow correctness
// (including embedded ShellCheck), standalone ShellCheck owns tracked shell
// files, and Trivy retains only vulnerability and secret scanning.
func TestPRSecurityUsesDedicatedScannerOwnership(t *testing.T) {
	job, ok := loadPRSecurityWorkflow(t).Jobs["scan"]
	if !ok {
		t.Fatal("jobs.scan is missing")
	}
	names := stepNames(job.Steps)
	if slicesContains(names, "Run Trivy misconfiguration gate") {
		t.Error("jobs.scan still contains the superseded Trivy misconfiguration gate")
	}

	actionlintStep, ok := findStep(job.Steps, "Run actionlint and embedded ShellCheck gate")
	if !ok {
		t.Fatal("jobs.scan is missing the actionlint gate")
	}
	for _, want := range []string{
		"git ls-files",
		"--config-file \"$GITHUB_WORKSPACE/_segh/.github/security/actionlint.yaml\"",
		"--shellcheck shellcheck",
		"security-results/actionlint.status",
	} {
		if !strings.Contains(actionlintStep.Run, want) {
			t.Errorf("actionlint gate does not contain %q", want)
		}
	}
	if opts := actionlintStep.Env["SHELLCHECK_OPTS"]; !strings.Contains(opts, "_segh/.github/security/shellcheckrc") {
		t.Errorf("actionlint gate SHELLCHECK_OPTS = %q, want trusted ShellCheck configuration", opts)
	}

	shellcheckStep, ok := findStep(job.Steps, "Run standalone ShellCheck gate")
	if !ok {
		t.Fatal("jobs.scan is missing the standalone ShellCheck gate")
	}
	for _, want := range []string{
		"git ls-files",
		"--rcfile \"$GITHUB_WORKSPACE/_segh/.github/security/shellcheckrc\"",
		"security-results/shellcheck.status",
	} {
		if !strings.Contains(shellcheckStep.Run, want) {
			t.Errorf("standalone ShellCheck gate does not contain %q", want)
		}
	}

	checkovStep, ok := findStep(job.Steps, "Run Checkov infrastructure-as-code gate")
	if !ok {
		t.Fatal("jobs.scan is missing the Checkov gate")
	}
	for _, want := range []string{
		"--config-file \"$GITHUB_WORKSPACE/_segh/.github/security/checkov.yaml\"",
		"--skip-download",
		"security-results/checkov.json",
		"security-results/checkov.txt",
		"security-results/checkov.status",
	} {
		if !strings.Contains(checkovStep.Run, want) {
			t.Errorf("Checkov gate does not contain %q", want)
		}
	}

	allScripts := make([]string, 0, len(job.Steps))
	for _, step := range job.Steps {
		allScripts = append(allScripts, step.Run)
	}
	joined := strings.Join(allScripts, "\n")
	if strings.Contains(joined, "--scanners misconfig") {
		t.Error("jobs.scan still invokes Trivy misconfiguration scanning")
	}
	for _, want := range []string{"--scanners vuln", "--scanners secret"} {
		if !strings.Contains(joined, want) {
			t.Errorf("jobs.scan no longer contains %q", want)
		}
	}
}

func slicesContains(haystack []string, needle string) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}
	return false
}

func findStep(steps []prSecurityStep, name string) (prSecurityStep, bool) {
	for _, step := range steps {
		if step.Name == name {
			return step, true
		}
	}
	return prSecurityStep{}, false
}

// TestPRSecurityScanSelfAllowsForkPullRequestCheckout pins that scan-self's
// pull_request_target checkout opts into fork PR head SHA checkout.
// actions/checkout v7 refuses that checkout by default, and since scan-self
// is the only required gate for fork pull requests once merged (scan
// excludes the source repository), losing this input would silently stop
// scan-self from running on any fork contribution.
func TestPRSecurityScanSelfAllowsForkPullRequestCheckout(t *testing.T) {
	workflow := loadPRSecuritySelfWorkflow(t)
	job, ok := workflow.Jobs["scan-self"]
	if !ok {
		t.Fatal("jobs.scan-self is missing")
	}
	step, ok := findStep(job.Steps, "Check out pull request")
	if !ok {
		t.Fatal("jobs.scan-self is missing step \"Check out pull request\"")
	}
	if allow, _ := step.With["allow-unsafe-pr-checkout"].(bool); !allow {
		t.Errorf("jobs.scan-self step \"Check out pull request\" with.allow-unsafe-pr-checkout = %v, want true", step.With["allow-unsafe-pr-checkout"])
	}
}

// TestPRSecurityScanTriggersOnMergeGroup pins that pr-security.yml's scan
// job also runs for merge_group. Organization rulesets can install this
// workflow as a required workflow; if a target repository enables a merge
// queue, GitHub only creates the required "PR security / scan" check for a
// merge-group commit when the workflow declares merge_group as a trigger
// and the job's own if condition permits that event, otherwise the queued
// merge can never complete.
func TestPRSecurityScanTriggersOnMergeGroup(t *testing.T) {
	workflow := loadPRSecurityWorkflow(t)
	if _, ok := workflow.On["merge_group"]; !ok {
		t.Error("on: is missing trigger \"merge_group\"")
	}
	job, ok := workflow.Jobs["scan"]
	if !ok {
		t.Fatal("jobs.scan is missing")
	}
	if !strings.Contains(job.If, "github.event_name == 'merge_group'") {
		t.Errorf("jobs.scan.if = %q, want it to also permit merge_group", job.If)
	}
}

// TestPRSecurityScanSelectsMergeGroupHeadSHA pins that scan's "Check out
// pull request" step scans the merge group's own head SHA under
// merge_group, since github.event.pull_request does not exist on that
// event and the merge-group commit (not any single queued pull request's
// head) is the untrusted content actually about to be merged.
func TestPRSecurityScanSelectsMergeGroupHeadSHA(t *testing.T) {
	job, ok := loadPRSecurityWorkflow(t).Jobs["scan"]
	if !ok {
		t.Fatal("jobs.scan is missing")
	}
	step, ok := findStep(job.Steps, "Check out pull request")
	if !ok {
		t.Fatal("jobs.scan is missing step \"Check out pull request\"")
	}
	ref, _ := step.With["ref"].(string)
	if !strings.Contains(ref, "github.event.merge_group.head_sha") {
		t.Errorf("jobs.scan step \"Check out pull request\" with.ref = %q, want it to reference github.event.merge_group.head_sha", ref)
	}
	if !strings.Contains(ref, "github.event.pull_request.head.sha") {
		t.Errorf("jobs.scan step \"Check out pull request\" with.ref = %q, want it to still fall back to github.event.pull_request.head.sha", ref)
	}
}

// TestPRSecuritySelfWorkflowDoesNotSupportMergeGroup pins that dceoy/segh's
// own enforcement intentionally does not support a merge queue: neither
// pr-security-self.yml's trigger nor publish-self-check's published ref
// handle merge_group, so enabling a merge queue on dceoy/segh must not
// happen without adding that support first (see docs/workflows.md).
func TestPRSecuritySelfWorkflowDoesNotSupportMergeGroup(t *testing.T) {
	workflow := loadPRSecuritySelfWorkflow(t)
	if _, ok := workflow.On["merge_group"]; ok {
		t.Error("on: declares \"merge_group\", but publish-self-check only publishes against github.event.pull_request.head.sha; add that support before declaring this trigger")
	}
	job, ok := workflow.Jobs["publish-self-check"]
	if !ok {
		t.Fatal("jobs.publish-self-check is missing")
	}
	step, ok := findStep(job.Steps, "Publish the gate result on the pull request's head commit")
	if !ok {
		t.Fatal("jobs.publish-self-check is missing step \"Publish the gate result on the pull request's head commit\"")
	}
	if !strings.Contains(step.Run, "github.event.pull_request.head.sha") {
		t.Error("jobs.publish-self-check no longer references github.event.pull_request.head.sha; update this test if merge_group support was added")
	}
}

// TestPRSecurityScorecardGatedToOrdinaryPullRequestEvent pins that scorecard
// only runs for the pull_request-triggered event. pr-security.yml declared
// both pull_request and pull_request_target as triggers until scan-self
// moved to its own pull_request_target-only workflow; this guard is now
// redundant but kept so a future re-addition of pull_request_target here
// does not silently double-run the informational Scorecard job again.
func TestPRSecurityScorecardGatedToOrdinaryPullRequestEvent(t *testing.T) {
	workflow := loadPRSecurityWorkflow(t)
	job, ok := workflow.Jobs["scorecard"]
	if !ok {
		t.Fatal("jobs.scorecard is missing")
	}
	if !strings.Contains(job.If, "github.event_name == 'pull_request'") {
		t.Errorf("jobs.scorecard.if = %q, want it to contain %q", job.If, "github.event_name == 'pull_request'")
	}
}

// runGit runs git against dir, failing the test on error.
func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "git", args...) // #nosec G204 -- args are fixed test-internal git subcommands, not external input.
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// writeExecutable writes an executable file, failing the test on error.
func writeExecutable(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- this temporary test fixture must be executable.
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

// writeStubShellCheck installs an executable "shellcheck" on PATH (via a
// dedicated directory returned for the caller to prepend) that records its
// arguments to argvLog instead of analyzing anything. Tests use it to
// observe which files the gate script decided to pass to ShellCheck without
// depending on ShellCheck's own installed version or diagnostics.
func writeStubShellCheck(t *testing.T, argvLog string) string {
	t.Helper()
	stubDir := t.TempDir()
	stub := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"" + argvLog + "\"\nexit 0\n"
	writeExecutable(t, filepath.Join(stubDir, "shellcheck"), stub)
	return stubDir
}

// TestPRSecurityStandaloneShellCheckGateDiscoversAllTrackedShellScripts pins
// that the standalone ShellCheck gate's file-discovery script in
// pr-security.yml (executed here for real against a throwaway git
// repository standing in for the pull request checkout) enumerates a
// non-executable, extensionless shell script and an executable script with
// a #!/bin/ash shebang: the two gaps issue #33's acceptance criterion called
// out, since shebang inspection used to be limited to executable (mode
// 100755) files and the recognized-interpreter pattern did not include
// "ash". It also pins that a tracked symlink is never passed to ShellCheck,
// even when its name matches a recognized extension, closing the same
// candidate-list invariant the actionlint gate needs (see
// TestPRSecurityUsesDedicatedScannerOwnership and the "Reject symlinks from
// the pull request checkout" step). It also pins that a tracked, executable
// #!/bin/zsh script is never passed to ShellCheck: ShellCheck 0.11 supports
// only sh/bash/dash/ksh and reports SC1071 for zsh scripts, so admitting one
// would fail the enforced gate on an otherwise-clean target repository. A
// stub "shellcheck" on PATH records its arguments so the test exercises only
// this enumeration logic, not ShellCheck's own installed behavior.
func TestPRSecurityStandaloneShellCheckGateDiscoversAllTrackedShellScripts(t *testing.T) {
	job, ok := loadPRSecurityWorkflow(t).Jobs["scan"]
	if !ok {
		t.Fatal("jobs.scan is missing")
	}
	step, ok := findStep(job.Steps, "Run standalone ShellCheck gate")
	if !ok {
		t.Fatal("jobs.scan is missing step \"Run standalone ShellCheck gate\"")
	}

	target := t.TempDir()
	runGit(t, target, "init", "-q")
	runGit(t, target, "config", "user.email", "test@example.invalid")
	runGit(t, target, "config", "user.name", "test")

	// #nosec G301 -- this temporary test fixture directory only holds throwaway files.
	if err := os.Mkdir(filepath.Join(target, "scripts"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Non-executable, extensionless: only a first-line shebang identifies it.
	if err := os.WriteFile(filepath.Join(target, "scripts", "tool"), []byte("#!/bin/bash\necho hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Executable, with a shebang the old pattern did not recognize.
	writeExecutable(t, filepath.Join(target, "scripts", "legacy-ash"), "#!/bin/ash\necho hi\n")
	// Executable, with a shebang naming an interpreter ShellCheck does not
	// support: must never be admitted as a scan candidate.
	writeExecutable(t, filepath.Join(target, "scripts", "legacy-zsh"), "#!/bin/zsh\necho hi\n")
	// Tracked symlink whose name matches a recognized extension: must never
	// be admitted as a scan candidate, wherever it points.
	if err := os.Symlink("/etc/passwd", filepath.Join(target, "scripts", "evil.sh")); err != nil {
		t.Fatal(err)
	}
	runGit(t, target, "add", "-A")

	workspace := t.TempDir()
	// #nosec G301 -- this temporary test fixture directory only holds throwaway files.
	if err := os.MkdirAll(filepath.Join(workspace, "security-results"), 0o700); err != nil {
		t.Fatal(err)
	}
	shellcheckrcDir := filepath.Join(workspace, "_segh", ".github", "security")
	// #nosec G301 -- this temporary test fixture directory only holds throwaway files.
	if err := os.MkdirAll(shellcheckrcDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shellcheckrcDir, "shellcheckrc"), []byte("# test\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	argvLog := filepath.Join(t.TempDir(), "argv.log")
	stubDir := writeStubShellCheck(t, argvLog)

	t.Setenv("GITHUB_WORKSPACE", workspace)
	t.Setenv("PATH", stubDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	cmd := exec.CommandContext(context.Background(), "bash", "-c", step.Run) // #nosec G204 -- step.Run is this repository's own gate script, not external input.
	cmd.Dir = target
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run standalone ShellCheck gate script: %v\n%s", err, out)
	}

	argv, err := os.ReadFile(argvLog) // #nosec G304 -- argvLog is created inside this test's unique temporary directory.
	if err != nil {
		t.Fatalf("stub shellcheck was not invoked: %v", err)
	}
	for _, want := range []string{"scripts/tool", "scripts/legacy-ash"} {
		if !strings.Contains(string(argv), want) {
			t.Errorf("standalone ShellCheck gate did not pass %q to ShellCheck; argv:\n%s", want, argv)
		}
	}
	if strings.Contains(string(argv), "evil.sh") {
		t.Errorf("standalone ShellCheck gate passed a tracked symlink to ShellCheck; argv:\n%s", argv)
	}
	if strings.Contains(string(argv), "legacy-zsh") {
		t.Errorf("standalone ShellCheck gate passed an unsupported zsh script to ShellCheck; argv:\n%s", argv)
	}
}

// TestPRSecurityStandaloneShellCheckGateSuppressesAshDialectNote pins that
// the organization-owned .github/security/shellcheckrc disables SC2187, the
// advisory ShellCheck emits on every #!/bin/ash script to note that it is
// checked as dash. ShellCheck has no native ash mode, so this note fires
// regardless of a script's content; left enabled it would fail the enforced
// standalone ShellCheck gate for any otherwise-clean tracked ash script. This
// test runs the real ShellCheck binary (skipping if one is not on PATH,
// since a stub cannot exercise ShellCheck's own diagnostics) against the
// gate script and the actual shellcheckrc file, rather than a synthetic
// fixture, so a regression that re-enables SC2187 is caught here.
func TestPRSecurityStandaloneShellCheckGateSuppressesAshDialectNote(t *testing.T) {
	if _, err := exec.LookPath("shellcheck"); err != nil {
		t.Skip("shellcheck is not installed; skipping a test that exercises its real diagnostics")
	}

	job, ok := loadPRSecurityWorkflow(t).Jobs["scan"]
	if !ok {
		t.Fatal("jobs.scan is missing")
	}
	step, ok := findStep(job.Steps, "Run standalone ShellCheck gate")
	if !ok {
		t.Fatal("jobs.scan is missing step \"Run standalone ShellCheck gate\"")
	}

	target := t.TempDir()
	runGit(t, target, "init", "-q")
	runGit(t, target, "config", "user.email", "test@example.invalid")
	runGit(t, target, "config", "user.name", "test")

	// A clean ash script: SC2187 is the only diagnostic ShellCheck would
	// otherwise raise against it.
	writeExecutable(t, filepath.Join(target, "legacy-ash"), "#!/bin/ash\necho \"hi\"\n")
	runGit(t, target, "add", "-A")

	workspace := t.TempDir()
	// #nosec G301 -- this temporary test fixture directory only holds throwaway files.
	if err := os.MkdirAll(filepath.Join(workspace, "security-results"), 0o700); err != nil {
		t.Fatal(err)
	}
	shellcheckrcDir := filepath.Join(workspace, "_segh", ".github", "security")
	// #nosec G301 -- this temporary test fixture directory only holds throwaway files.
	if err := os.MkdirAll(shellcheckrcDir, 0o700); err != nil {
		t.Fatal(err)
	}
	rc, err := os.ReadFile(shellcheckrcPath) // #nosec G304 -- shellcheckrcPath is a fixed repository-relative constant.
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shellcheckrcDir, "shellcheckrc"), rc, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GITHUB_WORKSPACE", workspace)
	cmd := exec.CommandContext(context.Background(), "bash", "-c", step.Run) // #nosec G204 -- step.Run is this repository's own gate script, not external input.
	cmd.Dir = target
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run standalone ShellCheck gate script: %v\n%s", err, out)
	}

	statusBytes, err := os.ReadFile(filepath.Join(workspace, "security-results", "shellcheck.status")) // #nosec G304 -- the path is created inside this test's unique temporary directory.
	if err != nil {
		t.Fatalf("shellcheck.status was not written: %v", err)
	}
	if status := strings.TrimSpace(string(statusBytes)); status != "0" {
		report, _ := os.ReadFile(filepath.Join(workspace, "security-results", "shellcheck.txt")) // #nosec G304 -- the path is created inside this test's unique temporary directory.
		t.Errorf("standalone ShellCheck gate exited %q against a clean ash script; report:\n%s", status, report)
	}
}

// TestPRSecurityRejectSymlinksStepRemovesTrackedSymlinks pins that the
// "Reject symlinks from the pull request checkout" step deletes every
// tracked symlink from the pull request checkout (protecting scanners like
// Checkov that walk the directory tree directly rather than through a
// git-ls-files candidate list, which a mode filter alone cannot cover) while
// leaving ordinary tracked files untouched, and records what it removed.
func TestPRSecurityRejectSymlinksStepRemovesTrackedSymlinks(t *testing.T) {
	job, ok := loadPRSecurityWorkflow(t).Jobs["scan"]
	if !ok {
		t.Fatal("jobs.scan is missing")
	}
	step, ok := findStep(job.Steps, "Reject symlinks from the pull request checkout")
	if !ok {
		t.Fatal("jobs.scan is missing step \"Reject symlinks from the pull request checkout\"")
	}

	target := t.TempDir()
	runGit(t, target, "init", "-q")
	runGit(t, target, "config", "user.email", "test@example.invalid")
	runGit(t, target, "config", "user.name", "test")

	regularPath := filepath.Join(target, "main.tf")
	if err := os.WriteFile(regularPath, []byte("# regular file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(target, "escape.tf")
	if err := os.Symlink("/etc/passwd", symlinkPath); err != nil {
		t.Fatal(err)
	}
	runGit(t, target, "add", "-A")

	workspace := t.TempDir()
	// #nosec G301 -- this temporary test fixture directory only holds throwaway files.
	if err := os.MkdirAll(filepath.Join(workspace, "security-results"), 0o700); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GITHUB_WORKSPACE", workspace)
	cmd := exec.CommandContext(context.Background(), "bash", "-c", step.Run) // #nosec G204 -- step.Run is this repository's own gate script, not external input.
	cmd.Dir = target
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run symlink-rejection step: %v\n%s", err, out)
	}

	if _, err := os.Lstat(symlinkPath); !os.IsNotExist(err) {
		t.Errorf("symlink %s still exists after the rejection step (err=%v)", symlinkPath, err)
	}
	if _, err := os.Lstat(regularPath); err != nil {
		t.Errorf("regular file %s was unexpectedly removed: %v", regularPath, err)
	}

	report, err := os.ReadFile(filepath.Join(workspace, "security-results", "rejected-symlinks.txt")) // #nosec G304 -- the path is created inside this test's unique temporary directory.
	if err != nil {
		t.Fatalf("rejected-symlinks.txt was not written: %v", err)
	}
	if !strings.Contains(string(report), "escape.tf") {
		t.Errorf("rejected-symlinks.txt does not mention the rejected symlink; report:\n%s", report)
	}
}
