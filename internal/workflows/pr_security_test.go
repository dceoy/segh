// Package workflows pins structural properties of the security-critical
// GitHub Actions workflows that a pull request could otherwise silently
// weaken, since GitHub Actions has no runtime to exercise those properties
// against.
package workflows

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	prSecurityWorkflowPath     = "../../.github/workflows/pr-security.yml"
	prSecuritySelfWorkflowPath = "../../.github/workflows/pr-security-self.yml"
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

// TestPRSecurityScanAndScanSelfStepsStayInSync pins that scan and scan-self
// run the same scanner and enforcement steps. A pull request cannot edit
// scan-self's own definition, but nothing stops a future change from
// updating scan's gate logic while forgetting scan-self's, silently
// reopening the enforcement gap scan-self exists to close.
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
		t.Errorf("jobs.scan and jobs.scan-self steps diverged:\nscan:      %v\nscan-self: %v", scanSteps, scanSelfSteps)
	}
	for _, want := range []string{"Run zizmor gate", "Run Trivy secret gate", "Enforce scanner gates"} {
		if !slicesContains(scanSelfSteps, want) {
			t.Errorf("jobs.scan-self is missing step %q", want)
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
