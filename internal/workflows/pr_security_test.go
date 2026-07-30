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

const prSecurityWorkflowPath = "../../.github/workflows/pr-security.yml"

type prSecurityStep struct {
	Name string         `yaml:"name"`
	With map[string]any `yaml:"with"`
}

type prSecurityJob struct {
	If    string           `yaml:"if"`
	Steps []prSecurityStep `yaml:"steps"`
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

func stepNames(steps []prSecurityStep) []string {
	names := make([]string, len(steps))
	for i, step := range steps {
		names[i] = step.Name
	}
	return names
}

// TestPRSecurityWorkflowTriggersOnPullRequestTarget pins that scan-self can
// keep running: its enforcement is only immune to a pull request editing
// this file because pull_request_target sources the job definition from the
// base branch. Losing that trigger would silently revert to a
// pull_request-only workflow a pull request can weaken.
func TestPRSecurityWorkflowTriggersOnPullRequestTarget(t *testing.T) {
	workflow := loadPRSecurityWorkflow(t)
	for _, trigger := range []string{"pull_request", "pull_request_target"} {
		if _, ok := workflow.On[trigger]; !ok {
			t.Errorf("on: is missing trigger %q", trigger)
		}
	}
}

// TestPRSecurityScanSelfGatedToSourceRepositoryPullRequestTarget pins that
// scan-self only runs for the source repository under the secure trigger,
// so it cannot double-run under the pull_request-triggered event too.
func TestPRSecurityScanSelfGatedToSourceRepositoryPullRequestTarget(t *testing.T) {
	workflow := loadPRSecurityWorkflow(t)
	job, ok := workflow.Jobs["scan-self"]
	if !ok {
		t.Fatal("jobs.scan-self is missing")
	}
	for _, want := range []string{"github.repository == 'dceoy/segh'", "github.event_name == 'pull_request_target'"} {
		if !strings.Contains(job.If, want) {
			t.Errorf("jobs.scan-self.if = %q, want it to contain %q", job.If, want)
		}
	}
}

// TestPRSecurityScanAndScanSelfStepsStayInSync pins that scan and scan-self
// run the same scanner and enforcement steps. A pull request cannot edit
// scan-self's own definition, but nothing stops a future change from
// updating scan's gate logic while forgetting scan-self's, silently
// reopening the enforcement gap scan-self exists to close.
func TestPRSecurityScanAndScanSelfStepsStayInSync(t *testing.T) {
	workflow := loadPRSecurityWorkflow(t)
	scan, ok := workflow.Jobs["scan"]
	if !ok {
		t.Fatal("jobs.scan is missing")
	}
	scanSelf, ok := workflow.Jobs["scan-self"]
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
	workflow := loadPRSecurityWorkflow(t)
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
// only runs for the pull_request-triggered event. This workflow declares
// both pull_request and pull_request_target as triggers; without this guard
// a target repository would run the informational Scorecard job twice per
// pull request.
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
