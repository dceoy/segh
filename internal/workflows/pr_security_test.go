// Package workflows pins repository-owned trust boundaries that cannot be
// exercised safely by a pull request against itself.
package workflows

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	prSecurityWorkflowPath     = "../../.github/workflows/pr-security.yml"
	prSecuritySelfWorkflowPath = "../../.github/workflows/pr-security-self.yml"
	upstreamSecurityWorkflow   = "dceoy/gha-for-devops/.github/workflows/repository-security-scan.yml@c84ceed28723b5cd5a93edb1febdfaad39e7c522"
)

type workflowStep struct {
	Name string         `yaml:"name"`
	Uses string         `yaml:"uses"`
	With map[string]any `yaml:"with"`
	Env  map[string]any `yaml:"env"`
	Run  string         `yaml:"run"`
}

type workflowJob struct {
	If          string            `yaml:"if"`
	Uses        string            `yaml:"uses"`
	Needs       any               `yaml:"needs"`
	Permissions map[string]string `yaml:"permissions"`
	Steps       []workflowStep    `yaml:"steps"`
}

type workflowDocument struct {
	On   map[string]any         `yaml:"on"`
	Jobs map[string]workflowJob `yaml:"jobs"`
}

func TestPRSecurityCompatibilityBridgeDelegatesScanningUpstream(t *testing.T) {
	workflow := loadWorkflow(t, prSecurityWorkflowPath)
	if _, ok := workflow.On["pull_request"]; !ok {
		t.Error("pr-security.yml is missing pull_request")
	}
	if _, ok := workflow.On["merge_group"]; !ok {
		t.Error("pr-security.yml is missing merge_group")
	}
	if _, ok := workflow.On["pull_request_target"]; ok {
		t.Error("pr-security.yml must not use pull_request_target")
	}
	upstream := workflow.Jobs["upstream"]
	if upstream.Uses != upstreamSecurityWorkflow {
		t.Fatalf("jobs.upstream.uses = %q", upstream.Uses)
	}
	if !strings.Contains(upstream.If, "github.repository != 'dceoy/segh'") {
		t.Fatalf("jobs.upstream.if = %q", upstream.If)
	}
	compatibility := workflow.Jobs["scan"]
	if compatibility.Needs != "upstream" || len(compatibility.Steps) != 1 {
		t.Fatalf("compatibility job = %#v", compatibility)
	}
	if strings.Contains(readFile(t, prSecurityWorkflowPath), "ossf/scorecard-action") {
		t.Error("the compatibility bridge must not retain PR-time Scorecard execution")
	}
	if strings.Contains(readFile(t, prSecurityWorkflowPath), "./_segh/.github/actions/pr-security") {
		t.Error("the downstream compatibility bridge must not invoke the local scanner")
	}
}

func TestSelfScanRemainsBaseControlledUntilAdministratorMigration(t *testing.T) {
	workflow := loadWorkflow(t, prSecuritySelfWorkflowPath)
	if len(workflow.On) != 1 {
		t.Fatalf("self-scan triggers = %#v", workflow.On)
	}
	if _, ok := workflow.On["pull_request_target"]; !ok {
		t.Error("pr-security-self.yml is missing pull_request_target")
	}
	self := workflow.Jobs["scan-self"]
	if !strings.Contains(self.If, "github.repository == 'dceoy/segh'") {
		t.Fatalf("jobs.scan-self.if = %q", self.If)
	}
	if !containsUse(self.Steps, "./_segh/.github/actions/pr-security") {
		t.Error("the legacy self gate must remain until the upstream ruleset is verified live")
	}
	publisher := workflow.Jobs["publish-self-check"]
	if publisher.Needs != "scan-self" || !containsRun(publisher.Steps, "github.event.pull_request.head.sha") {
		t.Fatalf("legacy head-check publisher changed unexpectedly: %#v", publisher)
	}
}

func loadWorkflow(t *testing.T, path string) workflowDocument {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var workflow workflowDocument
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	return workflow
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func containsUse(steps []workflowStep, want string) bool {
	for _, step := range steps {
		if step.Uses == want {
			return true
		}
	}
	return false
}

func containsRun(steps []workflowStep, want string) bool {
	for _, step := range steps {
		if strings.Contains(step.Run, want) {
			return true
		}
	}
	return false
}
