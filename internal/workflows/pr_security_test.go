// Package workflows pins the trust boundaries of the security-critical
// GitHub Actions workflows that cannot be exercised against themselves.
package workflows

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	prSecurityWorkflowPath     = "../../.github/workflows/pr-security.yml"
	prSecuritySelfWorkflowPath = "../../.github/workflows/pr-security-self.yml"
	prSecurityActionPath       = "../../.github/actions/pr-security/action.yml"
	prSecurityScriptPath       = "../../.github/actions/pr-security/scan.sh"
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
	Permissions map[string]string `yaml:"permissions"`
	Env         map[string]string `yaml:"env"`
	Steps       []workflowStep    `yaml:"steps"`
}

type workflowDocument struct {
	On   map[string]any         `yaml:"on"`
	Jobs map[string]workflowJob `yaml:"jobs"`
}

type actionDocument struct {
	Runs struct {
		Using string         `yaml:"using"`
		Steps []workflowStep `yaml:"steps"`
	} `yaml:"runs"`
}

func TestPRSecurityWrappersPreserveEventAndRepositoryBoundaries(t *testing.T) {
	ordinary := loadWorkflow(t, prSecurityWorkflowPath)
	if _, ok := ordinary.On["pull_request"]; !ok {
		t.Error("pr-security.yml is missing pull_request")
	}
	if _, ok := ordinary.On["merge_group"]; !ok {
		t.Error("pr-security.yml is missing merge_group")
	}
	if _, ok := ordinary.On["pull_request_target"]; ok {
		t.Error("pr-security.yml must not use pull_request_target")
	}
	scan := ordinary.Jobs["scan"]
	if !strings.Contains(scan.If, "github.repository != 'dceoy/segh'") ||
		!strings.Contains(scan.If, "github.event_name == 'merge_group'") {
		t.Fatalf("jobs.scan.if = %q", scan.If)
	}

	self := loadWorkflow(t, prSecuritySelfWorkflowPath)
	if len(self.On) != 1 {
		t.Fatalf("self-scan triggers = %#v, want only pull_request_target", self.On)
	}
	if _, ok := self.On["pull_request_target"]; !ok {
		t.Error("pr-security-self.yml is missing pull_request_target")
	}
	if condition := self.Jobs["scan-self"].If; !strings.Contains(condition, "github.repository == 'dceoy/segh'") {
		t.Fatalf("jobs.scan-self.if = %q", condition)
	}
}

func TestPRSecurityWrappersInvokeSameTrustedCompositeAction(t *testing.T) {
	for _, test := range []struct {
		path string
		job  string
	}{
		{prSecurityWorkflowPath, "scan"},
		{prSecuritySelfWorkflowPath, "scan-self"},
	} {
		job := loadWorkflow(t, test.path).Jobs[test.job]
		step, ok := findStep(job.Steps, "Run trusted scanner pipeline")
		if !ok {
			t.Fatalf("%s jobs.%s is missing the trusted scanner invocation", test.path, test.job)
		}
		if step.Uses != "./_segh/.github/actions/pr-security" {
			t.Errorf("%s jobs.%s scanner action = %q", test.path, test.job, step.Uses)
		}
		if len(job.Steps) != 3 {
			t.Errorf("%s jobs.%s has %d steps, want two checkouts and one action", test.path, test.job, len(job.Steps))
		}
		if config := job.Env["AQUA_CONFIG"]; !strings.Contains(config, "_segh/aqua.yaml") {
			t.Errorf("%s jobs.%s AQUA_CONFIG = %q", test.path, test.job, config)
		}
		if len(job.Permissions) != 1 || job.Permissions["contents"] != "read" {
			t.Errorf("%s jobs.%s permissions = %#v", test.path, test.job, job.Permissions)
		}
	}
}

func TestPRSecurityCheckoutRefsKeepTargetDataUntrusted(t *testing.T) {
	scan := loadWorkflow(t, prSecurityWorkflowPath).Jobs["scan"]
	trusted, _ := findStep(scan.Steps, "Check out trusted scanner configuration")
	if trusted.With["repository"] != "dceoy/segh" {
		t.Errorf("scan trusted repository = %#v", trusted.With["repository"])
	}
	trustedRef, _ := trusted.With["ref"].(string)
	if !strings.Contains(trustedRef, "github.workflow_sha") ||
		!strings.Contains(trustedRef, "github.event.pull_request.base.sha") ||
		trusted.With["path"] != "_segh" ||
		trusted.With["persist-credentials"] != false {
		t.Errorf("scan trusted checkout = %#v", trusted.With)
	}
	target, _ := findStep(scan.Steps, "Check out pull request")
	targetRef, _ := target.With["ref"].(string)
	if !strings.Contains(targetRef, "github.event.merge_group.head_sha") ||
		!strings.Contains(targetRef, "github.event.pull_request.head.sha") ||
		target.With["path"] != "_target" ||
		target.With["persist-credentials"] != false {
		t.Errorf("scan target checkout = %#v", target.With)
	}

	self := loadWorkflow(t, prSecuritySelfWorkflowPath).Jobs["scan-self"]
	selfTrusted, _ := findStep(self.Steps, "Check out trusted scanner configuration")
	if selfTrusted.With["ref"] != "${{ github.event.pull_request.base.sha }}" ||
		selfTrusted.With["path"] != "_segh" ||
		selfTrusted.With["persist-credentials"] != false {
		t.Errorf("self trusted checkout = %#v", selfTrusted.With)
	}
	selfTarget, _ := findStep(self.Steps, "Check out pull request")
	if selfTarget.With["allow-unsafe-pr-checkout"] != true ||
		selfTarget.With["persist-credentials"] != false ||
		selfTarget.With["path"] != "_target" {
		t.Errorf("self target checkout = %#v", selfTarget.With)
	}
}

func TestTrustedCompositeActionOwnsAllBlockingScannersAndArtifacts(t *testing.T) {
	action := loadAction(t)
	if action.Runs.Using != "composite" {
		t.Fatalf("runs.using = %q", action.Runs.Using)
	}
	names := stepNames(action.Runs.Steps)
	required := []string{
		"Install checksum-verified scanners",
		"Reject symlinks from the pull request checkout",
		"Run zizmor gate",
		"Run actionlint and embedded ShellCheck gate",
		"Run standalone ShellCheck gate",
		"Run Checkov infrastructure-as-code gate",
		"Run Trivy vulnerability gate",
		"Run Trivy secret gate",
		"Publish scanner summary",
		"Retain scanner reports",
		"Enforce scanner gates",
	}
	for _, name := range required {
		if !slices.Contains(names, name) {
			t.Errorf("composite action is missing %q", name)
		}
	}
	rejectIndex := slices.Index(names, "Reject symlinks from the pull request checkout")
	for _, scanner := range required[2:8] {
		if slices.Index(names, scanner) <= rejectIndex {
			t.Errorf("%q does not run after symlink rejection", scanner)
		}
	}
	aqua, _ := findStep(action.Runs.Steps, "Install checksum-verified scanners")
	if !strings.Contains(aqua.Uses, "@96a9bc20066c5bf5e275b41019cfc165b25f4e2e") ||
		aqua.With["working_directory"] != "_segh" {
		t.Errorf("Aqua installation is not pinned to the trusted checkout: %#v", aqua)
	}
	upload, _ := findStep(action.Runs.Steps, "Retain scanner reports")
	if upload.With["name"] != "pr-security-reports" || upload.With["path"] != "security-results" {
		t.Errorf("scanner artifact contract changed: %#v", upload.With)
	}
}

func TestTrustedScannerScriptPinsConfigurationAndThresholds(t *testing.T) {
	script := readFile(t, prSecurityScriptPath)
	for _, want := range []string{
		`trusted_dir="$GITHUB_WORKSPACE/_segh"`,
		`target_dir="$GITHUB_WORKSPACE/_target"`,
		"--offline",
		"--no-config",
		"--min-severity medium",
		"--min-confidence high",
		`--config-file "$trusted_dir/.github/security/actionlint.yaml"`,
		`--rcfile "$trusted_dir/.github/security/shellcheckrc"`,
		`--config-file "$trusted_dir/.github/security/checkov.yaml"`,
		"--skip-download",
		"--scanners vuln",
		"--severity HIGH,CRITICAL",
		`--secret-config "$trusted_dir/.github/security/trivy-secret.yaml"`,
		"--severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
		"zizmor.status",
		"actionlint.status",
		"shellcheck.status",
		"checkov.status",
		"trivy-vulnerability.status",
		"trivy-secret.status",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("trusted scanner script is missing %q", want)
		}
	}
	for _, path := range []string{prSecurityWorkflowPath, prSecuritySelfWorkflowPath} {
		wrapper := readFile(t, path)
		for _, scanner := range []string{"zizmor \\", "actionlint \\", "checkov \\", "trivy fs"} {
			if strings.Contains(wrapper, scanner) {
				t.Errorf("%s still duplicates scanner command %q", path, scanner)
			}
		}
	}
}

func TestStandaloneShellCheckDiscoversTrackedShellScriptsSafely(t *testing.T) {
	workspace := t.TempDir()
	target := filepath.Join(workspace, "_target")
	if err := os.MkdirAll(filepath.Join(target, "scripts"), 0o700); err != nil {
		t.Fatal(err)
	}
	runGit(t, target, "init", "-q")
	if err := os.WriteFile(filepath.Join(target, "scripts", "tool"), []byte("#!/bin/bash\necho hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(target, "scripts", "legacy-ash"), "#!/bin/ash\necho hi\n")
	writeExecutable(t, filepath.Join(target, "scripts", "legacy-zsh"), "#!/bin/zsh\necho hi\n")
	if err := os.Symlink("/etc/passwd", filepath.Join(target, "scripts", "evil.sh")); err != nil {
		t.Fatal(err)
	}
	runGit(t, target, "add", "-A")
	if err := os.MkdirAll(filepath.Join(workspace, "_segh", ".github", "security"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(workspace, "security-results"), 0o700); err != nil {
		t.Fatal(err)
	}
	argvLog := filepath.Join(t.TempDir(), "argv.log")
	stubDir := t.TempDir()
	writeExecutable(
		t,
		filepath.Join(stubDir, "shellcheck"),
		"#!/bin/sh\nprintf '%s\\n' \"$@\" > \""+argvLog+"\"\n",
	)
	t.Setenv("GITHUB_WORKSPACE", workspace)
	t.Setenv("PATH", stubDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	runScanner(t, "shellcheck")
	argv := readFile(t, argvLog)
	for _, want := range []string{"scripts/tool", "scripts/legacy-ash"} {
		if !strings.Contains(argv, want) {
			t.Errorf("ShellCheck argv is missing %q:\n%s", want, argv)
		}
	}
	for _, rejected := range []string{"evil.sh", "legacy-zsh"} {
		if strings.Contains(argv, rejected) {
			t.Errorf("ShellCheck argv unexpectedly contains %q:\n%s", rejected, argv)
		}
	}
}

func TestSymlinkRejectionRemovesTrackedLinksBeforeScanning(t *testing.T) {
	workspace := t.TempDir()
	target := filepath.Join(workspace, "_target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	runGit(t, target, "init", "-q")
	regular := filepath.Join(target, "main.tf")
	if err := os.WriteFile(regular, []byte("# fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(target, "escape.tf")
	if err := os.Symlink("/etc/passwd", symlink); err != nil {
		t.Fatal(err)
	}
	runGit(t, target, "add", "-A")
	if err := os.MkdirAll(filepath.Join(workspace, "security-results"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_WORKSPACE", workspace)
	runScanner(t, "reject-symlinks")
	if _, err := os.Lstat(symlink); !os.IsNotExist(err) {
		t.Errorf("tracked symlink still exists: %v", err)
	}
	if _, err := os.Stat(regular); err != nil {
		t.Errorf("regular file was removed: %v", err)
	}
	report := readFile(t, filepath.Join(workspace, "security-results", "rejected-symlinks.txt"))
	if !strings.Contains(report, "escape.tf") {
		t.Errorf("rejection report = %q", report)
	}
}

func TestSelfScanPublishesDedicatedAppCheckOnHeadCommit(t *testing.T) {
	job := loadWorkflow(t, prSecuritySelfWorkflowPath).Jobs["publish-self-check"]
	if _, hasChecks := job.Permissions["checks"]; hasChecks {
		t.Errorf("ambient token has checks permission: %#v", job.Permissions)
	}
	token, ok := findStep(job.Steps, "Create dedicated publisher App token")
	if !ok || !strings.Contains(token.Uses, "@bcd2ba49218906704ab6c1aa796996da409d3eb1") ||
		!strings.Contains(token.With["client-id"].(string), "vars.SEGH_SCAN_PUBLISHER_CLIENT_ID") ||
		!strings.Contains(token.With["private-key"].(string), "secrets.SEGH_SCAN_PUBLISHER_APP_PRIVATE_KEY") {
		t.Errorf("dedicated App token step = %#v", token)
	}
	publish, ok := findStep(job.Steps, "Publish the gate result on the pull request's head commit")
	if !ok || !strings.Contains(publish.Run, "github.event.pull_request.head.sha") ||
		!strings.Contains(publish.Env["GH_TOKEN"].(string), "steps.app-token.outputs.token") {
		t.Errorf("head-commit publisher step = %#v", publish)
	}
}

func TestScorecardRemainsInformationalAndPullRequestOnly(t *testing.T) {
	job := loadWorkflow(t, prSecurityWorkflowPath).Jobs["scorecard"]
	if !strings.Contains(job.If, "github.event_name == 'pull_request'") {
		t.Errorf("scorecard if = %q", job.If)
	}
	step, ok := findStep(job.Steps, "Run OpenSSF Scorecard")
	if !ok || !strings.Contains(step.Uses, "@2d1146689b8cda280b9bc96326124645441f03bc") {
		t.Errorf("Scorecard step = %#v", step)
	}
}

func loadWorkflow(t *testing.T, path string) workflowDocument {
	t.Helper()
	var workflow workflowDocument
	if err := yaml.Unmarshal([]byte(readFile(t, path)), &workflow); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return workflow
}

func loadAction(t *testing.T) actionDocument {
	t.Helper()
	var action actionDocument
	if err := yaml.Unmarshal([]byte(readFile(t, prSecurityActionPath)), &action); err != nil {
		t.Fatalf("parse action: %v", err)
	}
	return action
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- callers pass fixed repository paths or test-owned paths.
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func findStep(steps []workflowStep, name string) (workflowStep, bool) {
	for _, step := range steps {
		if step.Name == name {
			return step, true
		}
	}
	return workflowStep{}, false
}

func stepNames(steps []workflowStep) []string {
	names := make([]string, len(steps))
	for i, step := range steps {
		names[i] = step.Name
	}
	return names
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	command := exec.CommandContext(context.Background(), "git", args...) // #nosec G204 -- args are test-owned git subcommands.
	command.Dir = dir
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
}

func writeExecutable(t *testing.T, path, body string) {
	t.Helper()
	// #nosec G306 -- the temporary test fixture must be executable.
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
}

func runScanner(t *testing.T, operation string) {
	t.Helper()
	command := exec.CommandContext(context.Background(), "bash", prSecurityScriptPath, operation) // #nosec G204 -- operation is a fixed test value.
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("scan.sh %s: %v\n%s", operation, err, output)
	}
}
