package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestHelpAndVersionDoNotRequireConfiguration(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"--help"}, "GitHub security governance audit"},
		{[]string{"--version"}, "test-version"},
	} {
		var stdout, stderr bytes.Buffer
		if err := Run(context.Background(), test.args, "test-version", &stdout, &stderr); err != nil {
			t.Fatalf("%v: %v", test.args, err)
		}
		if !strings.Contains(stdout.String(), test.want) {
			t.Fatalf("%v output = %q", test.args, stdout.String())
		}
	}
}

func TestHelpPresentsOnlyAuditAsTheCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := Run(context.Background(), []string{"--help"}, "test-version", &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	output := stdout.String()
	if !strings.Contains(output, "segh audit --config segh.yaml") {
		t.Fatalf("help output does not present audit: %q", output)
	}
	for _, removed := range []string{"scan-plan", "scan-summary"} {
		if strings.Contains(output, removed) {
			t.Fatalf("help output = %q, contains removed command %q", output, removed)
		}
	}
}

func TestRemovedCommandsAndFlagsAreRejected(t *testing.T) {
	for _, args := range [][]string{
		{"validate"},
		{"inventory"},
		{"report"},
		{"scan-plan"},
		{"scan-summary"},
		{"--config", "segh.yaml", "audit"},
		{"audit", "--github-web-url", "https://github.com"},
	} {
		var stdout, stderr bytes.Buffer
		err := Run(context.Background(), args, "test", &stdout, &stderr)
		if err == nil || ExitCode(err) != exitUsage {
			t.Fatalf("%v: err=%v code=%d", args, err, ExitCode(err))
		}
	}
}

func TestAuditValidateOnlyDoesNotRequireCredentials(t *testing.T) {
	t.Setenv("GH_TOKEN", "")
	t.Setenv("SEGH_GITHUB_INSTALLATION_ID", "")
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{
		"audit", "--config", writeConfig(t, false, false), "--validate-only",
	}, "test", &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "configuration is valid\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestAuditRequiresInstallationIDAfterConfigurationValidation(t *testing.T) {
	t.Setenv("SEGH_GITHUB_INSTALLATION_ID", "")
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{
		"audit", "--config", writeConfig(t, false, false),
	}, "test", &stdout, &stderr)
	if err == nil || ExitCode(err) != exitAuth ||
		!strings.Contains(err.Error(), "SEGH_GITHUB_INSTALLATION_ID must be a positive integer") {
		t.Fatalf("err=%v code=%d", err, ExitCode(err))
	}
}
