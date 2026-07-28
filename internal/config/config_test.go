package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadExample(t *testing.T) {
	t.Setenv("SEGH_GITHUB_APP_ID", "")
	t.Setenv("SEGH_GITHUB_INSTALLATION_ID", "")
	cfg, data, err := Load(filepath.Join("..", "..", "segh.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != 1 || cfg.Organization != "example-org" || len(data) == 0 {
		t.Fatalf("unexpected config: %#v", cfg)
	}
	if got := cfg.Execution.RepositoryTimeout.String(); got != "25m0s" {
		t.Fatalf("duration = %s", got)
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "segh.yaml")
	data := strings.Replace(
		"version: 1\norganization: test\n",
		"organization: test", "organization: test\nsurprise: true", 1,
	)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path); err == nil || !strings.Contains(err.Error(), "field surprise not found") {
		t.Fatalf("expected unknown-field error, got %v", err)
	}
}

func TestEnvironmentIDs(t *testing.T) {
	t.Setenv("SEGH_GITHUB_APP_ID", "42")
	t.Setenv("SEGH_GITHUB_INSTALLATION_ID", "99")
	cfg, _, err := Load(filepath.Join("..", "..", "config", "organization.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Auth.AppID != 42 || cfg.Auth.InstallationID != 99 {
		t.Fatalf("environment overlay failed: %#v", cfg.Auth)
	}
}

func TestValidateRejectsUnsafeEndpointAndMissingVersion(t *testing.T) {
	cfg := Default()
	cfg.Organization = "test"
	cfg.GitHub.APIURL = "http://github.example/api/v3"
	cfg.Scanners.Zizmor.Enabled = true
	err := cfg.Validate(".")
	if err == nil || !strings.Contains(err.Error(), "must use HTTPS") || !strings.Contains(err.Error(), "zizmor.version") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRejectsSpoofedLocalEndpoints(t *testing.T) {
	unsafe := []string{
		"http://localhost.attacker.example",
		"http://localhost@attacker.example",
		"http://localhost:80@attacker.example",
		"http://attacker.example#localhost",
	}
	for _, raw := range unsafe {
		cfg := Default()
		cfg.Organization = "test"
		cfg.GitHub.APIURL = raw
		if err := cfg.Validate("."); err == nil || !strings.Contains(err.Error(), "must use HTTPS") {
			t.Fatalf("%s: expected HTTPS rejection, got %v", raw, err)
		}
	}
}

func TestValidateAcceptsGenuineLocalEndpoints(t *testing.T) {
	safe := []string{"http://localhost", "http://localhost:8080", "http://127.0.0.1:9000", "http://[::1]:9000"}
	for _, raw := range safe {
		cfg := Default()
		cfg.Organization = "test"
		cfg.GitHub.APIURL = raw
		if err := cfg.Validate("."); err != nil && strings.Contains(err.Error(), "must use HTTPS") {
			t.Fatalf("%s: unexpected HTTPS rejection: %v", raw, err)
		}
	}
}
