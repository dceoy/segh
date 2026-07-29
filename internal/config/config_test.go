package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadExample(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "segh.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != 2 || cfg.Organization != "example-org" || cfg.Inventory.Concurrency != 4 {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "segh.yaml")
	data := "version: 2\norganization: test\nsurprise: true\n"
	if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(configPath); err == nil || !strings.Contains(err.Error(), "field surprise not found") {
		t.Fatalf("expected unknown-field error, got %v", err)
	}
}

func TestLoadRejectsMissingPolicies(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "segh.yaml")
	data := "version: 2\norganization: test\n"
	if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(configPath); err == nil || !strings.Contains(err.Error(), "at least one policy must be configured") {
		t.Fatalf("expected missing-policy error, got %v", err)
	}
}

func TestLoadAcceptsDefaultedNonPolicySections(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "segh.yaml")
	data := "version: 2\norganization: test\npolicies:\n  repository:\n    require_ruleset: true\n"
	if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GitHub.WebURL != "https://github.com" || cfg.Inventory.Concurrency != 4 || cfg.Output.Directory != "segh-results" {
		t.Fatalf("defaults were not applied: %#v", cfg)
	}
}

func TestValidateRejectsSpoofedLocalEndpoints(t *testing.T) {
	unsafe := []string{
		"http://localhost.attacker.example",
		"http://localhost@attacker.example",
		"http://localhost:80@attacker.example",
		"http://attacker.example#localhost",
		"https://github.example/api/v3",
	}
	for _, raw := range unsafe {
		cfg := Default()
		cfg.Organization = "test"
		cfg.Policies.Repository.RequireRuleset = true
		cfg.GitHub.WebURL = raw
		if err := cfg.Validate(); err == nil {
			t.Fatalf("%s: expected URL rejection", raw)
		}
	}
}

func TestValidateAcceptsGenuineLocalEndpoints(t *testing.T) {
	safe := []string{"http://localhost", "http://localhost:8080", "http://127.0.0.1:9000", "http://[::1]:9000"}
	for _, raw := range safe {
		cfg := Default()
		cfg.Organization = "test"
		cfg.Policies.Repository.RequireRuleset = true
		cfg.GitHub.WebURL = raw
		if err := cfg.Validate(); err != nil {
			t.Fatalf("%s: unexpected rejection: %v", raw, err)
		}
	}
}
