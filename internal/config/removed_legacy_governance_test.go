package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRejectsRemovedLegacyGovernancePolicy(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "segh.yaml")
	data := "version: 5\norganization: test\npolicies:\n  repository:\n    require_branch_protection: true\n"
	if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(configPath); err == nil || !strings.Contains(err.Error(), "additional properties 'require_branch_protection' not allowed") {
		t.Fatalf("Load() = %v, want removed branch-protection field error", err)
	}
}
