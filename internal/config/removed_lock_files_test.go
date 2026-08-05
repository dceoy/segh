package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRejectsRemovedLockFilesDependencyPolicy(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "segh.yaml")
	data := "version: 5\norganization: test\npolicies:\n  dependencies:\n    lock_files: true\n"
	if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(configPath); err == nil ||
		!strings.Contains(err.Error(), "additional properties 'lock_files' not allowed") {
		t.Fatalf("Load() = %v, want removed lock_files field error", err)
	}
}
