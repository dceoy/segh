package github

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/dceoy/segh/internal/config"
	"github.com/dceoy/segh/internal/logging"
)

func TestExistingTokenRequiresExplicitFallback(t *testing.T) {
	cfg := config.Default()
	cfg.Organization = "org"
	t.Setenv(cfg.Auth.TokenEnv, "development-token")
	if _, err := NewAuth(cfg, logging.New(os.Stderr)); err == nil {
		t.Fatal("token was accepted without explicit fallback")
	}
	cfg.Auth.AllowExistingToken = true
	auth, err := NewAuth(cfg, logging.New(os.Stderr))
	if err != nil {
		t.Fatal(err)
	}
	token, err := auth.Token(context.Background())
	if err != nil || token != "development-token" {
		t.Fatalf("token=%q err=%v", token, err)
	}
}

func TestPrivateKeyFilePermissionsFailClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	cfg := config.Default()
	cfg.Organization = "org"
	cfg.Auth.AppID = 1
	cfg.Auth.PrivateKeyEnv = ""
	cfg.Auth.PrivateKeyFile = filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(cfg.Auth.PrivateKeyFile, []byte("not a key"), 0o644); err != nil { // #nosec G306 -- deliberately insecure mode verifies fail-closed behavior.
		t.Fatal(err)
	}
	_, err := NewAuth(cfg, logging.New(os.Stderr))
	if err == nil || !strings.Contains(err.Error(), "must not be accessible") {
		t.Fatalf("unexpected error: %v", err)
	}
}
