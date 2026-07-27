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
		{[]string{"--help"}, "Usage:"},
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

func TestUnknownCommandUsesStableUsageExit(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{"--config", "../../config/pr.yaml", "unknown"}, "test", &stdout, &stderr)
	if err == nil || ExitCode(err) != exitUsage {
		t.Fatalf("err=%v code=%d", err, ExitCode(err))
	}
}
