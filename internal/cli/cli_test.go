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

func TestRemovedCommandUsesStableUsageExit(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{"--config", "../../config/organization.yaml", "scan"}, "test", &stdout, &stderr)
	if err == nil || ExitCode(err) != exitUsage || !strings.Contains(err.Error(), `unknown command "scan"`) {
		t.Fatalf("err=%v code=%d", err, ExitCode(err))
	}
}
