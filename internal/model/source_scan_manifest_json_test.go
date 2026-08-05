package model

import (
	"encoding/json"
	"testing"
)

func TestSourceScanManifestRejectsUnsupportedGitHubHost(t *testing.T) {
	for _, host := range []string{"", "ghes.example"} {
		var manifest SourceScanManifest
		if err := json.Unmarshal([]byte("{\"github_host\":\""+host+"\"}"), &manifest); err == nil {
			t.Errorf("github_host %q was accepted", host)
		}
	}
}
