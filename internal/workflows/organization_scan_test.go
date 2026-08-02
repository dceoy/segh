package workflows

import (
	"strings"
	"testing"
)

const organizationAuditWorkflowPath = "../../.github/workflows/organization-audit.yml"

func TestOrganizationAuditSchedulesBoundedImmutableSourceScans(t *testing.T) {
	workflow := readFile(t, organizationAuditWorkflowPath)
	for _, required := range []string{
		`schedule:`,
		`scan-plan`,
		`fail-fast: false`,
		`max-parallel: ${{ fromJSON(needs.audit.outputs.scan-concurrency) }}`,
		`timeout-minutes: ${{ matrix.timeout_minutes }}`,
		`ref: ${{ matrix.commit_sha }}`,
		`persist-credentials: false`,
		`lfs: false`,
		`submodules: false`,
		`uses: actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9`,
		`~/.cache/trivy/db`,
		`uses: ./_segh/.github/actions/repository-scan`,
		`pattern: repository-scan-*`,
		`scan-summary`,
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("organization audit workflow is missing %q", required)
		}
	}
}

func TestOrganizationScanUsesPerRepositoryReadOnlyTokensAndSeparateEvidence(t *testing.T) {
	workflow := readFile(t, organizationAuditWorkflowPath)
	for _, required := range []string{
		`name: Create repository-scoped read-only App token`,
		`owner: ${{ matrix.owner }}`,
		`repositories: ${{ matrix.repository }}`,
		`permission-contents: read`,
		`artifact-name: repository-scan-${{ matrix.id }}`,
		`name: organization-source-scan-evidence`,
		`segh-results/scan-manifest.json`,
		`segh-results/scan-summary.json`,
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("organization audit workflow is missing %q", required)
		}
	}
	if strings.Contains(workflow, "permission-contents: write") ||
		strings.Contains(workflow, "persist-credentials: true") {
		t.Error("organization source scan grants write credentials")
	}
}

func TestRepositoryScannerRejectsIncompleteContentWithoutExecutingTargets(t *testing.T) {
	action := readFile(t, repositoryScanActionPath)
	script := readFile(t, repositoryScanScriptPath)
	for _, required := range []string{
		"Validate static target content",
		"Record repository and scanner status",
		"content-validation",
		"Git LFS pointer",
		"submodule gitlink",
		"incomplete",
	} {
		if !strings.Contains(action+script, required) {
			t.Errorf("repository scanner is missing %q", required)
		}
	}
	for _, forbidden := range []string{"npm install", "go test", "terraform init", "git submodule", "git lfs"} {
		if strings.Contains(action+script, forbidden) {
			t.Errorf("repository scanner can execute target-controlled code via %q", forbidden)
		}
	}
}
