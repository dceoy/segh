package merge

import (
	"fmt"
	"sort"
	"time"

	"github.com/dceoy/segh/internal/model"
)

func Scans(runs []model.ScanRun) (model.ScanRun, error) {
	if len(runs) == 0 {
		return model.ScanRun{}, fmt.Errorf("at least one scan run is required")
	}
	merged := model.ScanRun{
		SchemaVersion: model.ScanSchemaVersion,
		RunID:         runs[0].RunID,
		ConfigDigest:  runs[0].ConfigDigest,
		StartedAt:     runs[0].StartedAt,
		FinishedAt:    runs[0].FinishedAt,
	}
	seen := map[string]struct{}{}
	for _, run := range runs {
		if run.SchemaVersion != model.ScanSchemaVersion {
			return model.ScanRun{}, fmt.Errorf("unsupported scan schema version %d", run.SchemaVersion)
		}
		if run.ConfigDigest != merged.ConfigDigest {
			return model.ScanRun{}, fmt.Errorf("cannot merge scans from different configuration revisions")
		}
		if run.StartedAt.Before(merged.StartedAt) {
			merged.StartedAt = run.StartedAt
		}
		if run.FinishedAt.After(merged.FinishedAt) {
			merged.FinishedAt = run.FinishedAt
		}
		merged.Excluded += run.Excluded
		merged.Results = append(merged.Results, run.Results...)
		merged.Repositories = append(merged.Repositories, run.Repositories...)
		merged.Errors = append(merged.Errors, run.Errors...)
		for _, repository := range run.Repositories {
			seen[repository.Repository] = struct{}{}
		}
	}
	merged.Selected = len(seen)
	sort.Slice(merged.Results, func(i, j int) bool {
		if merged.Results[i].Repository != merged.Results[j].Repository {
			return merged.Results[i].Repository < merged.Results[j].Repository
		}
		return merged.Results[i].Scanner < merged.Results[j].Scanner
	})
	sort.Slice(merged.Repositories, func(i, j int) bool {
		return merged.Repositories[i].Repository < merged.Repositories[j].Repository
	})
	if merged.FinishedAt.IsZero() {
		merged.FinishedAt = time.Now().UTC()
	}
	return merged, nil
}
