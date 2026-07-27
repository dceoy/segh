package batch

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/dceoy/segh/internal/model"
)

func TestWriteDeterministicBatchesAndTargets(t *testing.T) {
	inventory := model.Inventory{
		SchemaVersion: 1,
		Repositories: []model.Repository{
			{FullName: "org/c"}, {FullName: "org/a"}, {FullName: "org/b"},
		},
	}
	dir := t.TempDir()
	matrix, err := Write(inventory, 1, []string{"org/c", "org/a"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(matrix.Include) != 2 {
		t.Fatalf("batches = %d", len(matrix.Include))
	}
	var first model.Inventory
	data, err := os.ReadFile(filepath.Join(dir, matrix.Include[0].Inventory)) // #nosec G304 -- path comes from the function under test.
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &first); err != nil {
		t.Fatal(err)
	}
	if first.Repositories[0].FullName != "org/a" {
		t.Fatalf("first repository = %s", first.Repositories[0].FullName)
	}
}

func TestWriteRejectsUnknownTarget(t *testing.T) {
	_, err := Write(model.Inventory{}, 10, []string{"org/missing"}, t.TempDir())
	if err == nil {
		t.Fatal("expected missing target error")
	}
}
