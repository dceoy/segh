package batch

import (
	"fmt"
	"path/filepath"
	"slices"
	"sort"

	"github.com/dceoy/segh/internal/model"
	"github.com/dceoy/segh/internal/output"
)

// maxMatrixEntries is GitHub Actions' hard limit on jobs generated from a single matrix.
const maxMatrixEntries = 256

type Matrix struct {
	Include []MatrixEntry `json:"include"`
}

type MatrixEntry struct {
	Batch     string `json:"batch"`
	Inventory string `json:"inventory"`
}

func Write(inventory model.Inventory, size int, repositories []string, outputDir string) (Matrix, error) {
	if size < 1 || size > 1000 {
		return Matrix{}, fmt.Errorf("batch size must be between 1 and 1000")
	}
	selected := append([]model.Repository(nil), inventory.Repositories...)
	sort.Slice(selected, func(i, j int) bool { return selected[i].FullName < selected[j].FullName })
	if len(repositories) > 0 {
		filtered := selected[:0]
		for _, repository := range selected {
			if slices.Contains(repositories, repository.FullName) {
				filtered = append(filtered, repository)
			}
		}
		selected = filtered
		for _, requested := range repositories {
			found := false
			for _, repository := range selected {
				if repository.FullName == requested {
					found = true
					break
				}
			}
			if !found {
				return Matrix{}, fmt.Errorf("target repository %q is not in the inventory", requested)
			}
		}
	}
	if batches := (len(selected) + size - 1) / size; batches > maxMatrixEntries {
		return Matrix{}, fmt.Errorf(
			"batch size %d over %d repositories would produce %d matrix entries, exceeding the GitHub Actions limit of %d; increase --size",
			size, len(selected), batches, maxMatrixEntries,
		)
	}
	matrix := Matrix{}
	for offset, index := 0, 0; offset < len(selected); offset, index = offset+size, index+1 {
		end := min(offset+size, len(selected))
		name := fmt.Sprintf("%04d", index)
		filename := "inventory-" + name + ".json"
		batchInventory := inventory
		batchInventory.Repositories = append([]model.Repository(nil), selected[offset:end]...)
		path := filepath.Join(outputDir, filename)
		if err := output.JSON(path, batchInventory); err != nil {
			return Matrix{}, err
		}
		matrix.Include = append(matrix.Include, MatrixEntry{Batch: name, Inventory: filename})
	}
	return matrix, nil
}
