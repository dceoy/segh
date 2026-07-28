package publication

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	gh "github.com/dceoy/segh/internal/github"
	"github.com/dceoy/segh/internal/model"
	"github.com/dceoy/segh/internal/sarif"
)

var (
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	shaPattern        = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	categoryPattern   = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,200}$`)
)

type Publisher struct {
	client      *gh.Client
	pollTimeout time.Duration
}

func New(client *gh.Client, pollTimeout time.Duration) *Publisher {
	return &Publisher{client: client, pollTimeout: pollTimeout}
}

func (p *Publisher) Upload(ctx context.Context, repository, scanner, category, commitSHA, ref, sarifPath string) model.Publication {
	result := model.Publication{
		Repository: repository, Scanner: scanner, Category: category,
		CommitSHA: commitSHA, Ref: ref, Status: model.PublicationPending,
	}
	if !repositoryPattern.MatchString(repository) {
		result.Status, result.Error = model.PublicationRejected, "invalid target repository"
		return result
	}
	if !shaPattern.MatchString(commitSHA) {
		result.Status, result.Error = model.PublicationRejected, "commit SHA must be a full 40-character hash"
		return result
	}
	if !strings.HasPrefix(ref, "refs/heads/") && !strings.HasPrefix(ref, "refs/pull/") {
		result.Status, result.Error = model.PublicationRejected, "ref must be a full heads or pull ref"
		return result
	}
	if !categoryPattern.MatchString(category) {
		result.Status, result.Error = model.PublicationRejected, "invalid analysis category"
		return result
	}
	if _, err := sarif.Read(sarifPath); err != nil {
		result.Status, result.Error = model.PublicationRejected, "invalid SARIF input"
		return result
	}
	data, err := os.ReadFile(sarifPath) // #nosec G304 -- the path has been parsed as a bounded SARIF document.
	if err != nil {
		result.Status, result.Error = model.PublicationFailed, "read SARIF"
		return result
	}
	if len(data) == 0 || len(data) > 50<<20 {
		result.Status, result.Error = model.PublicationRejected, "SARIF must be between 1 byte and 50 MiB"
		return result
	}
	// GitHub derives the analysis category from runs[].automationDetails.id, not from a
	// request-level "category" field, so it must be injected into the SARIF itself.
	data, err = sarif.InjectCategory(data, category)
	if err != nil {
		result.Status, result.Error = model.PublicationRejected, "inject analysis category into SARIF"
		return result
	}
	if len(data) > 50<<20 {
		result.Status, result.Error = model.PublicationRejected, "SARIF must be between 1 byte and 50 MiB"
		return result
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(data); err != nil {
		result.Status, result.Error = model.PublicationFailed, "compress SARIF"
		return result
	}
	if err := writer.Close(); err != nil {
		result.Status, result.Error = model.PublicationFailed, "compress SARIF"
		return result
	}
	payload := map[string]any{
		"commit_sha": commitSHA,
		"ref":        ref,
		"sarif":      base64.StdEncoding.EncodeToString(compressed.Bytes()),
		"tool_name":  scanner,
	}
	var response struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	path := "/repos/" + escapeRepository(repository) + "/code-scanning/sarifs"
	if err := p.client.Post(ctx, path, payload, &response); err != nil {
		result.Status, result.Error = classifyUploadError(err)
		return result
	}
	result.SARIFID, result.URL = response.ID, response.URL
	if response.ID == "" {
		result.Status, result.Error = model.PublicationFailed, "GitHub did not return a SARIF processing ID"
		return result
	}
	pollCtx, cancel := context.WithTimeout(ctx, p.pollTimeout)
	defer cancel()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		var status struct {
			ProcessingStatus string   `json:"processing_status"`
			Errors           []string `json:"errors"`
		}
		if err := p.client.Get(pollCtx, path+"/"+response.ID, &status); err != nil {
			result.Status, result.Error = classifyPollError(err)
			return result
		}
		switch status.ProcessingStatus {
		case "complete":
			result.Status = model.PublicationSucceeded
			return result
		case "failed":
			result.Status = model.PublicationFailed
			result.Error = "GitHub rejected SARIF during asynchronous processing"
			return result
		}
		select {
		case <-pollCtx.Done():
			result.Status, result.Error = model.PublicationFailed, "SARIF processing poll timeout"
			return result
		case <-ticker.C:
		}
	}
}

func classifyUploadError(err error) (model.PublicationStatus, string) {
	var apiErr *gh.APIError
	if !errors.As(err, &apiErr) {
		return model.PublicationFailed, "SARIF upload request failed"
	}
	switch apiErr.StatusCode {
	case 404, 410, 501:
		return model.PublicationUnsupported, "code scanning SARIF upload is unsupported or unavailable"
	case 401, 403:
		return model.PublicationRejected, "SARIF upload authentication or permission failure"
	default:
		return model.PublicationFailed, fmt.Sprintf("SARIF upload returned HTTP %d", apiErr.StatusCode)
	}
}

func classifyPollError(err error) (model.PublicationStatus, string) {
	var apiErr *gh.APIError
	if errors.As(err, &apiErr) && (apiErr.StatusCode == 404 || apiErr.StatusCode == 410 || apiErr.StatusCode == 501) {
		return model.PublicationUnsupported, "SARIF processing status is unsupported"
	}
	return model.PublicationFailed, "SARIF processing status request failed"
}

func escapeRepository(repository string) string {
	parts := strings.Split(repository, "/")
	return parts[0] + "/" + parts[1]
}
