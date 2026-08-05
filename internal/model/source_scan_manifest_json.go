package model

import (
	"bytes"
	"encoding/json"
	"errors"
)

func (m *SourceScanManifest) UnmarshalJSON(data []byte) error {
	type plainManifest SourceScanManifest
	var decoded plainManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	if decoded.GitHubHost != "github.com" {
		return errors.New("github_host must be \"github.com\"")
	}
	*m = SourceScanManifest(decoded)
	return nil
}
