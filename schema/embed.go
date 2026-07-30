package schema

import _ "embed"

//go:embed segh-config-v4.schema.json
var configV4 string

// ConfigV4 returns the published configuration contract used by the runtime.
func ConfigV4() string {
	return configV4
}
