package schema

import _ "embed"

//go:embed segh-config-v5.schema.json
var configV5 string

// ConfigV5 returns the published configuration contract used by the runtime.
func ConfigV5() string {
	return configV5
}
