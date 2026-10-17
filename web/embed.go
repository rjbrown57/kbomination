package web

import "embed"

// Assets contains the production frontend. Run mise run build:web before release builds.
//go:embed all:dist
var Assets embed.FS
