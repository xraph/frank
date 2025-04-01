package http

import (
	"embed"
)

//go:embed openapi3.yaml
var DocsFs embed.FS
