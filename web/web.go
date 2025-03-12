package web

import (
	"embed"
)

//go:embed client/dist
var WebUI embed.FS
