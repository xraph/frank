package web

import (
	"embed"
	"io/fs"
)

//go:embed apps/ui/out/**
var WebUI embed.FS

var WebUISub, _ = fs.Sub(WebUI, "apps/ui/out")
