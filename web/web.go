package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/xraph/frank/pkg/logging"
	"go.uber.org/zap"
)

//go:embed apps/dashboard/out/*
var frontendFiles embed.FS

//go:embed apps/dashboard/out/**
var WebUI embed.FS

var WebUISub, _ = fs.Sub(WebUI, "apps/dashboard/out")

// RegisterFrontendRoutes configures routes for serving the Next.js frontend
func RegisterFrontendRoutes(r chi.Router, logger logging.Logger) {
	// Get the embedded filesystem
	frontendFS, err := fs.Sub(frontendFiles, "web/apps/dashboard/out")
	if err != nil {
		logger.Error("Failed to setup frontend filesystem", zap.Error(err))
		return
	}

	// Create file server
	fileServer := http.FileServer(http.FS(frontendFS))

	// Handle static assets with proper caching
	r.Get("/static/*", func(w http.ResponseWriter, req *http.Request) {
		// Set aggressive caching for static assets
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		fileServer.ServeHTTP(w, req)
	})

	// Handle Next.js static files
	r.Get("/_next/*", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		fileServer.ServeHTTP(w, req)
	})

	// Handle API routes - these are already handled by Huma
	r.Route("/api", func(r chi.Router) {
		// API routes are handled by Huma - no additional setup needed
	})

	// Handle all other routes - serve the Next.js app (SPA fallback)
	r.Get("/*", func(w http.ResponseWriter, req *http.Request) {
		path := req.URL.Path

		// Skip if it's an API route
		if strings.HasPrefix(path, "/api/") {
			http.NotFound(w, req)
			return
		}

		// Try to serve the exact file first
		if _, err := frontendFS.Open(strings.TrimPrefix(path, "/")); err == nil {
			fileServer.ServeHTTP(w, req)
			return
		}

		// For SPA routes, serve index.html
		req.URL.Path = "/"
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		fileServer.ServeHTTP(w, req)
	})
}
