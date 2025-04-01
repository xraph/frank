package handlers

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/pkg/logging"
)

// WebUIHandler serves the web UI
type WebUIHandler struct {
	logger   logging.Logger
	isDev    bool
	devProxy string
}

// NewWebUIHandler creates a new web UI handler
func NewWebUIHandler(logger logging.Logger) *WebUIHandler {
	// Check if in development mode
	isDev := !config.IsDevelopment()
	devProxy := os.Getenv("DEV_PROXY_URL")
	if isDev && devProxy == "" {
		devProxy = "http://localhost:5173" // Default Vite dev server
	}

	return &WebUIHandler{
		logger:   logger,
		isDev:    isDev,
		devProxy: devProxy,
	}
}

// ServeHTTP handles HTTP requests for the web UI
func (h *WebUIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// In development mode, proxy to the Vite dev server
	if h.isDev {
		h.proxyToDevServer(w, r)
		return
	}

	// In production mode, serve the embedded files
	h.serveEmbeddedFiles(w, r)
}

// proxyToDevServer proxies requests to the Vite development server
func (h *WebUIHandler) proxyToDevServer(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("Proxying request to Vite dev server", logging.String("url", h.devProxy+r.URL.Path))
	// You may want to use a proper reverse proxy library like httputil.ReverseProxy
	// This is a simplified example
	http.Redirect(w, r, h.devProxy+r.URL.Path, http.StatusTemporaryRedirect)
}

// serveEmbeddedFiles serves files from the embedded FS
func (h *WebUIHandler) serveEmbeddedFiles(w http.ResponseWriter, r *http.Request) {
	// Get the path from the request
	path := r.URL.Path
	if path == "/" {
		path = "/index.html"
	}

	if path == "/dashboard/" {
		path = "/index.html"
	}

	// Construct the full path to the embedded file
	// Removing the leading slash and prepending the embedded directory path
	fsPath := filepath.Join("client/build/client", strings.TrimPrefix(path, "/"))

	h.logger.Debug("Serving embedded file", logging.String("path", fsPath))

	// // If the path doesn't exist, serve index.html for client-side routing
	// content, err := web.WebUI.ReadFile(fsPath)
	// if err != nil {
	// 	// For client-side routing, serve the index.html for any unrecognized path
	// 	indexPath := filepath.Join("client/build/client", "index.html")
	// 	h.logger.Debug("File not found, serving index.html instead",
	// 		logging.String("requested", fsPath),
	// 		logging.String("serving", indexPath))
	//
	// 	content, err = web.WebUI.ReadFile(indexPath)
	// 	if err != nil {
	// 		h.logger.Error("Failed to read index.html", logging.Error(err))
	// 		http.Error(w, "Not found", http.StatusNotFound)
	// 		return
	// 	}
	// }

	// Set the content type based on the file extension
	contentType := getContentType(path)
	w.Header().Set("Content-Type", contentType)
	// w.Write(content)
}

// getContentType determines the content type based on file extension
func getContentType(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".html":
		return "text/html"
	case ".css":
		return "text/css"
	case ".js":
		return "application/javascript"
	case ".json":
		return "application/json"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".svg":
		return "image/svg+xml"
	case ".ico":
		return "image/x-icon"
	default:
		return "application/octet-stream"
	}
}

// FileServer provides a static file server with proper handling for SPA routing
func FileServer(rootPath string, router chi.Router) http.Handler {
	fs := http.FileServer(http.Dir("./web/apps/ui/out"))
	router.Handle("/_astro/", fs)
	router.Handle("/assets/", fs)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.URL.Path) >= 4 && r.URL.Path[:4] == "/api" {
			http.NotFound(w, r)
			return
		}

		if len(r.URL.Path) >= 4 && r.URL.Path[:4] == "/v1" {
			http.NotFound(w, r)
			return
		}

		if len(r.URL.Path) >= 4 && strings.HasPrefix(r.URL.Path[:4], "/__") {
			http.NotFound(w, r)
			return
		}

		// Check if the path exists as a file in the dist directory
		requestedPath := filepath.Join(rootPath, r.URL.Path)
		if r.URL.Path != "/" && !strings.HasPrefix(r.URL.Path, "/_astro/") {
			// Add .html extension for non-root paths that don't have it
			if filepath.Ext(requestedPath) == "" {
				requestedPath += "/index.html"
			}
		}

		// If the file exists, serve it
		if _, err := os.Stat(requestedPath); err == nil {
			http.ServeFile(w, r, requestedPath)
			return
		}

		// For paths that don't exist as files, serve index.html
		// (This allows for client-side routing if you're using it)
		indexPath := filepath.Join(rootPath, "index.html")
		http.ServeFile(w, r, indexPath)
	})
}
