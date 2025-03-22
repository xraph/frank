package astro_fs

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/juicycleff/frank/pkg/logging"
)

// Configuration holds all server configuration options
type Configuration struct {
	Directory     string
	CacheTTL      int
	EnableGzip    bool
	LogFile       string
	Debug         bool
	SPA           bool
	IndexFile     string
	MaxLogSize    int
	MaxLogBackups int
	MaxLogAge     int
	LogFormat     string // "json" or "console"
	AstroMode     bool   // Enable special handling for Astro output structure
}

// MimeTypeMapping maps file extensions to MIME types
var MimeTypeMapping = map[string]string{
	".html":        "text/html; charset=utf-8",
	".css":         "text/css; charset=utf-8",
	".js":          "application/javascript; charset=utf-8",
	".json":        "application/json; charset=utf-8",
	".png":         "image/png",
	".jpg":         "image/jpeg",
	".jpeg":        "image/jpeg",
	".gif":         "image/gif",
	".svg":         "image/svg+xml",
	".webp":        "image/webp",
	".woff":        "font/woff",
	".woff2":       "font/woff2",
	".ttf":         "font/ttf",
	".otf":         "font/otf",
	".eot":         "application/vnd.ms-fontobject",
	".xml":         "application/xml",
	".txt":         "text/plain; charset=utf-8",
	".md":          "text/markdown; charset=utf-8",
	".webmanifest": "application/manifest+json",
	".pdf":         "application/pdf",
	".mp4":         "video/mp4",
	".webm":        "video/webm",
	".mp3":         "audio/mpeg",
	".wav":         "audio/wav",
	".ico":         "image/x-icon",
	".gz":          "application/gzip",
	".zip":         "application/zip",
	".wasm":        "application/wasm",
	".avif":        "image/avif",
	// Astro specific
	".astro": "text/html; charset=utf-8",
	".jsx":   "application/javascript; charset=utf-8",
	".tsx":   "application/javascript; charset=utf-8",
}

// Cache to store file info for better performance
type FileCache struct {
	mutex sync.RWMutex
	items map[string]*FileCacheItem
}

type FileCacheItem struct {
	ModTime      time.Time
	Size         int64
	ETag         string
	MimeType     string
	IsGzipped    bool
	GzippedCache []byte
}

var fileCache = FileCache{
	items: make(map[string]*FileCacheItem),
}

// CustomFileHandler handles file requests with enhanced features
type CustomFileHandler struct {
	rootDir string
	logger  logging.Logger
	config  *Configuration
}

// Initialize a new file server
func NewCustomFileHandler(rootDir string, logger logging.Logger, config *Configuration) *CustomFileHandler {
	return &CustomFileHandler{
		rootDir: rootDir,
		logger:  logger,
		config:  config,
	}
}

// Main handler function to serve files
func (h *CustomFileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestStartTime := time.Now()
	// Get clean file path
	urlPath := strings.TrimPrefix(r.URL.Path, "/")

	// Special handling for routes in Astro output format
	// Check if we need to adapt the path for Astro's generated structure
	if h.config.AstroMode {
		// If path is empty or root, serve index.html
		if urlPath == "" {
			urlPath = h.config.IndexFile
		} else if !strings.Contains(urlPath, ".") {
			// This is likely a route path without a file extension
			// Check if a directory with this name exists first
			dirPath := filepath.Join(h.rootDir, urlPath)
			if fi, err := os.Stat(dirPath); err == nil && fi.IsDir() {
				// Directory exists, check if it has an index.html
				indexPath := filepath.Join(dirPath, h.config.IndexFile)
				if _, err := os.Stat(indexPath); err == nil {
					urlPath = filepath.Join(urlPath, h.config.IndexFile)
				}
			} else {
				// No directory found, try to find a matching .html file for the route
				htmlPath := urlPath + ".html"
				if _, err := os.Stat(filepath.Join(h.rootDir, htmlPath)); err == nil {
					urlPath = htmlPath
				} else {
					// Fall back to index.html for client-side routing
					urlPath = h.config.IndexFile
				}
			}
		}
	} else if urlPath == "" {
		urlPath = h.config.IndexFile
	}

	filePath := filepath.Join(h.rootDir, filepath.Clean(urlPath))
	filePath = filepath.FromSlash(filePath)

	// Prevent directory traversal attacks
	if !strings.HasPrefix(filePath, h.rootDir) {
		fmt.Println(filePath, "Attempted directory traversal attack")
		h.logger.Sugar().Warnw("Attempted directory traversal attack", "path", urlPath)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Check if file exists
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// For SPA mode, serve index.html for 404s if it's not an API request
			if h.config.SPA && !strings.HasPrefix(urlPath, "api/") {
				h.logger.Sugar().Debugw("File not found, serving index.html (SPA mode)", "path", urlPath)
				filePath = filepath.Join(h.rootDir, h.config.IndexFile)
				var statErr error
				fileInfo, statErr = os.Stat(filePath)
				if statErr != nil {
					h.logger.Sugar().Errorw("Failed to stat index file", "error", statErr, "path", filePath)
					http.Error(w, "Not Found", http.StatusNotFound)
					return
				}
			} else {
				h.logger.Sugar().Infow("File not found", "path", urlPath)
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}
		} else {
			h.logger.Sugar().Errorw("Failed to stat file", "error", err, "path", filePath)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}

	// Handle directory listings or redirect
	if fileInfo.IsDir() {
		// Check for index file
		indexPath := filepath.Join(filePath, h.config.IndexFile)
		_, err := os.Stat(indexPath)
		if err == nil {
			filePath = indexPath
			// Update fileInfo to point to the index file
			fileInfo, err = os.Stat(filePath)
			if err != nil {
				h.logger.Sugar().Errorw("Failed to stat index file", "error", err, "path", filePath)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
		} else {
			// For Astro mode, we should be more thorough checking subdirectories
			if h.config.AstroMode {
				h.logger.Sugar().Debugw("Checking for Astro route structure in directory", "path", filePath)
				// Try to find any index.html files in subdirectories
				found := false
				entries, err := os.ReadDir(filePath)
				if err == nil {
					for _, entry := range entries {
						if entry.IsDir() {
							potentialIndex := filepath.Join(filePath, entry.Name(), h.config.IndexFile)
							if _, err := os.Stat(potentialIndex); err == nil {
								// Found an index.html in a subdirectory
								h.logger.Sugar().Debugw("Found index in subdirectory", "subdir", entry.Name())
								found = true
								break
							}
						}
					}
				}

				if found {
					// If we found index files in subdirectories, show directory listing in debug mode
					// or redirect to an appropriate landing page
					if h.config.Debug {
						h.serveDirListing(w, r, filePath)
						return
					} else if !strings.HasSuffix(r.URL.Path, "/") {
						http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
						return
					}
				}
			}

			// No index file, redirect if path doesn't end with '/'
			if !strings.HasSuffix(r.URL.Path, "/") {
				http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
				return
			}

			// Simple directory listing
			if h.config.Debug {
				h.serveDirListing(w, r, filePath)
				return
			} else {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
	}

	// Get file extension and determine content type
	ext := strings.ToLower(filepath.Ext(filePath))
	contentType, found := MimeTypeMapping[ext]
	if !found {
		contentType = "application/octet-stream"
	}

	// Check if we have a cached version of this file
	fileCache.mutex.RLock()
	cacheItem, found := fileCache.items[filePath]
	fileCache.mutex.RUnlock()

	// Generate ETag based on file modification time and size
	etag := fmt.Sprintf(`"%x-%x"`, fileInfo.ModTime().UnixNano(), fileInfo.Size())

	// If file is not in cache or has been modified, update cache
	if !found || cacheItem.ModTime.Before(fileInfo.ModTime()) || cacheItem.Size != fileInfo.Size() {
		h.logger.Sugar().Debugw("Refreshing file cache", "path", urlPath)

		cacheItem = &FileCacheItem{
			ModTime:  fileInfo.ModTime(),
			Size:     fileInfo.Size(),
			ETag:     etag,
			MimeType: contentType,
		}

		// Pre-compress file if gzip is enabled and file is not too small
		if h.config.EnableGzip && fileInfo.Size() > 1024 && isCompressibleType(contentType) {
			file, err := os.Open(filePath)
			if err == nil {
				defer file.Close()

				var gzippedBuf strings.Builder
				gzWriter := gzip.NewWriter(&gzippedBuf)

				_, err = io.Copy(gzWriter, file)
				gzWriter.Close()

				if err == nil {
					cacheItem.IsGzipped = true
					cacheItem.GzippedCache = []byte(gzippedBuf.String())
				} else {
					h.logger.Sugar().Errorw("Failed to compress file", "error", err, "path", filePath)
				}
			}
		}

		fileCache.mutex.Lock()
		fileCache.items[filePath] = cacheItem
		fileCache.mutex.Unlock()
	}

	// Set common headers
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("ETag", etag)

	// Set Cache-Control header if cache TTL is enabled
	if h.config.CacheTTL > 0 {
		w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", h.config.CacheTTL))
	} else {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	}

	// Check if client sent If-None-Match header (for cache validation)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	// Check if client accepts gzip encoding and we have a compressed version
	acceptsGzip := strings.Contains(r.Header.Get("Accept-Encoding"), "gzip")

	if acceptsGzip && cacheItem.IsGzipped {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Vary", "Accept-Encoding")
		w.WriteHeader(http.StatusOK)
		w.Write(cacheItem.GzippedCache)
	} else {
		// Serve regular file
		file, err := os.Open(filePath)
		if err != nil {
			h.logger.Sugar().Errorw("Failed to open file", "error", err, "path", filePath)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		// Set Content-Length header
		w.Header().Set("Content-Length", strconv.FormatInt(fileInfo.Size(), 10))

		// Add security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Log request before sending response
		requestDuration := time.Since(requestStartTime)
		h.logger.Sugar().Infow("Serving file",
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
			"user_agent", r.UserAgent(),
			"file_size", fileInfo.Size(),
			"duration", requestDuration.String())

		// Send the file
		w.WriteHeader(http.StatusOK)
		io.Copy(w, file)
	}
}

// Helper to determine if a content type should be compressed
func isCompressibleType(contentType string) bool {
	compressibleTypes := []string{
		"text/", "application/javascript", "application/json",
		"application/xml", "image/svg+xml", "application/manifest+json",
	}

	for _, t := range compressibleTypes {
		if strings.Contains(contentType, t) {
			return true
		}
	}
	return false
}

// Serve directory listing (only available in debug mode)
func (h *CustomFileHandler) serveDirListing(w http.ResponseWriter, r *http.Request, dirPath string) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		h.logger.Sugar().Errorw("Failed to read directory", "error", err, "path", dirPath)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><head><title>Directory listing for %s</title></head><body>", r.URL.Path)
	fmt.Fprintf(w, "<h1>Directory listing for %s</h1><hr><pre>", r.URL.Path)

	if r.URL.Path != "/" {
		fmt.Fprintf(w, "<a href=\"%s\">..</a>\n", path.Dir(r.URL.Path))
	}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			name += "/"
		}
		// Create a link to the file/directory
		fmt.Fprintf(w, "<a href=\"%s%s\">%s</a>\n", r.URL.Path, name, name)
	}

	fmt.Fprintf(w, "</pre><hr></body></html>")
}
