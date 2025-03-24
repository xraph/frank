package astro_fs

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/juicycleff/frank/pkg/logging"
	"golang.org/x/net/http2"
)

// Configuration holds all server configuration options
type Configuration struct {
	Directory     string
	CacheTTL      int
	EnableGzip    bool
	EnableBrotli  bool // Enable Brotli compression
	LogFile       string
	Debug         bool
	SPA           bool
	IndexFile     string
	MaxLogSize    int
	MaxLogBackups int
	MaxLogAge     int
	LogFormat     string // "json" or "console"
	AstroMode     bool   // Enable special handling for Astro output structure
	HTTP2         bool   // Enable HTTP/2 support
	PreloadAssets bool   // Enable preloading of critical assets
	AssetPrefix   string // Prefix for static assets (e.g., _astro/)
	MaxCacheSize  int    // Maximum cache size in MB
	EnableMetrics bool   // Enable performance metrics
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
	mutex     sync.RWMutex
	items     map[string]*FileCacheItem
	totalSize int64
	maxSize   int64
	hits      int64
	misses    int64
}

type FileCacheItem struct {
	ModTime       time.Time
	Size          int64
	ETag          string
	MimeType      string
	IsGzipped     bool
	IsBrotli      bool
	GzippedCache  []byte
	BrotliCache   []byte
	LastAccessed  time.Time
	AccessCount   int64
	LastRequested time.Time
	IsRouteIndex  bool // Indicates if this is an index.html file in a route directory
}

// Regex for identifying content hashed files (e.g., script.a1b2c3d4.js)
var contentHashPattern = regexp.MustCompile(`\.([a-f0-9]{8,})\.(?:js|css|webp|jpg|png|svg)$`)

var fileCache = FileCache{
	items:   make(map[string]*FileCacheItem),
	maxSize: 100 * 1024 * 1024, // Default 100MB max cache size
}

// ServerMetrics for tracking server performance
type ServerMetrics struct {
	mutex              sync.Mutex
	requestCount       int64
	cacheHits          int64
	cacheMisses        int64
	totalRequestTime   time.Duration
	routeRequests      map[string]int64
	compressionSaved   int64
	notModifiedCount   int64
	lastGarbageCollect time.Time
}

var metrics = ServerMetrics{
	routeRequests:      make(map[string]int64),
	lastGarbageCollect: time.Now(),
}

// CustomFileHandler handles file requests with enhanced features
type CustomFileHandler struct {
	rootDir        string
	logger         logging.Logger
	config         *Configuration
	preloadedPaths map[string][]string // Map of paths to their critical assets
	criticalAssets map[string]bool     // Set of critical assets
}

// Initialize a new file server
func NewCustomFileHandler(rootDir string, logger logging.Logger, config *Configuration) *CustomFileHandler {
	// Update cache max size if configured
	if config.MaxCacheSize > 0 {
		fileCache.maxSize = int64(config.MaxCacheSize * 1024 * 1024)
	}

	h := &CustomFileHandler{
		rootDir:        rootDir,
		logger:         logger,
		config:         config,
		preloadedPaths: make(map[string][]string),
		criticalAssets: make(map[string]bool),
	}

	// Preload critical assets and routes for faster responses
	if config.PreloadAssets {
		go h.preloadCriticalAssets()
	}

	// Start periodic cache maintenance
	go h.startCacheMaintenance()

	return h
}

// Preload critical assets and common routes
func (h *CustomFileHandler) preloadCriticalAssets() {
	// If we have an asset prefix (like _astro), preload those assets
	if h.config.AssetPrefix != "" {
		assetDir := filepath.Join(h.rootDir, h.config.AssetPrefix)
		if _, err := os.Stat(assetDir); err == nil {
			h.logger.Sugar().Infow("Preloading assets", "directory", assetDir)
			h.preloadDirectory(assetDir, true)
		}
	}

	// Preload root index.html as it's frequently accessed
	indexPath := filepath.Join(h.rootDir, h.config.IndexFile)
	h.preloadFile(indexPath, false)

	// Preload common route directories
	if h.config.AstroMode {
		entries, err := os.ReadDir(h.rootDir)
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") && entry.Name() != h.config.AssetPrefix {
					routeIndexPath := filepath.Join(h.rootDir, entry.Name(), h.config.IndexFile)
					h.preloadFile(routeIndexPath, true)
				}
			}
		}
	}
}

// Preload all files in a directory recursively
func (h *CustomFileHandler) preloadDirectory(dirPath string, isCritical bool) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		h.logger.Sugar().Warnw("Failed to read directory for preloading", "error", err, "path", dirPath)
		return
	}

	for _, entry := range entries {
		fullPath := filepath.Join(dirPath, entry.Name())
		if entry.IsDir() {
			h.preloadDirectory(fullPath, isCritical)
		} else {
			h.preloadFile(fullPath, isCritical)
		}
	}
}

// Preload a single file into cache
func (h *CustomFileHandler) preloadFile(filePath string, isCritical bool) {
	// Check if file exists
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return
	}

	// Skip large files to prevent cache overflow during preloading
	if fileInfo.Size() > 5*1024*1024 {
		return
	}

	relativePath, err := filepath.Rel(h.rootDir, filePath)
	if err != nil {
		return
	}

	// Mark as critical asset if needed
	if isCritical {
		h.criticalAssets["/"+filepath.ToSlash(relativePath)] = true
	}

	// Get file extension and determine content type
	ext := strings.ToLower(filepath.Ext(filePath))
	contentType, found := MimeTypeMapping[ext]
	if !found {
		contentType = "application/octet-stream"
	}

	// Generate ETag
	etag := fmt.Sprintf(`"%x-%x"`, fileInfo.ModTime().UnixNano(), fileInfo.Size())

	// Check if it's a content-hashed asset
	_ = contentHashPattern.MatchString(filepath.Base(filePath))
	// fmt.Println(isContentHashed)

	// Create cache item
	cacheItem := &FileCacheItem{
		ModTime:      fileInfo.ModTime(),
		Size:         fileInfo.Size(),
		ETag:         etag,
		MimeType:     contentType,
		LastAccessed: time.Now(),
		IsRouteIndex: isCritical && strings.HasSuffix(filePath, h.config.IndexFile),
	}

	// Pre-compress file if needed
	if (h.config.EnableGzip || h.config.EnableBrotli) && fileInfo.Size() > 1024 && isCompressibleType(contentType) {
		fileContent, err := os.ReadFile(filePath)
		if err == nil {
			// Gzip compression
			if h.config.EnableGzip {
				var gzippedBuf bytes.Buffer
				gzWriter, _ := gzip.NewWriterLevel(&gzippedBuf, gzip.BestCompression)
				gzWriter.Write(fileContent)
				gzWriter.Close()
				cacheItem.IsGzipped = true
				cacheItem.GzippedCache = gzippedBuf.Bytes()
			}

			// Brotli compression
			if h.config.EnableBrotli {
				var brotliBuf bytes.Buffer
				brotliWriter := brotli.NewWriterLevel(&brotliBuf, brotli.BestCompression)
				brotliWriter.Write(fileContent)
				brotliWriter.Close()
				cacheItem.IsBrotli = true
				cacheItem.BrotliCache = brotliBuf.Bytes()
			}
		}
	}

	// Add to cache
	fileCache.mutex.Lock()
	fileCache.totalSize += fileInfo.Size()
	if cacheItem.IsGzipped {
		fileCache.totalSize += int64(len(cacheItem.GzippedCache))
	}
	if cacheItem.IsBrotli {
		fileCache.totalSize += int64(len(cacheItem.BrotliCache))
	}
	fileCache.items[filePath] = cacheItem
	fileCache.mutex.Unlock()

	// Check if we need cache maintenance after adding
	if fileCache.totalSize > fileCache.maxSize {
		go h.cleanupCache()
	}
}

// Periodic cache maintenance
func (h *CustomFileHandler) startCacheMaintenance() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		h.cleanupCache()
		h.updateMetrics()
	}
}

// Clean up the cache if it's too large
func (h *CustomFileHandler) cleanupCache() {
	fileCache.mutex.Lock()
	defer fileCache.mutex.Unlock()

	// If cache size is below 80% of max, no cleanup needed
	if fileCache.totalSize < fileCache.maxSize*80/100 {
		return
	}

	h.logger.Sugar().Infow("Cleaning up cache",
		"currentSize", fileCache.totalSize,
		"maxSize", fileCache.maxSize,
		"itemCount", len(fileCache.items))

	// Create a sorted list of items based on last access time and frequency
	type cacheItemWithKey struct {
		key   string
		item  *FileCacheItem
		score float64
	}
	items := make([]cacheItemWithKey, 0, len(fileCache.items))

	now := time.Now()
	for key, item := range fileCache.items {
		// Calculate a score based on access recency and frequency
		// Higher score = more likely to keep
		timeScore := 1.0 / (now.Sub(item.LastAccessed).Hours() + 1.0)
		frequencyScore := float64(item.AccessCount)

		// Content-hashed assets and critical assets get a bonus
		bonus := 1.0
		if contentHashPattern.MatchString(key) {
			bonus += 2.0
		}
		if item.IsRouteIndex {
			bonus += 3.0
		}

		score := (timeScore + frequencyScore) * bonus

		items = append(items, cacheItemWithKey{key, item, score})
	}

	// Sort by score ascending (lowest score first - to be evicted)
	// Using simple bubble sort as this is not a hot path
	for i := 0; i < len(items)-1; i++ {
		for j := 0; j < len(items)-i-1; j++ {
			if items[j].score > items[j+1].score {
				items[j], items[j+1] = items[j+1], items[j]
			}
		}
	}

	// Remove items until cache is 60% full
	targetSize := fileCache.maxSize * 60 / 100
	removed := 0
	for fileCache.totalSize > targetSize && removed < len(items)/2 {
		item := items[removed]
		size := item.item.Size
		if item.item.IsGzipped {
			size += int64(len(item.item.GzippedCache))
		}
		if item.item.IsBrotli {
			size += int64(len(item.item.BrotliCache))
		}

		delete(fileCache.items, item.key)
		fileCache.totalSize -= size
		removed++
	}

	h.logger.Sugar().Infow("Cache cleanup completed",
		"removedItems", removed,
		"newSize", fileCache.totalSize,
		"remainingItems", len(fileCache.items))
}

// Update metrics for monitoring
func (h *CustomFileHandler) updateMetrics() {
	metrics.mutex.Lock()
	defer metrics.mutex.Unlock()

	fileCache.mutex.RLock()
	cacheHitRate := float64(0)
	if fileCache.hits+fileCache.misses > 0 {
		cacheHitRate = float64(fileCache.hits) / float64(fileCache.hits+fileCache.misses) * 100
	}
	fileCache.mutex.RUnlock()

	// Log current metrics
	h.logger.Sugar().Infow("Server metrics",
		"totalRequests", metrics.requestCount,
		"cacheHitRate", fmt.Sprintf("%.2f%%", cacheHitRate),
		"averageResponseTime", metrics.totalRequestTime.Milliseconds()/max(1, metrics.requestCount),
		"notModifiedRate", float64(metrics.notModifiedCount)/float64(max(1, metrics.requestCount))*100,
		"cacheSize", fileCache.totalSize,
		"compressionSaved", metrics.compressionSaved,
	)

	// Reset some counters
	metrics.lastGarbageCollect = time.Now()
}

// Main handler function to serve files
func (h *CustomFileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestStartTime := time.Now()

	// Update metrics
	metrics.mutex.Lock()
	metrics.requestCount++
	metrics.mutex.Unlock()

	// Get clean file path
	urlPath := strings.TrimPrefix(r.URL.Path, "/")

	// Handle metrics endpoint if enabled
	if h.config.EnableMetrics && urlPath == "metrics" {
		h.serveMetrics(w, r)
		return
	}

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

	// Update route metrics
	metrics.mutex.Lock()
	metrics.routeRequests[urlPath]++
	metrics.mutex.Unlock()

	filePath := filepath.Join(h.rootDir, filepath.Clean(urlPath))
	filePath = filepath.FromSlash(filePath)

	// Prevent directory traversal attacks
	if !strings.HasPrefix(filePath, h.rootDir) {
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

		// Update cache metrics
		if !found {
			fileCache.mutex.Lock()
			fileCache.misses++
			fileCache.mutex.Unlock()
		}

		cacheItem = &FileCacheItem{
			ModTime:       fileInfo.ModTime(),
			Size:          fileInfo.Size(),
			ETag:          etag,
			MimeType:      contentType,
			LastAccessed:  time.Now(),
			LastRequested: time.Now(),
			IsRouteIndex:  strings.HasSuffix(filePath, h.config.IndexFile) && strings.Count(urlPath, "/") >= 1,
		}

		// Check if the file is a content hashed asset
		isContentHashed := contentHashPattern.MatchString(filepath.Base(filePath))
		fmt.Println(isContentHashed)

		// Pre-compress file if compression is enabled and file meets criteria
		if (h.config.EnableGzip || h.config.EnableBrotli) &&
			fileInfo.Size() > 1024 &&
			fileInfo.Size() < 10*1024*1024 && // Don't compress files > 10MB
			isCompressibleType(contentType) {

			fileContent, err := os.ReadFile(filePath)
			if err == nil {
				// Gzip compression
				if h.config.EnableGzip {
					var gzippedBuf bytes.Buffer
					gzWriter, _ := gzip.NewWriterLevel(&gzippedBuf, gzip.BestCompression)
					gzWriter.Write(fileContent)
					gzWriter.Close()

					// Only use compression if it actually saves space
					if gzippedBuf.Len() < len(fileContent) {
						cacheItem.IsGzipped = true
						cacheItem.GzippedCache = gzippedBuf.Bytes()

						metrics.mutex.Lock()
						metrics.compressionSaved += int64(len(fileContent) - gzippedBuf.Len())
						metrics.mutex.Unlock()
					}
				}

				// Brotli compression (usually better than gzip)
				if h.config.EnableBrotli {
					var brotliBuf bytes.Buffer
					brotliWriter := brotli.NewWriterLevel(&brotliBuf, brotli.BestCompression)
					brotliWriter.Write(fileContent)
					brotliWriter.Close()

					// Only use compression if it actually saves space
					if brotliBuf.Len() < len(fileContent) {
						cacheItem.IsBrotli = true
						cacheItem.BrotliCache = brotliBuf.Bytes()

						metrics.mutex.Lock()
						metrics.compressionSaved += int64(len(fileContent) - brotliBuf.Len())
						metrics.mutex.Unlock()
					}
				}
			} else {
				h.logger.Sugar().Errorw("Failed to read file for compression", "error", err, "path", filePath)
			}
		}

		// Update the cache with the new or updated item
		fileCache.mutex.Lock()
		// If updating, remove old size first
		if oldItem, exists := fileCache.items[filePath]; exists {
			oldSize := oldItem.Size
			if oldItem.IsGzipped {
				oldSize += int64(len(oldItem.GzippedCache))
			}
			if oldItem.IsBrotli {
				oldSize += int64(len(oldItem.BrotliCache))
			}
			fileCache.totalSize -= oldSize
		}

		// Add new size
		newSize := cacheItem.Size
		if cacheItem.IsGzipped {
			newSize += int64(len(cacheItem.GzippedCache))
		}
		if cacheItem.IsBrotli {
			newSize += int64(len(cacheItem.BrotliCache))
		}
		fileCache.totalSize += newSize
		fileCache.items[filePath] = cacheItem
		fileCache.mutex.Unlock()

		// Check if we need cache maintenance after adding
		if fileCache.totalSize > fileCache.maxSize {
			go h.cleanupCache()
		}
	} else {
		// Update cache hit metrics
		fileCache.mutex.Lock()
		fileCache.hits++
		cacheItem.AccessCount++
		cacheItem.LastAccessed = time.Now()
		cacheItem.LastRequested = time.Now()
		fileCache.mutex.Unlock()
	}

	// Determine cache control headers
	var cacheControl string
	isContentHashed := contentHashPattern.MatchString(filepath.Base(filePath))

	if isContentHashed {
		// Content-hashed assets can be cached for a year (immutable)
		cacheControl = "public, max-age=31536000, immutable"
	} else if h.config.CacheTTL > 0 {
		// Use configured TTL for other assets
		cacheControl = fmt.Sprintf("max-age=%d", h.config.CacheTTL)
	} else {
		// Disable cache if no TTL is set
		cacheControl = "no-cache, no-store, must-revalidate"
	}

	// Set common headers
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", cacheControl)

	// Add security headers
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Check if client sent If-None-Match header (for cache validation)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)

		// Update not-modified metrics
		metrics.mutex.Lock()
		metrics.notModifiedCount++
		metrics.mutex.Unlock()

		return
	}

	// If this is an HTML file and HTTP/2 is enabled, set Link headers for preloading
	if h.config.HTTP2 && h.config.PreloadAssets && contentType == "text/html; charset=utf-8" {
		// Calculate relative URL path
		relPath, err := filepath.Rel(h.rootDir, filePath)
		if err == nil {
			urlPath := "/" + filepath.ToSlash(relPath)
			if preloadAssets, found := h.preloadedPaths[urlPath]; found && len(preloadAssets) > 0 {
				var preloadHeaders []string
				for _, asset := range preloadAssets {
					var asType string
					ext := filepath.Ext(asset)
					switch ext {
					case ".css":
						asType = "style"
					case ".js":
						asType = "script"
					case ".woff", ".woff2", ".ttf", ".otf":
						asType = "font"
					case ".svg", ".png", ".jpg", ".jpeg", ".webp", ".avif":
						asType = "image"
					default:
						continue
					}
					preloadHeaders = append(preloadHeaders, fmt.Sprintf("<%s>; rel=preload; as=%s", asset, asType))
				}
				if len(preloadHeaders) > 0 {
					w.Header().Set("Link", strings.Join(preloadHeaders, ", "))
				}
			}
		}
	}

	// Check if client accepts compression and we have a compressed version
	acceptEncoding := r.Header.Get("Accept-Encoding")

	// Try Brotli first as it's generally better
	if strings.Contains(acceptEncoding, "br") && cacheItem.IsBrotli {
		w.Header().Set("Content-Encoding", "br")
		w.Header().Set("Vary", "Accept-Encoding")
		w.WriteHeader(http.StatusOK)
		w.Write(cacheItem.BrotliCache)
	} else if strings.Contains(acceptEncoding, "gzip") && cacheItem.IsGzipped {
		// Fall back to gzip if Brotli is not available or not accepted
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

	// Update metrics
	metrics.mutex.Lock()
	metrics.totalRequestTime += time.Since(requestStartTime)
	metrics.mutex.Unlock()
}

// Serve metrics endpoint for monitoring
func (h *CustomFileHandler) serveMetrics(w http.ResponseWriter, r *http.Request) {
	fileCache.mutex.RLock()
	cacheHitRate := float64(0)
	if fileCache.hits+fileCache.misses > 0 {
		cacheHitRate = float64(fileCache.hits) / float64(fileCache.hits+fileCache.misses) * 100
	}
	fileCache.mutex.RUnlock()

	metrics.mutex.Lock()
	defer metrics.mutex.Unlock()

	// Create sorted slice of top routes
	type routeCount struct {
		route string
		count int64
	}
	routes := make([]routeCount, 0, len(metrics.routeRequests))
	for route, count := range metrics.routeRequests {
		routes = append(routes, routeCount{route, count})
	}
	// Simple bubble sort for top 10
	for i := 0; i < len(routes)-1; i++ {
		for j := 0; j < len(routes)-i-1; j++ {
			if routes[j].count < routes[j+1].count {
				routes[j], routes[j+1] = routes[j+1], routes[j]
			}
		}
	}

	// Limit to top 10
	if len(routes) > 10 {
		routes = routes[:10]
	}

	// Calculate average response time
	var avgResponseTime int64 = 0
	if metrics.requestCount > 0 {
		avgResponseTime = metrics.totalRequestTime.Milliseconds() / metrics.requestCount
	}

	// Set content type to plain text
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	// Write metrics to response
	fmt.Fprintf(w, "# Astro File Server Metrics\n\n")
	fmt.Fprintf(w, "## General Metrics\n")
	fmt.Fprintf(w, "Total Requests: %d\n", metrics.requestCount)
	fmt.Fprintf(w, "Average Response Time: %d ms\n", avgResponseTime)
	fmt.Fprintf(w, "304 Not Modified Rate: %.2f%%\n", float64(metrics.notModifiedCount)/float64(max(1, metrics.requestCount))*100)
	fmt.Fprintf(w, "Compression Savings: %s\n", formatSize(metrics.compressionSaved))

	fmt.Fprintf(w, "\n## Cache Metrics\n")
	fmt.Fprintf(w, "Cache Hit Rate: %.2f%%\n", cacheHitRate)
	fmt.Fprintf(w, "Cache Size: %s / %s\n", formatSize(fileCache.totalSize), formatSize(fileCache.maxSize))
	fmt.Fprintf(w, "Cached Items: %d\n", len(fileCache.items))

	fmt.Fprintf(w, "\n## Top Routes\n")
	for i, route := range routes {
		fmt.Fprintf(w, "%d. %s - %d requests\n", i+1, route.route, route.count)
	}
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

// EnableHTTP2 configures HTTP/2 support for the server
func EnableHTTP2(server *http.Server) error {
	http2Server := &http2.Server{
		MaxConcurrentStreams: 250,
		MaxReadFrameSize:     1 << 20, // 1MB
		IdleTimeout:          10 * time.Minute,
	}
	return http2.ConfigureServer(server, http2Server)
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

// formatSize converts a byte size to a human-readable string format
// It handles B, KB, MB, and GB units with appropriate precision
func formatSize(size int64) string {
	const (
		_          = iota
		KB float64 = 1 << (10 * iota) // 1 << (10*1) = 1024
		MB                            // 1 << (10*2) = 1048576
		GB                            // 1 << (10*3) = 1073741824
	)

	// Handle bytes (less than 1KB)
	if size < int64(KB) {
		return fmt.Sprintf("%d B", size)
	}

	// Handle kilobytes (less than 1MB)
	if size < int64(MB) {
		return fmt.Sprintf("%.1f KB", float64(size)/KB)
	}

	// Handle megabytes (less than 1GB)
	if size < int64(GB) {
		return fmt.Sprintf("%.1f MB", float64(size)/MB)
	}

	// Handle gigabytes and larger
	return fmt.Sprintf("%.2f GB", float64(size)/GB)
}
