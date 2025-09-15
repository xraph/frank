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
	"github.com/xraph/frank/pkg/logging"
	"golang.org/x/net/http2"
)

// Configuration holds all server configuration options
type Configuration struct {
	Directory     http.FileSystem
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
	NextJSMode    bool   // Enable special handling for Next.js output structure
	HTTP2         bool   // Enable HTTP/2 support
	PreloadAssets bool   // Enable preloading of critical assets
	AssetPrefix   string // Prefix for static assets (e.g., _astro/ or _next/)
	MaxCacheSize  int    // Maximum cache size in MB
	EnableMetrics bool   // Enable performance metrics
	URLPrefix     string // URL prefix for all paths
	BasePrefix    string // Base prefix for all paths
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

// FileCache Cache to store file info for better performance
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

// Regex for identifying content hashed files
// Updated to support both Astro and Next.js content hashing patterns
var contentHashPattern = regexp.MustCompile(`(\.([a-f0-9]{8,})\.(?:js|css|webp|jpg|png|svg)|_buildManifest\.js|_ssgManifest\.js|^chunks\/.+\.js$)`)

// Next.js specific patterns
var nextJsDataPattern = regexp.MustCompile(`^_next\/data\/[^\/]+\/`)
var nextJsStaticPattern = regexp.MustCompile(`^_next\/(static|images|media)\/`)
var nextJsApiPattern = regexp.MustCompile(`^api\/`)

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
	rootDir        http.FileSystem
	logger         logging.Logger
	config         *Configuration
	preloadedPaths map[string][]string // Map of paths to their critical assets
	criticalAssets map[string]bool     // Set of critical assets
	urlPrefix      string
	basePrefix     string
}

// NewCustomFileHandler Initialize a new file server
func NewCustomFileHandler(rootDir http.FileSystem, logger logging.Logger, config *Configuration) *CustomFileHandler {
	// Update cache max size if configured
	if config.MaxCacheSize > 0 {
		fileCache.maxSize = int64(config.MaxCacheSize * 1024 * 1024)
	}

	// Normalize URL prefix
	urlPrefix := config.URLPrefix
	if urlPrefix != "" && !strings.HasPrefix(urlPrefix, "/") {
		urlPrefix = "/" + urlPrefix
	}
	// Remove trailing slash if present
	urlPrefix = strings.TrimSuffix(urlPrefix, "/")

	basePrefix := config.BasePrefix
	if urlPrefix == "" {
		basePrefix = "/"
	}

	// Set default asset prefix based on framework mode if not provided
	if config.AssetPrefix == "" {
		if config.AstroMode {
			config.AssetPrefix = "_astro"
		} else if config.NextJSMode {
			config.AssetPrefix = "_next"
		}
	}

	h := &CustomFileHandler{
		rootDir:        rootDir,
		logger:         logger,
		config:         config,
		preloadedPaths: make(map[string][]string),
		criticalAssets: make(map[string]bool),
		urlPrefix:      urlPrefix,
		basePrefix:     basePrefix,
	}

	// Preload critical assets and routes for faster responses
	if config.PreloadAssets {
		go h.preloadCriticalAssets()
	}

	// OnStart periodic cache maintenance
	go h.startCacheMaintenance()

	return h
}

// Preload critical assets and common routes
func (h *CustomFileHandler) preloadCriticalAssets() {
	// If we have an asset prefix (like _astro or _next), preload those assets
	if h.config.AssetPrefix != "" {
		assetDirPath := h.config.AssetPrefix
		// Open the asset directory
		assetDir, err := h.rootDir.Open(assetDirPath)
		if err == nil {
			h.logger.Sugar().Infow("Preloading assets", "directory", assetDirPath)
			h.preloadDirectory(assetDirPath, true)
			assetDir.Close()
		}
	}

	// Preload root index.html as it's frequently accessed
	indexPath := h.config.IndexFile
	h.preloadFile(indexPath, false)

	// Preload common route directories based on framework
	if h.config.AstroMode {
		h.preloadAstroRoutes()
	} else if h.config.NextJSMode {
		h.preloadNextJSRoutes()
	}
}

// Preload Astro-specific route directories
func (h *CustomFileHandler) preloadAstroRoutes() {
	// Open root directory
	root, err := h.rootDir.Open("/")
	if err != nil {
		h.logger.Sugar().Errorw("Failed to open root directory", "error", err)
		return
	}
	defer root.Close()

	// Read directory entries
	dirEntries, err := root.(http.File).Readdir(-1)
	if err != nil {
		h.logger.Sugar().Errorw("Failed to read directory entries", "error", err)
		return
	}

	// Iterate through entries
	for _, entry := range dirEntries {
		if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") && entry.Name() != h.config.AssetPrefix {
			routeIndexPath := path.Join(entry.Name(), h.config.IndexFile)
			h.preloadFile(routeIndexPath, true)
		}
	}
}

// Preload Next.js-specific routes and assets
func (h *CustomFileHandler) preloadNextJSRoutes() {
	// Preload Next.js specific critical files
	criticalNextFiles := []string{
		"/_next/static/chunks/main.js",
		"/_next/static/chunks/webpack.js",
		"/_next/static/chunks/framework.js",
		"/_next/static/css/global.css",
		"/_next/static/runtime/main.js",
		"/_next/static/runtime/webpack.js",
		"/_next/static/development/_buildManifest.js",
		"/_next/static/development/_ssgManifest.js",
	}

	for _, file := range criticalNextFiles {
		h.preloadFile(file, true)
	}

	// For Next.js, also check for data directory which contains pre-rendered JSON
	dataDir := "/_next/data"
	dataDirFile, err := h.rootDir.Open(dataDir)
	if err == nil {
		h.logger.Sugar().Infow("Preloading Next.js data directory", "directory", dataDir)
		h.preloadDirectory(dataDir, true)
		dataDirFile.Close()
	}

	// Check for pages directory in Next.js static export
	pagesDir := "/pages"
	pagesDirFile, err := h.rootDir.Open(pagesDir)
	if err == nil {
		h.logger.Sugar().Infow("Preloading Next.js pages directory", "directory", pagesDir)
		h.preloadDirectory(pagesDir, true)
		pagesDirFile.Close()
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
	// Normalize path for http.FileSystem (ensure it starts with /)
	fsPath := filePath
	if !strings.HasPrefix(fsPath, "/") {
		fsPath = "/" + fsPath
	}

	// Open the file from the file system
	file, err := h.rootDir.Open(fsPath)
	if err != nil {
		return
	}
	defer file.Close()

	// Get file info
	fileInfo, err := file.Stat()
	if err != nil {
		return
	}

	// Skip large files to prevent cache overflow during preloading
	if fileInfo.Size() > 5*1024*1024 {
		return
	}

	// For http.FileSystem, we use the path directly as the relative path
	// We don't need filepath.Rel since we're dealing with URL paths
	relativePath := strings.TrimPrefix(fsPath, "/")

	// Construct path with URL prefix for critical assets mapping
	assetPath := "/" + filepath.ToSlash(relativePath)
	criticalAssetPath := assetPath

	// Add URL prefix if configured
	if h.urlPrefix != "" {
		criticalAssetPath = h.urlPrefix + assetPath
	}

	// Mark as critical asset if needed
	if isCritical {
		h.criticalAssets[criticalAssetPath] = true
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

	// Handle URL prefix - strip it from the request path
	originalPath := r.URL.Path
	urlPath := originalPath

	// Check if the request path starts with our prefix and strip it
	if h.urlPrefix != "" && strings.HasPrefix(urlPath, h.urlPrefix) {
		urlPath = strings.TrimPrefix(urlPath, h.urlPrefix)
		// Ensure the path starts with a slash
		if urlPath == "" || !strings.HasPrefix(urlPath, "/") {
			urlPath = "/" + urlPath
		}

		h.logger.Sugar().Debugw("Stripped URL prefix",
			"original", originalPath,
			"prefix", h.urlPrefix,
			"new_path", urlPath)
	}

	// Handle metrics endpoint if enabled
	if h.config.EnableMetrics && urlPath == "/metrics" {
		h.serveMetrics(w, r)
		return
	}

	// Normalize path for http.FileSystem
	fsPath := path.Clean(urlPath)
	if !strings.HasPrefix(fsPath, "/") {
		fsPath = "/" + fsPath
	}

	// Framework-specific path handling
	if h.config.AstroMode {
		fsPath = h.handleAstroPath(fsPath)
	} else if h.config.NextJSMode {
		fsPath = h.handleNextJSPath(fsPath, r)
	} else if fsPath == "/" {
		fsPath = "/" + h.config.IndexFile
	}

	// Update route metrics
	metrics.mutex.Lock()
	metrics.routeRequests[fsPath]++
	metrics.mutex.Unlock()

	// Open the file
	file, err := h.rootDir.Open(fsPath)

	if err != nil {
		if h.config.SPA && !strings.HasPrefix(fsPath, "/api/") {
			// For SPA mode, serve index.html for 404s if it's not an API request
			h.logger.Sugar().Debugw("File not found, serving index.html (SPA mode)", "path", fsPath)
			indexPath := "/" + h.config.IndexFile
			indexFile, indexErr := h.rootDir.Open(indexPath)
			if indexErr != nil {
				h.logger.Sugar().Errorw("Failed to open index file", "error", indexErr, "path", indexPath)
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}
			file = indexFile
			fsPath = indexPath
		} else {
			h.logger.Sugar().Infow("File not found", "path", fsPath)
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
	}
	defer file.Close()

	// Get file stat
	fileInfo, err := file.Stat()
	if err != nil {
		h.logger.Sugar().Errorw("Failed to stat file", "error", err, "path", fsPath)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Handle directory listings or redirect
	if fileInfo.IsDir() {
		// Check for index file
		indexPath := path.Join(fsPath, h.config.IndexFile)
		indexFile, err := h.rootDir.Open(indexPath)
		if err == nil {
			// Found index file
			indexFile.Close()
			file.Close()

			// Open the index file
			file, err = h.rootDir.Open(indexPath)
			if err != nil {
				h.logger.Sugar().Errorw("Failed to open index file", "error", err, "path", indexPath)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			defer file.Close()

			// Update fsPath and fileInfo
			fsPath = indexPath
			fileInfo, err = file.Stat()
			if err != nil {
				h.logger.Sugar().Errorw("Failed to stat index file", "error", err, "path", indexPath)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
		} else {
			// Framework-specific directory handling
			if h.config.AstroMode {
				if h.handleAstroDirPath(w, r, file, fsPath) {
					return
				}
			} else if h.config.NextJSMode {
				if h.handleNextJSDirPath(w, r, file, fsPath) {
					return
				}
			}

			// No index file, redirect if path doesn't end with '/'
			if !strings.HasSuffix(r.URL.Path, "/") {
				redirectURL := r.URL.Path + "/"
				if h.urlPrefix != "" {
					// Ensure the redirect maintains the URL prefix
					redirectURL = path.Join(h.urlPrefix, strings.TrimPrefix(redirectURL, h.urlPrefix))
				}
				http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)
				return
			}

			// Simple directory listing
			if h.config.Debug {
				h.serveDirListing(w, r, file)
				return
			} else {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
	}

	// Get file extension and determine content type
	ext := strings.ToLower(path.Ext(fsPath))
	contentType, found := MimeTypeMapping[ext]
	if !found {
		contentType = "application/octet-stream"
	}

	// Special case for Next.js JSON data files
	if h.config.NextJSMode && strings.HasPrefix(fsPath, "/_next/data/") && ext == ".json" {
		contentType = "application/json; charset=utf-8"
	}

	// Use fsPath as cache key
	fileCache.mutex.RLock()
	cacheItem, found := fileCache.items[fsPath]
	fileCache.mutex.RUnlock()

	// Generate ETag based on file modification time and size
	etag := fmt.Sprintf(`"%x-%x"`, fileInfo.ModTime().UnixNano(), fileInfo.Size())

	// If file is not in cache or has been modified, update cache
	if !found || cacheItem.ModTime.Before(fileInfo.ModTime()) || cacheItem.Size != fileInfo.Size() {
		h.logger.Sugar().Debugw("Refreshing file cache", "path", fsPath)

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
			IsRouteIndex:  strings.HasSuffix(fsPath, h.config.IndexFile) && strings.Count(fsPath, "/") >= 1,
		}

		// Check if the file is a content hashed asset
		isContentHashed := contentHashPattern.MatchString(path.Base(fsPath))
		fmt.Println(isContentHashed)

		// Pre-compress file if compression is enabled and file meets criteria
		if (h.config.EnableGzip || h.config.EnableBrotli) &&
			fileInfo.Size() > 1024 &&
			fileInfo.Size() < 10*1024*1024 && // Don't compress files > 10MB
			isCompressibleType(contentType) {

			// Read file content
			fileContent := make([]byte, fileInfo.Size())
			file.Seek(0, io.SeekStart) // Reset to beginning of file
			_, err := io.ReadFull(file, fileContent)

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

				// Reset file position for later reading if needed
				file.Seek(0, io.SeekStart)
			} else {
				h.logger.Sugar().Errorw("Failed to read file for compression", "error", err, "path", fsPath)
			}
		}

		// Update the cache with the new or updated item
		fileCache.mutex.Lock()
		// If updating, remove old size first
		if oldItem, exists := fileCache.items[fsPath]; exists {
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
		fileCache.items[fsPath] = cacheItem
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
	isContentHashed := contentHashPattern.MatchString(path.Base(fsPath))

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
		if preloadAssets, found := h.preloadedPaths[fsPath]; found && len(preloadAssets) > 0 {
			var preloadHeaders []string
			for _, asset := range preloadAssets {
				var asType string
				ext := path.Ext(asset)
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

				// Add URL prefix to preload assets if configured
				assetPath := asset
				if h.urlPrefix != "" && !strings.HasPrefix(asset, h.urlPrefix) {
					assetPath = path.Join(h.urlPrefix, asset)
				}

				preloadHeaders = append(preloadHeaders, fmt.Sprintf("<%s>; rel=preload; as=%s", assetPath, asType))
			}
			if len(preloadHeaders) > 0 {
				w.Header().Set("Link", strings.Join(preloadHeaders, ", "))
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
		file.Seek(0, io.SeekStart) // Reset to beginning of file

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

// Handle Astro-specific path adjustments
func (h *CustomFileHandler) handleAstroPath(fsPath string) string {
	// If path is empty or root, serve index.html
	if fsPath == "/" {
		return "/" + h.config.IndexFile
	} else if !strings.Contains(fsPath, ".") {
		// This is likely a route path without a file extension
		// First, check if a directory with this name exists
		dirFile, err := h.rootDir.Open(fsPath)
		if err == nil {
			dirInfo, err := dirFile.Stat()
			dirFile.Close()

			if err == nil && dirInfo.IsDir() {
				// Directory exists, check if it has an index.html
				indexPath := path.Join(fsPath, h.config.IndexFile)
				indexFile, err := h.rootDir.Open(indexPath)
				if err == nil {
					indexFile.Close()
					return indexPath
				}
			}
		}

		// If we haven't found a directory or index file, try with .html extension
		if fsPath == path.Clean(fsPath) {
			htmlPath := fsPath + ".html"
			htmlFile, err := h.rootDir.Open(htmlPath)
			if err == nil {
				htmlFile.Close()
				return htmlPath
			} else {
				// Fall back to index.html for client-side routing
				return "/" + h.config.IndexFile
			}
		}
	}
	return fsPath
}

// Handle Next.js-specific path adjustments
func (h *CustomFileHandler) handleNextJSPath(fsPath string, r *http.Request) string {
	// Root path handling
	if fsPath == "/" {
		return "/" + h.config.IndexFile
	}

	// Handle Next.js data routes (e.g., /_next/data/buildId/page.json)
	if nextJsDataPattern.MatchString(fsPath) {
		// Data routes are already properly formatted in Next.js
		return fsPath
	}

	// Handle API routes
	if nextJsApiPattern.MatchString(fsPath) {
		// API routes are handled separately, don't apply routing logic
		return fsPath
	}

	// Handle static assets routes
	if nextJsStaticPattern.MatchString(fsPath) {
		// Static assets are already properly formatted
		return fsPath
	}

	// Handle page routing for Next.js
	if !strings.Contains(fsPath, ".") {
		// Check for directory with index.html
		indexPath := path.Join(fsPath, h.config.IndexFile)
		indexFile, err := h.rootDir.Open(indexPath)
		if err == nil {
			indexFile.Close()
			return indexPath
		}

		// Check for .html file
		htmlPath := fsPath + ".html"
		htmlFile, err := h.rootDir.Open(htmlPath)
		if err == nil {
			htmlFile.Close()
			return htmlPath
		}

		// Next.js exported static pages structure
		pagesPath := path.Join("/pages", fsPath, h.config.IndexFile)
		pagesFile, err := h.rootDir.Open(pagesPath)
		if err == nil {
			pagesFile.Close()
			return pagesPath
		}

		// Next.js has dynamic routing feature
		// Check for bracket notation pages like /pages/[id].html
		// This requires scanning the pages directory

		// Fall back to serving index.html for client-side routing
		if h.config.SPA {
			return "/" + h.config.IndexFile
		}
	}

	return fsPath
}

// Handle Astro directory path logic
func (h *CustomFileHandler) handleAstroDirPath(w http.ResponseWriter, r *http.Request, file http.File, fsPath string) bool {
	// For Astro mode, check for subdirectories with index files
	h.logger.Sugar().Debugw("Checking for Astro route structure in directory", "path", fsPath)

	// Get directory entries
	dirEntries, err := file.(http.File).Readdir(-1)
	if err == nil {
		found := false
		for _, entry := range dirEntries {
			if entry.IsDir() {
				subDirPath := path.Join(fsPath, entry.Name())
				potentialIndex := path.Join(subDirPath, h.config.IndexFile)
				potentialFile, err := h.rootDir.Open(potentialIndex)
				if err == nil {
					potentialFile.Close()
					found = true
					h.logger.Sugar().Debugw("Found index in subdirectory", "subdir", entry.Name())
					break
				}
			}
		}

		if found {
			// If we found index files in subdirectories
			if h.config.Debug {
				h.serveDirListing(w, r, file)
				return true
			} else if !strings.HasSuffix(r.URL.Path, "/") {
				// Redirect if path doesn't end with '/'
				redirectURL := r.URL.Path + "/"
				if h.urlPrefix != "" {
					// Ensure the redirect maintains the URL prefix
					redirectURL = path.Join(h.urlPrefix, strings.TrimPrefix(redirectURL, h.urlPrefix))
				}
				http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)
				return true
			}
		}
	}
	return false
}

// Handle Next.js directory path logic
func (h *CustomFileHandler) handleNextJSDirPath(w http.ResponseWriter, r *http.Request, file http.File, fsPath string) bool {
	// Get directory entries
	dirEntries, err := file.(http.File).Readdir(-1)
	if err != nil {
		return false
	}

	// Look for Next.js specific files like _app.js, _document.js
	nextJsSpecificFiles := false
	for _, entry := range dirEntries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "_") {
			nextJsSpecificFiles = true
			break
		}
	}

	// Check for pages subdirectory
	pagesExists := false
	for _, entry := range dirEntries {
		if entry.IsDir() && entry.Name() == "pages" {
			pagesExists = true
			break
		}
	}

	if nextJsSpecificFiles || pagesExists {
		// This is likely a Next.js directory
		if h.config.Debug {
			h.serveDirListing(w, r, file)
			return true
		} else if !strings.HasSuffix(r.URL.Path, "/") {
			// Redirect if path doesn't end with '/'
			redirectURL := r.URL.Path + "/"
			if h.urlPrefix != "" {
				redirectURL = path.Join(h.urlPrefix, strings.TrimPrefix(redirectURL, h.urlPrefix))
			}
			http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)
			return true
		}
	}
	return false
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
	fmt.Fprintf(w, "# File Server Metrics\n\n")
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
func (h *CustomFileHandler) serveDirListing(w http.ResponseWriter, r *http.Request, dir http.File) {
	entries, err := dir.(http.File).Readdir(-1)
	if err != nil {
		h.logger.Sugar().Errorw("Failed to read directory", "error", err, "path", r.URL.Path)
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

// max returns the larger of x or y
func max(x, y int64) int64 {
	if x > y {
		return x
	}
	return y
}
