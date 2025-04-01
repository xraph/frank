package middleware

import (
	"bytes"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/juicycleff/frank/pkg/logging"
)

// AstroPathPrefixer is middleware that handles serving Astro apps under a prefix
type AstroPathPrefixer struct {
	prefix     string
	basePrefix string
	logger     logging.Logger
}

// NewAstroPathPrefixer creates a new middleware to handle Astro path prefixing
func NewAstroPathPrefixer(basePrefix string, prefix string, logger logging.Logger) *AstroPathPrefixer {
	// Ensure prefix starts with / and doesn't end with /
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	prefix = strings.TrimSuffix(prefix, "/")

	return &AstroPathPrefixer{
		basePrefix: basePrefix,
		prefix:     prefix,
		logger:     logger,
	}
}

// Middleware returns the actual middleware handler
func (a *AstroPathPrefixer) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Store original path for logging
		originalPath := r.URL.Path

		// Skip API or other non-asset paths
		if strings.HasPrefix(r.URL.Path, path.Join(a.basePrefix, "/v1/")) ||
			strings.HasPrefix(r.URL.Path, path.Join(a.basePrefix, "/api/")) ||
			strings.HasPrefix(r.URL.Path, path.Join(a.basePrefix, "/__")) {
			next.ServeHTTP(w, r)
			return
		}

		// 1. Strip prefix for downstream handlers
		if strings.HasPrefix(r.URL.Path, a.prefix) {
			r.URL.Path = strings.TrimPrefix(r.URL.Path, a.prefix)
			if r.URL.Path == "" {
				r.URL.Path = "/"
			}
		}

		// 2. Set up response wrapper to rewrite links in HTML/CSS/JS
		if shouldRewriteContent(r.URL.Path) {
			rww := &responseWriterWrapper{
				ResponseWriter: w,
				prefix:         a.prefix,
				path:           originalPath,
				buffer:         &bytes.Buffer{},
			}
			next.ServeHTTP(rww, r)
			rww.rewriteAndSend()
		} else {
			next.ServeHTTP(w, r)
		}
	})
}

// shouldRewriteContent determines if we should rewrite content based on file type
func shouldRewriteContent(p string) bool {
	ext := strings.ToLower(strings.TrimPrefix(path.Ext(p), "."))
	return ext == "html" || ext == "js" || ext == "css" || ext == "" || strings.HasSuffix(p, "/")
}

// responseWriterWrapper captures the response to rewrite paths
type responseWriterWrapper struct {
	http.ResponseWriter
	prefix        string
	path          string
	statusCode    int
	buffer        *bytes.Buffer
	headerWritten bool
}

// WriteHeader captures the status code
func (rww *responseWriterWrapper) WriteHeader(statusCode int) {
	rww.statusCode = statusCode
	// Don't actually write header yet - we'll do that when we send the rewritten content
	rww.headerWritten = true
}

// Write captures the response body
func (rww *responseWriterWrapper) Write(b []byte) (int, error) {
	if !rww.headerWritten {
		rww.statusCode = http.StatusOK
		rww.headerWritten = true
	}
	return rww.buffer.Write(b)
}

// rewriteAndSend processes content and sends the final response
func (rww *responseWriterWrapper) rewriteAndSend() {
	if rww.statusCode == 0 {
		rww.statusCode = http.StatusOK
	}

	// Get content type
	contentType := rww.Header().Get("Content-Type")
	content := rww.buffer.Bytes()

	// Process content based on type
	var processedContent []byte
	if strings.Contains(contentType, "text/html") {
		processedContent = rww.rewriteHTML(content)
	} else if strings.Contains(contentType, "application/javascript") {
		processedContent = rww.rewriteJS(content)
	} else if strings.Contains(contentType, "text/css") {
		processedContent = rww.rewriteCSS(content)
	} else {
		processedContent = content
	}

	// Set correct content length
	rww.Header().Set("Content-Length", strconv.Itoa(len(processedContent)))

	// Write headers and content
	rww.ResponseWriter.WriteHeader(rww.statusCode)
	rww.ResponseWriter.Write(processedContent)
}

// Regular expressions for different types of paths
var (
	// Match src, href, action attributes in HTML
	htmlRegexp = regexp.MustCompile(`(src|href|action)=["']([^"']+)["']`)

	// Match URLs in CSS
	cssUrlRegexp = regexp.MustCompile(`url\(["']?([^"')]+)["']?\)`)

	// Match import paths in JS
	jsImportRegexp = regexp.MustCompile(`(?:import|from)\s+["']([^"']+)["']`)

	// Match fetch/axios calls in JS
	jsPathRegexp = regexp.MustCompile(`(?:fetch|axios\.get|axios\.post|axios\.put|axios\.delete)\(["']([^"']+)["']`)
)

// rewriteHTML fixes HTML paths
func (rww *responseWriterWrapper) rewriteHTML(content []byte) []byte {
	// Fix asset paths in HTML
	rewrittenContent := htmlRegexp.ReplaceAllFunc(content, func(match []byte) []byte {
		parts := htmlRegexp.FindSubmatch(match)
		if len(parts) < 3 {
			return match
		}

		attr := string(parts[1])
		pathValue := string(parts[2])

		// Don't modify paths with these prefixes
		if strings.HasPrefix(pathValue, "http:") ||
			strings.HasPrefix(pathValue, "https:") ||
			strings.HasPrefix(pathValue, "mailto:") ||
			strings.HasPrefix(pathValue, "tel:") ||
			strings.HasPrefix(pathValue, "//") ||
			strings.HasPrefix(pathValue, "#") ||
			strings.HasPrefix(pathValue, rww.prefix+"/") {
			return match
		}

		// Add the prefix to the path
		newPath := path.Join(rww.prefix, pathValue)
		return []byte(fmt.Sprintf(`%s="%s"`, attr, newPath))
	})

	return rewrittenContent
}

// rewriteCSS fixes CSS paths
func (rww *responseWriterWrapper) rewriteCSS(content []byte) []byte {
	// Fix asset URLs in CSS
	return cssUrlRegexp.ReplaceAllFunc(content, func(match []byte) []byte {
		parts := cssUrlRegexp.FindSubmatch(match)
		if len(parts) < 2 {
			return match
		}

		pathValue := string(parts[1])
		if strings.HasPrefix(pathValue, rww.prefix) {
			return match
		}

		newPath := path.Join(rww.prefix, pathValue)
		// Keep the original quotes or lack thereof
		if bytes.Contains(match, []byte(`'`)) {
			return []byte(fmt.Sprintf(`url('%s')`, newPath))
		} else if bytes.Contains(match, []byte(`"`)) {
			return []byte(fmt.Sprintf(`url("%s")`, newPath))
		}
		return []byte(fmt.Sprintf(`url(%s)`, newPath))
	})
}

// rewriteJS fixes JavaScript paths
func (rww *responseWriterWrapper) rewriteJS(content []byte) []byte {
	// Fix import statements
	content = jsImportRegexp.ReplaceAllFunc(content, func(match []byte) []byte {
		parts := jsImportRegexp.FindSubmatch(match)
		if len(parts) < 2 {
			return match
		}

		pathValue := string(parts[1])
		if strings.HasPrefix(pathValue, rww.prefix) {
			return match
		}

		beforePath := string(match[:len(match)-len(pathValue)-1]) // -1 for closing quote
		quoteChar := string(match[len(match)-len(pathValue)-1])   // Get the quote character used

		newPath := path.Join(rww.prefix, pathValue)
		return []byte(fmt.Sprintf(`%s%s%s%s`, beforePath, quoteChar, newPath, quoteChar))
	})

	// Fix fetch/axios calls
	content = jsPathRegexp.ReplaceAllFunc(content, func(match []byte) []byte {
		parts := jsPathRegexp.FindSubmatch(match)
		if len(parts) < 2 {
			return match
		}

		pathValue := string(parts[1])
		if strings.HasPrefix(pathValue, rww.prefix) {
			return match
		}

		beforePath := string(match[:len(match)-len(pathValue)-1]) // -1 for closing quote
		quoteChar := string(match[len(match)-len(pathValue)-1])   // Get the quote character used

		newPath := path.Join(rww.prefix, pathValue)
		return []byte(fmt.Sprintf(`%s%s%s%s`, beforePath, quoteChar, newPath, quoteChar))
	})

	return content
}
