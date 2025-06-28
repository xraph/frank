package middleware

import (
	"strings"

	"github.com/juicycleff/frank/pkg/server"
)

// buildFullPathsWithBasePath constructs full paths considering mount options
func (tm *TenantMiddleware) buildFullPathsWithBasePath(basePaths []string) []string {
	return buildFullPathsWithBasePath(tm.mountOpts, basePaths)
}

// buildFullPathsWithBasePath constructs full paths considering mount options
func buildFullPathsWithBasePath(mountOpts *server.MountOptions, basePaths []string) []string {
	if mountOpts == nil || mountOpts.BasePath == "" {
		// No base path, use paths as-is but add common API prefixes
		var fullPaths []string
		for _, basePath := range basePaths {
			fullPaths = append(fullPaths, basePath)
			fullPaths = append(fullPaths, "/api/v1"+basePath)
			fullPaths = append(fullPaths, "/v1"+basePath)
		}
		return fullPaths
	}

	// Build paths with mount base path
	basePath := strings.TrimSuffix(mountOpts.BasePath, "/")
	var fullPaths []string

	for _, path := range basePaths {
		// Add the exact mounted path
		fullPaths = append(fullPaths, basePath+path)

		// Add common API version combinations
		fullPaths = append(fullPaths, basePath+"/api/v1"+path)
		fullPaths = append(fullPaths, basePath+"/v1"+path)

		// Also include the base path without prefix for flexibility
		fullPaths = append(fullPaths, path)
	}

	return fullPaths
}
