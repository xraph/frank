package utils

import (
	"net"
	"net/url"
	"strings"

	"github.com/xraph/frank/pkg/errors"
)

// URLValidationOptions contains options for URL validation
type URLValidationOptions struct {
	AllowedSchemes      []string // List of allowed schemes (e.g., http, https)
	RequireScheme       bool     // Whether the URL must have a scheme
	RequireHost         bool     // Whether the URL must have a host
	AllowIP             bool     // Whether IP addresses are allowed as hosts
	AllowLocalhost      bool     // Whether localhost is allowed
	AllowPrivateNetwork bool     // Whether private network IPs are allowed
	MaxLength           int      // Maximum length of the URL (0 means no limit)
}

// DefaultURLValidationOptions returns the default URL validation options
func DefaultURLValidationOptions() URLValidationOptions {
	return URLValidationOptions{
		AllowedSchemes:      []string{"http", "https"},
		RequireScheme:       true,
		RequireHost:         true,
		AllowIP:             true,
		AllowLocalhost:      false,
		AllowPrivateNetwork: false,
		MaxLength:           2048,
	}
}

// HTTPURLValidationOptions returns URL validation options for HTTP/HTTPS URLs
func HTTPURLValidationOptions() URLValidationOptions {
	return URLValidationOptions{
		AllowedSchemes:      []string{"http", "https"},
		RequireScheme:       true,
		RequireHost:         true,
		AllowIP:             true,
		AllowLocalhost:      false,
		AllowPrivateNetwork: false,
		MaxLength:           2048,
	}
}

// WebhookURLValidationOptions returns URL validation options for webhook URLs
func WebhookURLValidationOptions() URLValidationOptions {
	return URLValidationOptions{
		AllowedSchemes:      []string{"https"},
		RequireScheme:       true,
		RequireHost:         true,
		AllowIP:             false,
		AllowLocalhost:      false,
		AllowPrivateNetwork: false,
		MaxLength:           2048,
	}
}

// RedirectURLValidationOptions returns URL validation options for redirect URLs
func RedirectURLValidationOptions() URLValidationOptions {
	return URLValidationOptions{
		AllowedSchemes:      []string{"http", "https"},
		RequireScheme:       true,
		RequireHost:         true,
		AllowIP:             false,
		AllowLocalhost:      false,
		AllowPrivateNetwork: false,
		MaxLength:           2048,
	}
}

// ValidateURL validates a URL against the specified options
func ValidateURL(urlStr string, options URLValidationOptions) (bool, string) {
	// Check URL length if a maximum is specified
	if options.MaxLength > 0 && len(urlStr) > options.MaxLength {
		return false, "URL exceeds maximum length"
	}

	// Parse the URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false, "Invalid URL format"
	}

	// Check scheme
	if options.RequireScheme && parsedURL.Scheme == "" {
		return false, "URL scheme is required"
	}

	// Check allowed schemes
	if parsedURL.Scheme != "" && len(options.AllowedSchemes) > 0 {
		schemeAllowed := false
		for _, scheme := range options.AllowedSchemes {
			if parsedURL.Scheme == scheme {
				schemeAllowed = true
				break
			}
		}
		if !schemeAllowed {
			return false, "URL scheme is not allowed"
		}
	}

	// Check host
	if options.RequireHost && parsedURL.Host == "" {
		return false, "URL host is required"
	}

	// Check if host is an IP address
	host := parsedURL.Hostname()
	if host != "" {
		ip := net.ParseIP(host)
		if ip != nil {
			// Host is an IP address
			if !options.AllowIP {
				return false, "IP addresses are not allowed as hosts"
			}

			// Check if it's a private network IP
			if !options.AllowPrivateNetwork && isPrivateIP(ip) {
				return false, "Private network IP addresses are not allowed"
			}
		} else {
			// Host is not an IP address; check for localhost
			if !options.AllowLocalhost && isLocalhost(host) {
				return false, "Localhost is not allowed"
			}
		}
	}

	return true, ""
}

// isPrivateIP checks if an IP address is in a private network range
func isPrivateIP(ip net.IP) bool {
	// IPv4 private networks:
	// 10.0.0.0/8
	// 172.16.0.0/12
	// 192.168.0.0/16
	// 127.0.0.0/8 (localhost)
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1]&0xf0 == 16) ||
			(ip4[0] == 192 && ip4[1] == 168) ||
			ip4[0] == 127
	}

	// IPv6 private networks:
	// fc00::/7 (Unique Local Addresses)
	// fe80::/10 (Link-Local Addresses)
	// ::1/128 (localhost)
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// isLocalhost checks if a hostname is a localhost variant
func isLocalhost(host string) bool {
	lowercaseHost := strings.ToLower(host)
	return lowercaseHost == "localhost" ||
		strings.HasSuffix(lowercaseHost, ".localhost") ||
		lowercaseHost == "127.0.0.1" ||
		lowercaseHost == "::1" ||
		strings.HasSuffix(lowercaseHost, ".local")
}

// IsValidURLWithOptions checks if a URL is valid according to the provided options
func IsValidURLWithOptions(urlStr string, options URLValidationOptions) bool {
	valid, _ := ValidateURL(urlStr, options)
	return valid
}

// IsValidURL checks if a URL is valid using default options
func IsValidURL(urlStr string) bool {
	return IsValidURLWithOptions(urlStr, DefaultURLValidationOptions())
}

// IsValidHTTPURL checks if a URL is a valid HTTP or HTTPS URL
func IsValidHTTPURL(urlStr string) bool {
	return IsValidURLWithOptions(urlStr, HTTPURLValidationOptions())
}

// IsValidWebhookURL checks if a URL is a valid webhook URL
func IsValidWebhookURL(urlStr string) bool {
	return IsValidURLWithOptions(urlStr, WebhookURLValidationOptions())
}

// IsValidRedirectURL checks if a URL is a valid redirect URL
func IsValidRedirectURL(urlStr string) bool {
	return IsValidURLWithOptions(urlStr, RedirectURLValidationOptions())
}

// IsAbsoluteURL checks if a URL is absolute (has a scheme and host)
func IsAbsoluteURL(urlStr string) bool {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	return parsedURL.IsAbs()
}

// IsRelativeURL checks if a URL is relative (no scheme or host)
func IsRelativeURL(urlStr string) bool {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	return !parsedURL.IsAbs()
}

// SanitizeURL sanitizes a URL by removing potentially dangerous parts
func SanitizeURL(urlStr string, allowedSchemes []string) string {
	if allowedSchemes == nil {
		allowedSchemes = []string{"http", "https"}
	}

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}

	// Check scheme
	schemeAllowed := false
	for _, scheme := range allowedSchemes {
		if parsedURL.Scheme == scheme {
			schemeAllowed = true
			break
		}
	}

	if !schemeAllowed {
		// Default to https if scheme not allowed
		parsedURL.Scheme = "https"
	}

	// Remove user info (username and password)
	parsedURL.User = nil

	// Remove fragments
	parsedURL.Fragment = ""

	return parsedURL.String()
}

// ValidateRedirectURL validates a redirect URL against a list of allowed domains
func ValidateRedirectURL(redirectURL string, allowedDomains []string) bool {
	if !IsValidURL(redirectURL) {
		return false
	}

	// If no allowed domains specified, only allow relative URLs
	if len(allowedDomains) == 0 {
		return IsRelativeURL(redirectURL)
	}

	parsedURL, _ := url.Parse(redirectURL)
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return false
	}

	// Check if the host matches any allowed domain
	host := parsedURL.Hostname()
	for _, domain := range allowedDomains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}

	return false
}

// AllowedHosts checks if a URL's host is in the list of allowed hosts
func AllowedHosts(urlStr string, allowedHosts []string) bool {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	host := parsedURL.Hostname()

	for _, allowedHost := range allowedHosts {
		if host == allowedHost {
			return true
		}

		// Also check if it's a subdomain of an allowed host
		if strings.HasSuffix(host, "."+allowedHost) {
			return true
		}
	}

	return false
}

// NormalizeURL normalizes a URL (e.g., adds https:// if missing)
func NormalizeURL(urlStr string) (string, error) {
	// Check if the URL has a scheme
	if !strings.Contains(urlStr, "://") {
		// Add https:// to the URL
		urlStr = "https://" + urlStr
	}

	// Parse and validate the URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}

	// Ensure the URL has a scheme and host
	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return "", errors.New(errors.CodeBadRequest, "invalid URL format")
	}

	return parsedURL.String(), nil
}
