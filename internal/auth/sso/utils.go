package sso

import (
	"errors"
	"fmt"
	"strings"
)

// Common error definitions
var (
	ErrProviderNotConfigured = errors.New("provider not configured")
	ErrAuthorizationFailed   = errors.New("authorization failed")
)

// SSOProviderType represents the type of SSO provider
type SSOProviderType string

const (
	// ProviderTypeOAuth2 represents OAuth2-based providers (Google, GitHub, etc.)
	ProviderTypeOAuth2 SSOProviderType = "oauth2"

	// ProviderTypeOIDC represents OpenID Connect providers
	ProviderTypeOIDC SSOProviderType = "oidc"

	// ProviderTypeSAML represents SAML providers
	ProviderTypeSAML SSOProviderType = "saml"
)

// splitEmailParts splits an email address into local and domain parts
func splitEmailParts(email string) []string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return []string{email}
	}
	return parts
}

// getProviderMetadata returns a formatted provider metadata map
func getProviderMetadata(provider string, extraMetadata map[string]interface{}) map[string]interface{} {
	metadata := make(map[string]interface{})
	metadata["provider"] = provider

	// Add any extra metadata
	if extraMetadata != nil {
		for k, v := range extraMetadata {
			metadata[k] = v
		}
	}

	return metadata
}

// getCallbackURL generates a callback URL for a provider
func getCallbackURL(baseURL, provider string) string {
	return fmt.Sprintf("%s/api/v1/auth/sso/callback/%s", baseURL, provider)
}

// isAllowedDomain checks if a domain is in the list of allowed domains
func isAllowedDomain(domain string, allowedDomains []string) bool {
	if len(allowedDomains) == 0 {
		return true
	}

	for _, allowedDomain := range allowedDomains {
		if strings.EqualFold(domain, allowedDomain) {
			return true
		}

		// Check for wildcard domains
		if strings.HasPrefix(allowedDomain, "*.") {
			suffix := allowedDomain[1:] // Remove the '*'
			if strings.HasSuffix(domain, suffix) {
				return true
			}
		}
	}

	return false
}

// extractDomainFromEmail extracts the domain part from an email address
func extractDomainFromEmail(email string) string {
	parts := splitEmailParts(email)
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

// joinWithCommas joins a slice of strings with commas
func joinWithCommas(items []string) string {
	return strings.Join(items, ", ")
}

// contains checks if a string is in a slice of strings
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
