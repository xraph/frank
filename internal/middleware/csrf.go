package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/auth/session"
	"github.com/juicycleff/frank/pkg/crypto"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"
)

// CSRFConfig holds configuration for CSRF protection
type CSRFConfig struct {
	// Routes that are exempt from CSRF protection
	ExemptRoutes []string
	// Cookie expiration time
	CookieExpiry time.Duration
	// Whether to regenerate token on every request
	RegenerateOnRequest bool
}

// DefaultCSRFConfig returns the default CSRF configuration
func DefaultCSRFConfig() CSRFConfig {
	return CSRFConfig{
		ExemptRoutes: []string{
			"/v1/auth/login",
			"/v1/auth/register",
			"/v1/auth/signup",
			"/v1/auth/verify-email",
			"/v1/auth/forgot-password",
			"/v1/auth/reset-password",
			"/v1/auth/refresh-token",
			"/v1/auth/csrf-token", // Endpoint to get a new token
		},
		CookieExpiry:        24 * time.Hour,
		RegenerateOnRequest: false,
	}
}

// CSRFProtection returns a middleware that provides CSRF protection
func CSRFProtection(cfg *config.Config, logger logging.Logger) func(http.Handler) http.Handler {
	return CSRFProtectionWithConfig(cfg, logger, DefaultCSRFConfig())
}

// CSRFProtectionWithConfig returns a middleware that provides CSRF protection with custom config
func CSRFProtectionWithConfig(cfg *config.Config, logger logging.Logger, csrfConfig CSRFConfig) func(http.Handler) http.Handler {
	cookieHandler := session.NewCookieHandler(cfg, logger)

	// Convert exempt routes to a map for faster lookup
	exemptMap := make(map[string]bool)
	for _, route := range csrfConfig.ExemptRoutes {
		exemptMap[route] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip CSRF check for GET, HEAD, OPTIONS requests as they should be safe
			if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" || !cfg.Security.CSRFEnabled {
				next.ServeHTTP(w, r)
				return
			}

			// Check if this route is exempt from CSRF protection
			if exemptMap[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}

			// Get the token from the cookie
			cookieToken, err := cookieHandler.GetCSRFCookie(r)
			if err != nil {
				utils.RespondError(w, errors.New(errors.CodeForbidden, "CSRF token cookie missing or invalid"))
				return
			}

			// Get the token from the request (header or form)
			requestToken := extractCSRFToken(r)

			// Validate tokens
			if cookieToken == "" || requestToken == "" || cookieToken != requestToken {
				logger.Debug("CSRF validation failed",
					logging.String("path", r.URL.Path),
					logging.String("method", r.Method),
					logging.Bool("cookie_token_empty", cookieToken == ""),
					logging.Bool("request_token_empty", requestToken == ""))

				utils.RespondError(w, errors.New(errors.CodeForbidden, "CSRF token validation failed"))
				return
			}

			// Optionally regenerate token for enhanced security
			if csrfConfig.RegenerateOnRequest {
				newToken, err := crypto.GenerateRandomString(32)
				if err == nil {
					cookieHandler.SetCSRFCookie(w, newToken, csrfConfig.CookieExpiry)

					// Add the new token to the response header
					w.Header().Set("X-CSRF-Token", newToken)
				}
			}

			// Add the CSRF token to the request context
			ctx := context.WithValue(r.Context(), CSRFTokenKey, cookieToken)

			// Continue with the next handler
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GenerateCSRFToken generates a new CSRF token and sets it as a cookie
func GenerateCSRFToken(w http.ResponseWriter, cfg *config.Config, logger logging.Logger, expiry time.Duration) (string, error) {
	// Generate a secure random token
	token, err := crypto.GenerateRandomString(32)
	if err != nil {
		return "", err
	}

	// Set the token as a cookie
	cookieHandler := session.NewCookieHandler(cfg, logger)
	cookieHandler.SetCSRFCookie(w, token, expiry)

	return token, nil
}

// CSRFTokenKey is the context key for storing the CSRF token
type csrfTokenKey string

const CSRFTokenKey = csrfTokenKey("csrf_token")

// extractCSRFToken gets the CSRF token from various sources in the request
func extractCSRFToken(r *http.Request) string {
	// Try the standard header
	token := r.Header.Get("X-CSRF-Token")
	if token != "" {
		return token
	}

	// Try alternate header names
	token = r.Header.Get("CSRF-Token")
	if token != "" {
		return token
	}

	// For form submissions, check the form value
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/x-www-form-urlencoded") ||
		strings.Contains(contentType, "multipart/form-data") {
		r.ParseForm()
		token = r.FormValue("csrf_token")
		if token != "" {
			return token
		}
	}

	// For JSON requests, we've already checked the headers, so no need to parse body

	return ""
}

// UpdateLoginHandler modifies your existing login handler to return a CSRF token
func UpdateLoginHandler(originalHandler http.HandlerFunc, cfg *config.Config, logger logging.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Create a response writer that captures the response
		crw := utils.NewCaptureResponseWriter(w)

		// Call the original handler with our capturing writer
		originalHandler(crw, r)

		// If the status code indicates success (2xx)
		if crw.StatusCode >= 200 && crw.StatusCode < 300 {
			// Try to parse the existing response as JSON
			var response map[string]interface{}
			if err := json.Unmarshal(crw.Body.Bytes(), &response); err == nil {
				// Generate a new CSRF token
				token, err := GenerateCSRFToken(w, cfg, logger, 24*time.Hour)
				if err == nil {
					// Add the token to the response
					response["csrf_token"] = token

					// Write the modified response
					modifiedResponse, _ := json.Marshal(response)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(crw.StatusCode)
					w.Write(modifiedResponse)
					return
				}
			}
		}

		// If we couldn't modify the response, just pass through the original
		for k, v := range crw.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(crw.StatusCode)
		w.Write(crw.Body.Bytes())
	}
}

// GetCSRFToken gets the CSRF token from the request context
func GetCSRFToken(r *http.Request) (string, bool) {
	token, ok := r.Context().Value(CSRFTokenKey).(string)
	return token, ok
}
