package session

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/pkg/crypto"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// CookieHandler manages secure cookie operations
type CookieHandler struct {
	config *config.Config
	logger logging.Logger
}

// NewCookieHandler creates a new cookie handler
func NewCookieHandler(cfg *config.Config, logger logging.Logger) *CookieHandler {
	return &CookieHandler{
		config: cfg,
		logger: logger,
	}
}

// CookieSessionData represents session data stored in a cookie
type CookieSessionData struct {
	UserID         string                 `json:"user_id"`
	Token          string                 `json:"token"`
	OrganizationID string                 `json:"organization_id,omitempty"`
	ExpiresAt      time.Time              `json:"expires_at"`
	IssuedAt       time.Time              `json:"issued_at"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// SetSecureSessionCookie that just uses JWT for everything
func (h *CookieHandler) SetSecureSessionCookie(r *http.Request, w http.ResponseWriter, data *CookieSessionData, expiry time.Duration) error {
	h.logger.Debug("Setting secure session cookie",
		logging.String("user_id", data.UserID),
		logging.Duration("expiry", expiry))

	// Create JWT claims
	claims := map[string]interface{}{
		"user_id": data.UserID,
		"exp":     time.Now().Add(expiry).Unix(),
		"iat":     time.Now().Unix(),
		"iss":     h.config.Auth.TokenIssuer,
	}

	// Add organization ID if present
	if data.OrganizationID != "" {
		claims["organization_id"] = data.OrganizationID
	}

	// Add any metadata
	if data.Metadata != nil {
		for k, v := range data.Metadata {
			// Skip reserved claim names
			if k != "user_id" && k != "exp" && k != "iat" && k != "iss" && k != "organization_id" {
				claims[k] = v
			}
		}
	}

	// Create JWT token
	jwtConfig := &crypto.JWTConfig{
		SigningMethod: h.config.Auth.TokenSigningMethod,
		SignatureKey:  []byte(h.config.Auth.TokenSecretKey),
		ValidationKey: []byte(h.config.Auth.TokenSecretKey),
		Issuer:        h.config.Auth.TokenIssuer,
		Audience:      h.config.Auth.TokenAudience,
	}

	token, err := jwtConfig.GenerateToken(data.UserID, claims, expiry)
	if err != nil {
		h.logger.Error("Failed to create JWT token", logging.Error(err))
		return errors.Wrap(errors.CodeCryptoError, err, "failed to create session token")
	}

	// domain := h.config.Auth.CookieDomain
	// if domain == "" && r != nil {
	// 	// Extract host from request
	// 	host := r.Host
	// 	// Remove port if present
	// 	if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
	// 		host = host[:colonIndex]
	// 	}
	// 	domain = host
	// }

	// Domain handling
	domain := h.config.Auth.CookieDomain
	if domain == "" && r != nil {
		host := r.Host
		if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
			host = host[:colonIndex]
		}

		// For localhost, leave domain empty
		if host == "localhost" {
			domain = ""
		} else {
			domain = host
		}
	}

	secure := h.config.Auth.CookieSecure
	if config.IsDevelopment() {
		secure = false
	}

	// Create cookie with consistent settings
	cookie := &http.Cookie{
		Name:     h.getSessionCookieName(),
		Value:    token,
		Path:     "/",
		Domain:   domain,
		Expires:  time.Now().Add(expiry),
		MaxAge:   int(expiry.Seconds()),
		Secure:   secure,
		HttpOnly: h.config.Auth.CookieHTTPOnly,
		SameSite: http.SameSiteLaxMode, // Use Lax for frontend compatibility
	}

	h.logger.Debug("Setting JWT cookie",
		logging.String("name", cookie.Name),
		logging.String("domain", cookie.Domain),
		logging.String("path", cookie.Path),
		logging.Int("max_age", cookie.MaxAge))

	http.SetCookie(w, cookie)
	return nil
}

// GetSecureSessionCookie that just uses JWT for everything
func (h *CookieHandler) GetSecureSessionCookie(r *http.Request) (*CookieSessionData, error) {
	h.logger.Debug("Attempting to extract session cookie")

	// Get the cookie
	cookie, err := r.Cookie(h.getSessionCookieName())
	if err != nil {
		h.logger.Debug("Cookie not found", logging.Error(err))
		return nil, errors.New(errors.CodeSessionExpired, "session cookie not found")
	}

	h.logger.Debug("Found cookie",
		logging.String("cookie_value_prefix", cookie.Value[:10]+"..."),
		logging.String("domain", cookie.Domain),
		logging.String("path", cookie.Path),
		logging.Int("max_age", cookie.MaxAge))

	// Log the cookie value for debugging
	h.logger.Debug("cookie value: ", logging.String("cookie_value", cookie.Value))

	// If this is not a JWT token, we can't process it
	if !strings.HasPrefix(cookie.Value, "eyJ") {
		h.logger.Debug("Cookie value is not a JWT token")
		return nil, errors.New(errors.CodeInvalidToken, "invalid token format")
	}

	// Validate JWT token
	jwtConfig := &crypto.JWTConfig{
		SigningMethod: h.config.Auth.TokenSigningMethod,
		SignatureKey:  []byte(h.config.Auth.TokenSecretKey),
		ValidationKey: []byte(h.config.Auth.TokenSecretKey),
		Issuer:        h.config.Auth.TokenIssuer,
		Audience:      h.config.Auth.TokenAudience,
	}

	claims, err := jwtConfig.ValidateToken(cookie.Value)
	if err != nil {
		h.logger.Debug("Failed to validate JWT token", logging.Error(err))
		return nil, errors.Wrap(errors.CodeInvalidToken, err, "invalid session token")
	}

	// Create session data from JWT claims
	sessionData := &CookieSessionData{
		Token:     cookie.Value,
		ExpiresAt: time.Now().Add(h.config.Auth.SessionDuration),
		IssuedAt:  time.Now(),
	}

	// Extract user ID
	if userID, ok := claims["user_id"].(string); ok && userID != "" {
		sessionData.UserID = userID
	} else if userID, ok := claims["sub"].(string); ok && userID != "" {
		sessionData.UserID = userID
	} else {
		h.logger.Debug("JWT token does not contain user ID")
		return nil, errors.New(errors.CodeInvalidToken, "invalid token: missing user ID")
	}

	// Extract organization ID if present
	if orgID, ok := claims["organization_id"].(string); ok && orgID != "" {
		sessionData.OrganizationID = orgID
	}

	// Extract metadata
	metadata := make(map[string]interface{})
	for k, v := range claims {
		// Skip reserved claim names
		if k != "user_id" && k != "exp" && k != "iat" && k != "iss" &&
			k != "organization_id" && k != "sub" && k != "aud" && k != "nbf" {
			metadata[k] = v
		}
	}

	if len(metadata) > 0 {
		sessionData.Metadata = metadata
	}

	h.logger.Debug("Successfully extracted session data from JWT",
		logging.String("user_id", sessionData.UserID))

	return sessionData, nil
}

// ClearSessionCookie clears the session cookie
func (h *CookieHandler) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     h.getSessionCookieName(),
		Value:    "",
		Path:     "/",
		Domain:   h.config.Auth.CookieDomain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   h.config.Auth.CookieSecure,
		HttpOnly: h.config.Auth.CookieHTTPOnly,
		SameSite: parseCookieSameSite(h.config.Auth.CookieSameSite),
	})
}

// SetAuthStateCookie sets a cookie for OAuth/SSO state
func (h *CookieHandler) SetAuthStateCookie(w http.ResponseWriter, state string, expiry time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_state",
		Value:    state,
		Path:     "/",
		Domain:   h.config.Auth.CookieDomain,
		Expires:  time.Now().Add(expiry),
		MaxAge:   int(expiry.Seconds()),
		Secure:   h.config.Auth.CookieSecure,
		HttpOnly: h.config.Auth.CookieHTTPOnly,
		SameSite: parseCookieSameSite(h.config.Auth.CookieSameSite),
	})
}

// GetAuthStateCookie gets the OAuth/SSO state from a cookie
func (h *CookieHandler) GetAuthStateCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie("auth_state")
	if err != nil {
		if err == http.ErrNoCookie {
			return "", errors.New(errors.CodeInvalidOAuthState, "state cookie not found")
		}
		return "", errors.Wrap(errors.CodeInvalidOAuthState, err, "failed to read state cookie")
	}

	return cookie.Value, nil
}

// ClearAuthStateCookie clears the OAuth/SSO state cookie
func (h *CookieHandler) ClearAuthStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_state",
		Value:    "",
		Path:     "/",
		Domain:   h.config.Auth.CookieDomain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   h.config.Auth.CookieSecure,
		HttpOnly: h.config.Auth.CookieHTTPOnly,
		SameSite: parseCookieSameSite(h.config.Auth.CookieSameSite),
	})
}

// getSessionCookieName returns the name of the session cookie
func (h *CookieHandler) getSessionCookieName() string {
	return "frank_session"
}

// parseCookieSameSite converts a string to http.SameSite
func parseCookieSameSite(sameSite string) http.SameSite {
	switch strings.ToLower(sameSite) {
	case "strict":
		return http.SameSiteStrictMode
	case "lax":
		return http.SameSiteLaxMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

// SetRememberMeCookie sets a long-lived "remember me" cookie for token refresh
func (h *CookieHandler) SetRememberMeCookie(w http.ResponseWriter, userID string, expiry time.Duration) error {
	// Create a simple data structure for the cookie
	data := map[string]interface{}{
		"user_id":    userID,
		"created_at": time.Now(),
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return errors.Wrap(errors.CodeInternalServer, err, "failed to marshal remember me data")
	}

	// Generate a random IV
	iv, err := crypto.RandomBytes(16)
	if err != nil {
		return errors.Wrap(errors.CodeCryptoError, err, "failed to generate IV")
	}

	// Encrypt the data
	encrypted, err := crypto.Encrypt(jsonData, []byte(h.config.Auth.SessionSecretKey), iv)
	if err != nil {
		return errors.Wrap(errors.CodeCryptoError, err, "failed to encrypt remember me data")
	}

	// Combine IV and ciphertext
	combined := append(iv, encrypted...)

	// Encode to base64
	cookieValue := base64.URLEncoding.EncodeToString(combined)

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "frank_remember",
		Value:    cookieValue,
		Path:     "/",
		Domain:   h.config.Auth.CookieDomain,
		Expires:  time.Now().Add(expiry),
		MaxAge:   int(expiry.Seconds()),
		Secure:   h.config.Auth.CookieSecure,
		HttpOnly: h.config.Auth.CookieHTTPOnly,
		SameSite: parseCookieSameSite(h.config.Auth.CookieSameSite),
	})

	return nil
}

// GetRememberMeCookie gets the user ID from a "remember me" cookie
func (h *CookieHandler) GetRememberMeCookie(r *http.Request) (string, error) {
	// Get the cookie
	cookie, err := r.Cookie("frank_remember")
	if err != nil {
		if err == http.ErrNoCookie {
			return "", errors.New(errors.CodeNotFound, "remember me cookie not found")
		}
		return "", errors.Wrap(errors.CodeInvalidToken, err, "failed to read remember me cookie")
	}

	// Decode from base64
	combined, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return "", errors.Wrap(errors.CodeInvalidToken, err, "failed to decode remember me cookie value")
	}

	// Extract IV and ciphertext
	if len(combined) < 16 {
		return "", errors.New(errors.CodeInvalidToken, "invalid remember me cookie data")
	}

	iv := combined[:16]
	encrypted := combined[16:]

	// Decrypt the data
	decrypted, err := crypto.Decrypt(encrypted, []byte(h.config.Auth.SessionSecretKey), iv)
	if err != nil {
		return "", errors.Wrap(errors.CodeInvalidToken, err, "failed to decrypt remember me cookie")
	}

	// Unmarshal the JSON data
	var data map[string]interface{}
	if err := json.Unmarshal(decrypted, &data); err != nil {
		return "", errors.Wrap(errors.CodeInvalidToken, err, "failed to unmarshal remember me data")
	}

	// Get the user ID
	userID, ok := data["user_id"].(string)
	if !ok {
		return "", errors.New(errors.CodeInvalidToken, "invalid user ID in remember me cookie")
	}

	return userID, nil
}

// ClearRememberMeCookie clears the "remember me" cookie
func (h *CookieHandler) ClearRememberMeCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "frank_remember",
		Value:    "",
		Path:     "/",
		Domain:   h.config.Auth.CookieDomain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   h.config.Auth.CookieSecure,
		HttpOnly: h.config.Auth.CookieHTTPOnly,
		SameSite: parseCookieSameSite(h.config.Auth.CookieSameSite),
	})
}

// SetCSRFCookie sets a CSRF token cookie
func (h *CookieHandler) SetCSRFCookie(w http.ResponseWriter, token string, expiry time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    token,
		Path:     "/",
		Domain:   h.config.Auth.CookieDomain,
		Expires:  time.Now().Add(expiry),
		MaxAge:   int(expiry.Seconds()),
		Secure:   h.config.Auth.CookieSecure,
		HttpOnly: false, // CSRF token needs to be readable by JavaScript
		SameSite: parseCookieSameSite(h.config.Auth.CookieSameSite),
	})
}

// GetCSRFCookie gets the CSRF token from a cookie
func (h *CookieHandler) GetCSRFCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie("csrf_token")
	if err != nil {
		if err == http.ErrNoCookie {
			return "", errors.New(errors.CodeInvalidInput, "CSRF token cookie not found")
		}
		return "", errors.Wrap(errors.CodeInvalidInput, err, "failed to read CSRF token cookie")
	}

	return cookie.Value, nil
}

// ClearCSRFCookie clears the CSRF token cookie
func (h *CookieHandler) ClearCSRFCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Path:     "/",
		Domain:   h.config.Auth.CookieDomain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   h.config.Auth.CookieSecure,
		HttpOnly: false,
		SameSite: parseCookieSameSite(h.config.Auth.CookieSameSite),
	})
}

// todo: Please keep this code for reference.
// // SetSecureSessionCookie with simpler GCM encryption
// func (h *CookieHandler) SetSecureSessionCookie(r *http.Request, w http.ResponseWriter, data *CookieSessionData, expiry time.Duration) error {
// 	h.logger.Debug("Setting secure session cookie",
// 		logging.String("user_id", data.UserID),
// 		logging.Duration("expiry", expiry))
//
// 	// Marshal the data to JSON
// 	jsonData, err := json.Marshal(data)
// 	if err != nil {
// 		h.logger.Error("Failed to marshal cookie data", logging.Error(err))
// 		return errors.Wrap(errors.CodeInternalServer, err, "failed to marshal cookie session data")
// 	}
//
// 	// Use EncryptWithRandomIV from your crypto package - this is simpler and more robust
// 	// It creates a random IV, prepends it to the ciphertext, and uses AES-GCM
// 	encrypted, err := crypto.EncryptWithRandomIV(jsonData, []byte(h.config.Auth.SessionSecretKey))
// 	if err != nil {
// 		h.logger.Error("Failed to encrypt data", logging.Error(err))
// 		return errors.Wrap(errors.CodeCryptoError, err, "failed to encrypt session data")
// 	}
//
// 	// Use URL-safe base64 encoding
// 	cookieValue := base64.URLEncoding.EncodeToString(encrypted)
//
// 	// Domain handling
// 	domain := h.config.Auth.CookieDomain
// 	if domain == "" && r != nil {
// 		host := r.Host
// 		if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
// 			host = host[:colonIndex]
// 		}
//
// 		// For localhost, leave domain empty
// 		if host == "localhost" {
// 			domain = ""
// 		} else {
// 			domain = host
// 		}
// 	}
//
// 	fmt.Println("Setting session cookie secure CH => ", h.config.Auth.CookieSecure)
//
// 	// Create cookie with consistent settings
// 	cookie := &http.Cookie{
// 		Name:     h.getSessionCookieName(),
// 		Value:    cookieValue,
// 		Path:     "/",
// 		Domain:   domain,
// 		Expires:  time.Now().Add(expiry),
// 		MaxAge:   int(expiry.Seconds()),
// 		Secure:   h.config.Auth.CookieSecure,
// 		HttpOnly: h.config.Auth.CookieHTTPOnly,
// 		SameSite: http.SameSiteLaxMode, // Use Lax for frontend compatibility
// 	}
//
// 	h.logger.Debug("Setting cookie",
// 		logging.String("name", cookie.Name),
// 		logging.String("domain", cookie.Domain),
// 		logging.String("path", cookie.Path),
// 		logging.Int("max_age", cookie.MaxAge))
//
// 	http.SetCookie(w, cookie)
// 	return nil
// }
//
// // GetSecureSessionCookie with simpler GCM decryption
// func (h *CookieHandler) GetSecureSessionCookie(r *http.Request) (*CookieSessionData, error) {
// 	h.logger.Debug("Attempting to extract session cookie")
//
// 	// Get the cookie
// 	cookie, err := r.Cookie(h.getSessionCookieName())
// 	if err != nil {
// 		h.logger.Debug("Cookie not found", logging.Error(err))
// 		return nil, errors.New(errors.CodeSessionExpired, "session cookie not found")
// 	}
//
// 	h.logger.Debug("Found cookie",
// 		logging.String("cookie_value_prefix", cookie.Value[:10]+"..."),
// 		logging.String("domain", cookie.Domain),
// 		logging.String("path", cookie.Path),
// 		logging.Int("max_age", cookie.MaxAge))
//
// 	// Log the cookie value for debugging
// 	h.logger.Debug("cookie value: ", logging.String("cookie_value", cookie.Value))
//
// 	// First, check if this is a JWT token (for Swagger UI compatibility)
// 	if strings.HasPrefix(cookie.Value, "eyJ") {
// 		jwtConfig := &crypto.JWTConfig{
// 			SigningMethod: h.config.Auth.TokenSigningMethod,
// 			SignatureKey:  []byte(h.config.Auth.TokenSecretKey),
// 			ValidationKey: []byte(h.config.Auth.TokenSecretKey),
// 			Issuer:        h.config.Auth.TokenIssuer,
// 			Audience:      h.config.Auth.TokenAudience,
// 		}
//
// 		claims, err := jwtConfig.ValidateToken(cookie.Value)
// 		if err == nil {
// 			// Create session data from JWT
// 			sessionData := &CookieSessionData{
// 				Token:     cookie.Value,
// 				ExpiresAt: time.Now().Add(h.config.Auth.SessionDuration),
// 				IssuedAt:  time.Now(),
// 			}
//
// 			if userID, ok := claims["user_id"].(string); ok && userID != "" {
// 				sessionData.UserID = userID
// 			} else if userID, ok := claims["sub"].(string); ok && userID != "" {
// 				sessionData.UserID = userID
// 			}
//
// 			if orgID, ok := claims["organization_id"].(string); ok && orgID != "" {
// 				sessionData.OrganizationID = orgID
// 			}
//
// 			h.logger.Debug("Successfully extracted session data from JWT",
// 				logging.String("user_id", sessionData.UserID))
//
// 			return sessionData, nil
// 		}
// 	}
//
// 	// Handle URL-encoded cookie value
// 	cookieValue := cookie.Value
//
// 	// URL-unescape the cookie value if needed
// 	unescapedValue, err := url.QueryUnescape(cookieValue)
// 	if err == nil {
// 		cookieValue = unescapedValue
// 	}
//
// 	// Decode from base64
// 	encrypted, err := base64.URLEncoding.DecodeString(cookieValue)
// 	if err != nil {
// 		h.logger.Debug("Failed URLEncoding decode, trying StdEncoding", logging.Error(err))
// 		encrypted, err = base64.StdEncoding.DecodeString(cookieValue)
// 		if err != nil {
// 			h.logger.Debug("All base64 decode attempts failed", logging.Error(err))
// 			return nil, errors.Wrap(errors.CodeInvalidToken, err, "failed to decode session cookie value")
// 		}
// 	}
//
// 	// Use DecryptWithPrependedIV from your crypto package
// 	// This handles the IV properly and uses AES-GCM
// 	jsonData, err := crypto.DecryptWithPrependedIV(encrypted, []byte(h.config.Auth.SessionSecretKey))
// 	if err != nil {
// 		h.logger.Debug("Failed to decrypt data", logging.Error(err))
// 		return nil, errors.Wrap(errors.CodeInvalidToken, err, "failed to decrypt session cookie")
// 	}
//
// 	// Unmarshal the JSON data
// 	var data CookieSessionData
// 	if err = json.Unmarshal(jsonData, &data); err != nil {
// 		h.logger.Debug("Failed to unmarshal JSON", logging.Error(err))
// 		return nil, errors.Wrap(errors.CodeInvalidToken, err, "failed to unmarshal session data")
// 	}
//
// 	// Check if the session has expired
// 	if time.Now().After(data.ExpiresAt) {
// 		h.logger.Debug("Session has expired",
// 			logging.Time("expires_at", data.ExpiresAt),
// 			logging.Time("now", time.Now()))
// 		return nil, errors.New(errors.CodeSessionExpired, "session has expired")
// 	}
//
// 	h.logger.Debug("Successfully extracted session data",
// 		logging.String("user_id", data.UserID),
// 		logging.Time("expires_at", data.ExpiresAt))
//
// 	return &data, nil
// }
