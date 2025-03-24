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

// SetSecureSessionCookie sets a secure, encrypted session cookie
func (h *CookieHandler) SetSecureSessionCookie(r *http.Request, w http.ResponseWriter, data *CookieSessionData, expiry time.Duration) error {
	// Marshal the data to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return errors.Wrap(errors.CodeInternalServer, err, "failed to marshal cookie session data")
	}

	// Generate a random IV
	iv, err := crypto.GenerateEncryptionAESKey(h.config.Auth.SessionSecretKey)
	if err != nil {
		return errors.Wrap(errors.CodeCryptoError, err, "failed to generate IV")
	}

	// Encrypt the data
	encrypted, err := crypto.EncryptAES(jsonData, h.config.Auth.SessionSecretKey, iv)
	if err != nil {
		return errors.Wrap(errors.CodeCryptoError, err, "failed to encrypt session data")
	}

	// Combine IV and ciphertext
	combined := encrypted

	// Encode to base64
	cookieValue := base64.URLEncoding.EncodeToString(combined)

	domain := h.config.Auth.CookieDomain
	if domain == "" && r != nil {
		// Extract host from request
		host := r.Host
		// Remove port if present
		if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
			host = host[:colonIndex]
		}
		domain = host
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     h.getSessionCookieName(),
		Value:    cookieValue,
		Path:     "/",
		Domain:   domain,
		Expires:  time.Now().Add(expiry),
		MaxAge:   int(expiry.Seconds()),
		Secure:   h.config.Auth.CookieSecure,
		HttpOnly: h.config.Auth.CookieHTTPOnly,
		SameSite: parseCookieSameSite(h.config.Auth.CookieSameSite),
	})

	return nil
}

// GetSecureSessionCookie gets and decrypts a secure session cookie
func (h *CookieHandler) GetSecureSessionCookie(r *http.Request) (*CookieSessionData, error) {
	// Get the cookie
	cookie, err := r.Cookie(h.getSessionCookieName())
	if err != nil {
		if err == http.ErrNoCookie {
			return nil, errors.New(errors.CodeSessionExpired, "session cookie not found")
		}
		return nil, errors.Wrap(errors.CodeInvalidToken, err, "failed to read session cookie")
	}

	// Decode from base64
	combined, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, errors.Wrap(errors.CodeInvalidToken, err, "failed to decode session cookie value")
	}

	// Extract IV and ciphertext
	if len(combined) < 16 {
		return nil, errors.New(errors.CodeInvalidToken, "invalid session cookie data")
	}

	// iv := combined[:16]
	// encrypted := combined[16:]
	encrypted := combined

	// Decrypt the data
	decrypted, err := crypto.DecryptAES(encrypted, h.config.Auth.SessionSecretKey, nil)
	if err != nil {
		return nil, errors.Wrap(errors.CodeInvalidToken, err, "failed to decrypt session cookie")
	}

	// Unmarshal the JSON data
	var data CookieSessionData
	if err = json.Unmarshal(decrypted, &data); err != nil {
		return nil, errors.Wrap(errors.CodeInvalidToken, err, "failed to unmarshal session data")
	}

	// Check if the session has expired
	if time.Now().After(data.ExpiresAt) {
		return nil, errors.New(errors.CodeSessionExpired, "session has expired")
	}

	return &data, nil
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
