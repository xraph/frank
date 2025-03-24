package session

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// CookieStore implements a session store that uses HTTP cookies
type CookieStore struct {
	cookieName     string
	cookieDomain   string
	cookieSecure   bool
	cookieHTTPOnly bool
	cookieSameSite string
	secretKey      string
	logger         logging.Logger
}

// NewCookieStore creates a new cookie-based session store
func NewCookieStore(
	cookieName string,
	cookieDomain string,
	cookieSecure bool,
	cookieHTTPOnly bool,
	cookieSameSite string,
	secretKey string,
	logger logging.Logger,
) *CookieStore {
	return &CookieStore{
		cookieName:     cookieName,
		cookieDomain:   cookieDomain,
		cookieSecure:   cookieSecure,
		cookieHTTPOnly: cookieHTTPOnly,
		cookieSameSite: cookieSameSite,
		secretKey:      secretKey,
		logger:         logger,
	}
}

// StoreSession stores a session in a cookie
func (s *CookieStore) StoreSession(ctx context.Context, token string, session *SessionInfo, expiry time.Duration) (string, error) {
	// This is a no-op for the cookie store
	// The actual storage happens in the HTTP handler when the response is sent
	return "", nil
}

// GetSession retrieves a session from the cookie
func (s *CookieStore) GetSession(ctx context.Context, token string) (*SessionInfo, error) {
	// This should never be called directly
	// The session is extracted from the cookie in the HTTP handler
	return nil, errors.New(errors.CodeUnsupportedOperation, "direct session retrieval not supported by cookie store")
}

// UpdateSession updates a session in the cookie
func (s *CookieStore) UpdateSession(ctx context.Context, token string, session *SessionInfo) error {
	// This is a no-op for the cookie store
	// The actual update happens in the HTTP handler when the response is sent
	return nil
}

// DeleteSession deletes a session from the cookie
func (s *CookieStore) DeleteSession(ctx context.Context, token string) error {
	// This is a no-op for the cookie store
	// The actual deletion happens in the HTTP handler when the response is sent
	return nil
}

// SetSessionCookie sets a session cookie in the HTTP response
func (s *CookieStore) SetSessionCookie(w http.ResponseWriter, token string, expiry time.Duration) {
	// Create a cookie with the session token
	cookie := &http.Cookie{
		Name:     s.cookieName,
		Value:    token,
		Path:     "/",
		Domain:   s.cookieDomain,
		Expires:  time.Now().Add(expiry),
		MaxAge:   int(expiry.Seconds()),
		Secure:   s.cookieSecure,
		HttpOnly: s.cookieHTTPOnly,
		SameSite: parseSameSite(s.cookieSameSite),
	}

	http.SetCookie(w, cookie)
}

// GetSessionFromCookie gets a session token from an HTTP request cookie
func (s *CookieStore) GetSessionFromCookie(r *http.Request) (string, error) {
	// Get the cookie
	cookie, err := r.Cookie(s.cookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			return "", errors.New(errors.CodeSessionExpired, "session cookie not found")
		}
		return "", errors.Wrap(errors.CodeInvalidToken, err, "failed to read session cookie")
	}

	return cookie.Value, nil
}

// DeleteSessionCookie deletes a session cookie
func (s *CookieStore) DeleteSessionCookie(w http.ResponseWriter) {
	// Set a cookie with an expiration in the past to delete it
	cookie := &http.Cookie{
		Name:     s.cookieName,
		Value:    "",
		Path:     "/",
		Domain:   s.cookieDomain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   s.cookieSecure,
		HttpOnly: s.cookieHTTPOnly,
		SameSite: parseSameSite(s.cookieSameSite),
	}

	http.SetCookie(w, cookie)
}

// parseSameSite converts a string to http.SameSite
func parseSameSite(sameSite string) http.SameSite {
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
