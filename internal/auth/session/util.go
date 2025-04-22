package session

import (
	"net/http"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/pkg/crypto"
	"github.com/juicycleff/frank/pkg/logging"
)

// SessionStore is a shared session store for the application
var sessionStore sessions.Store

// InitSessionStore initializes the session store with the provided secret
func InitSessionStore(cfg *config.Config) {
	// Use the session secret key from config
	sessionStore = sessions.NewCookieStore([]byte(cfg.Auth.SessionSecretKey))
}

// GetSessionHelper retrieves the current session or creates a new one
func GetSessionHelper(
	r *http.Request,
	cfg *config.Config,
	cookieHandler *CookieHandler,
	sessionStore sessions.Store,
	logger logging.Logger,
) (*sessions.Session, error) {

	// Log detailed request info
	if logger != nil {
		// Log request details
		logger.Debug("Processing request",
			logging.String("method", r.Method),
			logging.String("url", r.URL.String()),
			logging.String("user_agent", r.UserAgent()),
			logging.String("referer", r.Referer()),
			logging.String("host", r.Host),
		)

		// Log cookie details
		if cookie, err := r.Cookie("frank_session"); err == nil {
			logger.Debug("Session cookie found",
				logging.String("value_preview", cookie.Value[:10]+"..."),
				logging.String("domain", cookie.Domain),
				logging.Int("max_age", cookie.MaxAge),
				logging.String("path", cookie.Path),
			)
		} else {
			logger.Debug("No session cookie found")
		}
	}

	// Use a consistent session name
	const sessionName = "frank_session"

	// Create a session to return in case we need a new one
	newSession, _ := sessionStore.New(r, sessionName)

	// First check for session cookie
	cookie, err := r.Cookie(sessionName)
	if err == nil && cookie.Value != "" {
		// We have a cookie, now try different authentication methods

		// 1. Try to decrypt secure cookie
		cookieSessionData, err := cookieHandler.GetSecureSessionCookie(r)
		if err == nil && cookieSessionData != nil {
			// Copy values to the session
			newSession.Values["user_id"] = cookieSessionData.UserID
			newSession.Values["token"] = cookieSessionData.Token
			newSession.IsNew = false

			if cookieSessionData.OrganizationID != "" {
				newSession.Values["organization_id"] = cookieSessionData.OrganizationID
			}

			if cookieSessionData.Metadata != nil {
				for k, v := range cookieSessionData.Metadata {
					newSession.Values[k] = v
				}
			}

			return newSession, nil
		}

		// 2. Try JWT format directly in cookie
		if strings.HasPrefix(cookie.Value, "eyJ") {
			jwtConfig := &crypto.JWTConfig{
				SigningMethod: cfg.Auth.TokenSigningMethod,
				SignatureKey:  []byte(cfg.Auth.TokenSecretKey),
				ValidationKey: []byte(cfg.Auth.TokenSecretKey),
				Issuer:        cfg.Auth.TokenIssuer,
				Audience:      cfg.Auth.TokenAudience,
			}

			claims, err := jwtConfig.ValidateToken(cookie.Value)
			if err == nil {
				if userID, ok := claims["user_id"].(string); ok && userID != "" {
					newSession.Values["user_id"] = userID
				} else if userID, ok := claims["sub"].(string); ok && userID != "" {
					newSession.Values["user_id"] = userID
				}

				if orgID, ok := claims["organization_id"].(string); ok && orgID != "" {
					newSession.Values["organization_id"] = orgID
				}

				newSession.Values["token"] = cookie.Value
				newSession.IsNew = false

				return newSession, nil
			}
		}

		// 3. Try standard session store
		storedSession, err := sessionStore.Get(r, sessionName)
		if err == nil && storedSession.Values["user_id"] != nil {
			return storedSession, nil
		}
	}

	// If cookie approaches failed, check Authorization header (for Swagger/API clients)
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")

		jwtConfig := &crypto.JWTConfig{
			SigningMethod: cfg.Auth.TokenSigningMethod,
			SignatureKey:  []byte(cfg.Auth.TokenSecretKey),
			ValidationKey: []byte(cfg.Auth.TokenSecretKey),
			Issuer:        cfg.Auth.TokenIssuer,
			Audience:      cfg.Auth.TokenAudience,
		}

		claims, err := jwtConfig.ValidateToken(token)
		if err == nil {
			if userID, ok := claims["user_id"].(string); ok && userID != "" {
				newSession.Values["user_id"] = userID
			} else if userID, ok := claims["sub"].(string); ok && userID != "" {
				newSession.Values["user_id"] = userID
			}

			if orgID, ok := claims["organization_id"].(string); ok && orgID != "" {
				newSession.Values["organization_id"] = orgID
			}

			newSession.Values["token"] = token
			newSession.IsNew = false

			return newSession, nil
		}
	}

	// No valid auth found, return empty session
	return newSession, nil
}

// InitSessionStoreWithStore initializes the session store with the provided secret
func InitSessionStoreWithStore(store sessions.Store) {
	// Use the session secret key from config
	sessionStore = store
}
