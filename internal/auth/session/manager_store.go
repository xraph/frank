package session

import (
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"github.com/juicycleff/frank/config"
)

type ManagerStore struct {
	manager       *Manager
	cookieHandler *CookieHandler
	cookieOptions *sessions.Options
}

func NewManagerStore(
	manager *Manager,
	cookieHandler *CookieHandler,
	cfg *config.Config,
) sessions.Store {
	return &ManagerStore{
		manager:       manager,
		cookieHandler: cookieHandler,
		cookieOptions: &sessions.Options{
			Path:     "/",
			Domain:   cfg.Auth.CookieDomain,
			MaxAge:   int(cfg.Auth.SessionDuration.Seconds()),
			Secure:   cfg.Auth.CookieSecure,
			HttpOnly: cfg.Auth.CookieHTTPOnly,
			SameSite: parseSameSite(cfg.Auth.CookieSameSite),
		},
	}
}

func (s *ManagerStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	// Create a new session
	session := sessions.NewSession(s, name)
	session.Options = s.cookieOptions
	session.IsNew = true

	// Get the session token from cookie
	cookieSessionData, err := s.cookieHandler.GetSecureSessionCookie(r)
	if err != nil {
		// No existing session
		return session, nil
	}

	// Token is in the cookie value
	token := cookieSessionData.Token

	// Retrieve session from Manager
	ctx := r.Context()

	sessionInfo, err := s.manager.GetSession(ctx, token)
	if err != nil {
		// Session not found or expired - return new session
		return session, nil
	}

	// Session exists - load values
	session.IsNew = false
	session.Values["user_id"] = sessionInfo.UserID
	session.Values["token"] = token
	if sessionInfo.OrganizationID != "" {
		session.Values["organization_id"] = sessionInfo.OrganizationID
	}

	// Add any other metadata from the session
	if sessionInfo.Metadata != nil {
		for k, v := range sessionInfo.Metadata {
			session.Values[k] = v
		}
	}

	return session, nil
}

func (s *ManagerStore) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(s, name)
	session.Options = s.cookieOptions
	session.IsNew = true
	return session, nil
}

func (s *ManagerStore) Save(r *http.Request, w http.ResponseWriter, sess *sessions.Session) error {
	// If the session is being deleted
	if sess.Options.MaxAge < 0 {
		// If there's a token in the session, revoke it
		if token, ok := sess.Values["token"].(string); ok && token != "" {
			_ = s.manager.RevokeSession(r.Context(), token)
		}

		// Clear the cookie
		s.cookieHandler.ClearSessionCookie(w)
		return nil
	}

	expiry := time.Duration(sess.Options.MaxAge) * time.Second
	if expiry <= 0 {
		expiry = s.manager.config.Auth.SessionDuration
	}

	// Prepare cookie data
	cookieData := &CookieSessionData{
		ExpiresAt: time.Now().Add(expiry),
		IssuedAt:  time.Now(),
	}

	// Extract important values
	if userID, ok := sess.Values["user_id"].(string); ok && userID != "" {
		cookieData.UserID = userID
	}

	if token, ok := sess.Values["token"].(string); ok && token != "" {
		cookieData.Token = token
	}

	if orgID, ok := sess.Values["organization_id"].(string); ok && orgID != "" {
		cookieData.OrganizationID = orgID
	}

	// Add metadata
	metadata := make(map[string]interface{})
	for k, v := range sess.Values {
		if k != "user_id" && k != "organization_id" && k != "token" {
			metadata[k.(string)] = v
		}
	}

	if len(metadata) > 0 {
		cookieData.Metadata = metadata
	}

	// For existing sessions
	if !sess.IsNew && cookieData.Token != "" {
		// Update session expiry in the store
		_ = s.manager.ExtendSession(r.Context(), cookieData.Token, expiry)
	} else if cookieData.UserID != "" {
		// Create a new session
		options := []Option{
			WithExpiration(expiry),
		}

		if cookieData.OrganizationID != "" {
			options = append(options, WithOrganizationID(cookieData.OrganizationID))
		}

		if len(metadata) > 0 {
			options = append(options, WithMetadata(metadata))
		}

		// Create a new session token
		sessionInfo, err := s.manager.CreateSession(r.Context(), cookieData.UserID, options...)
		if err != nil {
			return err
		}

		// Update token in cookie data and session
		cookieData.Token = sessionInfo.Token
		sess.Values["token"] = sessionInfo.Token
	}

	// If we have a valid token, set the cookie
	if cookieData.Token != "" && cookieData.UserID != "" {
		err := s.cookieHandler.SetSecureSessionCookie(r, w, cookieData, expiry)
		if err != nil {
			return err
		}
	}

	return nil
}
