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
			err := s.manager.RevokeSession(r.Context(), token)
			if err != nil {
				return err
			}
		}

		s.cookieHandler.ClearSessionCookie(w)

		// // Delete the cookie
		// http.SetCookie(w, &http.Cookie{
		// 	Name:     sess.Name(),
		// 	Path:     sess.Options.Path,
		// 	Domain:   sess.Options.Domain,
		// 	MaxAge:   -1,
		// 	Secure:   sess.Options.Secure,
		// 	HttpOnly: sess.Options.HttpOnly,
		// 	SameSite: sess.Options.SameSite,
		// })

		return nil
	}

	cookieData := &CookieSessionData{}

	// For existing sessions
	if !sess.IsNew {
		// Update the session if needed
		if token, ok := sess.Values["token"].(string); ok && token != "" {
			// You might want to update the session in the store
			// For example, extending the expiration time
			expiry := time.Duration(sess.Options.MaxAge) * time.Second
			_ = s.manager.ExtendSession(r.Context(), token, expiry)

			// // Set the cookie with the existing token
			// http.SetCookie(w, &http.Cookie{
			// 	Name:     sess.Name(),
			// 	Value:    token,
			// 	Path:     sess.Options.Path,
			// 	Domain:   sess.Options.Domain,
			// 	MaxAge:   sess.Options.MaxAge,
			// 	Secure:   sess.Options.Secure,
			// 	HttpOnly: sess.Options.HttpOnly,
			// 	SameSite: sess.Options.SameSite,
			// })

			if v, ok := sess.Values["metadata"].(map[string]interface{}); ok {
				cookieData.Metadata = v
			}

			if v, ok := sess.Values["organization_id"].(string); ok {
				cookieData.OrganizationID = v
			}

			if v, ok := sess.Values["user_id"].(string); ok {
				cookieData.UserID = v
			}

			cookieData.Token = token
			cookieData.ExpiresAt = time.Now().Add(expiry)
			err := s.cookieHandler.SetSecureSessionCookie(r, w, cookieData, expiry)
			if err != nil {
				return err
			}

			return nil
		}
	}

	// For new sessions or sessions without a token
	userID, _ := sess.Values["user_id"].(string)
	if userID == "" {
		// Can't create session without a user ID
		return nil
	}

	// Create a new session in the Manager
	// Prepare metadata from session values
	metadata := make(map[string]interface{})
	for k, v := range sess.Values {
		if k != "user_id" && k != "organization_id" && k != "token" {
			metadata[k.(string)] = v
		}
	}

	// Create session options
	options := []Option{WithMetadata(metadata)}

	// Add organization ID if present
	if orgID, ok := sess.Values["organization_id"].(string); ok && orgID != "" {
		options = append(options, WithOrganizationID(orgID))
	}

	expiry := time.Duration(sess.Options.MaxAge) * time.Second
	// Set expiration
	options = append(options, WithExpiration(expiry))

	// Create the session
	sessionInfo, err := s.manager.CreateSession(r.Context(), userID, options...)
	if err != nil {
		return err
	}

	// Store the token in session values
	sess.Values["token"] = sessionInfo.Token

	// Set the cookie
	// http.SetCookie(w, &http.Cookie{
	// 	Name:     sess.Name(),
	// 	Value:    sessionInfo.Token,
	// 	Path:     sess.Options.Path,
	// 	Domain:   sess.Options.Domain,
	// 	MaxAge:   sess.Options.MaxAge,
	// 	Secure:   sess.Options.Secure,
	// 	HttpOnly: sess.Options.HttpOnly,
	// 	SameSite: sess.Options.SameSite,
	// })

	if v, ok := sess.Values["metadata"].(map[string]interface{}); ok {
		cookieData.Metadata = v
	}

	if v, ok := sess.Values["organization_id"].(string); ok {
		cookieData.OrganizationID = v
	}

	if v, ok := sess.Values["user_id"].(string); ok {
		cookieData.UserID = v
	}

	cookieData.Token = sessionInfo.Token
	cookieData.ExpiresAt = time.Now().Add(expiry)
	err = s.cookieHandler.SetSecureSessionCookie(r, w, cookieData, expiry)
	if err != nil {
		return err
	}

	return nil
}
