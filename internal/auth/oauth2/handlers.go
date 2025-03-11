package oauth2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"
	"go.uber.org/zap"
)

// Handlers provides HTTP handlers for the OAuth2 functionality
type Handlers struct {
	server *Server
	config *config.Config
	db     *ent.Client
	logger logging.Logger
}

// NewHandlers creates a new OAuth2 handlers
func NewHandlers(server *Server, cfg *config.Config, db *ent.Client, logger logging.Logger) *Handlers {
	return &Handlers{
		server: server,
		config: cfg,
		db:     db,
		logger: logger,
	}
}

// HandleAuthorize handles the OAuth2 authorization endpoint
func (h *Handlers) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	// Only GET method is supported for authorization endpoint
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate the authorization request
	authReq, err := h.server.ValidateAuthorizationRequest(r)
	if err != nil {
		h.logger.Error("Invalid authorization request", zap.Error(err))
		http.Error(w, fmt.Sprintf("Invalid request: %s", err.Error()), http.StatusBadRequest)
		return
	}

	// Store the authorization request in the session for later use
	// This assumes you have a session mechanism in place
	session, err := utils.GetSession(r, h.config)
	if err != nil {
		h.logger.Error("Failed to get session", zap.Error(err))
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Store the auth request in the session
	session.Values["oauth_auth_request"] = authReq
	if err := session.Save(r, w); err != nil {
		h.logger.Error("Failed to save session", zap.Error(err))
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Check if user is already authenticated
	userID, ok := session.Values["user_id"].(string)
	if !ok || userID == "" {
		// User is not authenticated, redirect to login
		loginURL := fmt.Sprintf("/login?redirect=%s", url.QueryEscape(r.URL.String()))
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// User is authenticated, check if consent is required
	if authReq.Client.RequiresConsent {
		// Redirect to consent page
		consentURL := fmt.Sprintf("/oauth/consent?client_id=%s&redirect_uri=%s&state=%s",
			url.QueryEscape(authReq.ClientID),
			url.QueryEscape(authReq.RedirectURI),
			url.QueryEscape(authReq.State))
		http.Redirect(w, r, consentURL, http.StatusFound)
		return
	}

	// No consent required, proceed with authorization
	h.completeAuthorization(w, r, authReq, userID, "")
}

// HandleConsent handles the OAuth2 consent endpoint
func (h *Handlers) HandleConsent(w http.ResponseWriter, r *http.Request) {
	// GET shows the consent form, POST processes the form submission
	if r.Method == http.MethodGet {
		// Get client details
		clientID := r.URL.Query().Get("client_id")
		if clientID == "" {
			http.Error(w, "Missing client_id parameter", http.StatusBadRequest)
			return
		}

		client, err := h.server.storage.GetClient(r.Context(), clientID)
		if err != nil {
			h.logger.Error("Failed to get client", zap.Error(err), zap.String("client_id", clientID))
			http.Error(w, "Invalid client", http.StatusBadRequest)
			return
		}

		// Get session
		session, err := utils.GetSession(r, h.config)
		if err != nil {
			h.logger.Error("Failed to get session", zap.Error(err))
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}

		// Check if user is authenticated
		userID, ok := session.Values["user_id"].(string)
		if !ok || userID == "" {
			// User is not authenticated, redirect to login
			loginURL := fmt.Sprintf("/login?redirect=%s", url.QueryEscape(r.URL.String()))
			http.Redirect(w, r, loginURL, http.StatusFound)
			return
		}

		// Render consent page
		// This is just an example, you would typically use a template engine
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `
			<html>
			<head><title>Authorize %s</title></head>
			<body>
				<h1>Authorize %s</h1>
				<p>%s is requesting access to your account.</p>
				<form method="post" action="/oauth/consent">
					<input type="hidden" name="client_id" value="%s">
					<input type="hidden" name="redirect_uri" value="%s">
					<input type="hidden" name="state" value="%s">
					<button type="submit" name="action" value="approve">Approve</button>
					<button type="submit" name="action" value="deny">Deny</button>
				</form>
			</body>
			</html>
		`, client.Name, client.Name, client.Description,
			clientID,
			r.URL.Query().Get("redirect_uri"),
			r.URL.Query().Get("state"))
		return
	}

	if r.Method == http.MethodPost {
		// Process consent form
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Error parsing form", http.StatusBadRequest)
			return
		}

		// Get form values
		clientID := r.FormValue("client_id")
		redirectURI := r.FormValue("redirect_uri")
		state := r.FormValue("state")
		action := r.FormValue("action")

		// Check if user approved or denied
		if action != "approve" {
			// User denied, redirect with error
			redirectURL := fmt.Sprintf("%s?error=access_denied&state=%s",
				redirectURI, url.QueryEscape(state))
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}

		// Get session and authorization request
		session, err := utils.GetSession(r, h.config)
		if err != nil {
			h.logger.Error("Failed to get session", zap.Error(err))
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}

		// Get the authorization request from session
		authReq, ok := session.Values["oauth_auth_request"].(*AuthorizationRequest)
		if !ok {
			http.Error(w, "Invalid authorization session", http.StatusBadRequest)
			return
		}

		// Validate the client and redirect URI match
		if authReq.ClientID != clientID || authReq.RedirectURI != redirectURI {
			http.Error(w, "Client/redirect mismatch", http.StatusBadRequest)
			return
		}

		// Get user ID from session
		userID, ok := session.Values["user_id"].(string)
		if !ok || userID == "" {
			http.Error(w, "User not authenticated", http.StatusUnauthorized)
			return
		}

		// Complete the authorization
		h.completeAuthorization(w, r, authReq, userID, "")
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// completeAuthorization generates an authorization code and redirects the user
func (h *Handlers) completeAuthorization(w http.ResponseWriter, r *http.Request, authReq *AuthorizationRequest, userID string, organizationID string) {
	// Generate the authorization code
	code, err := h.server.CreateAuthorizationCode(r.Context(), authReq, userID, organizationID)
	if err != nil {
		h.logger.Error("Failed to create authorization code", zap.Error(err))
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Build the redirect URL
	redirectURL := fmt.Sprintf("%s?code=%s", authReq.RedirectURI, url.QueryEscape(code))

	// Add state if provided
	if authReq.State != "" {
		redirectURL = fmt.Sprintf("%s&state=%s", redirectURL, url.QueryEscape(authReq.State))
	}

	// Redirect the user
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// HandleToken handles the OAuth2 token endpoint
func (h *Handlers) HandleToken(w http.ResponseWriter, r *http.Request) {
	// Only POST method is allowed for token endpoint
	if r.Method != http.MethodPost {
		h.respondWithError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the form
	if err := r.ParseForm(); err != nil {
		h.respondWithError(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	// Get grant type
	grantType := r.FormValue("grant_type")
	if grantType == "" {
		h.respondWithError(w, "Missing grant_type parameter", http.StatusBadRequest)
		return
	}

	// Get client credentials from Authorization header or form params
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		// Try form parameters
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	// Client ID is required for all grant types
	if clientID == "" {
		h.respondWithError(w, "Missing client_id", http.StatusBadRequest)
		return
	}

	// Handle different grant types
	var tokenResponse *TokenResponse
	var err error

	switch grantType {
	case "authorization_code":
		// Get required parameters
		code := r.FormValue("code")
		redirectURI := r.FormValue("redirect_uri")
		codeVerifier := r.FormValue("code_verifier")

		if code == "" || redirectURI == "" {
			h.respondWithError(w, "Missing required parameters for authorization_code grant", http.StatusBadRequest)
			return
		}

		// Exchange authorization code for tokens
		tokenResponse, err = h.server.ExchangeAuthorizationCode(r.Context(), code, clientID, clientSecret, redirectURI, codeVerifier)
		if err != nil {
			h.logger.Error("Authorization code exchange failed",
				zap.Error(err),
				zap.String("client_id", clientID),
			)
			h.respondWithError(w, fmt.Sprintf("Invalid authorization code: %s", err.Error()), http.StatusBadRequest)
			return
		}

	case "refresh_token":
		// Get the refresh token
		refreshToken := r.FormValue("refresh_token")
		if refreshToken == "" {
			h.respondWithError(w, "Missing refresh_token parameter", http.StatusBadRequest)
			return
		}

		// Refresh the access token
		tokenResponse, err = h.server.RefreshAccessToken(r.Context(), refreshToken, clientID, clientSecret)
		if err != nil {
			h.logger.Error("Refresh token exchange failed", zap.Error(err), zap.String("client_id", clientID))
			h.respondWithError(w, fmt.Sprintf("Invalid refresh token: %s", err.Error()), http.StatusBadRequest)
			return
		}

	case "client_credentials":
		// Parse scopes
		scope := r.FormValue("scope")
		var scopes []string
		if scope != "" {
			scopes = strings.Split(scope, " ")
		}

		// Handle client credentials grant
		tokenResponse, err = h.server.HandleClientCredentials(r.Context(), clientID, clientSecret, scopes)
		if err != nil {
			h.logger.Error("Client credentials grant failed", zap.Error(err), zap.String("client_id", clientID))
			h.respondWithError(w, fmt.Sprintf("Invalid client credentials: %s", err.Error()), http.StatusBadRequest)
			return
		}

	default:
		h.respondWithError(w, fmt.Sprintf("Unsupported grant_type: %s", grantType), http.StatusBadRequest)
		return
	}

	// Respond with token
	h.respondWithJSON(w, tokenResponse, http.StatusOK)
}

// HandleRevoke handles the OAuth2 token revocation endpoint
func (h *Handlers) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	// Only POST method is allowed for revocation endpoint
	if r.Method != http.MethodPost {
		h.respondWithError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the form
	if err := r.ParseForm(); err != nil {
		h.respondWithError(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	// Get token and token type hint
	token := r.FormValue("token")
	tokenTypeHint := r.FormValue("token_type_hint") // Optional

	if token == "" {
		h.respondWithError(w, "Missing token parameter", http.StatusBadRequest)
		return
	}

	// Get client credentials
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		// Try form parameters
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	// Client ID is required
	if clientID == "" {
		h.respondWithError(w, "Missing client_id", http.StatusBadRequest)
		return
	}

	// Revoke the token
	err := h.server.RevokeToken(r.Context(), token, tokenTypeHint, clientID, clientSecret)
	if err != nil {
		// RFC 7009 states that the authorization server responds with HTTP status
		// code 200 even in case of an error where the client is not authenticated.
		h.logger.Error("Token revocation failed", zap.Error(err), zap.String("client_id", clientID))
	}

	// Always return 200 OK response with an empty body per RFC 7009
	w.WriteHeader(http.StatusOK)
}

// HandleIntrospect handles the OAuth2 token introspection endpoint
func (h *Handlers) HandleIntrospect(w http.ResponseWriter, r *http.Request) {
	// Only POST method is allowed for introspection endpoint
	if r.Method != http.MethodPost {
		h.respondWithError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the form
	if err := r.ParseForm(); err != nil {
		h.respondWithError(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	// Get token and token type hint
	token := r.FormValue("token")
	tokenTypeHint := r.FormValue("token_type_hint") // Optional

	if token == "" {
		h.respondWithError(w, "Missing token parameter", http.StatusBadRequest)
		return
	}

	// Get client credentials
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		// Try form parameters
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	// Client ID is required
	if clientID == "" {
		h.respondWithError(w, "Missing client_id", http.StatusBadRequest)
		return
	}

	// Validate client credentials
	client, err := h.server.storage.GetClient(r.Context(), clientID)
	if err != nil {
		h.respondWithError(w, "Invalid client", http.StatusUnauthorized)
		return
	}

	// For confidential clients, validate client secret
	if !client.Public && client.ClientSecret != clientSecret {
		h.respondWithError(w, "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	// Default to access token if no hint provided
	if tokenTypeHint == "" {
		tokenTypeHint = "access_token"
	}

	var tokenInfo *TokenInfo
	var activeToken bool

	// Try to introspect based on token type hint
	if tokenTypeHint == "access_token" {
		// Validate access token
		tokenInfo, err = h.server.ValidateAccessToken(r.Context(), token)
		if err == nil {
			activeToken = true
		}
	} else if tokenTypeHint == "refresh_token" {
		// Validate refresh token
		tokenInfo, err = h.server.storage.GetRefreshToken(r.Context(), token)
		if err == nil && !tokenInfo.Revoked && time.Now().Before(tokenInfo.ExpiresAt) {
			activeToken = true
		}
	} else {
		// Try both types
		tokenInfo, err = h.server.ValidateAccessToken(r.Context(), token)
		if err == nil {
			activeToken = true
		} else {
			// Try as refresh token
			tokenInfo, err = h.server.storage.GetRefreshToken(r.Context(), token)
			if err == nil && !tokenInfo.Revoked && time.Now().Before(tokenInfo.ExpiresAt) {
				activeToken = true
			}
		}
	}

	// Prepare introspection response per RFC 7662
	introspectionResponse := map[string]interface{}{
		"active": activeToken,
	}

	// If token is active, include additional info
	if activeToken && tokenInfo != nil {
		// Get current Unix timestamp
		_ = time.Now().Unix()

		// Add token info
		introspectionResponse["client_id"] = tokenInfo.ClientID
		introspectionResponse["exp"] = tokenInfo.ExpiresAt.Unix()
		introspectionResponse["iat"] = tokenInfo.CreatedAt.Unix()
		introspectionResponse["scope"] = strings.Join(tokenInfo.Scopes, " ")
		introspectionResponse["token_type"] = tokenInfo.TokenType

		// Add user info if available
		if tokenInfo.UserID != "" {
			introspectionResponse["sub"] = tokenInfo.UserID
		}

		// Add organization info if available
		if tokenInfo.OrganizationID != "" {
			introspectionResponse["organization_id"] = tokenInfo.OrganizationID
		}
	}

	// Respond with introspection result
	h.respondWithJSON(w, introspectionResponse, http.StatusOK)
}

// respondWithJSON writes a JSON response
func (h *Handlers) respondWithJSON(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

// respondWithError writes an error response in OAuth2 format
func (h *Handlers) respondWithError(w http.ResponseWriter, message string, statusCode int) {
	// Format in accordance with OAuth2 error responses (RFC 6749)
	errorResponse := map[string]string{
		"error":             "invalid_request",
		"error_description": message,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(errorResponse)
}

// RegisterRoutes registers all the OAuth2 routes
func (h *Handlers) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/oauth2/authorize", h.HandleAuthorize)
	mux.HandleFunc("/oauth2/token", h.HandleToken)
	mux.HandleFunc("/oauth2/revoke", h.HandleRevoke)
	mux.HandleFunc("/oauth2/introspect", h.HandleIntrospect)
	mux.HandleFunc("/oauth/consent", h.HandleConsent)
}
