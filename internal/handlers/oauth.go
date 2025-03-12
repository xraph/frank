package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/internal/auth/oauth2"
	"github.com/juicycleff/frank/internal/user"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"
)

// OAuthHandler handles OAuth2 operations
type OAuthHandler struct {
	oauthServer   *oauth2.Server
	oauthClient   *oauth2.Client
	oauthProvider *oauth2.Provider
	oauthHandlers *oauth2.Handlers
	userService   user.Service
	config        *config.Config
	logger        logging.Logger
}

// NewOAuthHandler creates a new OAuth handler
func NewOAuthHandler(
	oauthServer *oauth2.Server,
	oauthClient *oauth2.Client,
	oauthProvider *oauth2.Provider,
	userService user.Service,
	db *ent.Client,
	cfg *config.Config,
	logger logging.Logger,
) *OAuthHandler {

	oauthHandlers := oauth2.NewHandlers(oauthServer, cfg, db, logger)
	return &OAuthHandler{
		oauthServer:   oauthServer,
		oauthClient:   oauthClient,
		oauthProvider: oauthProvider,
		userService:   userService,
		oauthHandlers: oauthHandlers,
		config:        cfg,
		logger:        logger,
	}
}

// OAuthAuthorize handles the OAuth2 authorization endpoint
func (h *OAuthHandler) OAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	// This can be used as both provider and client
	if r.URL.Path == "/oauth/authorize" {
		// Acting as provider - handle authorization requests from third-party clients
		h.handleProviderAuthorize(w, r)
	} else {
		// Acting as client - handle redirects to third-party providers
		h.handleClientAuthorize(w, r)
	}
}

// handleProviderAuthorize handles OAuth2 authorization requests when acting as a provider
func (h *OAuthHandler) handleProviderAuthorize(w http.ResponseWriter, r *http.Request) {
	// Only GET and POST methods are allowed
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Let the OAuth server handle the authorization endpoint
	h.oauthHandlers.HandleAuthorize(w, r)
}

// handleClientAuthorize handles OAuth2 authorization when acting as a client
func (h *OAuthHandler) handleClientAuthorize(w http.ResponseWriter, r *http.Request) {
	// Get provider from query parameter
	provider := r.URL.Query().Get("provider")
	if provider == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "provider parameter is required"))
		return
	}

	// Check if we have this provider configured
	loginURL, err := h.oauthClient.GetLoginURL(provider, "", nil)
	if err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodeProviderNotFound, err, "provider not found or not configured"))
		return
	}

	fmt.Println(loginURL)

	// Generate state parameter for CSRF protection
	state, err := utils.GenerateStateToken()
	if err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodeCryptoError, err, "failed to generate state token"))
		return
	}

	// Get redirect URI from query parameter or use default
	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		redirectURI = h.config.Server.BaseURL + "/oauth/callback/" + provider
	}

	// Store state and redirect URI in session
	session, err := utils.GetSession(r, h.config)
	if err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodeInternalServer, err, "failed to get session"))
		return
	}

	session.Values["oauth_state"] = state
	session.Values["oauth_provider"] = provider
	session.Values["oauth_redirect_uri"] = redirectURI
	if err := session.Save(r, w); err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodeInternalServer, err, "failed to save session"))
		return
	}

	// Generate login URL with state
	loginURLWithState, err := h.oauthClient.GetLoginURL(provider, state, nil)
	if err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodeInternalServer, err, "failed to generate login URL"))
		return
	}

	// Redirect user to login URL
	http.Redirect(w, r, loginURLWithState, http.StatusFound)
}

// OAuthProvidersList lists available OAuth providers
func (h *OAuthHandler) OAuthProvidersList(w http.ResponseWriter, r *http.Request) {
	// This should return a list of configured providers
	// For now, return a hardcoded list
	providers := []map[string]interface{}{
		{"id": "google", "name": "Google", "type": "oauth2"},
		{"id": "github", "name": "GitHub", "type": "oauth2"},
		// Add more providers as needed
	}

	utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"providers": providers,
	})
}

// OAuthProviderAuth initiates OAuth authentication with a provider
func (h *OAuthHandler) OAuthProviderAuth(w http.ResponseWriter, r *http.Request) {
	// Get provider from path
	provider := utils.GetPathVar(r, "provider")
	if provider == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "provider is required"))
		return
	}

	// Generate state parameter for CSRF protection
	state, err := utils.GenerateStateToken()
	if err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodeCryptoError, err, "failed to generate state token"))
		return
	}

	// Get redirect URI from query parameter or use default
	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		redirectURI = h.config.Server.BaseURL + "/oauth/callback/" + provider
	}

	// Store state and redirect URI in session
	session, err := utils.GetSession(r, h.config)
	if err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodeInternalServer, err, "failed to get session"))
		return
	}

	session.Values["oauth_state"] = state
	session.Values["oauth_provider"] = provider
	session.Values["oauth_redirect_uri"] = redirectURI
	if err := session.Save(r, w); err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodeInternalServer, err, "failed to save session"))
		return
	}

	// Generate login URL with state
	loginURL, err := h.oauthClient.GetLoginURL(provider, state, nil)
	if err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodeInternalServer, err, "failed to generate login URL"))
		return
	}

	// Redirect user to login URL
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// OAuthProviderCallback handles OAuth callback from a provider
func (h *OAuthHandler) OAuthProviderCallback(w http.ResponseWriter, r *http.Request) {
	// Get provider from path
	provider := utils.GetPathVar(r, "provider")
	if provider == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "provider is required"))
		return
	}

	// Get code from query parameter
	code := r.URL.Query().Get("code")
	if code == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "authorization code is required"))
		return
	}

	// Get state from query parameter
	state := r.URL.Query().Get("state")
	if state == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "state parameter is required"))
		return
	}

	// Verify state matches stored state
	session, err := utils.GetSession(r, h.config)
	if err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodeInternalServer, err, "failed to get session"))
		return
	}

	storedState, ok := session.Values["oauth_state"].(string)
	if !ok || storedState != state {
		utils.RespondError(w, errors.New(errors.CodeInvalidOAuthState, "invalid state parameter"))
		return
	}

	storedProvider, ok := session.Values["oauth_provider"].(string)
	if !ok || storedProvider != provider {
		utils.RespondError(w, errors.New(errors.CodeInvalidOAuthState, "provider mismatch"))
		return
	}

	// Exchange code for access token
	token, err := h.oauthClient.Exchange(r.Context(), provider, code)
	if err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodeOAuthFailed, err, "failed to exchange code for token"))
		return
	}

	// Get user info from provider
	userInfo, err := h.oauthClient.GetUserInfo(r.Context(), provider, token)
	if err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodeOAuthFailed, err, "failed to get user info"))
		return
	}

	// Map provider user data to our internal format
	userData, err := h.oauthClient.MapUserData(provider, userInfo)
	if err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodeOAuthFailed, err, "failed to map user data"))
		return
	}

	// Check if user exists by email
	email, _ := userData["email"].(string)
	if email == "" {
		utils.RespondError(w, errors.New(errors.CodeMissingRequiredField, "email is required from OAuth provider"))
		return
	}

	var userEntity *ent.User
	userEntity, err = h.userService.GetByEmail(r.Context(), email)
	if err != nil {
		if !errors.IsNotFound(err) {
			utils.RespondError(w, errors.Wrap(errors.CodeDatabaseError, err, "failed to check for existing user"))
			return
		}

		// User doesn't exist, create a new user
		firstName, _ := userData["first_name"].(string)
		lastName, _ := userData["last_name"].(string)
		profileImageURL, _ := userData["profile_image_url"].(string)

		// Create metadata with provider information
		metadata := map[string]interface{}{
			"oauth_provider": provider,
			"oauth_id":       userData["id"],
		}

		// Create user
		createInput := user.CreateUserInput{
			Email:           email,
			FirstName:       firstName,
			LastName:        lastName,
			ProfileImageURL: profileImageURL,
			Metadata:        metadata,
		}

		userEntity, err = h.userService.Create(r.Context(), createInput)
		if err != nil {
			utils.RespondError(w, errors.Wrap(errors.CodeDatabaseError, err, "failed to create user"))
			return
		}
	}

	// Create a session for the user
	session.Values["user_id"] = userEntity.ID
	session.Values["authenticated"] = true
	if err := session.Save(r, w); err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodeInternalServer, err, "failed to save session"))
		return
	}

	// Clear OAuth-specific values
	delete(session.Values, "oauth_state")
	delete(session.Values, "oauth_provider")

	// Redirect to the redirect URI if specified
	redirectURI, ok := session.Values["oauth_redirect_uri"].(string)
	delete(session.Values, "oauth_redirect_uri")

	if ok && redirectURI != "" {
		// Save session before redirect
		if err := session.Save(r, w); err != nil {
			utils.RespondError(w, errors.Wrap(errors.CodeInternalServer, err, "failed to save session"))
			return
		}

		http.Redirect(w, r, redirectURI, http.StatusFound)
		return
	}

	// If no redirect URI specified, return success
	utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"message": "OAuth authentication successful",
		"user":    userEntity,
	})
}

// OAuthToken handles the OAuth2 token endpoint
func (h *OAuthHandler) OAuthToken(w http.ResponseWriter, r *http.Request) {
	// Only POST method is allowed
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Acting as a provider
	h.oauthHandlers.HandleToken(w, r)
}

// OAuthIntrospect handles the OAuth2 token introspection endpoint
func (h *OAuthHandler) OAuthIntrospect(w http.ResponseWriter, r *http.Request) {
	// Only POST method is allowed
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Acting as a provider
	h.oauthHandlers.HandleIntrospect(w, r)
}

// OAuthRevoke handles the OAuth2 token revocation endpoint
func (h *OAuthHandler) OAuthRevoke(w http.ResponseWriter, r *http.Request) {
	// Only POST method is allowed
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Acting as a provider
	h.oauthHandlers.HandleRevoke(w, r)
}

// HandleConsent handles the OAuth2 token revocation endpoint
func (h *OAuthHandler) HandleConsent(w http.ResponseWriter, r *http.Request) {
	// Only POST method is allowed
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Acting as a provider
	h.oauthHandlers.HandleConsent(w, r)
}

// OAuthUserInfo handles the OAuth2 userinfo endpoint
func (h *OAuthHandler) OAuthUserInfo(w http.ResponseWriter, r *http.Request) {
	// Extract token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		utils.RespondError(w, errors.New(errors.CodeUnauthorized, "missing authorization header"))
		return
	}

	// Check if it's a Bearer token
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		utils.RespondError(w, errors.New(errors.CodeUnauthorized, "invalid authorization header format"))
		return
	}

	token := parts[1]

	// Validate token and get claims
	claims, err := h.oauthServer.ValidateAccessToken(r.Context(), token)
	if err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodeInvalidToken, err, "invalid access token"))
		return
	}

	// Get user ID from token
	userID := claims.Subject
	if userID == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidToken, "token missing user ID"))
		return
	}

	// Get user from database
	userEntity, err := h.userService.Get(r.Context(), userID)
	if err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodeDatabaseError, err, "failed to get user"))
		return
	}

	// Create userinfo response
	userinfo := map[string]interface{}{
		"sub":            userEntity.ID,
		"email":          userEntity.Email,
		"email_verified": userEntity.EmailVerified,
		"name":           fmt.Sprintf("%s %s", userEntity.FirstName, userEntity.LastName),
		"given_name":     userEntity.FirstName,
		"family_name":    userEntity.LastName,
		"locale":         userEntity.Locale,
	}

	if userEntity.ProfileImageURL != "" {
		userinfo["picture"] = userEntity.ProfileImageURL
	}

	utils.RespondJSON(w, http.StatusOK, userinfo)
}

// OAuthConfiguration handles the OpenID Connect configuration endpoint
func (h *OAuthHandler) OAuthConfiguration(w http.ResponseWriter, r *http.Request) {
	baseURL := h.config.Server.BaseURL

	// Create OpenID Connect configuration
	config := map[string]interface{}{
		"issuer":                 baseURL,
		"authorization_endpoint": baseURL + "/oauth/authorize",
		"token_endpoint":         baseURL + "/oauth/token",
		"userinfo_endpoint":      baseURL + "/oauth/userinfo",
		"jwks_uri":               baseURL + "/.well-known/jwks.json",
		"response_types_supported": []string{
			"code",
			"token",
			"id_token",
			"code token",
			"code id_token",
			"token id_token",
			"code token id_token",
		},
		"subject_types_supported": []string{
			"public",
		},
		"id_token_signing_alg_values_supported": []string{
			"RS256",
		},
		"scopes_supported": []string{
			"openid",
			"email",
			"profile",
		},
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
		},
		"claims_supported": []string{
			"sub",
			"iss",
			"auth_time",
			"name",
			"given_name",
			"family_name",
			"email",
			"email_verified",
		},
	}

	utils.RespondJSON(w, http.StatusOK, config)
}

// OAuthJWKS handles the JWKS endpoint for OpenID Connect
func (h *OAuthHandler) OAuthJWKS(w http.ResponseWriter, r *http.Request) {
	// For now, return a minimal JWKS
	// In production, this would return the actual JWKs used for token signing
	jwks := map[string]interface{}{
		"keys": []interface{}{},
	}

	utils.RespondJSON(w, http.StatusOK, jwks)
}

// SetupRoutes sets up the OAuth routes
func (h *OAuthHandler) SetupRoutes(router chi.Router) {
	// Provider endpoints
	router.HandleFunc("/oauth/authorize", h.OAuthAuthorize)
	router.HandleFunc("/oauth/token", h.OAuthToken)
	router.HandleFunc("/oauth/introspect", h.OAuthIntrospect)
	router.HandleFunc("/oauth/revoke", h.OAuthRevoke)
	router.HandleFunc("/oauth/userinfo", h.OAuthUserInfo)
	router.HandleFunc("/.well-known/openid-configuration", h.OAuthConfiguration)
	router.HandleFunc("/.well-known/jwks.json", h.OAuthJWKS)

	// Client endpoints
	router.HandleFunc("/api/v1/auth/oauth/providers", h.OAuthProvidersList)
	router.HandleFunc("/api/v1/auth/oauth/providers/{provider}", h.OAuthProviderAuth)
	router.HandleFunc("/api/v1/auth/oauth/callback/{provider}", h.OAuthProviderCallback)
}

// OAuthAuthorize handles the OAuth2 authorization endpoint
func OAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).OAuth.OAuthAuthorize(w, r)
}

// OAuthToken handles the OAuth2 token endpoint
func OAuthToken(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).OAuth.OAuthToken(w, r)
}

// OAuthIntrospect handles the OAuth2 introspection endpoint
func OAuthIntrospect(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).OAuth.OAuthIntrospect(w, r)
}

// OAuthRevoke handles the OAuth2 revocation endpoint
func OAuthRevoke(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).OAuth.OAuthRevoke(w, r)
}

// OAuthUserInfo handles the OAuth2 userinfo endpoint
func OAuthUserInfo(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).OAuth.OAuthUserInfo(w, r)
}

// OAuthConfiguration handles the OpenID Connect configuration endpoint
func OAuthConfiguration(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).OAuth.OAuthConfiguration(w, r)
}

// OAuthJWKS handles the JWKS endpoint for OpenID Connect
func OAuthJWKS(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).OAuth.OAuthJWKS(w, r)
}

// OAuthProvidersList handles listing OAuth providers
func OAuthProvidersList(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).OAuth.OAuthProvidersList(w, r)
}

// OAuthProviderAuth handles OAuth provider authentication
func OAuthProviderAuth(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).OAuth.OAuthProviderAuth(w, r)
}

// OAuthProviderCallback handles OAuth provider callback
func OAuthProviderCallback(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).OAuth.OAuthProviderCallback(w, r)
}

// OAuthConsent handles OAuth provider callback
func OAuthConsent(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).OAuth.HandleConsent(w, r)
}
