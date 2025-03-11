package handlers

import (
	"net/http"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/auth/sso"
	"github.com/juicycleff/frank/internal/middleware"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"
)

// SSOHandler handles Single Sign-On operations
type SSOHandler struct {
	ssoService *sso.Service
	config     *config.Config
	logger     logging.Logger
}

// NewSSOHandler creates a new SSO handler
func NewSSOHandler(
	ssoService *sso.Service,
	config *config.Config,
	logger logging.Logger,
) *SSOHandler {
	return &SSOHandler{
		ssoService: ssoService,
		config:     config,
		logger:     logger,
	}
}

// SSOInitiateRequest represents the input for initiating SSO
type SSOInitiateRequest struct {
	ProviderID  string                 `json:"provider_id" validate:"required"`
	RedirectURI string                 `json:"redirect_uri,omitempty"`
	Options     map[string]interface{} `json:"options,omitempty"`
}

// SSOCompleteRequest represents the input for completing SSO
type SSOCompleteRequest struct {
	ProviderID string `json:"provider_id" validate:"required"`
	State      string `json:"state" validate:"required"`
	Code       string `json:"code" validate:"required"`
}

// SSOProvidersList handles listing SSO providers
func (h *SSOHandler) SSOProvidersList(w http.ResponseWriter, r *http.Request) {
	// Get organization ID if available
	orgID, _ := middleware.GetOrganizationID(r)

	// Get providers
	providers, err := h.ssoService.GetProviders(r.Context(), orgID)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Return providers
	utils.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"providers": providers,
	})
}

// SSOProviderAuth handles initiating SSO with a provider
func (h *SSOHandler) SSOProviderAuth(w http.ResponseWriter, r *http.Request) {
	// Get provider ID from path
	providerID := utils.GetPathVar(r, "provider")
	if providerID == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "provider ID is required"))
		return
	}

	// Get redirect URI from query parameter
	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		redirectURI = h.config.Server.BaseURL + "/api/v1/auth/sso/callback/" + providerID
	}

	// Create options
	options := map[string]interface{}{}

	// Store state in session
	state, err := utils.GenerateStateToken()
	if err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodeCryptoError, err, "failed to generate state token"))
		return
	}

	// Store state and other data in session
	session, err := utils.GetSession(r, h.config)
	if err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodeInternalServer, err, "failed to get session"))
		return
	}

	session.Values["sso_state"] = state
	session.Values["sso_provider"] = providerID
	session.Values["sso_redirect_uri"] = redirectURI
	if err := session.Save(r, w); err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodeInternalServer, err, "failed to save session"))
		return
	}

	// Initiate SSO
	authURL, err := h.ssoService.InitiateSSO(r.Context(), providerID, redirectURI, options)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Redirect to authorization URL
	http.Redirect(w, r, authURL, http.StatusFound)
}

// SSOProviderCallback handles SSO callback from a provider
func (h *SSOHandler) SSOProviderCallback(w http.ResponseWriter, r *http.Request) {
	// Get provider ID from path
	providerID := utils.GetPathVar(r, "provider")
	if providerID == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "provider ID is required"))
		return
	}

	// Get code and state from query parameters
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		utils.RespondError(w, errors.New(errors.CodeInvalidInput, "code and state parameters are required"))
		return
	}

	// Verify state
	session, err := utils.GetSession(r, h.config)
	if err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodeInternalServer, err, "failed to get session"))
		return
	}

	storedState, ok := session.Values["sso_state"].(string)
	if !ok || storedState != state {
		utils.RespondError(w, errors.New(errors.CodeInvalidOAuthState, "invalid state parameter"))
		return
	}

	storedProvider, ok := session.Values["sso_provider"].(string)
	if !ok || storedProvider != providerID {
		utils.RespondError(w, errors.New(errors.CodeSSOMismatch, "provider mismatch"))
		return
	}

	// Complete SSO
	userInfo, err := h.ssoService.CompleteSSO(r.Context(), state, code)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Find or create user
	user, err := h.ssoService.FindOrCreateUser(r.Context(), userInfo)
	if err != nil {
		utils.RespondError(w, err)
		return
	}

	// Update session
	session.Values["user_id"] = user.ID
	session.Values["authenticated"] = true

	// Add organization ID if available
	if userInfo.OrganizationID != "" {
		session.Values["organization_id"] = userInfo.OrganizationID
	}

	// Save session
	if err := session.Save(r, w); err != nil {
		utils.RespondError(w, errors.Wrap(errors.CodeInternalServer, err, "failed to save session"))
		return
	}

	// Clear SSO-specific values
	delete(session.Values, "sso_state")
	delete(session.Values, "sso_provider")

	// Redirect to the redirect URI if specified
	redirectURI, ok := session.Values["sso_redirect_uri"].(string)
	delete(session.Values, "sso_redirect_uri")

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
		"message": "SSO authentication successful",
		"user":    user,
	})
}

// SetupRoutes sets up the SSO routes
func (h *SSOHandler) SetupRoutes(router *http.ServeMux) {
	router.HandleFunc("/api/v1/auth/sso/providers", h.SSOProvidersList)
	router.HandleFunc("/api/v1/auth/sso/providers/{provider}", h.SSOProviderAuth)
	router.HandleFunc("/api/v1/auth/sso/callback/{provider}", h.SSOProviderCallback)
}

// Static handler functions for direct router registration

// SSOProvidersList handles listing SSO providers API endpoint
func SSOProvidersList(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).SSO.SSOProvidersList(w, r)
}

// SSOProviderAuth handles SSO provider authentication API endpoint
func SSOProviderAuth(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).SSO.SSOProviderAuth(w, r)
}

// SSOProviderCallback handles SSO provider callback API endpoint
func SSOProviderCallback(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).SSO.SSOProviderCallback(w, r)
}
