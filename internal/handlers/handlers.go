package handlers

import (
	"net/http"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/data"
	"github.com/juicycleff/frank/internal/services"
	"github.com/juicycleff/frank/pkg/logging"
)

func New(
	svcs *services.Services,
	clients *data.Clients,
	cfg *config.Config,
	logger logging.Logger,
) *Handlers {
	return &Handlers{
		Auth:         NewAuthHandler(svcs.User, cfg, logger, svcs.Session),
		User:         NewUserHandler(svcs.User, cfg, logger),
		Organization: NewOrganizationHandler(svcs.Organization, cfg, logger),
		OAuth: NewOAuthHandler(
			svcs.OAuth.Server,
			svcs.OAuth.Client,
			svcs.OAuth.Provider,
			svcs.User,
			clients.DB,
			cfg,
			logger,
		),
		Webhook:      NewWebhookHandler(svcs.Webhook, cfg, logger),
		APIKey:       NewAPIKeyHandler(svcs.APIKey, cfg, logger),
		MFA:          NewMFAHandler(svcs.MFA, svcs.User, cfg, logger),
		Passkey:      NewPasskeyHandler(svcs.PassKey, cfg, logger),
		SSO:          NewSSOHandler(svcs.SSO, cfg, logger),
		Passwordless: NewPasswordlessHandler(svcs.Passwordless, svcs.User, cfg, logger),
	}
}

// RegisterRoutes sets up all routes
func (h *Handlers) RegisterRoutes(router *http.ServeMux) {
	h.Auth.SetupRoutes(router)
	h.User.SetupRoutes(router)
	h.Organization.SetupRoutes(router)
	h.OAuth.SetupRoutes(router)
	h.Passwordless.SetupRoutes(router)
	h.MFA.SetupRoutes(router)
	h.Passkey.SetupRoutes(router)
	h.SSO.SetupRoutes(router)
	h.Webhook.SetupRoutes(router)
	h.APIKey.SetupRoutes(router)
	// h.SMS.SetupRoutes(router) // Setup SMS routes
}
