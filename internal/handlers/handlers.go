package handlers

import (
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/services"
	"github.com/juicycleff/frank/pkg/data"
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
		RBAC:         NewRBACHandler(svcs.RBAC, cfg, logger),
		Passwordless: NewPasswordlessHandler(svcs.Passwordless, svcs.User, cfg, logger),
		Swagger:      NewSwaggerHandler(cfg),
		Email:        NewEmailHandler(svcs.Email, cfg, logger),
		Health:       NewHealthChecker(clients, cfg),
		WebUI:        NewWebUIHandler(logger),
	}
}
