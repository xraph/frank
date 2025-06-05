package routesgoa

import (
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/services"
	"github.com/juicycleff/frank/pkg/data"
	"github.com/juicycleff/frank/pkg/logging"
)

// Factory creates and manages all route handlers
type Factory struct {
	Auth         *AuthRoutes
	User         *UserRoutes
	Organization *OrganizationRoutes
	APIKey       *APIKeyRoutes
	Webhook      *WebhookRoutes
	MFA          *MFARoutes
	Passwordless *PasswordlessRoutes
	Passkey      *PasskeyRoutes
	SSO          *SSORoutes
	OAuth        *OAuthRoutes
	RBAC         *RBACRoutes
	Email        *EmailRoutes
	Health       *HealthRoutes
}

// NewFactory creates a new route handler factory
func NewFactory(
	svcs *services.Services,
	clients *data.Clients,
	cfg *config.Config,
	logger logging.Logger,
) *Factory {
	return &Factory{
		Auth:         NewAuthRoutes(svcs.User, svcs.Session, cfg, logger),
		User:         NewUserRoutes(svcs.User, cfg, logger),
		Organization: NewOrganizationRoutes(svcs.Organization, cfg, logger),
		APIKey:       NewAPIKeyRoutes(svcs.APIKey, cfg, logger),
		Webhook:      NewWebhookRoutes(svcs.Webhook, cfg, logger),
		MFA:          NewMFARoutes(svcs.MFA, svcs.User, cfg, logger),
		Passwordless: NewPasswordlessRoutes(svcs.Passwordless, svcs.User, cfg, logger),
		Passkey:      NewPasskeyRoutes(svcs.PassKey, cfg, logger),
		SSO:          NewSSORoutes(svcs.SSO, cfg, logger),
		OAuth:        NewOAuthRoutes(svcs.OAuth, clients, svcs.User, cfg, logger),
		RBAC:         NewRBACRoutes(svcs.RBAC, cfg, logger),
		Email:        NewEmailRoutes(svcs.Email, cfg, logger),
		Health:       NewHealthRoutes(clients, cfg, logger),
	}
}
