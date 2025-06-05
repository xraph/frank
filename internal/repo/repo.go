package repo

import (
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/apikeys"
	"github.com/juicycleff/frank/internal/auth/passkeys"
	"github.com/juicycleff/frank/internal/auth/session"
	"github.com/juicycleff/frank/internal/rbac"
	"github.com/juicycleff/frank/internal/webhook"
	"github.com/juicycleff/frank/pkg/data"
	"github.com/juicycleff/frank/pkg/email"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/organization"
	"github.com/juicycleff/frank/pkg/user"
)

// Repo contains all the service dependencies
type Repo struct {
	APIKey       apikeys.Repository
	Organization organization.Repository
	User         user.Repository
	Webhook      webhook.Repository
	Template     email.TemplateRepository
	Passkeys     passkeys.Repository
	WebhookEvent webhook.EventRepository
	RBAC         rbac.Repository
	Session      session.Store
}

func New(cfg *config.Config, client *data.Clients, logger logging.Logger) *Repo {
	apiKeyRepo := apikeys.NewRepository(client.DB)
	orgRepo := organization.NewRepository(client.DB)
	userRepo := user.NewRepository(client.DB)
	webhookRepo := webhook.NewRepository(client.DB)
	webhookEventRepo := webhook.NewEventRepository(client.DB)
	sessStore := session.NewRedisStore(client.Redis, "frank_", logger)
	templateRepo := email.NewTemplateRepository(client.DB)
	rbacRepo := rbac.NewRepository(client.DB)
	// templateRepo := passkeys.New(client)

	// Determine repository type from config
	repoPassKeyType := passkeys.RepositoryTypeEnt
	if cfg.Passkeys.UseInMemoryRepository {
		repoPassKeyType = passkeys.RepositoryTypeInMemory
	}

	// Create repo container
	repos := &Repo{
		APIKey:       apiKeyRepo,
		Organization: orgRepo,
		User:         userRepo,
		Webhook:      webhookRepo,
		Session:      sessStore,
		Template:     templateRepo,
		WebhookEvent: webhookEventRepo,
		RBAC:         rbacRepo,
	}

	repos.Passkeys = passkeys.CreateRepository(repoPassKeyType, client.DB, logger)

	return repos
}
