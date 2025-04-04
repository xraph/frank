package repo

import (
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/internal/apikeys"
	"github.com/juicycleff/frank/internal/auth/passkeys"
	"github.com/juicycleff/frank/internal/auth/session"
	"github.com/juicycleff/frank/internal/email"
	"github.com/juicycleff/frank/internal/rbac"
	"github.com/juicycleff/frank/internal/webhook"
	"github.com/juicycleff/frank/organization"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/user"
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

func New(cfg *config.Config, client *ent.Client, logger logging.Logger) *Repo {
	apiKeyRepo := apikeys.NewRepository(client)
	orgRepo := organization.NewRepository(client)
	userRepo := user.NewRepository(client)
	webhookRepo := webhook.NewRepository(client)
	webhookEventRepo := webhook.NewEventRepository(client)
	sessStore := session.NewInMemoryStore(logger, time.Hour*24)
	templateRepo := email.NewTemplateRepository(client)
	rbacRepo := rbac.NewRepository(client)
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

	repos.Passkeys = passkeys.CreateRepository(repoPassKeyType, client, logger)

	return repos
}
