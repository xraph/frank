package auth

import (
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/internal/apikeys"
	"github.com/juicycleff/frank/internal/auth/mfa"
	"github.com/juicycleff/frank/internal/auth/oauth2"
	"github.com/juicycleff/frank/internal/auth/passkeys"
	"github.com/juicycleff/frank/internal/auth/passwordless"
	"github.com/juicycleff/frank/internal/auth/session"
	"github.com/juicycleff/frank/internal/auth/sso"
	"github.com/juicycleff/frank/internal/email"
	"github.com/juicycleff/frank/internal/sms"
	"github.com/juicycleff/frank/internal/user"
	"github.com/juicycleff/frank/internal/webhook"
	"github.com/juicycleff/frank/pkg/logging"
)

// Registry provides access to all authentication services
type Registry struct {
	// Services
	UserService         user.Service
	SessionManager      *session.Manager
	PasskeyService      *passkeys.Service
	MFAService          *mfa.Service
	PasswordlessService *passwordless.Service
	OAuthServer         *oauth2.Server
	OAuthClient         *oauth2.Client
	OAuthProvider       *oauth2.Provider
	SSOService          *sso.Service
	APIKeyService       apikeys.Service
	WebhookService      webhook.Service

	// Repositories
	PasskeyRepository passkeys.Repository

	// Session Stores
	PasskeySessionStore passkeys.SessionStore

	// Dependencies
	Config *config.Config
	Client *ent.Client
	Logger logging.Logger
	Redis  *redis.Client
}

// NewRegistry creates a new auth registry
func NewRegistry(
	cfg *config.Config,
	client *ent.Client,
	logger logging.Logger,
	redis *redis.Client,
) (*Registry, error) {
	registry := &Registry{
		Config: cfg,
		Client: client,
		Logger: logger,
		Redis:  redis,
	}

	var err error

	// Initialize session manager
	cookieHandler := session.NewCookieHandler(cfg, logger)

	var sessionStore session.Store
	if cfg.Redis.Enabled {
		sessionStore = session.NewRedisStore(redis, "session", logger)
	} else {
		sessionStore = session.NewInMemoryStore(logger, 10*time.Minute)
	}

	registry.SessionManager = session.NewManager(client, cfg, logger, sessionStore)

	// Initialize user service
	registry.UserService = user.NewService(client, cfg, logger)

	// Initialize passkey repository and session store
	if cfg.Features.EnablePasskeys {
		// Initialize passkey repository
		registry.PasskeyRepository = passkeys.CreateRepository(
			passkeys.RepositoryTypeEnt,
			client,
			logger,
		)

		// Initialize passkey session store
		storeType := passkeys.SessionStoreTypeInMemory
		if cfg.Redis.Enabled && cfg.Passkeys.UseRedisSessionStore {
			storeType = passkeys.SessionStoreTypeRedis
		}
		registry.PasskeySessionStore = passkeys.CreateSessionStore(
			storeType,
			cfg,
			redis,
			logger,
		)

		// Initialize passkey service
		registry.PasskeyService, err = passkeys.NewService(
			cfg,
			client,
			logger,
			registry.PasskeySessionStore,
		)
		if err != nil {
			return nil, err
		}
	}

	// Initialize MFA service
	if cfg.Features.EnableMFA {
		registry.MFAService = mfa.NewService(client, cfg, logger)
	}

	// Initialize passwordless service
	if cfg.Features.EnablePasswordless {
		emailService := email.NewService(cfg, logger)
		smsService := sms.NewService(cfg, logger)
		registry.PasswordlessService, err = passwordless.NewService(
			cfg,
			client,
			logger,
			emailService,
			smsService,
		)
		if err != nil {
			return nil, err
		}
	}

	// Initialize OAuth components
	if cfg.Features.EnableOAuth2Provider {
		// Storage for OAuth server
		oauthStorage := oauth2.NewEntStorage(client, logger)

		// Initialize OAuth server
		registry.OAuthServer = oauth2.NewServer(client, cfg, logger, oauth2.WithStorage(oauthStorage))

		// Initialize OAuth client for consuming third-party OAuth services
		registry.OAuthClient = oauth2.NewClient(cfg, logger)
		err = registry.OAuthClient.InitializeDefaultProviders()
		if err != nil {
			logger.Warn("Failed to initialize some OAuth providers", logging.Error(err))
		}

		// Initialize OAuth provider for providing OAuth services
		registry.OAuthProvider = oauth2.NewProvider(client, cfg, logger)
	}

	// Initialize SSO service
	if cfg.Features.EnableSSO {
		registry.SSOService = sso.NewService(client, cfg, logger)
	}

	// Initialize API key service
	if cfg.Features.EnableAPIKeys {
		apiKeyRepo := apikeys.NewEntRepository(client, logger)
		apiKeyValidator := apikeys.NewValidator(logger)
		registry.APIKeyService = apikeys.NewService(apiKeyRepo, apiKeyValidator, cfg)
	}

	// Initialize webhook service
	if cfg.Features.EnableWebhooks {
		webhookRepo := webhook.NewEntRepository(client, logger)
		registry.WebhookService = webhook.NewService(webhookRepo, cfg, logger)
	}

	return registry, nil
}
