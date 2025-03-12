package services

import (
	"fmt"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/apikeys"
	"github.com/juicycleff/frank/internal/auth/mfa"
	"github.com/juicycleff/frank/internal/auth/oauth2"
	"github.com/juicycleff/frank/internal/auth/passkeys"
	"github.com/juicycleff/frank/internal/auth/passwordless"
	"github.com/juicycleff/frank/internal/auth/session"
	"github.com/juicycleff/frank/internal/auth/sso"
	"github.com/juicycleff/frank/internal/email"
	"github.com/juicycleff/frank/internal/organization"
	"github.com/juicycleff/frank/internal/rbac"
	"github.com/juicycleff/frank/internal/repo"
	"github.com/juicycleff/frank/internal/sms"
	"github.com/juicycleff/frank/internal/user"
	"github.com/juicycleff/frank/internal/webhook"
	"github.com/juicycleff/frank/pkg/data"
	"github.com/juicycleff/frank/pkg/logging"
)

// Services contains all the service dependencies
type Services struct {
	APIKey              apikeys.Service
	Organization        organization.Service
	User                user.Service
	Webhook             webhook.Service
	Email               email.Service
	SMS                 sms.Service
	Session             *session.Manager
	MFA                 mfa.Service
	Passwordless        passwordless.Service
	OAuth               *OAuthServices
	SSO                 sso.Service
	RBAC                rbac.Service
	CookieHandler       *session.CookieHandler
	PassKey             passkeys.Service
	PasskeySessionStore passkeys.SessionStore
}

// OAuthServices contains OAuth2 related services
type OAuthServices struct {
	Server   *oauth2.Server
	Client   *oauth2.Client
	Provider *oauth2.Provider
}

func New(repos *repo.Repo, cfg *config.Config, client *data.Clients, logger logging.Logger) (*Services, error) {
	// Initialize services
	orgService := organization.NewService(repos.Organization, logger)
	pwdVerifyManger := user.NewVerificationManager(client.DB)
	pwdManger := user.NewPasswordManager(cfg, client.DB, pwdVerifyManger)

	enforce := rbac.NewEnforcer(repos.RBAC, logger)
	rbacService := rbac.NewService(repos.RBAC, enforce, logger)
	userService := user.NewService(repos.User, pwdManger, pwdVerifyManger, orgService, logger)

	// Initialize auth services
	cookieHandler := session.NewCookieHandler(cfg, logger)
	cookieStore := session.NewCookieStore(
		"frank_session",
		cfg.Auth.CookieDomain,
		cfg.Auth.CookieSecure,
		cfg.Auth.CookieHTTPOnly,
		cfg.Auth.CookieSameSite,
		cfg.Auth.SessionSecretKey,
		logger,
	)
	sessionManager := session.NewManager(client.DB, cfg, logger, cookieStore)

	sender := email.SenderFactory(cfg, logger)
	emailTemplateManager := email.NewTemplateManager(cfg, logger)
	emailService := email.NewService(cfg, sender, emailTemplateManager, repos.Template, logger)

	emailProvider := sms.SenderFactory(cfg, logger)
	smsService := sms.NewService(cfg, emailProvider, logger)

	// Create services container
	services := &Services{
		Organization:  orgService,
		User:          userService,
		Session:       sessionManager,
		CookieHandler: cookieHandler,
		Email:         emailService,
		SMS:           smsService,
		RBAC:          rbacService,
	}

	if cfg.Features.EnableMFA {
		logger.Info("Initializing MFA")
		mfaService := mfa.NewService(client.DB, cfg, logger)
		services.MFA = mfaService
	}

	if cfg.Features.EnablePasswordless {
		logger.Info("Initializing passwordless")
		passwordlessService, err := passwordless.NewService(cfg, client.DB, logger, emailService, smsService)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize passwordless service: %w", err)
		}
		services.Passwordless = passwordlessService
	}

	if cfg.Features.EnableAPIKeys {
		logger.Info("Initializing MFA")
		mfaService := mfa.NewService(client.DB, cfg, logger)
		services.MFA = mfaService
	}

	if cfg.Features.EnableWebhooks {
		logger.Info("Initializing Webhooks")
		webhookDeliverer := webhook.NewDeliverer(repos.WebhookEvent, repos.Webhook, cfg, logger)
		webhookService := webhook.NewService(repos.Webhook, repos.WebhookEvent, webhookDeliverer, cfg, logger)
		services.Webhook = webhookService
	}

	if cfg.Features.EnableAPIKeys {
		apiKeysValidator := apikeys.NewValidator(logger)
		apiKeyService := apikeys.NewService(repos.APIKey, apiKeysValidator, cfg)
		services.APIKey = apiKeyService
	}

	if cfg.Features.EnableSSO {
		logger.Info("Initializing SSO")
		// Initialize SSO service
		statsStore := sso.NewEntStateStore(client.DB, logger)
		ssoService := sso.New(client.DB, statsStore, cfg, logger)
		services.SSO = ssoService
	}

	if cfg.Features.EnableOAuth2 {
		logger.Info("Initializing OAuth2")
		// Initialize OAuth services
		oauthStorage := oauth2.NewEntStorage(client.DB, logger)
		oauthServer := oauth2.NewServer(client.DB, cfg, logger, oauth2.WithStorage(oauthStorage))
		oauthClient := oauth2.NewClient(cfg, logger)
		if err := oauthClient.InitializeDefaultProviders(); err != nil {
			return nil, fmt.Errorf("failed to initialize OAuth providers: %w", err)
		}
		oauthProvider := oauth2.NewProvider(client.DB, cfg, logger)

		services.OAuth = &OAuthServices{
			Server:   oauthServer,
			Client:   oauthClient,
			Provider: oauthProvider,
		}
	}

	if cfg.Features.EnablePasskeys {
		logger.Info("Initializing passkeys")
		// Initialize passkey session store
		storeType := passkeys.SessionStoreTypeInMemory
		if cfg.Redis.Enabled && cfg.Passkeys.UseRedisSessionStore {
			storeType = passkeys.SessionStoreTypeRedis
		}

		services.PasskeySessionStore = passkeys.CreateSessionStore(
			storeType,
			cfg,
			client.Redis,
			logger,
		)

		// Initialize passkey service
		pk, err := passkeys.NewService(
			cfg,
			client.DB,
			logger,
			services.PasskeySessionStore,
		)
		if err != nil {
			return nil, err
		}

		services.PassKey = pk
	}

	return services, nil
}
