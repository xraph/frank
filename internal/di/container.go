package di

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/internal/authz"
	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/internal/services/audit"
	"github.com/juicycleff/frank/internal/services/auth"
	"github.com/juicycleff/frank/internal/services/mfa"
	"github.com/juicycleff/frank/internal/services/notification"
	"github.com/juicycleff/frank/internal/services/oauth"
	"github.com/juicycleff/frank/internal/services/organization"
	"github.com/juicycleff/frank/internal/services/passkey"
	"github.com/juicycleff/frank/internal/services/rbac"
	"github.com/juicycleff/frank/internal/services/sso"
	"github.com/juicycleff/frank/internal/services/user"
	"github.com/juicycleff/frank/internal/services/webhook"
	"github.com/juicycleff/frank/internal/sms"
	"github.com/juicycleff/frank/pkg/crypto"
	"github.com/juicycleff/frank/pkg/data"
	"github.com/juicycleff/frank/pkg/email"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/validation"
)

// Container holds all application dependencies
type Container interface {
	// Core dependencies
	Config() *config.Config
	Logger() logging.Logger
	Data() *data.Clients
	DB() *ent.Client
	Redis() redis.UniversalClient
	Validator() validation.Validator
	Repo() repository.Repository
	EmailSender() email.Sender

	// Services
	Auth() auth.AuthService
	AuthZ() authz.Service
	UserService() user.Service
	ProfileService() user.ProfileService
	UserPrefService() user.PreferencesService
	OrganizationService() organization.Service
	MembershipService() organization.MembershipService
	RBACService() rbac.Service
	EmailService() email.Service
	NotificationService() notification.Service
	WebhookService() webhook.Service
	MFAService() mfa.Service
	PasskeyService() passkey.Service
	OAuthService() oauth.Service
	SSOService() sso.Service
	AuditService() audit.Service
	TokenService() auth.TokenService
	SessionService() auth.SessionService
	PasswordService() auth.PasswordService
	SAMLService() sso.SAMLService
	OIDCService() sso.OIDCService

	// Utilities
	Crypto() crypto.Util

	// Lifecycle
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Health(ctx context.Context) error
}

// container implements the Container interface
type container struct {
	config      *config.Config
	logger      logging.Logger
	dataClients *data.Clients
	repo        repository.Repository

	// Utilities
	validator validation.Validator
	crypto    crypto.Util

	// Core services
	tokenService        auth.TokenService
	sessionService      auth.SessionService
	passwordService     auth.PasswordService
	authService         auth.AuthService
	authzService        authz.Service
	userService         user.Service
	userPrefService     user.PreferencesService
	profileService      user.ProfileService
	organizationService organization.Service
	membershipService   organization.MembershipService
	rbacService         rbac.Service
	emailService        email.Service
	notificationService notification.Service
	webhookService      webhook.Service
	mfaService          mfa.Service
	passkeyService      passkey.Service
	webAuthn            passkey.WebAuthnService
	oauthService        oauth.Service
	samlService         sso.SAMLService
	oidcService         sso.OIDCService
	ssoService          sso.Service
	auditService        audit.Service

	emailSender      email.Sender
	templatesManager *email.TemplateManager
	smsSender        sms.Provider

	// Internal state
	started bool
}

// NewContainer creates a new dependency injection container
func NewContainer(cfg *config.Config, logger logging.Logger) (Container, error) {
	return NewContainerWithData(cfg, logger, nil)
}

// NewContainerWithData creates a new dependency injection container with optional data clients
func NewContainerWithData(cfg *config.Config, logger logging.Logger, dataClients *data.Clients) (Container, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	c := &container{
		config: cfg,
		logger: logger,
	}

	// Initialize core dependencies
	if err := c.initCore(dataClients); err != nil {
		return nil, fmt.Errorf("failed to initialize core dependencies: %w", err)
	}

	// Initialize services
	if err := c.initServices(); err != nil {
		return nil, fmt.Errorf("failed to initialize services: %w", err)
	}

	return c, nil
}

// initCore initializes core dependencies
func (c *container) initCore(dataClients *data.Clients) error {
	var err error

	// Initialize data clients (database, Redis, etc.)
	if err = c.initDataClients(dataClients); err != nil {
		return fmt.Errorf("failed to initialize data clients: %w", err)
	}

	// Initialize validator
	c.validator = validation.New()

	// Initialize crypto utilities
	c.crypto, err = crypto.New(c.config)
	if err != nil {
		return fmt.Errorf("failed to initialize crypto: %w", err)
	}

	// Initialize repo
	c.repo = repository.New(c.dataClients, c.logger)

	// Initialize email / sms templates
	oldRepo := email.NewTemplateRepository(c.dataClients.DB)
	c.templatesManager = email.NewTemplateManager(oldRepo, c.repo.SMSTemplate(), &c.config.Email, c.logger)
	c.emailSender = email.SenderFactory(&c.config.Email, c.logger)

	// Initialize sms sender
	c.smsSender = sms.SenderFactory(&c.config.SMS, c.logger)

	return err
}

// initDataClients initializes the data clients (database, Redis, etc.)
func (c *container) initDataClients(dataClients *data.Clients) error {
	if dataClients != nil {
		// Use provided data clients
		c.dataClients = dataClients
		c.logger.Info("Using provided data clients")
		return nil
	}

	// Create new data clients
	c.logger.Info("Creating new data clients")

	// Initialize Redis client if enabled
	var redisClient redis.UniversalClient
	if c.config.Redis.Enabled {
		c.logger.Info("Initializing Redis client")

		// Set default values if not configured
		host := c.config.Redis.Host
		if host == "" {
			host = "localhost"
		}
		port := c.config.Redis.Port
		if port == 0 {
			port = 6379
		}

		redisClient = redis.NewUniversalClient(&redis.UniversalOptions{
			Addrs:    []string{fmt.Sprintf("%s:%d", host, port)},
			Username: c.config.Redis.Username,
			Password: c.config.Redis.Password,
			DB:       c.config.Redis.Database,
		})

		// Test Redis connection
		ctx := context.Background()
		if err := redisClient.Ping(ctx).Err(); err != nil {
			c.logger.Warn("Redis connection failed", logging.Error(err))
			// Don't fail if Redis is not required
			redisClient = nil
		}
	}

	// Create data clients
	c.dataClients = data.NewClients(c.config, c.logger, nil, redisClient)

	// Run auto migration if enabled
	if err := c.dataClients.RunAutoMigration(); err != nil {
		return fmt.Errorf("failed to run auto migration: %w", err)
	}

	return nil
}

// initServices initializes all application services
func (c *container) initServices() error {
	var err error

	// Initialize audit service
	c.auditService = audit.NewAuditService(c.repo, c.logger, nil)

	// Initialize authorization services
	c.authzService = authz.NewService(c.dataClients)

	// Initialize webhook service
	c.webhookService = webhook.NewService(c.repo.Webhook(), nil, c.logger)

	// Initialize RBAC service first (required by others)
	c.rbacService = rbac.NewService(
		c.repo.Role(),
		c.repo.Permission(),
		c.repo.User(),
		c.repo.Organization(),
		c.logger,
	)

	// Initialize user service
	c.profileService = user.NewProfileService(
		c.repo.User(),
		c.repo.Verification(),
		c.repo.Audit(),
		c.logger,
	)
	c.userPrefService = user.NewPreferencesService(
		c.repo.User(),
		c.repo.Audit(),
		c.logger,
	)
	c.userService = user.NewService(
		c.repo.User(),
		c.repo.Verification(),
		c.repo.Audit(),
		c.logger,
	)

	// Initialize organization member service
	c.membershipService = organization.NewMembershipService(
		c.repo,
		c.logger,
	)

	// Initialize organization service
	c.organizationService = organization.NewService(
		c.repo.Organization(),
		c.repo.Membership(),
		c.repo.User(),
		c.repo.Audit(),
		c.logger,
	)

	// Initialize notification service
	c.notificationService, err = notification.NewService(c.repo, c.emailSender, c.smsSender, c.config, c.logger)
	if err != nil {
		return fmt.Errorf("failed to create notification service: %w", err)
	}

	// Initialize email service
	// c.emailService = c.notificationService.Email()

	// Initialize session and passwords services
	c.tokenService = auth.NewTokenService(c.repo, c.crypto, c.logger, &c.config.Auth)
	c.sessionService = auth.NewSessionService(c.repo, c.crypto, c.logger, &c.config.Auth)
	c.passwordService = auth.NewPasswordService(
		c.repo,
		c.userService,
		c.notificationService,
		c.sessionService,
		c.crypto,
		c.logger,
		&c.config.Auth,
	)

	// Initialize MFA service
	c.mfaService = mfa.NewService(c.repo, c.smsSender, c.logger, c.config)

	// Initialize passkey service
	c.webAuthn = passkey.NewWebAuthnService(passkey.WebAuthnConfig{}, c.logger)
	c.passkeyService = passkey.NewService(c.repo.PassKey(), c.repo.User(), c.webAuthn, c.logger)

	// Initialize OAuth service
	c.oauthService = oauth.NewService(c.repo, c.crypto, c.logger)

	// Initialize SSO service
	c.samlService, err = sso.NewSAMLService(c.config.BasePath, c.logger)
	if err != nil {
		return fmt.Errorf("failed to create SAML service: %w", err)
	}
	c.oidcService = sso.NewOIDCService(c.config.BasePath, c.logger)
	c.ssoService = sso.NewService(c.repo, c.samlService, c.oidcService, c.logger)

	// initialize Auth service
	c.authService = auth.NewAuthService(
		c.config,
		c.repo,
		c.tokenService,
		c.passwordService,
		c.sessionService,
		c.userService,
		c.notificationService,
		c.mfaService,
		c.oauthService,
		c.auditService,
		c.crypto,
		c.logger,
	)

	c.logger.Info("All services initialized successfully")
	return nil
}

func (c *container) Config() *config.Config {
	return c.config
}

func (c *container) Logger() logging.Logger {
	return c.logger
}

func (c *container) Data() *data.Clients {
	return c.dataClients
}

func (c *container) DB() *ent.Client {
	return c.dataClients.DB
}

func (c *container) Redis() redis.UniversalClient {
	return c.dataClients.Redis
}

func (c *container) Validator() validation.Validator {
	return c.validator
}

func (c *container) AuthZ() authz.Service {
	return c.authzService
}

func (c *container) UserService() user.Service {
	return c.userService
}

func (c *container) ProfileService() user.ProfileService {
	return c.profileService
}

func (c *container) UserPrefService() user.PreferencesService {
	return c.userPrefService
}

func (c *container) OrganizationService() organization.Service {
	return c.organizationService
}

func (c *container) MembershipService() organization.MembershipService {
	return c.membershipService
}

func (c *container) RBACService() rbac.Service {
	return c.rbacService
}

func (c *container) EmailService() email.Service {
	return c.emailService
}

func (c *container) NotificationService() notification.Service {
	return c.notificationService
}

func (c *container) WebhookService() webhook.Service {
	return c.webhookService
}

func (c *container) MFAService() mfa.Service {
	return c.mfaService
}

func (c *container) PasskeyService() passkey.Service {
	return c.passkeyService
}

func (c *container) OAuthService() oauth.Service {
	return c.oauthService
}

func (c *container) SSOService() sso.Service {
	return c.ssoService
}

func (c *container) AuditService() audit.Service {
	return c.auditService
}

func (c *container) Repo() repository.Repository {
	return c.repo
}

func (c *container) EmailSender() email.Sender {
	return c.emailSender
}

func (c *container) Auth() auth.AuthService {
	return c.authService
}

func (c *container) TokenService() auth.TokenService {
	return c.tokenService
}

func (c *container) SessionService() auth.SessionService {
	return c.sessionService
}

func (c *container) PasswordService() auth.PasswordService {
	return c.passwordService
}

func (c *container) Crypto() crypto.Util {
	return c.crypto
}

func (c *container) SAMLService() sso.SAMLService {
	return c.samlService
}

func (c *container) OIDCService() sso.OIDCService {
	return c.oidcService
}

func (c *container) Start(ctx context.Context) error {
	if c.started {
		return fmt.Errorf("container already started")
	}

	c.logger.Info("Starting application container")

	// Start services that need lifecycle management
	if starter, ok := c.webhookService.(interface{ Start(context.Context) error }); ok {
		if err := starter.Start(ctx); err != nil {
			return fmt.Errorf("failed to start webhook service: %w", err)
		}
	}

	if starter, ok := c.auditService.(interface{ Start(context.Context) error }); ok {
		if err := starter.Start(ctx); err != nil {
			return fmt.Errorf("failed to start audit service: %w", err)
		}
	}

	c.started = true
	c.logger.Info("Application container started successfully")
	return nil
}

func (c *container) Stop(ctx context.Context) error {
	if !c.started {
		return nil
	}

	c.logger.Info("Stopping application container")

	// Stop services in reverse order
	if stopper, ok := c.auditService.(interface{ Stop(context.Context) error }); ok {
		if err := stopper.Stop(ctx); err != nil {
			c.logger.Error("failed to stop audit service", logging.Error(err))
		}
	}

	if stopper, ok := c.webhookService.(interface{ Stop(context.Context) error }); ok {
		if err := stopper.Stop(ctx); err != nil {
			c.logger.Error("failed to stop webhook service", logging.Error(err))
		}
	}

	// Close data clients (database, Redis, etc.)
	if c.dataClients != nil {
		if err := c.dataClients.Close(); err != nil {
			c.logger.Error("failed to close data clients", logging.Error(err))
		}
	}

	c.started = false
	c.logger.Info("Application container stopped")
	return nil
}

func (c *container) Health(ctx context.Context) error {
	// Check database health using data clients
	if c.dataClients != nil && c.dataClients.DBPinger != nil {
		if err := c.dataClients.DBPinger.Ping(ctx); err != nil {
			return fmt.Errorf("database health check failed: %w", err)
		}
	}

	// Check Redis health if enabled
	if c.dataClients != nil && c.dataClients.Redis != nil {
		if err := c.dataClients.Redis.Ping(ctx).Err(); err != nil {
			return fmt.Errorf("redis health check failed: %w", err)
		}
	}

	// Check service health if they implement health checks
	if healthChecker, ok := c.webhookService.(interface{ Health(context.Context) error }); ok {
		if err := healthChecker.Health(ctx); err != nil {
			return fmt.Errorf("webhook service health check failed: %w", err)
		}
	}

	return nil
}

// NewContainerFromConfig creates a container from config with default logger
func NewContainerFromConfig(cfg *config.Config) (Container, error) {
	logger := logging.NewLogger(&logging.LoggerConfig{
		Level:       cfg.Logging.Level,
		Environment: cfg.Environment,
	})

	return NewContainer(cfg, logger)
}

// NewContainerFromConfigWithData creates a container from config with existing data clients
func NewContainerFromConfigWithData(cfg *config.Config, dataClients *data.Clients) (Container, error) {
	logger := logging.NewLogger(&logging.LoggerConfig{
		Level:       cfg.Logging.Level,
		Environment: cfg.Environment,
	})

	return NewContainerWithData(cfg, logger, dataClients)
}

// MustNewContainer creates a container and panics on error (for use in main functions)
func MustNewContainer(cfg *config.Config, logger logging.Logger) Container {
	container, err := NewContainer(cfg, logger)
	if err != nil {
		panic(fmt.Sprintf("failed to create container: %v", err))
	}
	return container
}

// MustNewContainerWithData creates a container with data clients and panics on error
func MustNewContainerWithData(cfg *config.Config, logger logging.Logger, dataClients *data.Clients) Container {
	container, err := NewContainerWithData(cfg, logger, dataClients)
	if err != nil {
		panic(fmt.Sprintf("failed to create container: %v", err))
	}
	return container
}
