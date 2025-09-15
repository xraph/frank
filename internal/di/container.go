package di

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
	"github.com/xraph/frank/pkg/validation"

	"github.com/xraph/frank/config"
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/internal/authz"
	"github.com/xraph/frank/internal/repository"
	"github.com/xraph/frank/pkg/crypto"
	"github.com/xraph/frank/pkg/data"
	"github.com/xraph/frank/pkg/email"
	"github.com/xraph/frank/pkg/hooks"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/services/activity"
	"github.com/xraph/frank/pkg/services/apikey"
	"github.com/xraph/frank/pkg/services/audit"
	auth2 "github.com/xraph/frank/pkg/services/auth"
	"github.com/xraph/frank/pkg/services/mfa"
	"github.com/xraph/frank/pkg/services/notification"
	"github.com/xraph/frank/pkg/services/oauth"
	organization2 "github.com/xraph/frank/pkg/services/organization"
	passkey2 "github.com/xraph/frank/pkg/services/passkey"
	rbac2 "github.com/xraph/frank/pkg/services/rbac"
	sso2 "github.com/xraph/frank/pkg/services/sso"
	user2 "github.com/xraph/frank/pkg/services/user"
	"github.com/xraph/frank/pkg/services/webhook"
	sms2 "github.com/xraph/frank/pkg/sms"
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

	ActivityService() activity.Service

	// Services
	Auth() auth2.AuthService
	AuthZ() authz.Service
	UserService() user2.Service
	ProfileService() user2.ProfileService
	UserPrefService() user2.PreferencesService
	OrganizationService() organization2.Service
	BillingService() organization2.BillingService
	MembershipService() organization2.MembershipService
	InvitationService() organization2.InvitationService

	RBACService() rbac2.Service
	RoleService() rbac2.RoleService
	APIKeyService() apikey.Service
	PermissionService() rbac2.PermissionService
	PermissionTemplateService() *rbac2.PermissionTemplateService
	ResourceDiscoveryService() *rbac2.ResourceDiscoveryService
	ConditionalPermissionEngine() *rbac2.ConditionalPermissionEngine
	RoleHierarchyService() *rbac2.RoleHierarchyService
	RoleAuditService() *rbac2.AuditTrailService
	RoleAnalyticsService() *rbac2.AnalyticsService
	RBACChecker() *rbac2.RBACChecker
	Enforcer() rbac2.Enforcer
	RBACServiceV2() *rbac2.PerformanceOptimizedRBACService

	EmailService() email.Service
	NotificationService() notification.Service
	WebhookService() webhook.Service
	MFAService() mfa.Service
	PasskeyService() passkey2.Service
	OAuthService() oauth.Service
	SSOService() sso2.Service
	ProviderCatalogService() sso2.ProviderCatalogService
	AuditService() audit.Service
	TokenService() auth2.TokenService
	SessionService() auth2.SessionService
	PasswordService() auth2.PasswordService
	SAMLService() sso2.SAMLService
	OIDCService() sso2.OIDCService
	RoleSeeder() *rbac2.RBACSeeder

	Hooks() hooks.Hooks

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
	hooks       hooks.Hooks

	// Utilities
	validator validation.Validator
	crypto    crypto.Util

	// Core services
	tokenService    auth2.TokenService
	sessionService  auth2.SessionService
	passwordService auth2.PasswordService
	authService     auth2.AuthService
	authzService    authz.Service
	userService     user2.Service
	userPrefService user2.PreferencesService
	profileService  user2.ProfileService
	apikeyService   apikey.Service

	organizationService organization2.Service
	membershipService   organization2.MembershipService
	invitationService   organization2.InvitationService
	billingService      organization2.BillingService

	emailService        email.Service
	notificationService notification.Service
	webhookService      webhook.Service

	mfaService             mfa.Service
	passkeyService         passkey2.Service
	webAuthn               passkey2.WebAuthnService
	oauthService           oauth.Service
	samlService            sso2.SAMLService
	oidcService            sso2.OIDCService
	ssoService             sso2.Service
	providerCatalogService sso2.ProviderCatalogService

	auditService    audit.Service
	activityService activity.Service

	emailSender      email.Sender
	templatesManager *email.TemplateManager
	smsSender        sms2.Provider

	rbacService               rbac2.Service
	enforcer                  rbac2.Enforcer
	permissionService         rbac2.PermissionService
	userRoleCache             rbac2.UserRoleCache
	rbacServiceV2             *rbac2.PerformanceOptimizedRBACService
	roleService               rbac2.RoleService
	rbacChecker               *rbac2.RBACChecker
	roleHierarchyService      *rbac2.RoleHierarchyService
	roleAuditService          *rbac2.AuditTrailService
	roleAnalyticsService      *rbac2.AnalyticsService
	permissionTemplateService *rbac2.PermissionTemplateService
	resourceDiscoveryService  *rbac2.ResourceDiscoveryService
	rbacConditionalEngine     *rbac2.ConditionalPermissionEngine
	roleSeeder                *rbac2.RBACSeeder

	// Internal state
	started bool
}

func (c *container) InvitationService() organization2.InvitationService {
	return c.invitationService
}

func (c *container) RoleSeeder() *rbac2.RBACSeeder {
	return c.roleSeeder
}

func (c *container) ActivityService() activity.Service {
	return c.activityService
}

func (c *container) PermissionTemplateService() *rbac2.PermissionTemplateService {
	return c.permissionTemplateService
}

func (c *container) ResourceDiscoveryService() *rbac2.ResourceDiscoveryService {
	return c.resourceDiscoveryService
}

func (c *container) ConditionalPermissionEngine() *rbac2.ConditionalPermissionEngine {
	return c.rbacConditionalEngine
}

func (c *container) RoleHierarchyService() *rbac2.RoleHierarchyService {
	return c.roleHierarchyService
}

func (c *container) RoleAuditService() *rbac2.AuditTrailService {
	return c.roleAuditService
}

func (c *container) RoleAnalyticsService() *rbac2.AnalyticsService {
	return c.roleAnalyticsService
}

func (c *container) RBACChecker() *rbac2.RBACChecker {
	return c.rbacChecker
}

func (c *container) Enforcer() rbac2.Enforcer {
	return c.enforcer
}

func (c *container) RBACServiceV2() *rbac2.PerformanceOptimizedRBACService {
	return c.rbacServiceV2
}

func (c *container) BillingService() organization2.BillingService {
	return c.billingService
}

func (c *container) APIKeyService() apikey.Service {
	return c.apikeyService
}

func (c *container) Hooks() hooks.Hooks {
	return c.hooks
}

// NewContainer creates a new dependency injection container
func NewContainer(cfg *config.Config, logger logging.Logger) (Container, error) {
	return NewContainerWithData(cfg, logger, nil, nil)
}

// NewContainerWithData creates a new dependency injection container with optional data clients
func NewContainerWithData(
	cfg *config.Config,
	logger logging.Logger,
	dataClients *data.Clients,
	hooks hooks.Hooks,
) (Container, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	c := &container{
		config: cfg,
		logger: logger,
		hooks:  hooks,
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

	// Initialize hooks
	if c.hooks == nil {
		c.hooks = hooks.NewNoOpHooks(c.logger)
	}

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
	c.smsSender = sms2.SenderFactory(&c.config.SMS, c.logger)

	// Initialize activity service
	c.activityService = activity.NewService(c.repo.Activity(), c.logger)

	c.roleSeeder = rbac2.NewRBACSeeder(c.dataClients, c.logger)

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
	c.enforcer = rbac2.NewEnforcer(c.repo, c.logger)
	c.permissionService = rbac2.NewPermissionService(c.repo, c.logger)
	c.roleHierarchyService = rbac2.NewRoleHierarchyService(
		c.repo.Role(),
		rbac2.NewMemoryHierarchyCache(),
		c.logger,
	)
	c.roleAuditService = rbac2.NewAuditTrailService(c.repo.Role(), c.logger)
	c.roleAnalyticsService = rbac2.NewAnalyticsService(c.repo, c.roleAuditService, c.logger)
	c.resourceDiscoveryService = rbac2.NewResourceDiscoveryService(c.repo.Role(), c.logger)
	c.permissionTemplateService = rbac2.NewPermissionTemplateService(c.repo, c.resourceDiscoveryService, c.logger)
	c.rbacConditionalEngine = rbac2.NewConditionalPermissionEngine(c.repo.Role(), c.logger)
	c.roleService = rbac2.NewRoleService(c.repo, c.logger)
	c.rbacService = rbac2.NewService(
		c.enforcer,
		c.repo,
		c.roleHierarchyService,
		c.roleAuditService,
		c.roleAnalyticsService,
		c.permissionTemplateService,
		c.resourceDiscoveryService,
		c.rbacConditionalEngine,
		c.roleService,
		c.permissionService,
		c.logger,
	)
	c.rbacChecker = rbac2.NewRBACChecker(c.rbacService, c.logger)
	// c.rbacServiceV2 = rbac2.NewPerformanceOptimizedRBACService(c.rbacService, c.roleHierarchyService, )

	// Initialize user service
	c.profileService = user2.NewProfileService(
		c.repo.User(),
		c.repo.Verification(),
		c.repo.Audit(),
		c.logger,
	)
	c.userPrefService = user2.NewPreferencesService(
		c.repo.User(),
		c.repo.Audit(),
		c.logger,
	)
	c.userService = user2.NewService(
		c.repo,
		c.hooks,
		c.logger,
	)

	// Initialize MFA service
	c.mfaService = mfa.NewService(c.repo, c.dataClients, c.smsSender, c.logger, c.config)

	// Initialize passkey service
	c.webAuthn = passkey2.NewWebAuthnService(passkey2.WebAuthnConfig{}, c.logger)
	c.passkeyService = passkey2.NewService(c.repo.PassKey(), c.repo.User(), c.webAuthn, c.logger)

	// Initialize OAuth service
	c.oauthService = oauth.NewService(c.repo, c.crypto, c.logger)

	// Initialize SSO service
	c.samlService, err = sso2.NewSAMLService(c.config.App.BasePath, c.logger)
	if err != nil {
		return fmt.Errorf("failed to create SAML service: %w", err)
	}

	c.oidcService = sso2.NewOIDCService(c.config.App.BasePath, c.logger)
	c.ssoService = sso2.NewService(c.repo, c.samlService, c.oidcService, c.logger)
	c.providerCatalogService = sso2.NewProviderCatalogService(
		c.repo,
		c.ssoService,
		c.logger,
	)

	// Initialize organization member service
	c.invitationService = organization2.NewInvitationService(
		c.repo,
		c.notificationService,
		c.logger,
		"",
	)

	c.membershipService = organization2.NewMembershipService(
		c.repo,
		c.logger,
	)

	// Initialize organization service
	c.organizationService = organization2.NewService(
		c.repo,
		c.ssoService,
		c.roleSeeder,
		c.membershipService,
		c.logger,
	)
	c.billingService = organization2.NewBillingService(c.repo, nil, c.logger)

	// Initialize notification service
	c.notificationService, err = notification.NewService(c.repo, c.emailSender, c.smsSender, c.config, c.logger)
	if err != nil {
		return fmt.Errorf("failed to create notification service: %w", err)
	}

	// Initialize email service
	// c.emailService = c.notificationService.Email()

	// Initialize session and passwords services
	c.tokenService = auth2.NewTokenService(c.repo, c.crypto, c.logger, &c.config.Auth)
	c.sessionService = auth2.NewSessionService(c.repo, c.crypto, c.logger, &c.config.Auth)
	c.passwordService = auth2.NewPasswordService(
		c.repo,
		c.userService,
		c.notificationService,
		c.sessionService,
		c.crypto,
		c.logger,
		&c.config.Auth,
	)

	c.apikeyService = apikey.NewService(
		c.Repo(), c.Crypto(), c.AuditService(),
		c.ActivityService(), c.RBACService(), c.Logger(),
	)

	// initialize Auth service
	c.authService = auth2.NewAuthService(
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
		c.organizationService,
		c.hooks,
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

func (c *container) UserService() user2.Service {
	return c.userService
}

func (c *container) ProfileService() user2.ProfileService {
	return c.profileService
}

func (c *container) UserPrefService() user2.PreferencesService {
	return c.userPrefService
}

func (c *container) OrganizationService() organization2.Service {
	return c.organizationService
}

func (c *container) MembershipService() organization2.MembershipService {
	return c.membershipService
}

func (c *container) RBACService() rbac2.Service {
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

func (c *container) PasskeyService() passkey2.Service {
	return c.passkeyService
}

func (c *container) OAuthService() oauth.Service {
	return c.oauthService
}

func (c *container) SSOService() sso2.Service {
	return c.ssoService
}

func (c *container) AuditService() audit.Service {
	return c.auditService
}

func (c *container) Repo() repository.Repository {
	return c.repo
}

func (c *container) ProviderCatalogService() sso2.ProviderCatalogService {
	return c.providerCatalogService
}

func (c *container) EmailSender() email.Sender {
	return c.emailSender
}

func (c *container) Auth() auth2.AuthService {
	return c.authService
}

func (c *container) TokenService() auth2.TokenService {
	return c.tokenService
}

func (c *container) SessionService() auth2.SessionService {
	return c.sessionService
}

func (c *container) PasswordService() auth2.PasswordService {
	return c.passwordService
}

func (c *container) Crypto() crypto.Util {
	return c.crypto
}

func (c *container) SAMLService() sso2.SAMLService {
	return c.samlService
}

func (c *container) OIDCService() sso2.OIDCService {
	return c.oidcService
}

func (c *container) RoleService() rbac2.RoleService {
	return c.roleService
}

func (c *container) PermissionService() rbac2.PermissionService {
	return c.permissionService
}

func (c *container) Start(ctx context.Context) error {
	if c.started {
		return fmt.Errorf("container already started")
	}

	c.roleSeeder.SeedRBACData(ctx)

	c.logger.Info("Starting application container")

	c.logger.Info("Initializing email templates")
	err := c.providerCatalogService.SeedProviderCatalog(ctx)
	if err != nil {
		return fmt.Errorf("failed to seed provider catalog: %w", err)
	}

	// OnStart services that need lifecycle management
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

	// OnStop services in reverse order
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
		Environment: cfg.App.Environment,
	})

	return NewContainer(cfg, logger)
}

// NewContainerFromConfigWithData creates a container from config with existing data clients
func NewContainerFromConfigWithData(cfg *config.Config, dataClients *data.Clients, hooks hooks.Hooks) (Container, error) {
	logger := logging.NewLogger(&logging.LoggerConfig{
		Level:       cfg.Logging.Level,
		Environment: cfg.App.Environment,
	})

	return NewContainerWithData(cfg, logger, dataClients, hooks)
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
func MustNewContainerWithData(cfg *config.Config, logger logging.Logger, dataClients *data.Clients, hooks hooks.Hooks) Container {
	container, err := NewContainerWithData(cfg, logger, dataClients, hooks)
	if err != nil {
		panic(fmt.Sprintf("failed to create container: %v", err))
	}
	return container
}
