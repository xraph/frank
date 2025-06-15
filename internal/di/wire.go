//go:build wireinject
// +build wireinject

package di

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
	"github.com/google/wire"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/internal/authz"
	"github.com/juicycleff/frank/internal/rbac"
	"github.com/juicycleff/frank/internal/services/audit"
	"github.com/juicycleff/frank/internal/services/auth"
	"github.com/juicycleff/frank/pkg/crypto"
	"github.com/juicycleff/frank/pkg/data"
	"github.com/juicycleff/frank/pkg/email"
	"github.com/juicycleff/frank/pkg/logging"
	audit2 "github.com/juicycleff/frank/pkg/services/audit"
	auth2 "github.com/juicycleff/frank/pkg/services/auth"
	"github.com/juicycleff/frank/pkg/services/mfa"
	"github.com/juicycleff/frank/pkg/services/notification"
	"github.com/juicycleff/frank/pkg/services/oauth"
	"github.com/juicycleff/frank/pkg/services/organization"
	"github.com/juicycleff/frank/pkg/services/passkey"
	"github.com/juicycleff/frank/pkg/services/sso"
	"github.com/juicycleff/frank/pkg/services/user"
	"github.com/juicycleff/frank/pkg/services/webhook"
	"github.com/juicycleff/frank/pkg/validation"

	_ "github.com/go-sql-driver/mysql" // MySQL
	// Database drivers
	_ "github.com/lib/pq"           // PostgreSQL
	_ "github.com/mattn/go-sqlite3" // SQLite
)

// Provider functions for core dependencies

// ProvideRedisClient provides a Redis client
func ProvideRedisClient(cfg *config.Config, logger logging.Logger) redis.UniversalClient {
	if !cfg.Redis.Enabled {
		return nil
	}

	logger.Info("Initializing Redis client")

	// Set default values if not configured
	host := cfg.Redis.Host
	if host == "" {
		host = "localhost"
	}
	port := cfg.Redis.Port
	if port == 0 {
		port = 6379
	}

	redisClient := redis.NewUniversalClient(&redis.UniversalOptions{
		Addrs:    []string{fmt.Sprintf("%s:%d", host, port)},
		Username: cfg.Redis.Username,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})

	// Test Redis connection
	ctx := context.Background()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		logger.Warn("Redis connection failed", logging.Error(err))
		return nil
	}

	return redisClient
}

// ProvideDataClients provides data clients wrapper
func ProvideDataClients(cfg *config.Config, logger logging.Logger, redisClient redis.UniversalClient) (*data.Clients, error) {
	dataClients := data.NewClients(cfg, logger, nil, redisClient)

	// Run auto migration if enabled
	if err := dataClients.RunAutoMigration(); err != nil {
		return nil, err
	}

	return dataClients, nil
}

// ProvideExistingDataClients provides a way to use existing data clients in Wire
func ProvideExistingDataClients(dataClients *data.Clients) *data.Clients {
	return dataClients
}

// ProvideEntClient provides the Ent client from data clients
func ProvideEntClient(dataClients *data.Clients) *ent.Client {
	return dataClients.DB
}

// ProvideRedisFromDataClients provides Redis client from data clients
func ProvideRedisFromDataClients(dataClients *data.Clients) redis.UniversalClient {
	return dataClients.Redis
}

// ProvideValidator provides a validator instance
func ProvideValidator() validation.Validator {
	return validation.New()
}

// ProvideCrypto provides crypto utilities
func ProvideCrypto(cfg *config.Config) crypto.Util {
	return crypto.New(cfg.Auth.TokenSecretKey)
}

// Provider functions for services

// ProvideRBACService provides the RBAC service
func ProvideRBACService(entClient *ent.Client, logger logging.Logger) rbac.Service {
	return rbac.NewService(entClient, logger)
}

// ProvideUserService provides the user service
func ProvideUserService(entClient *ent.Client, logger logging.Logger, cfg *config.Config) user.Service {
	return user.NewService(entClient, logger, cfg)
}

// ProvideOrganizationService provides the organization service
func ProvideOrganizationService(entClient *ent.Client, logger logging.Logger, cfg *config.Config) organization.Service {
	return organization.NewService(entClient, logger, cfg)
}

// ProvideNotificationService provides the notification service
func ProvideNotificationService(cfg *config.Config, logger logging.Logger) notification.Service {
	return notification.NewService(cfg, logger)
}

// ProvideEmailService provides the email service
func ProvideEmailService(cfg *config.Config, logger logging.Logger, notificationService notification.Service) email.Service {
	return email.NewService(cfg, logger, notificationService)
}

// ProvideAuthChecker provides the authorization checker
func ProvideAuthChecker(rbacService rbac.Service, logger logging.Logger) authz.Checker {
	return authz.NewChecker(rbacService, logger)
}

// ProvidePermissionChecker provides the permission checker
func ProvidePermissionChecker(rbacService rbac.Service, logger logging.Logger) authz.PermissionChecker {
	return authz.NewPermissionChecker(rbacService, logger)
}

// ProvideRoleChecker provides the role checker
func ProvideRoleChecker(rbacService rbac.Service, logger logging.Logger) authz.RoleChecker {
	return authz.NewRoleChecker(rbacService, logger)
}

// ProvideAuthZService provides the authorization service
func ProvideAuthZService(
	checker authz.Checker,
	permissionChecker authz.PermissionChecker,
	roleChecker authz.RoleChecker,
) AuthZService {
	return &authzService{
		checker:           checker,
		permissionChecker: permissionChecker,
		roleChecker:       roleChecker,
	}
}

// ProvideTokenService provides the token service
func ProvideTokenService(cfg *config.Config, crypto crypto.Util, logger logging.Logger) auth2.TokenService {
	return auth2.NewTokenService(cfg, crypto, logger)
}

// ProvideSessionService provides the session service
func ProvideSessionService(entClient *ent.Client, cfg *config.Config, logger logging.Logger) auth2.SessionService {
	return auth2.NewSessionService(entClient, cfg, logger)
}

// ProvidePasswordService provides the password service
func ProvidePasswordService(cfg *config.Config, crypto crypto.Util, logger logging.Logger) auth2.PasswordService {
	return auth2.NewPasswordService(cfg, crypto, logger)
}

// ProvideFrankAuth provides the Frank authentication service
func ProvideFrankAuth(entClient *ent.Client, cfg *config.Config, logger logging.Logger, crypto crypto.Util) auth.FrankAuth {
	return auth.NewFrankAuth(entClient, cfg, logger, crypto)
}

// ProvideAuthService provides the authentication service
func ProvideAuthService(
	frank auth.FrankAuth,
	tokenService auth2.TokenService,
	sessionService auth2.SessionService,
	passwordService auth2.PasswordService,
) AuthService {
	return &authService{
		frank:           frank,
		tokenService:    tokenService,
		sessionService:  sessionService,
		passwordService: passwordService,
	}
}

// ProvideWebhookService provides the webhook service
func ProvideWebhookService(entClient *ent.Client, logger logging.Logger, cfg *config.Config) webhook.Service {
	return webhook.NewService(entClient, logger, cfg)
}

// ProvideMFAService provides the MFA service
func ProvideMFAService(entClient *ent.Client, cfg *config.Config, logger logging.Logger, notificationService notification.Service) mfa.Service {
	return mfa.NewService(entClient, cfg, logger, notificationService)
}

// ProvidePasskeyService provides the passkey service
func ProvidePasskeyService(entClient *ent.Client, cfg *config.Config, logger logging.Logger) passkey.Service {
	return passkey.NewService(entClient, cfg, logger)
}

// ProvideOAuthService provides the OAuth service
func ProvideOAuthService(entClient *ent.Client, cfg *config.Config, logger logging.Logger, crypto crypto.Util) oauth.Service {
	return oauth.NewService(entClient, cfg, logger, crypto)
}

// ProvideSSOService provides the SSO service
func ProvideSSOService(entClient *ent.Client, cfg *config.Config, logger logging.Logger) sso.Service {
	return sso.NewService(entClient, cfg, logger)
}

// ProvideAuditService provides the audit service
func ProvideAuditService(entClient *ent.Client, logger logging.Logger, cfg *config.Config) audit2.Service {
	return audit.NewService(entClient, logger, cfg)
}

// Provider sets group related providers together

// CoreProviderSet includes core infrastructure dependencies (creates new data clients)
var CoreProviderSet = wire.NewSet(
	ProvideRedisClient,
	ProvideDataClients,
	ProvideEntClient,
	ProvideValidator,
	ProvideCrypto,
)

// CoreWithExistingDataSet includes core dependencies with existing data clients
var CoreWithExistingDataSet = wire.NewSet(
	ProvideExistingDataClients,
	ProvideEntClient,
	ProvideRedisFromDataClients,
	ProvideValidator,
	ProvideCrypto,
)

// AuthProviderSet includes authentication and authorization providers
var AuthProviderSet = wire.NewSet(
	ProvideAuthChecker,
	ProvidePermissionChecker,
	ProvideRoleChecker,
	ProvideAuthZService,
	ProvideTokenService,
	ProvideSessionService,
	ProvidePasswordService,
	ProvideFrankAuth,
	ProvideAuthService,
)

// ServiceProviderSet includes business service providers
var ServiceProviderSet = wire.NewSet(
	ProvideRBACService,
	ProvideUserService,
	ProvideOrganizationService,
	ProvideNotificationService,
	ProvideEmailService,
	ProvideWebhookService,
	ProvideMFAService,
	ProvidePasskeyService,
	ProvideOAuthService,
	ProvideSSOService,
	ProvideAuditService,
)

// AllProviderSet includes all providers (creates new data clients)
var AllProviderSet = wire.NewSet(
	CoreProviderSet,
	AuthProviderSet,
	ServiceProviderSet,
)

// AllWithExistingDataSet includes all providers with existing data clients
var AllWithExistingDataSet = wire.NewSet(
	CoreWithExistingDataSet,
	AuthProviderSet,
	ServiceProviderSet,
)

// Wire injector functions

// InitializeContainer initializes a complete container with all dependencies
func InitializeContainer(cfg *config.Config, logger logging.Logger) (Container, error) {
	wire.Build(
		AllProviderSet,
		wire.Struct(new(container), "*"),
		wire.Bind(new(Container), new(*container)),
	)
	return nil, nil
}

// InitializeContainerWithData initializes a container with existing data clients
func InitializeContainerWithData(cfg *config.Config, logger logging.Logger, dataClients *data.Clients) (Container, error) {
	wire.Build(
		AllWithExistingDataSet,
		wire.Struct(new(container), "*"),
		wire.Bind(new(Container), new(*container)),
	)
	return nil, nil
}

// InitializeCoreContainer initializes a container with only core dependencies
func InitializeCoreContainer(cfg *config.Config, logger logging.Logger) (Container, error) {
	wire.Build(
		CoreProviderSet,
		wire.Struct(new(container), "config", "logger", "dataClients", "validator", "crypto"),
		wire.Bind(new(Container), new(*container)),
	)
	return nil, nil
}

// InitializeAuthContainer initializes a container with auth dependencies
func InitializeAuthContainer(cfg *config.Config, logger logging.Logger) (Container, error) {
	wire.Build(
		CoreProviderSet,
		AuthProviderSet,
		// Include RBAC service as it's needed by auth
		ProvideRBACService,
		wire.Struct(new(container), "*"),
		wire.Bind(new(Container), new(*container)),
	)
	return nil, nil
}

// Provider functions for testing

// ProvideTestContainer provides a container configured for testing
func ProvideTestContainer(cfg *config.Config, logger logging.Logger) Container {
	// This would typically include test-specific configurations
	// and mock services for testing
	container, err := InitializeContainer(cfg, logger)
	if err != nil {
		panic(err)
	}
	return container
}

// Wire sets for different environments

// ProductionProviderSet includes all providers needed for production
var ProductionProviderSet = wire.NewSet(
	AllProviderSet,
)

// DevelopmentProviderSet includes providers with development-specific configurations
var DevelopmentProviderSet = wire.NewSet(
	AllProviderSet,
)

// TestProviderSet includes providers with test-specific configurations
var TestProviderSet = wire.NewSet(
	AllProviderSet,
)

// Environment-specific injector functions

// InitializeProductionContainer initializes a container for production
func InitializeProductionContainer(cfg *config.Config, logger logging.Logger) (Container, error) {
	wire.Build(
		ProductionProviderSet,
		wire.Struct(new(container), "*"),
		wire.Bind(new(Container), new(*container)),
	)
	return nil, nil
}

// InitializeProductionContainerWithData initializes a production container with existing data clients
func InitializeProductionContainerWithData(cfg *config.Config, logger logging.Logger, dataClients *data.Clients) (Container, error) {
	wire.Build(
		AllWithExistingDataSet, // Use existing data set for production too
		wire.Struct(new(container), "*"),
		wire.Bind(new(Container), new(*container)),
	)
	return nil, nil
}

// InitializeDevelopmentContainer initializes a container for development
func InitializeDevelopmentContainer(cfg *config.Config, logger logging.Logger) (Container, error) {
	wire.Build(
		DevelopmentProviderSet,
		wire.Struct(new(container), "*"),
		wire.Bind(new(Container), new(*container)),
	)
	return nil, nil
}

// InitializeDevelopmentContainerWithData initializes a development container with existing data clients
func InitializeDevelopmentContainerWithData(cfg *config.Config, logger logging.Logger, dataClients *data.Clients) (Container, error) {
	wire.Build(
		AllWithExistingDataSet,
		wire.Struct(new(container), "*"),
		wire.Bind(new(Container), new(*container)),
	)
	return nil, nil
}

// InitializeTestContainer initializes a container for testing
func InitializeTestContainer(cfg *config.Config, logger logging.Logger) (Container, error) {
	wire.Build(
		TestProviderSet,
		wire.Struct(new(container), "*"),
		wire.Bind(new(Container), new(*container)),
	)
	return nil, nil
}

// InitializeTestContainerWithData initializes a test container with existing data clients
func InitializeTestContainerWithData(cfg *config.Config, logger logging.Logger, dataClients *data.Clients) (Container, error) {
	wire.Build(
		AllWithExistingDataSet,
		wire.Struct(new(container), "*"),
		wire.Bind(new(Container), new(*container)),
	)
	return nil, nil
}

// Cleanup functions for proper resource management

// CleanupDataClients properly closes data clients
func CleanupDataClients(dataClients *data.Clients) error {
	if dataClients != nil {
		return dataClients.Close()
	}
	return nil
}

// Helper functions for configuration

// ConfigureForProduction applies production-specific configurations
func ConfigureForProduction(container Container) Container {
	// Apply production-specific configurations
	// This could include setting up monitoring, metrics, etc.
	return container
}

// ConfigureForDevelopment applies development-specific configurations
func ConfigureForDevelopment(container Container) Container {
	// Apply development-specific configurations
	// This could include additional logging, debug endpoints, etc.
	return container
}

// ConfigureForTesting applies test-specific configurations
func ConfigureForTesting(container Container) Container {
	// Apply test-specific configurations
	// This could include in-memory databases, mock services, etc.
	return container
}
