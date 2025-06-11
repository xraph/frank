package di

//
// import (
// 	"fmt"
//
// 	"github.com/juicycleff/frank/config"
// 	"github.com/juicycleff/frank/internal/apikeys"
// 	"github.com/juicycleff/frank/internal/auth/mfa"
// 	"github.com/juicycleff/frank/internal/auth/oauth2"
// 	"github.com/juicycleff/frank/internal/auth/passkeys"
// 	"github.com/juicycleff/frank/internal/auth/passwordless"
// 	"github.com/juicycleff/frank/internal/auth/session"
// 	"github.com/juicycleff/frank/internal/auth/sso"
// 	"github.com/juicycleff/frank/internal/authz"
// 	"github.com/juicycleff/frank/internal/rbac"
// 	"github.com/juicycleff/frank/internal/sms"
// 	"github.com/juicycleff/frank/internal/webhook"
// 	"github.com/juicycleff/frank/pkg/data"
// 	"github.com/juicycleff/frank/pkg/email"
// 	"github.com/juicycleff/frank/pkg/logging"
// 	"github.com/juicycleff/frank/pkg/organization"
// 	"github.com/juicycleff/frank/pkg/user"
// )
//
// // ContainerInner defines the interface for accessing all services and components within the application
// type ContainerInner interface {
// 	// Configuration and core components
// 	Config() *config.Config
// 	Data() *data.Clients
// 	Logger() logging.Logger
//
// 	// // Encryption
// 	// EncryptionService() *encryption.Service
//
// 	// User and organization management
// 	UserRepo() user.Repository
// 	UserService() user.Service
// 	OrgRepo() organization.Repository
// 	OrgService() organization.Service
// 	APIKeyRepo() apikeys.Repository
// 	APIKeyService() apikeys.Service
// 	WebhookRepo() webhook.Repository
// 	WebhookEventRepo() webhook.EventRepository
// 	WebhookService() webhook.Service
// 	SessionSore() session.Store
//
// 	// // Audit logging
// 	// AuditLogRepo() auditlog.Repository
// 	// AuditLogService() auditlog.Service
// 	// AuditLogReportingService() auditlog.ReportingService
//
// 	EmailService() email.Service
// 	RBACRepo() rbac.Repository
// 	RBACService() rbac.Service
// 	PasswordlessService() passwordless.Service
// 	Passwordless() passwordless.Service
// 	PassKeysRepo() passkeys.Repository
// 	PassKeysService() passkeys.Service
// 	PassKeySessionStore() passkeys.SessionStore
// 	MFAService() mfa.Service
// 	SSOService() sso.Service
//
// 	AuthZ() authz.Service
//
// 	Close() error
// 	Start() error
// }
//
// type containerImpl struct {
// 	cfg  *config.Config
// 	data *data.Clients
// 	log  logging.Logger
//
// 	orgRepo    organization.Repository
// 	orgService organization.Service
//
// 	rbacRepo    rbac.Repository
// 	rbacService rbac.Service
//
// 	passKeyRepo         passkeys.Repository
// 	passkeyService      passkeys.Service
// 	passkeySessionStore passkeys.SessionStore
//
// 	mfaService mfa.Service
//
// 	ssoService sso.Service
//
// 	passwordlessRepo    passkeys.Repository
// 	passwordlessService passwordless.Service
//
// 	userRepo    user.Repository
// 	userService user.Service
//
// 	apiKeyRepo    apikeys.Repository
// 	apiKeyService apikeys.Service
//
// 	webhookRepo      webhook.Repository
// 	webhookEventRepo webhook.EventRepository
// 	webhookService   webhook.Service
//
// 	sessionSore session.Store
//
// 	emailService email.Service
// 	templateRepo email.TemplateRepository
//
// 	oauthService *OAuthServices
//
// 	authz authz.Service
// }
//
// // OAuthServices contains OAuth2 related services
// type OAuthServices struct {
// 	Server   *oauth2.Server
// 	Client   *oauth2.Client
// 	Provider *oauth2.Provider
// }
//
// // Ensure containerImpl implements ServicecontainerImpl interface
// var _ ContainerInner = (*containerImpl)(nil)
//
// func NewContainers(
// 	client *data.Clients,
// 	cfg *config.Config,
// 	l logging.Logger,
// ) (ContainerInner, error) {
//
// 	// Initialize logger
// 	var logger logging.Logger
// 	if l != nil {
// 		logger = l
// 	} else {
// 		logging.Init(cfg.Logging.Level, cfg.Environment)
// 		logger = logging.GetLogger()
// 		logger.Info("Starting Frank Server",
// 			logging.String("version", cfg.Version),
// 			logging.String("environment", cfg.Environment),
// 		)
// 	}
//
// 	// init repo
// 	apiKeyRepo := apikeys.NewRepository(client.DB)
// 	orgRepo := organization.NewRepository(client.DB)
// 	userRepo := user.NewRepository(client.DB)
// 	webhookRepo := webhook.NewRepository(client.DB)
// 	webhookEventRepo := webhook.NewEventRepository(client.DB)
// 	sessStore := session.NewRedisStore(client.Redis, "frank_", logger)
// 	templateRepo := email.NewTemplateRepository(client.DB)
// 	rbacRepo := rbac.NewRepository(client)
// 	// templateRepo := passkeys.New(client)
//
// 	// Determine repository type from config
// 	repoPassKeyType := passkeys.RepositoryTypeEnt
// 	if cfg.Passkeys.UseInMemoryRepository {
// 		repoPassKeyType = passkeys.RepositoryTypeInMemory
// 	}
// 	passKeyRepo := passkeys.CreateRepository(repoPassKeyType, client.DB, logger)
//
// 	// Initialize audit log reporting service
// 	// auditLogReportingService := auditlog.NewReportingService(auditLogService, storageService, emailService, logger)
//
// 	sender := email.SenderFactory(&cfg.Email, logger)
// 	emailTemplateManager := email.NewTemplateManager(templateRepo, &cfg.Email, logger)
// 	emailService := email.NewService(&cfg.Email, sender, emailTemplateManager, templateRepo, logger)
//
// 	emailProvider := sms.SenderFactory(cfg, logger)
// 	smsService := sms.NewService(cfg, emailProvider, logger)
//
// 	orgService := organization.NewService(orgRepo, logger)
// 	pwdVerifyManger := user.NewVerificationManager(client.DB, emailService, logger)
// 	pwdManger := user.NewPasswordManager(cfg, client.DB, pwdVerifyManger)
//
// 	enforce := rbac.NewEnforcer(rbacRepo, logger)
// 	rbacService := rbac.NewService(rbacRepo, enforce, logger)
// 	userService := user.NewService(userRepo, pwdManger, pwdVerifyManger, orgService, cfg, logger)
//
// 	// Initialize auth services
// 	cookieHandler := session.NewCookieHandler(cfg, logger)
// 	cookieStore := session.NewCookieStore(
// 		"frank_session",
// 		cfg.Auth.CookieDomain,
// 		cfg.Auth.CookieSecure,
// 		cfg.Auth.CookieHTTPOnly,
// 		cfg.Auth.CookieSameSite,
// 		cfg.Auth.SessionSecretKey,
// 		logger,
// 	)
//
// 	// Initialize session store
// 	sessionManager := session.NewManager(client.DB, cfg, logger, cookieStore)
// 	sessionStore := session.NewManagerStore(sessionManager, cookieHandler, cfg)
// 	session.InitSessionStoreWithStore(sessionStore)
//
// 	authzServ := authz.NewService(client)
//
// 	container := &containerImpl{
// 		cfg:              cfg,
// 		data:             client,
// 		log:              logger,
// 		userRepo:         userRepo,
// 		orgRepo:          orgRepo,
// 		apiKeyRepo:       apiKeyRepo,
// 		webhookRepo:      webhookRepo,
// 		webhookEventRepo: webhookEventRepo,
// 		sessionSore:      sessStore,
// 		templateRepo:     templateRepo,
// 		rbacRepo:         rbacRepo,
// 		passKeyRepo:      passKeyRepo,
// 		rbacService:      rbacService,
//
// 		userService:  userService,
// 		emailService: emailService,
// 		orgService:   orgService,
// 		authz:        authzServ,
// 	}
//
// 	if cfg.Features.EnableMFA {
// 		logger.Info("Initializing MFA")
// 		mfaService := mfa.NewService(client.DB, cfg, logger)
// 		container.mfaService = mfaService
// 	}
//
// 	if cfg.Features.EnablePasswordless {
// 		logger.Info("Initializing passwordless")
// 		passwordlessService, err := passwordless.NewService(cfg, client.DB, logger, emailService, smsService)
// 		if err != nil {
// 			return nil, fmt.Errorf("failed to initialize passwordless service: %w", err)
// 		}
// 		container.passwordlessService = passwordlessService
// 	}
//
// 	if cfg.Features.EnableAPIKeys {
// 		logger.Info("Initializing api keys")
// 		apiKeyService := apikeys.NewService(apiKeyRepo, apikeys.NewValidator(logger), cfg)
// 		container.apiKeyService = apiKeyService
// 	}
//
// 	if cfg.Features.EnableWebhooks {
// 		logger.Info("Initializing Webhooks")
// 		webhookDeliverer := webhook.NewDeliverer(webhookEventRepo, webhookRepo, cfg, logger)
// 		webhookService := webhook.NewService(webhookRepo, webhookEventRepo, webhookDeliverer, cfg, logger)
// 		container.webhookService = webhookService
// 	}
//
// 	if cfg.Features.EnableAPIKeys {
// 		apiKeysValidator := apikeys.NewValidator(logger)
// 		apiKeyService := apikeys.NewService(apiKeyRepo, apiKeysValidator, cfg)
// 		container.apiKeyService = apiKeyService
// 	}
//
// 	if cfg.Features.EnableSSO {
// 		logger.Info("Initializing SSO")
// 		// Initialize SSO service
// 		statsStore := sso.NewEntStateStore(client.DB, logger)
// 		ssoService := sso.New(client.DB, statsStore, cfg, logger)
// 		container.ssoService = ssoService
// 	}
//
// 	if cfg.Features.EnableOAuth2 {
// 		logger.Info("Initializing OAuth2")
// 		// Initialize OAuth services
// 		oauthStorage := oauth2.NewEntStorage(client.DB, logger)
// 		oauthServer := oauth2.NewServer(client.DB, cfg, logger, oauth2.WithStorage(oauthStorage))
// 		oauthClient := oauth2.NewClient(cfg, logger)
// 		if err := oauthClient.InitializeDefaultProviders(); err != nil {
// 			return nil, fmt.Errorf("failed to initialize OAuth providers: %w", err)
// 		}
// 		oauthProvider := oauth2.NewProvider(client.DB, cfg, logger)
//
// 		container.oauthService = &OAuthServices{
// 			Server:   oauthServer,
// 			Client:   oauthClient,
// 			Provider: oauthProvider,
// 		}
// 	}
//
// 	if cfg.Features.EnablePasskeys {
// 		logger.Info("Initializing passkeys")
// 		// Initialize passkey session store
// 		storeType := passkeys.SessionStoreTypeInMemory
// 		if cfg.Redis.Enabled && cfg.Passkeys.UseRedisSessionStore {
// 			storeType = passkeys.SessionStoreTypeRedis
// 		}
//
// 		container.passkeySessionStore = passkeys.CreateSessionStore(
// 			storeType,
// 			cfg,
// 			client.Redis,
// 			logger,
// 		)
//
// 		// Initialize passkey service
// 		pk, err := passkeys.NewService(
// 			cfg,
// 			client.DB,
// 			logger,
// 			container.passkeySessionStore,
// 		)
// 		if err != nil {
// 			return nil, err
// 		}
//
// 		container.passkeyService = pk
// 	}
//
// 	return container, nil
// }
//
// func (d *containerImpl) Config() *config.Config {
// 	return d.cfg
// }
//
// func (d *containerImpl) Cancel() error {
// 	err := d.data.Close()
// 	if err != nil {
// 		return err
// 	}
//
// 	return nil
// }
//
// func (d *containerImpl) AuthZ() authz.Service {
// 	return d.authz
// }
//
// func (d *containerImpl) Close() error {
// 	err := d.data.Close()
// 	if err != nil {
// 		return err
// 	}
//
// 	return nil
// }
//
// func (d *containerImpl) Start() error {
// 	return nil
// }
//
// func (d *containerImpl) Data() *data.Clients {
// 	return d.data
// }
//
// func (d *containerImpl) Logger() logging.Logger {
// 	return d.log
// }
//
// func (d *containerImpl) UserRepo() user.Repository {
// 	return d.userRepo
// }
//
// func (d *containerImpl) UserService() user.Service {
// 	return d.userService
// }
//
// func (d *containerImpl) OrgRepo() organization.Repository {
// 	return d.orgRepo
// }
//
// func (d *containerImpl) OrgService() organization.Service {
// 	return d.orgService
// }
//
// func (d *containerImpl) APIKeyRepo() apikeys.Repository {
// 	return d.apiKeyRepo
// }
//
// func (d *containerImpl) APIKeyService() apikeys.Service {
// 	return d.apiKeyService
// }
//
// func (d *containerImpl) WebhookRepo() webhook.Repository {
// 	return d.webhookRepo
// }
//
// func (d *containerImpl) WebhookEventRepo() webhook.EventRepository {
// 	return d.webhookEventRepo
// }
//
// func (d *containerImpl) WebhookService() webhook.Service {
// 	return d.webhookService
// }
//
// func (d *containerImpl) SessionSore() session.Store {
// 	return d.sessionSore
// }
//
// func (d *containerImpl) EmailService() email.Service {
// 	return d.emailService
// }
//
// func (d *containerImpl) RBACRepo() rbac.Repository {
// 	return d.rbacRepo
// }
//
// func (d *containerImpl) RBACService() rbac.Service {
// 	return d.rbacService
// }
//
// func (d *containerImpl) PasswordlessService() passwordless.Service {
// 	return d.passwordlessService
// }
//
// func (d *containerImpl) Passwordless() passwordless.Service {
// 	return d.passwordlessService
// }
//
// func (d *containerImpl) PassKeysRepo() passkeys.Repository {
// 	return d.passKeyRepo
// }
//
// func (d *containerImpl) PassKeysService() passkeys.Service {
// 	return d.passkeyService
// }
//
// func (d *containerImpl) PassKeySessionStore() passkeys.SessionStore {
// 	return d.passkeySessionStore
// }
//
// func (d *containerImpl) MFAService() mfa.Service {
// 	return d.mfaService
// }
//
// func (d *containerImpl) SSOService() sso.Service {
// 	return d.ssoService
// }
