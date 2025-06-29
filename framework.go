package frank

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/redis/go-redis/v9"
	server2 "github.com/xraph/frank/pkg/server"

	"github.com/xraph/frank/config"
	"github.com/xraph/frank/internal/di"
	"github.com/xraph/frank/internal/routes"
	"github.com/xraph/frank/pkg/data"
	"github.com/xraph/frank/pkg/hooks"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
	"go.uber.org/zap"
)

// Option represents a functional option for configuring Frank
type Option func(*Frank) error

// WithChiRouter sets up Frank to use Chi router instead of the default Goa router
func WithChiRouter(mux chi.Router) Option {
	return func(f *Frank) error {
		f.chiMux = mux
		return nil
	}
}

// WithHooks sets up Frank to use custom hooks
func WithHooks(hooks hooks.Hooks) Option {
	return func(f *Frank) error {
		f.hooks = hooks
		return nil
	}
}

// WithCustomRouter allows setting a custom router implementation
func WithCustomRouter(customRouter server2.Router) Option {
	return func(f *Frank) error {
		f.router = customRouter
		return nil
	}
}

func WithDataClients(clients *data.Clients) Option {
	return func(f *Frank) error {
		f.clients = clients
		return nil
	}
}

// WithPluginManager sets up Frank to use a plugin manager
func WithPluginManager(pluginManager *hooks.PluginManager) Option {
	return func(f *Frank) error {
		f.pluginManager = pluginManager
		return nil
	}
}

// WithAutoHooksSetup automatically sets up enhanced hooks system
func WithAutoHooksSetup() Option {
	return func(f *Frank) error {
		if f.log == nil {
			f.log = logging.NewDefaultLogger()
		}

		// Create enhanced hooks system
		f.hooks = hooks.NewHooks(f.log)

		// Create plugin manager
		f.pluginManager = hooks.NewPluginManager(f.log)

		// Setup default hooks
		setupDefaultHooks(f.hooks, f.log)

		return nil
	}
}

// WithLogger sets a custom logger
func WithLogger(logger logging.Logger) Option {
	return func(f *Frank) error {
		f.log = logger
		return nil
	}
}

// WithConfig sets a custom config
func WithConfig(cfg *config.Config) Option {
	return func(f *Frank) error {
		f.cfg = cfg
		return nil
	}
}

// WithConfigPath loads config from specified path
func WithConfigPath(configPath string) Option {
	return func(f *Frank) error {
		cfg, err := config.Load(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config from path %s: %w", configPath, err)
		}
		f.cfg = cfg
		return nil
	}
}

// WithDefaultConfig creates a default configuration
func WithDefaultConfig() Option {
	return func(f *Frank) error {
		cfg, err := config.Load("")
		if err != nil {
			return fmt.Errorf("failed to load default config: %w", err)
		}
		f.cfg = cfg
		return nil
	}
}

func WithNoOpsForTesting() Option {
	return func(f *Frank) error {
		if f.log == nil {
			f.log = logging.NewDefaultLogger()
		}

		// Create mock registry with NoOps
		mockRegistry := hooks.NewMockHookRegistry(f.log)
		f.hooks = hooks.NewNoOpHooks(f.log)

		// Enable mock mode immediately
		mockRegistry.EnableMockMode()

		return nil
	}
}

// WithConfigOrDefault tries to load config from path, falls back to defaults
func WithConfigOrDefault(configPath string) Option {
	return func(f *Frank) error {
		if configPath == "" {
			f.log.Info("No config path provided, using default config")
			cfg, err := config.Load("")
			if err != nil {
				return fmt.Errorf("failed to load default config: %w", err)
			}
			f.cfg = cfg
			return nil
		}

		cfg, err := config.Load(configPath)
		if err != nil {
			f.log.Warn("Failed to load config from path, using defaults", zap.String("path", configPath), zap.Error(err))
			cfg, err := config.Load("")
			if err != nil {
				return fmt.Errorf("failed to load default config: %w", err)
			}
			f.cfg = cfg
			return nil
		}

		f.cfg = cfg
		f.log.Info("Successfully loaded config", zap.String("path", configPath))
		return nil
	}
}

func WithRedisClient(client *redis.Client) Option {
	return func(f *Frank) error {
		f.clients.Redis = client
		return nil
	}
}

func WithServerEnabled() Option {
	return func(f *Frank) error {
		f.withServer = true
		return nil
	}
}

func WithRoutesDisabled() Option {
	return func(f *Frank) error {
		f.disableRoutes = true
		return nil
	}
}

func WithMountOptions(mountOpts *server2.MountOptions) Option {
	return func(f *Frank) error {
		f.mountOpts = mountOpts
		return nil
	}
}

// Defaults returns a slice of default options for Frank
func Defaults() []Option {
	return []Option{
		WithDefaultConfig(),
		WithLogger(logging.NewDefaultLogger()),
	}
}

// WithDefaults applies all default options
func WithDefaults() Option {
	return func(f *Frank) error {
		defaults := Defaults()
		for _, opt := range defaults {
			if err := opt(f); err != nil {
				return fmt.Errorf("failed to apply default option: %w", err)
			}
		}
		return nil
	}
}

// WithProductionDefaults applies production-ready defaults
func WithProductionDefaults() Option {
	return func(f *Frank) error {
		productionOpts := []Option{
			WithLogger(logging.NewProductionLogger()),
		}

		for _, opt := range productionOpts {
			if err := opt(f); err != nil {
				return fmt.Errorf("failed to apply production default: %w", err)
			}
		}
		return nil
	}
}

// WithDevelopmentDefaults applies development-friendly defaults
func WithDevelopmentDefaults() Option {
	return func(f *Frank) error {
		devOpts := []Option{
			WithLogger(logging.NewDevelopmentLogger()),
		}

		for _, opt := range devOpts {
			if err := opt(f); err != nil {
				return fmt.Errorf("failed to apply development default: %w", err)
			}
		}
		return nil
	}
}

type Frank struct {
	router        server2.Router
	cfg           *config.Config
	log           logging.Logger
	clients       *data.Clients
	hooks         hooks.Hooks
	chiMux        chi.Router
	di            di.Container
	server        *server2.Server
	mountOpts     *server2.MountOptions
	withServer    bool
	disableRoutes bool

	// Plugin system
	pluginManager *hooks.PluginManager
}

// New initializes and returns a new instance of Frank, setting up session store, repositories, services, and routes.
// If cfg is nil, config must be provided via options or defaults will be used.
func New(flagsOpts *server2.ConfigFlags, opts ...Option) (*Frank, error) {
	// Initialize Frank with minimal setup
	f := &Frank{}

	// Apply default options first if no custom options provided
	if len(opts) == 0 {
		defaults := Defaults()
		for _, opt := range defaults {
			if err := opt(f); err != nil {
				return nil, fmt.Errorf("failed to apply default option: %w", err)
			}
		}
	} else {
		// Apply provided options
		for _, opt := range opts {
			if err := opt(f); err != nil {
				return nil, fmt.Errorf("failed to apply option: %w", err)
			}
		}
	}

	// Ensure we have essential components
	if f.log == nil {
		f.log = logging.NewDefaultLogger()
	}

	if f.cfg == nil {
		cfg2, err := config.Load(flagsOpts.ConfigPath)
		if err != nil {
			f.log.Error("Failed to load configuration default", zap.Error(err))
			return nil, fmt.Errorf("failed to load configuration: %w", err)
		}
		f.cfg = cfg2
	}

	if f.clients == nil {
		dataClients := data.NewClients(f.cfg, f.log, nil, nil)

		if f.cfg.Redis.Enabled {
			redisClient := redis.NewUniversalClient(&redis.UniversalOptions{
				Addrs:           strings.Split(f.cfg.Redis.Host, ","),
				Password:        f.cfg.Redis.Password,
				DB:              f.cfg.Redis.Database,
				MaxRetries:      f.cfg.Redis.MaxRetries,
				MinRetryBackoff: f.cfg.Redis.MinRetryBackoff,
				MaxRetryBackoff: f.cfg.Redis.MaxRetryBackoff,
				DialTimeout:     f.cfg.Redis.DialTimeout,
				ReadTimeout:     f.cfg.Redis.ReadTimeout,
				WriteTimeout:    f.cfg.Redis.WriteTimeout,
			})
			dataClients.Redis = redisClient
		}

		f.clients = dataClients
	}

	// Run Migration only if not skipped
	if f.cfg.Database.AutoMigrate {
		f.log.Info("Running auto migration...")
		err := f.clients.RunAutoMigration()
		if err != nil {
			f.log.Error("Failed to run auto migration", zap.Error(err))
			// Instead of failing completely, log the error and continue
			// This allows the application to start even if migration fails
			f.log.Warn("Continuing without migration - some features may not work properly")
		} else {
			f.log.Info("Auto migration completed successfully")
		}
	} else {
		f.log.Info("Skipping auto migration")
	}

	// Init repos - ensure this happens after migration attempt
	container, err := di.NewContainerWithData(f.cfg, f.log, f.clients, f.hooks)
	if err != nil {
		return nil, fmt.Errorf("failed to init container: %w", err)
	}
	f.di = container

	// Initialize plugins with the hook registry
	if f.pluginManager != nil && f.hooks != nil {
		if err := f.pluginManager.Initialize(f.hooks.Registry()); err != nil {
			f.log.Error("Failed to initialize plugins", zap.Error(err))
		}
	}

	// Initialize router if not set via options
	if f.router == nil {
		f.log.Info("Using Huma framework (default)")
		if f.mountOpts == nil {
			f.log.Info("Using default router setup")
			f.router = routes.NewRouter(f.di, f.chiMux)
		} else {
			f.log.Info("Using router with embedded options", zap.String("base_path", f.mountOpts.BasePath))
			f.router = routes.NewRouterWithOptions(f.di, f.chiMux, f.mountOpts)
		}
	}

	if !f.disableRoutes {
		f.router.RegisterRoutes()
	}

	if f.withServer {
		f.server = server2.NewServer(f.router.Chi(), f.di.Config(), f.di.Logger())
	}

	return f, nil
}

// NewWithDefaults creates a new Frank instance with explicit defaults applied
func NewWithDefaults(flagsOpts *server2.ConfigFlags, opts ...Option) (*Frank, error) {
	// Prepend defaults to user options
	allOpts := append(Defaults(), opts...)
	return New(flagsOpts, allOpts...)
}

// NewForProduction creates a new Frank instance optimized for production
func NewForProduction(flagsOpts *server2.ConfigFlags, opts ...Option) (*Frank, error) {
	// Prepend production defaults to user options
	allOpts := append([]Option{WithProductionDefaults()}, opts...)
	return New(flagsOpts, allOpts...)
}

// NewForDevelopment creates a new Frank instance optimized for development
func NewForDevelopment(flagsOpts *server2.ConfigFlags, opts ...Option) (*Frank, error) {
	// Prepend development defaults to user options
	allOpts := append([]Option{WithDevelopmentDefaults()}, opts...)
	return New(flagsOpts, allOpts...)
}

// NewWithConfigPath creates a new Frank instance loading config from specified path
func NewWithConfigPath(flagsOpts *server2.ConfigFlags, configPath string, opts ...Option) (*Frank, error) {
	// Prepend config loading option
	allOpts := append([]Option{WithConfigPath(configPath)}, opts...)
	return New(flagsOpts, allOpts...)
}

// NewWithConfigOrDefaults creates a Frank instance, trying to load config or falling back to defaults
func NewWithConfigOrDefaults(flagsOpts *server2.ConfigFlags, configPath string, opts ...Option) (*Frank, error) {
	// Use the flexible config loading option
	allOpts := append([]Option{WithConfigOrDefault(configPath)}, opts...)
	return New(flagsOpts, allOpts...)
}

// NewFromConfigFile loads both framework config and app config, with fallbacks
func NewFromConfigFile(flagsOpts *server2.ConfigFlags, configPath string, appCfg *config.Config, opts ...Option) (*Frank, error) {
	var configOpts []Option

	// Handle app config priority
	if appCfg != nil {
		configOpts = append(configOpts, WithConfig(appCfg))
	} else {
		// Try to load from file, fall back to defaults
		configOpts = append(configOpts, WithConfigOrDefault(configPath))
	}

	// Add other options
	allOpts := append(configOpts, opts...)
	return New(flagsOpts, allOpts...)
}

// LoadConfigWithFallback replicates your original config loading pattern
// This is a helper that matches your exact code logic
func LoadConfigWithFallback(configPath string, appCfg *config.Config) (*config.Config, error) {
	if appCfg != nil {
		return appCfg, nil
	}

	// Try to load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		// Return default config instead of failing
		return config.Load("")
	}

	return cfg, nil
}

// Start starts the Frank server (add this method for completeness)
func (f *Frank) Start() error {
	f.log.Info("Starting Frank systems")

	// Execute system startup hooks
	if f.hooks != nil {
		ctx := context.Background()
		result := f.hooks.Registry().Execute(ctx, hooks.HookSystemStartup, nil)
		if !result.Success && result.Error != nil {
			f.log.Error("Startup hooks failed", zap.Error(result.Error))
			// Continue startup even if hooks fail
		}
	}

	return f.DI().Start(context.Background())
}

// Stop gracefully stops the Frank server
func (f *Frank) Stop() error {
	f.log.Info("Stopping Frank systems")

	// Execute system shutdown hooks
	if f.hooks != nil {
		ctx := context.Background()
		result := f.hooks.Registry().Execute(ctx, hooks.HookSystemShutdown, nil)
		if !result.Success && result.Error != nil {
			f.log.Error("Shutdown hooks failed", zap.Error(result.Error))
		}
	}

	// Shutdown plugin manager
	if f.pluginManager != nil {
		if err := f.pluginManager.Shutdown(); err != nil {
			f.log.Error("Failed to shutdown plugin manager", zap.Error(err))
		}
	}

	return f.di.Stop(context.Background())
}

func (f *Frank) Router() server2.Router {
	return f.router
}

func (f *Frank) DI() di.Container {
	return f.di
}

func (f *Frank) Server() *server2.Server {
	// Add nil checks to prevent panic
	if f == nil {
		return nil
	}

	if f.server == nil {
		// Ensure dependencies are not nil before creating server
		if f.router == nil || f.di == nil {
			// Log the error if possible
			if f.log != nil {
				f.log.Error("Cannot create server: missing dependencies",
					zap.Bool("router_nil", f.router == nil),
					zap.Bool("di_nil", f.di == nil))
			}
			return nil
		}

		f.server = server2.NewServer(f.router.Chi(), f.di.Config(), f.di.Logger())
	}
	return f.server
}

// IsReady checks if Frank is properly initialized and ready to use
func (f *Frank) IsReady() bool {
	return f != nil && f.router != nil && f.di != nil && f.cfg != nil && f.log != nil
}

// Hooks returns the enhanced hooks system
func (f *Frank) Hooks() hooks.Hooks {
	return f.hooks
}

// PluginManager returns the plugin manager
func (f *Frank) PluginManager() *hooks.PluginManager {
	return f.pluginManager
}

// RegisterPlugin registers a new plugin
func (f *Frank) RegisterPlugin(plugin hooks.HookPlugin) error {
	if f.pluginManager == nil {
		return fmt.Errorf("plugin manager not initialized")
	}

	if err := f.pluginManager.Register(plugin); err != nil {
		return err
	}

	// Initialize the plugin with the hook registry
	if f.hooks != nil {
		return plugin.Initialize(f.hooks.Registry())
	}

	return nil
}

/*
Usage Examples:

1. Basic usage with automatic defaults:
   frank, err := frank.New(clients, nil) // Config will use defaults

2. With existing config:
   frank, err := frank.New(clients, config)

3. Load config from file:
   frank, err := frank.NewWithConfigPath(clients, "config.yaml")

4. Load config with fallback to defaults:
   frank, err := frank.NewWithConfigOrDefaults(clients, "config.yaml")

5. Replicate your original config loading pattern:
   frank, err := frank.NewFromConfigFile(clients, opts.ConfigPath, appCfg)

6. Production setup with config file:
   frank, err := frank.NewForProduction(clients, nil,
       frank.WithConfigPath("production.yaml"),
   )

7. Development setup with config fallback:
   frank, err := frank.NewForDevelopment(clients, nil,
       frank.WithConfigOrDefault(opts.ConfigPath),
   )

8. Custom configuration with explicit options:
   frank, err := frank.New(clients, nil,
       frank.WithConfigPath("my-config.yaml"),
       frank.WithLogger(customLogger),
       frank.WithChiRouter(chiMux),
   )

9. Handle missing config gracefully:
   frank, err := frank.New(clients, nil,
       frank.WithConfigOrDefault(""), // Empty path uses defaults
       frank.WithProductionDefaults(),
   )

10. Your original pattern simplified:
    // Instead of:
    // var cfg *config.Config
    // if appCfg != nil {
    //     cfg = appCfg
    // } else {
    //     cfg, err = config.Load(opts.ConfigPath)
    //     if err != nil {
    //        log.Fatalf(ctx, err, "Failed to load configuration: ")
    //     }
    // }
    // frank, err := frank.New(clients, cfg)

    // Use this:
    frank, err := frank.NewFromConfigFile(clients, opts.ConfigPath, appCfg)
*/

func setupDefaultHooks(enhancedHooks hooks.Hooks, logger logging.Logger) {
	// Default login hook - log successful logins
	enhancedHooks.OnLogin(func(ctx *hooks.HookContext) *hooks.HookResult {
		if loginResponse, ok := ctx.Data.(*model.LoginResponse); ok {
			logger.Info("User login successful",
				logging.String("user_id", loginResponse.User.ID.String()),
				logging.String("email", loginResponse.User.Email),
				logging.String("ip", ctx.IPAddress),
				logging.String("user_agent", ctx.UserAgent),
			)
		}
		return &hooks.HookResult{Success: true}
	})

	// Default registration hook - log new user registrations
	enhancedHooks.OnRegister(func(ctx *hooks.HookContext) *hooks.HookResult {
		if registerResponse, ok := ctx.Data.(*model.RegisterResponse); ok {
			logger.Info("New user registered",
				logging.String("user_id", registerResponse.User.ID.String()),
				logging.String("email", registerResponse.User.Email),
				logging.String("ip", ctx.IPAddress),
			)
		}
		return &hooks.HookResult{Success: true}
	})

	// Default user creation hook - initialize user defaults
	enhancedHooks.OnUserCreate(func(ctx *hooks.HookContext) *hooks.HookResult {
		if user, ok := ctx.Data.(*model.User); ok {
			logger.Info("User created",
				logging.String("user_id", user.ID.String()),
				logging.String("email", user.Email),
				logging.String("type", user.UserType.String()),
			)
		}
		return &hooks.HookResult{Success: true}
	})

	// Security monitoring hook - detect suspicious activities
	enhancedHooks.Registry().Register(hooks.HookAfterLogin,
		hooks.NewBaseHookHandler("security_monitor").
			WithPriority(hooks.PriorityCritical).
			WithTimeout(5*time.Second).
			WithExecuteFunc(func(ctx *hooks.HookContext) *hooks.HookResult {
				// Basic security checks
				if ctx.IPAddress != "" {
					// Could integrate with threat intelligence, rate limiting, etc.
					logger.Debug("Security check passed",
						logging.String("ip", ctx.IPAddress),
						logging.String("user_agent", ctx.UserAgent),
					)
				}
				return &hooks.HookResult{Success: true}
			}))

	// System health check hook
	enhancedHooks.Registry().Register(hooks.HookHealthCheck,
		hooks.NewBaseHookHandler("health_check").
			WithExecuteFunc(func(ctx *hooks.HookContext) *hooks.HookResult {
				// Perform health checks
				logger.Debug("Health check executed")
				return &hooks.HookResult{Success: true}
			}))
}
