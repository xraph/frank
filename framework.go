package frank

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-redis/redis/v8"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/di"
	"github.com/juicycleff/frank/internal/routes"
	"github.com/juicycleff/frank/internal/server"
	"github.com/juicycleff/frank/pkg/data"
	"github.com/juicycleff/frank/pkg/hooks"
	"github.com/juicycleff/frank/pkg/logging"
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
func WithHooks(hooks *hooks.Hooks) Option {
	return func(f *Frank) error {
		f.hooks = hooks
		return nil
	}
}

// WithCustomRouter allows setting a custom router implementation
func WithCustomRouter(customRouter server.Router) Option {
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
	router        server.Router
	cfg           *config.Config
	log           logging.Logger
	clients       *data.Clients
	hooks         *hooks.Hooks
	chiMux        chi.Router
	di            di.Container
	server        *server.Server
	withServer    bool
	disableRoutes bool
}

// New initializes and returns a new instance of Frank, setting up session store, repositories, services, and routes.
// If cfg is nil, config must be provided via options or defaults will be used.
func New(flagsOpts *server.ConfigFlags, opts ...Option) (*Frank, error) {
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
	container, err := di.NewContainerWithData(f.cfg, f.log, f.clients)
	if err != nil {
		return nil, fmt.Errorf("failed to init container: %w", err)
	}
	f.di = container

	// Initialize router if not set via options
	if f.router == nil {
		f.log.Info("Using Huma framework (default)")
		f.router = routes.NewRouter(f.di, f.chiMux)
	}

	if !f.disableRoutes {
		f.router.RegisterRoutes()
	}

	if f.withServer {
		f.server = server.NewServer(f.router.Chi(), f.di.Config(), f.di.Logger())
	}

	return f, nil
}

// NewWithDefaults creates a new Frank instance with explicit defaults applied
func NewWithDefaults(flagsOpts *server.ConfigFlags, opts ...Option) (*Frank, error) {
	// Prepend defaults to user options
	allOpts := append(Defaults(), opts...)
	return New(flagsOpts, allOpts...)
}

// NewForProduction creates a new Frank instance optimized for production
func NewForProduction(flagsOpts *server.ConfigFlags, opts ...Option) (*Frank, error) {
	// Prepend production defaults to user options
	allOpts := append([]Option{WithProductionDefaults()}, opts...)
	return New(flagsOpts, allOpts...)
}

// NewForDevelopment creates a new Frank instance optimized for development
func NewForDevelopment(flagsOpts *server.ConfigFlags, opts ...Option) (*Frank, error) {
	// Prepend development defaults to user options
	allOpts := append([]Option{WithDevelopmentDefaults()}, opts...)
	return New(flagsOpts, allOpts...)
}

// NewWithConfigPath creates a new Frank instance loading config from specified path
func NewWithConfigPath(flagsOpts *server.ConfigFlags, configPath string, opts ...Option) (*Frank, error) {
	// Prepend config loading option
	allOpts := append([]Option{WithConfigPath(configPath)}, opts...)
	return New(flagsOpts, allOpts...)
}

// NewWithConfigOrDefaults creates a Frank instance, trying to load config or falling back to defaults
func NewWithConfigOrDefaults(flagsOpts *server.ConfigFlags, configPath string, opts ...Option) (*Frank, error) {
	// Use the flexible config loading option
	allOpts := append([]Option{WithConfigOrDefault(configPath)}, opts...)
	return New(flagsOpts, allOpts...)
}

// NewFromConfigFile loads both framework config and app config, with fallbacks
func NewFromConfigFile(flagsOpts *server.ConfigFlags, configPath string, appCfg *config.Config, opts ...Option) (*Frank, error) {
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
	return f.DI().Start(context.Background())
}

// Stop gracefully stops the Frank server
func (f *Frank) Stop() error {
	f.log.Info("Stopping Frank systems")
	return f.di.Stop(context.Background())
}

func (f *Frank) Router() server.Router {
	return f.router
}

func (f *Frank) DI() di.Container {
	return f.di
}

func (f *Frank) Server() *server.Server {
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

		f.server = server.NewServer(f.router.Chi(), f.di.Config(), f.di.Logger())
	}
	return f.server
}

// IsReady checks if Frank is properly initialized and ready to use
func (f *Frank) IsReady() bool {
	return f != nil && f.router != nil && f.di != nil && f.cfg != nil && f.log != nil
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
