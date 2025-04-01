package frank

import (
	"fmt"

	"github.com/go-chi/chi/v5"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/controllers"
	"github.com/juicycleff/frank/internal/hooks"
	"github.com/juicycleff/frank/internal/repo"
	"github.com/juicycleff/frank/internal/router"
	"github.com/juicycleff/frank/internal/services"
	"github.com/juicycleff/frank/pkg/data"
	"github.com/juicycleff/frank/pkg/logging"
)

// Option represents a functional option for configuring Frank
type Option func(*Frank) error

// WithChiRouter sets up Frank to use Chi router instead of the default Goa router
func WithChiRouter(mux *chi.Mux) Option {
	return func(f *Frank) error {
		f.chiMux = mux
		return nil
	}
}

// WithHooks sets up Frank to use Chi router instead of the default Goa router
func WithHooks(hooks *hooks.Hooks) Option {
	return func(f *Frank) error {
		f.hooks = hooks
		return nil
	}
}

// WithCustomRouter allows setting a custom router implementation
func WithCustomRouter(customRouter router.FrankRouter) Option {
	return func(f *Frank) error {
		f.Router = customRouter
		return nil
	}
}

type Frank struct {
	Router   router.FrankRouter
	Services *services.Services
	Config   *config.Config
	Logger   logging.Logger
	Clients  *data.Clients
	Repo     *repo.Repo
	hooks    *hooks.Hooks

	chiMux *chi.Mux
}

// New initializes and returns a new instance of Frank, setting up session store, repositories, services, and routes.
func New(clients *data.Clients, cfg *config.Config, logger logging.Logger, opts ...Option) (*Frank, error) {
	// Run Migration
	err := clients.RunAutoMigration()
	if err != nil {
		return nil, err
	}

	// Init repos
	repos := repo.New(cfg, clients.DB, logger)

	// Initialize services
	svcs, err := services.New(repos, cfg, clients, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize user service: %w", err)
	}

	// Init routes
	var rtr router.FrankRouter

	f := &Frank{
		Router:   rtr,
		Services: svcs,
		Config:   cfg,
		Logger:   logger,
		Clients:  clients,
		Repo:     repos,
	}

	// Apply options if any
	for _, opt := range opts {
		if err := opt(f); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	logger.Info("Using Goa framework (default)")
	f.Router = controllers.NewControllers(clients, svcs, cfg, f.hooks, logger, f.chiMux)

	return f, nil
}
