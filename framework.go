package frank

import (
	"fmt"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/controllers"
	"github.com/juicycleff/frank/internal/repo"
	"github.com/juicycleff/frank/internal/router"
	"github.com/juicycleff/frank/internal/routes"
	"github.com/juicycleff/frank/internal/services"
	"github.com/juicycleff/frank/pkg/data"
	"github.com/juicycleff/frank/pkg/logging"
)

type Frank struct {
	Router   router.FrankRouter
	Services *services.Services
	Config   *config.Config
	Logger   logging.Logger
	Clients  *data.Clients
	Repo     *repo.Repo
}

// New initializes and returns a new instance of Frank, setting up session store, repositories, services, and routes.
func New(clients *data.Clients, cfg *config.Config, logger logging.Logger) (*Frank, error) {
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
	if cfg.UseGoa {
		logger.Info("Using Goa framework")
		rtr = controllers.NewControllers(clients, svcs, cfg, logger)
	} else if cfg.UseHuma {
		logger.Info("Using Huma with Chi router")
		rtr = routes.NewHumaRouter(clients, svcs, cfg, logger)
	} else {
		logger.Info("Using Chi router")
		rtr = routes.NewRouter(clients, svcs, cfg, logger)
	}

	return &Frank{
		Router:   rtr,
		Services: svcs,
		Config:   cfg,
		Logger:   logger,
		Clients:  clients,
		Repo:     repos,
	}, nil
}
