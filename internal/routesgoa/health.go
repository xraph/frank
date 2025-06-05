package routesgoa

import (
	"github.com/go-chi/chi/v5"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/handlers"
	"github.com/juicycleff/frank/pkg/data"
	"github.com/juicycleff/frank/pkg/logging"
)

// HealthRoutes handles user-related routes
type HealthRoutes struct {
	config  *config.Config
	logger  logging.Logger
	handler *handlers.HealthChecker
}

// NewHealthRoutes creates a new user routes handler
func NewHealthRoutes(
	clients *data.Clients,
	cfg *config.Config,
	logger logging.Logger,
) *HealthRoutes {
	handler := handlers.NewHealthChecker(clients, cfg)

	return &HealthRoutes{
		config:  cfg,
		logger:  logger,
		handler: handler,
	}
}

// RegisterPublicRoutes registers public Permission routes
func (r *HealthRoutes) RegisterPublicRoutes(router chi.Router) {
	router.Group(func(router chi.Router) {
		router.Get("/__health", r.handler.HealthCheck)
		router.Post("/__ready", r.handler.ReadyCheck)
	})
}
