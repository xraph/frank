package routes

import (
	"github.com/go-chi/chi/v5"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/apikeys"
	"github.com/juicycleff/frank/internal/handlers"
	"github.com/juicycleff/frank/pkg/logging"
)

// APIKeyRoutes handles API key routes
type APIKeyRoutes struct {
	apiKeyService apikeys.Service
	config        *config.Config
	logger        logging.Logger
	handler       *handlers.APIKeyHandler
}

// NewAPIKeyRoutes creates a new API key routes handler
func NewAPIKeyRoutes(
	apiKeyService apikeys.Service,
	config *config.Config,
	logger logging.Logger,
) *APIKeyRoutes {
	handler := handlers.NewAPIKeyHandler(apiKeyService, config, logger)

	return &APIKeyRoutes{
		apiKeyService: apiKeyService,
		config:        config,
		logger:        logger,
		handler:       handler,
	}
}

// RegisterRoutes registers API key routes
func (r *APIKeyRoutes) RegisterRoutes(router chi.Router) {
	router.Route("/api-keys", func(router chi.Router) {
		router.Get("/", r.handler.ListAPIKeys)
		router.Post("/", r.handler.CreateAPIKey)
		router.Get("/validate", r.handler.ValidateAPIKey)

		router.Route("/{id}", func(router chi.Router) {
			router.Get("/", r.handler.GetAPIKey)
			router.Put("/", r.handler.UpdateAPIKey)
			router.Delete("/", r.handler.DeleteAPIKey)
		})
	})
}
