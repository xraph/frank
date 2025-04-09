package routes

import (
	"github.com/go-chi/chi/v5"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/email"
	"github.com/juicycleff/frank/internal/handlers"
	"github.com/juicycleff/frank/pkg/logging"
)

// EmailRoutes handles authentication routes
type EmailRoutes struct {
	emailService email.Service
	config       *config.Config
	logger       logging.Logger
	handler      *handlers.EmailHandler
}

// NewEmailRoutes creates a new auth routes handler
func NewEmailRoutes(
	emailService email.Service,
	config *config.Config,
	logger logging.Logger,
) *EmailRoutes {
	handler := handlers.NewEmailHandler(emailService, config, logger)

	return &EmailRoutes{
		emailService: emailService,
		config:       config,
		logger:       logger,
		handler:      handler,
	}
}

// RegisterRoutes registers routes that require authentication
func (r *EmailRoutes) RegisterRoutes(router chi.Router) {
	// Email template routes
	router.Route("/email-templates", func(router chi.Router) {
		router.Get("/", r.handler.ListTemplates)
		router.Post("/", r.handler.CreateTemplate)
		router.Get("/{id}", r.handler.GetTemplate)
		router.Put("/{id}", r.handler.UpdateTemplate)
		router.Delete("/{id}", r.handler.DeleteTemplate)
	})
}
