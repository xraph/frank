package routesgoa

import (
	"github.com/go-chi/chi/v5"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/auth/passwordless"
	"github.com/juicycleff/frank/internal/handlers"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/user"
)

// PasswordlessRoutes handles passwordless authentication routes
type PasswordlessRoutes struct {
	passwordlessService passwordless.Service
	userService         user.Service
	config              *config.Config
	logger              logging.Logger
	handler             *handlers.PasswordlessHandler
}

// NewPasswordlessRoutes creates a new passwordless routes handler
func NewPasswordlessRoutes(
	passwordlessService passwordless.Service,
	userService user.Service,
	config *config.Config,
	logger logging.Logger,
) *PasswordlessRoutes {
	handler := handlers.NewPasswordlessHandler(passwordlessService, userService, config, logger)

	return &PasswordlessRoutes{
		passwordlessService: passwordlessService,
		userService:         userService,
		config:              config,
		logger:              logger,
		handler:             handler,
	}
}

// RegisterPublicRoutes registers public passwordless routes
func (r *PasswordlessRoutes) RegisterPublicRoutes(router chi.Router) {
	router.Route("/auth/passwordless", func(router chi.Router) {
		router.Post("/email", r.handler.PasswordlessEmail)
		router.Post("/sms", r.handler.PasswordlessSMS)
		router.Post("/verify", r.handler.PasswordlessVerify)
		router.Get("/methods", r.handler.GetPasswordlessMethods)
	})
}

// RegisterRoutes registers protected passwordless routes
func (r *PasswordlessRoutes) RegisterRoutes(router chi.Router) {
	router.Post("/auth/passwordless/magic-link", r.handler.GenerateMagicLink)
}
