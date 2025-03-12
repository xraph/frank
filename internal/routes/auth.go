package routes

import (
	"github.com/go-chi/chi/v5"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/auth/session"
	"github.com/juicycleff/frank/internal/handlers"
	"github.com/juicycleff/frank/internal/user"
	"github.com/juicycleff/frank/pkg/logging"
)

// AuthRoutes handles authentication routes
type AuthRoutes struct {
	userService    user.Service
	sessionManager *session.Manager
	config         *config.Config
	logger         logging.Logger
	handler        *handlers.AuthHandler
}

// NewAuthRoutes creates a new auth routes handler
func NewAuthRoutes(
	userService user.Service,
	sessionManager *session.Manager,
	config *config.Config,
	logger logging.Logger,
) *AuthRoutes {
	handler := handlers.NewAuthHandler(userService, config, logger, sessionManager)

	return &AuthRoutes{
		userService:    userService,
		sessionManager: sessionManager,
		config:         config,
		logger:         logger,
		handler:        handler,
	}
}

// RegisterPublicRoutes registers routes that don't require authentication
func (r *AuthRoutes) RegisterPublicRoutes(router chi.Router) {
	router.Route("/auth", func(router chi.Router) {
		router.Post("/login", r.handler.Login)
		router.Post("/register", r.handler.Register)
		router.Post("/refresh", r.handler.RefreshToken)
		router.Post("/forgot-password", r.handler.ForgotPassword)
		router.Post("/reset-password", r.handler.ResetPassword)
		router.Post("/verify-email", r.handler.VerifyEmail)
	})
}

// RegisterRoutes registers routes that require authentication
func (r *AuthRoutes) RegisterRoutes(router chi.Router) {
	router.Post("/auth/logout", r.handler.Logout)
	router.Get("/auth/me", r.handler.GetCurrentUser)
	// router.Route("", func(router chi.Router) {
	// })
}
