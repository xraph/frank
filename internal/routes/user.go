package routes

import (
	"github.com/go-chi/chi/v5"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/handlers"
	"github.com/juicycleff/frank/internal/user"
	"github.com/juicycleff/frank/pkg/logging"
)

// UserRoutes handles user-related routes
type UserRoutes struct {
	userService user.Service
	config      *config.Config
	logger      logging.Logger
	handler     *handlers.UserHandler
}

// NewUserRoutes creates a new user routes handler
func NewUserRoutes(
	userService user.Service,
	config *config.Config,
	logger logging.Logger,
) *UserRoutes {
	handler := handlers.NewUserHandler(userService, config, logger)

	return &UserRoutes{
		userService: userService,
		config:      config,
		logger:      logger,
		handler:     handler,
	}
}

// RegisterRoutes registers user routes
func (r *UserRoutes) RegisterRoutes(router chi.Router) {
	router.Route("/users", func(router chi.Router) {
		// User profile routes
		router.Put("/me", r.handler.UpdateCurrentUser)
		router.Get("/me/sessions", r.handler.GetUserSessions)
		router.Delete("/me/sessions/{id}", r.handler.DeleteUserSession)

		// Admin routes
		router.Get("/", r.handler.ListUsers)
		router.Post("/", r.handler.CreateUser)
		router.Get("/{id}", r.handler.GetUser)
		router.Put("/{id}", r.handler.UpdateUser)
		router.Delete("/{id}", r.handler.DeleteUser)
	})
}
