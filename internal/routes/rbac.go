package routes

import (
	"github.com/go-chi/chi/v5"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/handlers"
	"github.com/juicycleff/frank/internal/rbac"
	"github.com/juicycleff/frank/pkg/logging"
)

// RBACRoutes handles user-related routes
type RBACRoutes struct {
	rbacService rbac.Service
	config      *config.Config
	logger      logging.Logger
	handler     *handlers.RBACHandler
}

// NewRBACRoutes creates a new user routes handler
func NewRBACRoutes(
	rbacService rbac.Service,
	config *config.Config,
	logger logging.Logger,
) *RBACRoutes {
	handler := handlers.NewRBACHandler(rbacService, config, logger)

	return &RBACRoutes{
		rbacService: rbacService,
		config:      config,
		logger:      logger,
		handler:     handler,
	}
}

// RegisterPublicRoutes registers public Permission routes
func (r *RBACRoutes) RegisterPublicRoutes(router chi.Router) {}

// RegisterPermissionsRoutes registers routes for managing permissions, including create, read, update, and delete operations.
func (r *RBACRoutes) RegisterPermissionsRoutes(router chi.Router) {
	router.Route("/permissions", func(router chi.Router) {
		router.Get("/", r.handler.ListPermissions)
		router.Post("/", r.handler.CreatePermission)
		router.Get("/{id}", r.handler.GetPermission)
		router.Put("/{id}", r.handler.UpdatePermission)
		router.Delete("/{id}", r.handler.DeletePermission)
	})
}

// RegisterRolesRoutes registers HTTP routes for role management, including CRUD operations and permissions management.
func (r *RBACRoutes) RegisterRolesRoutes(router chi.Router) {
	router.Route("/roles", func(router chi.Router) {
		router.Get("/", r.handler.ListRoles)
		router.Post("/", r.handler.CreateRole)
		router.Get("/{id}", r.handler.GetRole)
		router.Put("/{id}", r.handler.UpdateRole)
		router.Delete("/{id}", r.handler.DeleteRole)

		// Role permissions
		router.Get("/{id}/permissions", r.handler.ListRolePermissions)
		router.Post("/{id}/permissions", r.handler.AddRolePermission)
		router.Delete("/{id}/permissions/{permissionId}", r.handler.RemoveRolePermission)
	})
}
