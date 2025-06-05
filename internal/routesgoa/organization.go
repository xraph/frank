package routesgoa

import (
	"github.com/go-chi/chi/v5"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/handlers"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/organization"
)

// OrganizationRoutes handles organization routes
type OrganizationRoutes struct {
	orgService organization.Service
	config     *config.Config
	logger     logging.Logger
	handler    *handlers.OrganizationHandler
}

// NewOrganizationRoutes creates a new organization routes handler
func NewOrganizationRoutes(
	orgService organization.Service,
	config *config.Config,
	logger logging.Logger,
) *OrganizationRoutes {
	handler := handlers.NewOrganizationHandler(orgService, config, logger)

	return &OrganizationRoutes{
		orgService: orgService,
		config:     config,
		logger:     logger,
		handler:    handler,
	}
}

// RegisterRoutes registers general organization routes
func (r *OrganizationRoutes) RegisterRoutes(router chi.Router) {
	router.Get("/organizations", r.handler.ListOrganizations)
	router.Post("/organizations", r.handler.CreateOrganization)
	router.Get("/organizations/{id}", r.handler.GetOrganization)
}

// RegisterOrganizationRoutes registers routes that require organization context
func (r *OrganizationRoutes) RegisterOrganizationRoutes(router chi.Router) {
	router.Route("/organizations", func(router chi.Router) {
		// Organization management
		router.Put("/{id}", r.handler.UpdateOrganization)
		router.Delete("/{id}", r.handler.DeleteOrganization)

		// Member management
		router.Get("/{id}/members", r.handler.ListOrganizationMembers)
		router.Post("/{id}/members", r.handler.AddOrganizationMember)
		router.Put("/{id}/members/{userId}", r.handler.UpdateOrganizationMember)
		router.Delete("/{id}/members/{userId}", r.handler.RemoveOrganizationMember)

		// Feature management
		router.Get("/{id}/features", r.handler.ListOrganizationFeatures)
		router.Post("/{id}/features", r.handler.EnableOrganizationFeature)
		router.Delete("/{id}/features/{featureKey}", r.handler.DisableOrganizationFeature)
	})
}
