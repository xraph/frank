package routesgoa

import (
	"github.com/go-chi/chi/v5"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/auth/sso"
	"github.com/juicycleff/frank/internal/handlers"
	"github.com/juicycleff/frank/pkg/logging"
)

// SSORoutes handles Single Sign-On routes
type SSORoutes struct {
	ssoService sso.Service
	config     *config.Config
	logger     logging.Logger
	handler    *handlers.SSOHandler
}

// NewSSORoutes creates a new SSO routes handler
func NewSSORoutes(
	ssoService sso.Service,
	config *config.Config,
	logger logging.Logger,
) *SSORoutes {
	handler := handlers.NewSSOHandler(ssoService, config, logger)

	return &SSORoutes{
		ssoService: ssoService,
		config:     config,
		logger:     logger,
		handler:    handler,
	}
}

// RegisterPublicRoutes registers public SSO routes
func (r *SSORoutes) RegisterPublicRoutes(router chi.Router) {
	router.Route("/auth/sso", func(router chi.Router) {
		router.Get("/providers", r.handler.SSOProvidersList)
		router.Get("/providers/{provider}", r.handler.SSOProviderAuth)
		router.Get("/callback/{provider}", r.handler.SSOProviderCallback)
	})
}

// RegisterRoutes registers protected SSO routes that don't require org context
func (r *SSORoutes) RegisterRoutes(router chi.Router) {
	// Currently empty - all routes require either public access or org context
}

// RegisterOrganizationRoutes registers organization-specific SSO routes
func (r *SSORoutes) RegisterOrganizationRoutes(router chi.Router) {
	router.Route("/organizations/{orgId}/sso", func(router chi.Router) {
		// Organization-specific SSO provider management would go here
		// This is for enterprise SSO configuration
		// router.Get("/providers", r.handler.GetOrganizationSSOProviders)
		// router.Post("/providers", r.handler.CreateOrganizationSSOProvider)
		// router.Get("/providers/{id}", r.handler.GetOrganizationSSOProvider)
		// router.Put("/providers/{id}", r.handler.UpdateOrganizationSSOProvider)
		// router.Delete("/providers/{id}", r.handler.DeleteOrganizationSSOProvider)
	})
}
