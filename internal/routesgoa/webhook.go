package routesgoa

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/handlers"
	"github.com/juicycleff/frank/internal/webhook"
	"github.com/juicycleff/frank/pkg/logging"
)

// WebhookRoutes handles webhook routes
type WebhookRoutes struct {
	webhookService webhook.Service
	config         *config.Config
	logger         logging.Logger
	handler        *handlers.WebhookHandler
}

// NewWebhookRoutes creates a new webhook routes handler
func NewWebhookRoutes(
	webhookService webhook.Service,
	config *config.Config,
	logger logging.Logger,
) *WebhookRoutes {
	handler := handlers.NewWebhookHandler(webhookService, config, logger)

	return &WebhookRoutes{
		webhookService: webhookService,
		config:         config,
		logger:         logger,
		handler:        handler,
	}
}

// RegisterRoutes registers webhook routes
func (r *WebhookRoutes) RegisterRoutes(router chi.Router) {
	router.Get("/webhooks", r.handler.ListWebhooks)
	router.Post("/webhooks/trigger", r.handler.TriggerWebhookEvent)
	// router.Route("/webhooks", func(router chi.HumaRouter) {
	// })
}

// RegisterOrganizationRoutes registers organization-specific webhook routes
func (r *WebhookRoutes) RegisterOrganizationRoutes(router chi.Router) {
	router.Route("/webhooks", func(router chi.Router) {
		router.Post("/", r.handler.CreateWebhook)

		router.Route("/{id}", func(router chi.Router) {
			router.Get("/", r.handler.GetWebhook)
			router.Put("/", r.handler.UpdateWebhook)
			router.Delete("/", r.handler.DeleteWebhook)

			router.Get("/events", r.handler.ListWebhookEvents)
			router.Post("/events/{eventId}/replay", r.handler.ReplayWebhookEvent)
		})
	})
}

// ReceiveWebhook handles incoming webhook requests
func (r *WebhookRoutes) ReceiveWebhook(w http.ResponseWriter, req *http.Request) {
	r.handler.ReceiveWebhook(w, req)
}
