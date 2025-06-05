package routesgoa

import (
	"github.com/go-chi/chi/v5"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/auth/passkeys"
	"github.com/juicycleff/frank/internal/handlers"
	"github.com/juicycleff/frank/pkg/logging"
)

// PasskeyRoutes handles passkey (WebAuthn) authentication routes
type PasskeyRoutes struct {
	passkeyService passkeys.Service
	config         *config.Config
	logger         logging.Logger
	handler        *handlers.PasskeyHandler
}

// NewPasskeyRoutes creates a new passkey routes handler
func NewPasskeyRoutes(
	passkeyService passkeys.Service,
	config *config.Config,
	logger logging.Logger,
) *PasskeyRoutes {
	handler := handlers.NewPasskeyHandler(passkeyService, config, logger)

	return &PasskeyRoutes{
		passkeyService: passkeyService,
		config:         config,
		logger:         logger,
		handler:        handler,
	}
}

// RegisterPublicRoutes registers public passkey routes
func (r *PasskeyRoutes) RegisterPublicRoutes(router chi.Router) {
	router.Post("/auth/passkeys/login/begin", r.handler.PasskeyLoginBegin)
	router.Post("/auth/passkeys/login/complete", r.handler.PasskeyLoginComplete)
}

// RegisterRoutes registers protected passkey routes
func (r *PasskeyRoutes) RegisterRoutes(router chi.Router) {
	router.Route("/auth/passkeys", func(router chi.Router) {
		router.Post("/register/begin", r.handler.PasskeyRegisterBegin)
		router.Post("/register/complete", r.handler.PasskeyRegisterComplete)
		router.Get("/", r.handler.GetUserPasskeys)

		router.Route("/{id}", func(router chi.Router) {
			router.Put("/", r.handler.UpdatePasskey)
			router.Delete("/", r.handler.DeletePasskey)
		})
	})
}
