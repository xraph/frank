package routes

import (
	"github.com/go-chi/chi/v5"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/auth/mfa"
	"github.com/juicycleff/frank/internal/handlers"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/user"
)

// MFARoutes handles multi-factor authentication routes
type MFARoutes struct {
	mfaService  mfa.Service
	userService user.Service
	config      *config.Config
	logger      logging.Logger
	handler     *handlers.MFAHandler
}

// NewMFARoutes creates a new MFA routes handler
func NewMFARoutes(
	mfaService mfa.Service,
	userService user.Service,
	config *config.Config,
	logger logging.Logger,
) *MFARoutes {
	handler := handlers.NewMFAHandler(mfaService, userService, config, logger)

	return &MFARoutes{
		mfaService:  mfaService,
		userService: userService,
		config:      config,
		logger:      logger,
		handler:     handler,
	}
}

// RegisterRoutes registers MFA routes
func (r *MFARoutes) RegisterRoutes(router chi.Router) {
	router.Route("/auth/mfa", func(router chi.Router) {
		router.Post("/enroll", r.handler.MFAEnroll)
		router.Post("/verify", r.handler.MFAVerify)
		router.Post("/unenroll", r.handler.MFAUnenroll)
		router.Get("/methods", r.handler.GetMFAMethods)
		router.Post("/send-code", r.handler.SendMFACode)
	})
}
