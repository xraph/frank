package handlers

import (
	"github.com/go-chi/chi/v5"
	"github.com/juicycleff/frank/config"
	httpSwagger "github.com/swaggo/http-swagger"
)

type SwaggerHandler struct {
	cfg *config.Config
}

func NewSwaggerHandler(cfg *config.Config) *SwaggerHandler {
	return &SwaggerHandler{
		cfg: cfg,
	}
}

// SetupRoutes sets up the API key routes
func (h *SwaggerHandler) SetupRoutes(r chi.Router) {
	r.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL("http://localhost:1323/swagger/doc.json"), // The url pointing to API definition
	))

}
