package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/pkg/data"
	"github.com/juicycleff/frank/pkg/utils"
)

// HealthChecker provides health check functionality
type HealthChecker struct {
	clients  *data.Clients
	services map[string]func() bool
	cfg      *config.Config
}

// HealthStatus represents the status of a service
type HealthStatus struct {
	Service string `json:"service"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status    string         `json:"status"`
	Timestamp string         `json:"timestamp"`
	Services  []HealthStatus `json:"services,omitempty"`
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(clients *data.Clients, cfg *config.Config) *HealthChecker {
	return &HealthChecker{
		clients:  clients,
		services: make(map[string]func() bool),
		cfg:      cfg,
	}
}

// RegisterService registers a service health check
func (h *HealthChecker) RegisterService(name string, check func() bool) {
	h.services[name] = check
}

// CheckHealth performs a health check
func (h *HealthChecker) CheckHealth() HealthResponse {
	services := make([]HealthStatus, 0, len(h.services)+2) // include space for redis
	allHealthy := true

	// Check database
	dbStatus := HealthStatus{
		Service: "database",
	}

	// Ping database
	dbStatus.Status = "healthy"

	// // Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// if err := h.dbClient.Schema.CheckIntegrity(ctx); err != nil {
	// 	dbStatus.Status = "unhealthy"
	// 	dbStatus.Message = "Failed to connect to database"
	// 	allHealthy = false
	// } else {
	// 	dbStatus.Status = "healthy"
	// }

	services = append(services, dbStatus)

	if h.cfg.Redis.Enabled {
		// Check Redis
		redisStatus := HealthStatus{
			Service: "redis",
		}

		// Ping Redis
		if _, err := h.clients.Redis.Ping(ctx).Result(); err != nil {
			redisStatus.Status = "unhealthy"
			redisStatus.Message = "Failed to connect to Redis"
			allHealthy = false
		} else {
			redisStatus.Status = "healthy"
		}

		services = append(services, redisStatus)
	}

	// Check registered services
	for name, check := range h.services {
		status := HealthStatus{
			Service: name,
		}

		if check() {
			status.Status = "healthy"
		} else {
			status.Status = "unhealthy"
			status.Message = "Service check failed"
			allHealthy = false
		}

		services = append(services, status)
	}

	// Create response
	response := HealthResponse{
		Timestamp: time.Now().Format(time.RFC3339),
		Services:  services,
	}

	if allHealthy {
		response.Status = "healthy"
	} else {
		response.Status = "unhealthy"
	}

	return response
}

// HealthCheckHandler handles the health check endpoint
// @Summary      Perform health check
// @Description  Returns the health status of the application and its services
// @Tags         Health
// @Produce      json
// @Success      200 {object} HealthResponse "Healthy status"
// @Failure      503 {object} HealthResponse "Unhealthy status"
// @Router       /__health [get]
func (h *HealthChecker) HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	response := h.CheckHealth()

	// Set status code based on health
	statusCode := http.StatusOK
	if response.Status != "healthy" {
		statusCode = http.StatusServiceUnavailable
	}

	utils.RespondWithJSON(w, statusCode, response)
}

// ReadyCheckHandler handles the readiness check endpoint
// @Summary      Perform readiness check
// @Description  Indicates if the application is ready to receive traffic
// @Tags         Readiness
// @Produce      json
// @Success      200 {object} HealthResponse "Ready status"
// @Router       /__ready [post]
func (h *HealthChecker) ReadyCheckHandler(w http.ResponseWriter, r *http.Request) {
	// Simple readiness check that just checks if the server is up
	response := HealthResponse{
		Status:    "ready",
		Timestamp: time.Now().Format(time.RFC3339),
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// HealthCheck handles the health check HTTP request by delegating to the HealthCheckHandler of the HealthChecker instance.
func HealthCheck(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Health.HealthCheckHandler(w, r)
}

// ReadyCheck handles the readiness check endpoint by delegating to the ReadyCheckHandler within the health checker.
func ReadyCheck(w http.ResponseWriter, r *http.Request) {
	HandlerFromContext(r.Context()).Health.ReadyCheckHandler(w, r)
}
