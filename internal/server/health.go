package server

import (
	"context"
	"net/http"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/pkg/utils"
)

// HealthChecker provides health check functionality
type HealthChecker struct {
	dbClient *ent.Client
	services map[string]func() bool
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
func NewHealthChecker(dbClient *ent.Client) *HealthChecker {
	return &HealthChecker{
		dbClient: dbClient,
		services: make(map[string]func() bool),
	}
}

// RegisterService registers a service health check
func (h *HealthChecker) RegisterService(name string, check func() bool) {
	h.services[name] = check
}

// CheckHealth performs a health check
func (h *HealthChecker) CheckHealth() HealthResponse {
	services := make([]HealthStatus, 0, len(h.services)+1)
	allHealthy := true

	// Check database
	dbStatus := HealthStatus{
		Service: "database",
	}

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Ping database
	if err := h.dbClient.Schema.CheckIntegrity(ctx); err != nil {
		dbStatus.Status = "unhealthy"
		dbStatus.Message = "Failed to connect to database"
		allHealthy = false
	} else {
		dbStatus.Status = "healthy"
	}

	services = append(services, dbStatus)

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
func (h *HealthChecker) ReadyCheckHandler(w http.ResponseWriter, r *http.Request) {
	// Simple readiness check that just checks if the server is up
	response := HealthResponse{
		Status:    "ready",
		Timestamp: time.Now().Format(time.RFC3339),
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}
