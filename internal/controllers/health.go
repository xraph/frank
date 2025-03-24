package controllers

import (
	"context"
	"runtime"
	"strconv"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/gen/designtypes"
	healthsvc "github.com/juicycleff/frank/gen/health"
	healthhttp "github.com/juicycleff/frank/gen/http/health/server"
	"github.com/juicycleff/frank/internal/services"
	"github.com/juicycleff/frank/pkg/data"
	"github.com/juicycleff/frank/pkg/logging"
	"goa.design/clue/health"
	goahttp "goa.design/goa/v3/http"
)

type HealthService struct {
	clients *data.Clients
	config  *config.Config
	logger  logging.Logger
	auther  *AutherService
	checker health.Checker
}

func (h *HealthService) Check(ctx context.Context) (res *designtypes.HealthResponse, err error) {
	output, ok := h.checker.Check(ctx)

	status := "healthy"
	if !ok {
		status = "unhealthy"
	}

	rsponse := &designtypes.HealthResponse{
		Status:    status,
		Timestamp: strconv.FormatInt(output.Uptime, 10),
	}

	// Check registered services
	for name, check := range output.Status {
		rsponse.Services = append(rsponse.Services, &designtypes.HealthStatus{
			Service: name,
			Status:  check,
			Message: nil,
		})

		if check != "ok" {
			rsponse.Status = "unhealthy"
		}
	}

	return rsponse, nil
}

func (h *HealthService) Ready(ctx context.Context) (res *designtypes.ReadyResponse, err error) {
	res = &designtypes.ReadyResponse{}
	res.Status = "healthy"
	res.Timestamp = time.Now().Format(time.RFC3339)

	return res, err
}

func (h *HealthService) Version(ctx context.Context) (res *healthsvc.VersionResult, err error) {
	res = &healthsvc.VersionResult{}
	gv := runtime.Version()

	res.Version = h.config.Version
	res.GoVersion = &gv

	res.BuildDate = h.config.BuildDate
	res.GitCommit = &h.config.GitCommit

	return res, err
}

func (h *HealthService) Metrics(ctx context.Context) (res *healthsvc.MetricsResult, err error) {
	// TODO implement me
	panic("implement me")
}

func (h *HealthService) Debug(ctx context.Context) (res any, err error) {
	// TODO implement me
	panic("implement me")
}

func NewHealthService(
	clients *data.Clients,
	cfg *config.Config,
	logger logging.Logger,
	auther *AutherService,
) healthsvc.Service {

	checker := health.NewChecker(
		clients.DBPinger,
		health.NewPinger("cache", cfg.Redis.GetAddress()),
	)

	return &HealthService{
		clients: clients,
		logger:  logger,
		auther:  auther,
		checker: checker,
		config:  cfg,
	}
}

func RegisterHealthHTTPService(
	mux goahttp.Muxer,
	clients *data.Clients,
	svcs *services.Services,
	config *config.Config,
	logger logging.Logger,
	auther *AutherService,
) {
	eh := errorHandler(logger)
	svc := NewHealthService(clients, config, logger, auther)
	endpoints := healthsvc.NewEndpoints(svc)
	handler := healthhttp.New(endpoints, mux, decoder, encoder, eh, nil)
	// handler2 := otelhttp.NewHandler(handler, "auth-service")
	healthhttp.Mount(mux, handler)
}
