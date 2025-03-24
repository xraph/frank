package controllers

import "C"
import (
	"context"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/gen/auth"
	customMiddleware "github.com/juicycleff/frank/internal/middleware"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"
	goa "goa.design/goa/v3/pkg"
)

type CSRFInterceptor struct {
	cfg    *config.Config
	logger logging.Logger
}

func (c *CSRFInterceptor) CSRFToken(ctx context.Context, info *auth.CSRFTokenInfo, next goa.Endpoint) (any, error) {
	reqInfo, ok := customMiddleware.GetRequestInfo(ctx)
	if !ok {
		return nil, errors.New(errors.CodeInternalServer, "failed to get request info")
	}

	// Create a response writer that captures the response
	crw := utils.NewCaptureResponseWriter(reqInfo.Res)

	// Call the original handler with our capturing writer
	resp, err := next(ctx, info.RawPayload())
	if err != nil {
		return nil, err
	}

	// Process the response
	if result := info.Result(resp); result != nil {
		// Generate a new CSRF token
		token, err := customMiddleware.GenerateCSRFToken(crw, c.cfg, c.logger, 24*time.Hour)
		if err == nil {
			result.SetCsrfToken(token)
			return resp, nil
		}
		// Cache the result...
	}
	return resp, nil
}

func NewCSRFInterceptor(cfg *config.Config, logger logging.Logger) auth.ServerInterceptors {
	return &CSRFInterceptor{
		cfg: cfg,
	}
}
