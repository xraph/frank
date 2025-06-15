package sms

import (
	"context"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/pkg/logging"
)

// mockProvider implements a mock SMS provider for testing
type mockProvider struct {
	config *config.SMSConfig
	logger logging.Logger
}

// NewMockProvider creates a new mock SMS provider
func NewMockProvider(cfg *config.SMSConfig, logger logging.Logger) Provider {
	return &mockProvider{
		config: cfg,
		logger: logger,
	}
}

// Send sends an SMS via the mock provider
func (p *mockProvider) Send(ctx context.Context, input SMS) error {
	p.logger.Info("Mock SMS provider: message would be sent",
		logging.String("to", input.To),
		logging.String("from", input.From),
		logging.String("message", input.Message),
	)
	return nil
}

// Name returns the name of the provider
func (p *mockProvider) Name() string {
	return "mock"
}
