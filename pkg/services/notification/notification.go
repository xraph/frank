package notification

import (
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/pkg/email"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/sms"
)

type Service interface {
	Email() EmailService
	SMS() SMSService
}

type service struct {
	email       EmailService
	sms         SMSService
	smsProvider sms.Provider
}

func NewService(
	repo repository.Repository,
	sender email.Sender,
	smsProvider sms.Provider,
	cfg *config.Config,
	logger logging.Logger,
) (Service, error) {
	emailServ := NewEmailService(cfg, sender, repo.EmailTemplate(), repo.Organization(), repo.User(), logger, &EmailServiceConfig{
		DefaultProvider:     cfg.Email.Provider,
		EnableTemplateCache: true,
		TrackClicks:         true,
		FromEmail:           cfg.Email.FromEmail,
		TemplateDirectory:   cfg.Templates.Path,
		FromName:            cfg.Email.FromName,
		AppName:             cfg.Organization.DefaultName,
	})

	phoneVal, err := NewPhoneValidator(PhoneValidatorConfig{
		CacheEnabled: true,
	}, logger)
	if err != nil {
		return nil, err
	}

	rateLimStore := NewInMemoryRateLimitStorage()
	rateLim, err := NewRateLimiter(RateLimiterConfig{
		EnableMetrics: true,
	}, rateLimStore, logger)
	if err != nil {
		return nil, err
	}

	smsServ, err := NewSMSService(
		cfg,
		smsProvider,
		SMSServiceConfig{},
		repo.SMSTemplate(),
		nil,
		rateLim,
		phoneVal,
		logger,
	)
	if err != nil {
		return nil, err
	}

	return &service{
		email: emailServ,
		sms:   smsServ,
	}, nil
}

func (s *service) Email() EmailService {
	return s.email
}

func (s *service) SMS() SMSService {
	return s.sms
}
