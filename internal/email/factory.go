package email

import (
	"strings"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/pkg/logging"
)

// SenderFactory creates an email sender based on configuration
func SenderFactory(cfg *config.Config, logger logging.Logger) Sender {
	provider := strings.ToLower(cfg.Email.Provider)

	if cfg.Environment == "development" {
		logger.Warn("dev email provider, using mock sender", logging.String("provider", provider))
		return NewMockEmailSender("./tmp/emails")
	}

	switch provider {
	case "smtp":
		return NewSMTPSender(cfg, logger)
	case "sendgrid":
		return NewSendgridSender(cfg, logger)
	case "mailgun":
		return NewMailerSendSender(cfg, logger)
	case "ses":
		return NewAmazonSESSender(cfg, logger)
	case "mailersend":
		return NewMailerSendSender(cfg, logger)
	case "resend":
		return NewResendSender(cfg, logger)
	default:
		logger.Warn("Unknown email provider, defaulting to SMTP", logging.String("provider", provider))
		return NewSMTPSender(cfg, logger)
	}
}
