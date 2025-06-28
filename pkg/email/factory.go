package email

import (
	"strings"

	"github.com/xraph/frank/config"
	"github.com/xraph/frank/pkg/logging"
)

// SenderFactory creates an email sender based on configuration
func SenderFactory(cfg *config.EmailConfig, logger logging.Logger) Sender {
	provider := strings.ToLower(cfg.Provider)

	if config.IsDevelopment() && !cfg.ForceLive {
		logger.Warn("dev email provider, using mock sender",
			logging.String("provider", provider),
			logging.Bool("force_live", cfg.ForceLive),
		)
		return NewMockEmailSender("./tmp/emails")
	}

	switch provider {
	case "smtp":
		return NewSMTPSender(cfg, logger)
	case "sendgrid":
		return NewSendgridSender(cfg, logger)
	case "mailgun":
		return NewMailerSendSender(cfg, logger)
	case "twilio":
		return NewTwillioSender(cfg, logger)
	case "ses":
		return NewAmazonSESSender(cfg, logger)
	case "mailersend":
		return NewMailerSendSender(cfg, logger)
	case "resend":
		return NewResendSender(cfg, logger)
	case "postmark":
		return NewPostmarkSender(cfg, logger)
	default:
		logger.Warn("Unknown email provider, defaulting to SMTP", logging.String("provider", provider))
		return NewSMTPSender(cfg, logger)
	}
}
