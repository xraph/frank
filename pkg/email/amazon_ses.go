package email

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/ses/types"
	frankconfig "github.com/xraph/frank/config"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
)

// AmazonSESSender sends emails using SNS SES
type AmazonSESSender struct {
	config *frankconfig.EmailConfig
	logger logging.Logger
	client *ses.Client
}

// NewAmazonSESSender creates a new SNS SES sender
func NewAmazonSESSender(cfg *frankconfig.EmailConfig, logger logging.Logger) Sender {
	// Create SNS config
	var awsCfg aws.Config
	var err error

	ctx := context.Background()
	if cfg.SES.AccessKey != "" && cfg.SES.SecretKey != "" {
		// Use static credentials if provided
		awsCfg, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(cfg.SES.Region),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				cfg.SES.AccessKey,
				cfg.SES.SecretKey,
				"",
			)),
		)
	} else {
		// Use default credentials provider chain
		awsCfg, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(cfg.SES.Region),
		)
	}

	if err != nil {
		logger.Error("Failed to create SNS config", logging.Error(err))
		// Return with nil client, will be checked on Send
		return &AmazonSESSender{
			config: cfg,
			logger: logger,
		}
	}

	// Create SES client
	client := ses.NewFromConfig(awsCfg)

	return &AmazonSESSender{
		config: cfg,
		logger: logger,
		client: client,
	}
}

// Send sends an email using SNS SES
func (s *AmazonSESSender) Send(ctx context.Context, email Email) error {
	// Check if client was created successfully
	if s.client == nil {
		return errors.New(errors.CodeConfigurationError, "SNS SES client not configured properly")
	}

	// Set from email if not provided
	from := email.From
	if from == "" {
		from = s.config.FromEmail
	}

	// Create message
	message := &types.Message{
		Subject: &types.Content{
			Data:    aws.String(email.Subject),
			Charset: aws.String("UTF-8"),
		},
		Body: &types.Body{},
	}

	// Add HTML content if provided
	if email.HTMLContent != "" {
		message.Body.Html = &types.Content{
			Data:    aws.String(email.HTMLContent),
			Charset: aws.String("UTF-8"),
		}
	}

	// Add text content if provided
	if email.TextContent != "" {
		message.Body.Text = &types.Content{
			Data:    aws.String(email.TextContent),
			Charset: aws.String("UTF-8"),
		}
	}

	// Create destination
	destination := &types.Destination{
		ToAddresses: email.To,
	}

	// Add CC if present
	if len(email.CC) > 0 {
		destination.CcAddresses = email.CC
	}

	// Add BCC if present
	if len(email.BCC) > 0 {
		destination.BccAddresses = email.BCC
	}

	// Create email input
	input := &ses.SendEmailInput{
		Source:      aws.String(from),
		Destination: destination,
		Message:     message,
	}

	// Add reply-to if provided
	if email.ReplyTo != "" {
		input.ReplyToAddresses = []string{email.ReplyTo}
	}

	// Add configuration set if configured
	if s.config.SES.ConfigurationSet != "" {
		input.ConfigurationSetName = aws.String(s.config.SES.ConfigurationSet)
	}

	// Send email
	_, err := s.client.SendEmail(ctx, input)
	if err != nil {
		return errors.Wrap(err, errors.CodeEmailDeliveryFail, "failed to send email via SNS SES")
	}

	// If there are attachments, we need to use the SendRawEmail API
	if len(email.Attachments) > 0 {
		return s.sendWithAttachments(ctx, email)
	}

	s.logger.Info("Email sent successfully via SNS SES",
		logging.String("subject", email.Subject),
		logging.Int("recipients", len(email.To)),
	)

	return nil
}

// sendWithAttachments sends an email with attachments using SNS SES Raw Email
func (s *AmazonSESSender) sendWithAttachments(ctx context.Context, email Email) error {
	// Set from email if not provided
	from := email.From
	if from == "" {
		from = s.config.FromEmail
	}

	// Create a unique boundary for the multipart message
	boundary := fmt.Sprintf("_boundary_%d", time.Now().UnixNano())

	// Create raw message
	var rawMessage strings.Builder

	// Add headers
	rawMessage.WriteString(fmt.Sprintf("From: %s\r\n", from))
	rawMessage.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(email.To, ", ")))
	rawMessage.WriteString(fmt.Sprintf("Subject: %s\r\n", email.Subject))

	// Add CC if present
	if len(email.CC) > 0 {
		rawMessage.WriteString(fmt.Sprintf("CC: %s\r\n", strings.Join(email.CC, ", ")))
	}

	// Add Reply-To if present
	if email.ReplyTo != "" {
		rawMessage.WriteString(fmt.Sprintf("Reply-To: %s\r\n", email.ReplyTo))
	}

	// Add MIME version and multipart content type
	rawMessage.WriteString("MIME-Version: 1.0\r\n")
	rawMessage.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"\r\n", boundary))

	// Add custom headers
	for key, value := range email.Headers {
		rawMessage.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
	}

	// Start multipart message
	rawMessage.WriteString("\r\n")
	rawMessage.WriteString(fmt.Sprintf("--%s\r\n", boundary))

	// Add alternative content (HTML and text)
	if email.HTMLContent != "" || email.TextContent != "" {
		altBoundary := fmt.Sprintf("_alt_boundary_%d", time.Now().UnixNano())
		rawMessage.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n\r\n", altBoundary))

		// Add text content if provided
		if email.TextContent != "" {
			rawMessage.WriteString(fmt.Sprintf("--%s\r\n", altBoundary))
			rawMessage.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
			rawMessage.WriteString("Content-Transfer-Encoding: 7bit\r\n\r\n")
			rawMessage.WriteString(email.TextContent)
			rawMessage.WriteString("\r\n")
		}

		// Add HTML content if provided
		if email.HTMLContent != "" {
			rawMessage.WriteString(fmt.Sprintf("--%s\r\n", altBoundary))
			rawMessage.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
			rawMessage.WriteString("Content-Transfer-Encoding: 7bit\r\n\r\n")
			rawMessage.WriteString(email.HTMLContent)
			rawMessage.WriteString("\r\n")
		}

		// Close alternative part
		rawMessage.WriteString(fmt.Sprintf("--%s--\r\n", altBoundary))
	}

	// Add attachments
	for _, attachment := range email.Attachments {
		rawMessage.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		rawMessage.WriteString(fmt.Sprintf("Content-Type: %s; name=\"%s\"\r\n", attachment.ContentType, attachment.Filename))
		rawMessage.WriteString("Content-Transfer-Encoding: base64\r\n")
		rawMessage.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"\r\n\r\n", attachment.Filename))

		// Add base64 encoded content in chunks of 76 characters
		content := attachment.Base64Content
		for i := 0; i < len(content); i += 76 {
			end := i + 76
			if end > len(content) {
				end = len(content)
			}
			rawMessage.WriteString(content[i:end])
			rawMessage.WriteString("\r\n")
		}
		rawMessage.WriteString("\r\n")
	}

	// Close multipart message
	rawMessage.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	// Create raw email input
	rawEmailInput := &ses.SendRawEmailInput{
		Source:       aws.String(from),
		Destinations: append(email.To, append(email.CC, email.BCC...)...),
		RawMessage: &types.RawMessage{
			Data: []byte(rawMessage.String()),
		},
	}

	// Send raw email
	_, err := s.client.SendRawEmail(ctx, rawEmailInput)
	if err != nil {
		return errors.Wrap(err, errors.CodeEmailDeliveryFail, "failed to send raw email via SNS SES")
	}

	s.logger.Info("Email with attachments sent successfully via SNS SES",
		logging.String("subject", email.Subject),
		logging.Int("recipients", len(email.To)),
		logging.Int("attachments", len(email.Attachments)),
	)

	return nil
}

func (s *AmazonSESSender) SendBulkEmails(ctx context.Context, emails []Email) (*BulkEmailResult, error) {
	// TODO implement me
	panic("implement me")
}

func (s *AmazonSESSender) TestConnection(ctx context.Context) error {
	// TODO implement me
	panic("implement me")
}

func (s *AmazonSESSender) GetDeliveryStatus(ctx context.Context, messageID string) (*DeliveryInfo, error) {
	// TODO implement me
	panic("implement me")
}

func (s *AmazonSESSender) Name() string {
	return "ses"
}
