package sms

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/xraph/frank/config"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
)

// awsProvider implements the SNS SNS SMS provider
type awsProvider struct {
	config      *config.SMSConfig
	logger      logging.Logger
	snsClient   *sns.Client
	initialized bool
}

// NewAWSProvider creates a new SNS SNS SMS provider
func NewAWSProvider(cfg *config.SMSConfig, logger logging.Logger) Provider {
	return &awsProvider{
		config:      cfg,
		logger:      logger,
		initialized: false,
	}
}

// initClient initializes the SNS SNS client
func (p *awsProvider) initClient(ctx context.Context) error {
	if p.initialized {
		return nil
	}

	// Check credentials
	if p.config.AWS.AccessKeyID == "" || p.config.AWS.SecretAccessKey == "" {
		return errors.New(errors.CodeConfigurationError, "SNS access key ID and secret access key are required")
	}

	// Create SNS credentials
	creds := credentials.NewStaticCredentialsProvider(
		p.config.AWS.AccessKeyID,
		p.config.AWS.SecretAccessKey,
		p.config.AWS.SessionToken,
	)

	// Load SNS configuration
	region := p.config.AWS.Region
	if region == "" {
		region = "us-east-1" // Default region
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(creds),
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeConfigurationError, "failed to load SNS configuration")
	}

	// Create SNS client
	p.snsClient = sns.NewFromConfig(awsCfg)
	p.initialized = true

	return nil
}

// Send sends an SMS via SNS SNS
func (p *awsProvider) Send(ctx context.Context, input SMS) error {
	// Initialize client if needed
	if err := p.initClient(ctx); err != nil {
		return err
	}

	// Set sender (From) if configured
	attributes := map[string]string{}
	if input.From != "" {
		attributes["SNS.SNS.SMS.SenderID"] = input.From
	}

	// Set SMS type (Promotional or Transactional)
	smsType := "Transactional" // Default to higher priority
	if smsTypeAttr, ok := input.Metadata["sms_type"].(string); ok {
		if smsTypeAttr == "Promotional" {
			smsType = "Promotional"
		}
	}
	attributes["SNS.SNS.SMS.SMSType"] = smsType

	// Add other message attributes
	messageAttributes := make(map[string]snstypes.MessageAttributeValue)
	for key, value := range attributes {
		messageAttributes[key] = snstypes.MessageAttributeValue{
			DataType:    aws.String("String"),
			StringValue: aws.String(value),
		}
	}

	// Send the message
	_, err := p.snsClient.Publish(ctx, &sns.PublishInput{
		Message:           aws.String(input.Message),
		PhoneNumber:       aws.String(input.To),
		MessageAttributes: messageAttributes,
	})

	if err != nil {
		return errors.Wrap(err, errors.CodeSMSDeliveryFail, "failed to send SMS via SNS SNS")
	}

	return nil
}

// Name returns the name of the provider
func (p *awsProvider) Name() string {
	return "aws-sns"
}
