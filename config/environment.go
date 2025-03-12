package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/joho/godotenv"

	"github.com/spf13/viper"
)

// Environment variables prefix
const envPrefix = "FRANK"

// LoadEnvironment loads configuration from environment variables
func LoadEnvironment(v *viper.Viper) {
	// Use environment variables with prefix
	v.SetEnvPrefix(envPrefix)

	// First try to load .env file
	if err := loadDotEnvFile(); err != nil {
		// Log the error but continue, as .env file might be optional
		fmt.Printf("Warning: Error loading .env file: %v\n", err)
	}

	// Replace dots with underscores in env names
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Read environment variables
	v.AutomaticEnv()

	// Load specific environment variables
	loadSpecificEnvVars(v)
}

// loadDotEnvFile attempts to load variables from .env file
func loadDotEnvFile() error {
	// First try loading from the current directory
	err := godotenv.Load()
	if err == nil {
		fmt.Println("Loaded configuration from .env file")
		return nil
	}

	// If that fails, try looking in common locations
	locations := []string{
		"./.env",
		"../.env",
		"../../.env",
		"../config/.env",
		"./config/.env",
	}

	for _, location := range locations {
		err = godotenv.Load(location)
		if err == nil {
			fmt.Printf("Loaded configuration from %s\n", location)
			return nil
		}
	}

	return fmt.Errorf("no .env file found")
}

// loadEnvironmentSpecificConfig loads configuration based on the current environment
func loadEnvironmentSpecificConfig(v *viper.Viper, env string) {
	// Try to load environment-specific config file
	v.SetConfigName(fmt.Sprintf("config.%s", env))
	if err := v.MergeInConfig(); err != nil {
		// It's okay if the environment-specific config doesn't exist
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			fmt.Printf("Warning: Error loading environment config: %v\n", err)
		}
	}

	// Set environment-specific defaults
	switch env {
	case "development":
		v.Set("server.debug_mode", true)
		v.Set("database.log_sql", true)
		v.Set("logging.level", "debug")
	case "testing":
		v.Set("server.debug_mode", true)
		v.Set("database.log_sql", false)
		v.Set("logging.level", "error")
	case "production":
		v.Set("server.debug_mode", false)
		v.Set("database.log_sql", false)
		v.Set("logging.level", "info")
		v.Set("security.allowed_origins", []string{}) // Override in production for security
	}
}

// loadSpecificEnvVars loads specific environment variables with custom handling
func loadSpecificEnvVars(v *viper.Viper) {
	// Database connection string
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		v.Set("database.dsn", dsn)
	}

	// Server port - often provided by hosting platforms
	if port := os.Getenv("PORT"); port != "" {
		v.Set("server.port", port)
	}

	// Application environment
	if env := os.Getenv("GO_ENV"); env != "" {
		// Load environment-specific config
		loadEnvironmentSpecificConfig(v, env)
	} else {
		// Default to development if not specified
		os.Setenv("GO_ENV", "development")
		loadEnvironmentSpecificConfig(v, "development")
	}

	// Webhook secret
	if secret := os.Getenv(fmt.Sprintf("%s_WEBHOOK_SECRET", envPrefix)); secret != "" {
		v.Set("webhooks.signing_secret", secret)
	}

	// Session secret
	if secret := os.Getenv(fmt.Sprintf("%s_SESSION_SECRET", envPrefix)); secret != "" {
		v.Set("auth.session_secret_key", secret)
	}

	// JWT secret
	if secret := os.Getenv(fmt.Sprintf("%s_JWT_SECRET", envPrefix)); secret != "" {
		v.Set("auth.jwt_secret_key", secret)
	}

	// CSRF secret
	if secret := os.Getenv(fmt.Sprintf("%s_CSRF_SECRET", envPrefix)); secret != "" {
		v.Set("security.csrf_secret_key", secret)
	}

	// Application URL
	if url := os.Getenv(fmt.Sprintf("%s_APP_URL", envPrefix)); url != "" {
		v.Set("server.base_url", url)
	}

	// Email provider configuration
	loadEmailProviderConfig(v)

	// SMS provider configuration
	loadSMSProviderConfig(v)

	// OAuth providers
	loadOAuthProvidersConfig(v)

	// Feature flags
	loadFeatureFlagsConfig(v)
}

// loadEmailProviderConfig loads email provider configuration from environment variables
func loadEmailProviderConfig(v *viper.Viper) {
	// Email provider selection
	if provider := os.Getenv(fmt.Sprintf("%s_EMAIL_PROVIDER", envPrefix)); provider != "" {
		v.Set("email.provider", strings.ToLower(provider))
	}

	// Email sender details
	if email := os.Getenv(fmt.Sprintf("%s_EMAIL_FROM", envPrefix)); email != "" {
		v.Set("email.from_email", email)
	}
	if name := os.Getenv(fmt.Sprintf("%s_EMAIL_FROM_NAME", envPrefix)); name != "" {
		v.Set("email.from_name", name)
	}

	// SMTP configuration
	if host := os.Getenv(fmt.Sprintf("%s_SMTP_HOST", envPrefix)); host != "" {
		v.Set("email.smtp.host", host)
	}
	if port := os.Getenv(fmt.Sprintf("%s_SMTP_PORT", envPrefix)); port != "" {
		v.Set("email.smtp.port", port)
	}
	if user := os.Getenv(fmt.Sprintf("%s_SMTP_USER", envPrefix)); user != "" {
		v.Set("email.smtp.username", user)
	}
	if pass := os.Getenv(fmt.Sprintf("%s_SMTP_PASSWORD", envPrefix)); pass != "" {
		v.Set("email.smtp.password", pass)
	}
	if tls := os.Getenv(fmt.Sprintf("%s_SMTP_TLS", envPrefix)); tls == "true" {
		v.Set("email.smtp.use_tls", true)
	}

	// Sendgrid configuration
	if apiKey := os.Getenv(fmt.Sprintf("%s_SENDGRID_API_KEY", envPrefix)); apiKey != "" {
		v.Set("email.sendgrid.api_key", apiKey)
	}

	// Mailgun configuration
	if apiKey := os.Getenv(fmt.Sprintf("%s_MAILGUN_API_KEY", envPrefix)); apiKey != "" {
		v.Set("email.mailgun.api_key", apiKey)
	}
	if domain := os.Getenv(fmt.Sprintf("%s_MAILGUN_DOMAIN", envPrefix)); domain != "" {
		v.Set("email.mailgun.domain", domain)
	}
	if endpoint := os.Getenv(fmt.Sprintf("%s_MAILGUN_ENDPOINT", envPrefix)); endpoint != "" {
		v.Set("email.mailgun.api_endpoint", endpoint)
	}

	// SNS SES configuration
	if accessKey := os.Getenv(fmt.Sprintf("%s_AWS_SES_ACCESS_KEY", envPrefix)); accessKey != "" {
		v.Set("email.amazon_ses.access_key", accessKey)
	}
	if secretKey := os.Getenv(fmt.Sprintf("%s_AWS_SES_SECRET_KEY", envPrefix)); secretKey != "" {
		v.Set("email.amazon_ses.secret_key", secretKey)
	}
	if region := os.Getenv(fmt.Sprintf("%s_AWS_SES_REGION", envPrefix)); region != "" {
		v.Set("email.amazon_ses.region", region)
	}
}

// loadSMSProviderConfig loads SMS provider configuration from environment variables
func loadSMSProviderConfig(v *viper.Viper) {
	// SMS provider selection
	if provider := os.Getenv(fmt.Sprintf("%s_SMS_PROVIDER", envPrefix)); provider != "" {
		v.Set("sms.provider", strings.ToLower(provider))
	}

	// SMS sender phone
	if phone := os.Getenv(fmt.Sprintf("%s_SMS_FROM_PHONE", envPrefix)); phone != "" {
		v.Set("sms.from_phone", phone)
	}

	// Twilio configuration
	if accountSid := os.Getenv(fmt.Sprintf("%s_TWILIO_ACCOUNT_SID", envPrefix)); accountSid != "" {
		v.Set("sms.twilio.account_sid", accountSid)
	}
	if authToken := os.Getenv(fmt.Sprintf("%s_TWILIO_AUTH_TOKEN", envPrefix)); authToken != "" {
		v.Set("sms.twilio.auth_token", authToken)
	}
	if serviceSid := os.Getenv(fmt.Sprintf("%s_TWILIO_SERVICE_SID", envPrefix)); serviceSid != "" {
		v.Set("sms.twilio.service_sid", serviceSid)
	}

	// SNS SNS configuration
	if accessKey := os.Getenv(fmt.Sprintf("%s_AWS_SNS_ACCESS_KEY", envPrefix)); accessKey != "" {
		v.Set("sms.aws_sns.access_key", accessKey)
	}
	if secretKey := os.Getenv(fmt.Sprintf("%s_AWS_SNS_SECRET_KEY", envPrefix)); secretKey != "" {
		v.Set("sms.aws_sns.secret_key", secretKey)
	}
	if region := os.Getenv(fmt.Sprintf("%s_AWS_SNS_REGION", envPrefix)); region != "" {
		v.Set("sms.aws_sns.region", region)
	}

	// Vonage configuration
	if apiKey := os.Getenv(fmt.Sprintf("%s_VONAGE_API_KEY", envPrefix)); apiKey != "" {
		v.Set("sms.vonage.api_key", apiKey)
	}
	if apiSecret := os.Getenv(fmt.Sprintf("%s_VONAGE_API_SECRET", envPrefix)); apiSecret != "" {
		v.Set("sms.vonage.api_secret", apiSecret)
	}
}

// loadOAuthProvidersConfig loads OAuth providers configuration from environment variables
func loadOAuthProvidersConfig(v *viper.Viper) {
	// Check for each common OAuth provider
	providers := []string{"google", "github", "facebook", "apple", "microsoft", "linkedin", "twitter"}

	for _, provider := range providers {
		upperProvider := strings.ToUpper(provider)

		// Client ID and Secret (the minimum required)
		clientID := os.Getenv(fmt.Sprintf("%s_%s_CLIENT_ID", envPrefix, upperProvider))
		clientSecret := os.Getenv(fmt.Sprintf("%s_%s_CLIENT_SECRET", envPrefix, upperProvider))

		// Only configure if we have the minimum credentials
		if clientID != "" && clientSecret != "" {
			providerPath := fmt.Sprintf("oauth.providers.%s", provider)

			v.Set(fmt.Sprintf("%s.client_id", providerPath), clientID)
			v.Set(fmt.Sprintf("%s.client_secret", providerPath), clientSecret)

			// Optional redirect URI
			if redirectURI := os.Getenv(fmt.Sprintf("%s_%s_REDIRECT_URI", envPrefix, upperProvider)); redirectURI != "" {
				v.Set(fmt.Sprintf("%s.redirect_uri", providerPath), redirectURI)
			}

			// Optional scopes (comma-separated)
			if scopes := os.Getenv(fmt.Sprintf("%s_%s_SCOPES", envPrefix, upperProvider)); scopes != "" {
				v.Set(fmt.Sprintf("%s.scopes", providerPath), strings.Split(scopes, ","))
			}
		}
	}
}

// loadFeatureFlagsConfig loads feature flags configuration from environment variables
func loadFeatureFlagsConfig(v *viper.Viper) {
	features := []string{
		"oauth2",
		"passwordless",
		"mfa",
		"passkeys",
		"sso",
		"enterprise_sso",
		"webhooks",
		"api_keys",
		"rbac",
		"organizations",
	}

	for _, feature := range features {
		envName := fmt.Sprintf("%s_ENABLE_%s", envPrefix, strings.ToUpper(feature))
		configName := fmt.Sprintf("features.enable_%s", feature)

		if val := os.Getenv(envName); val != "" {
			enabled := val == "true" || val == "1" || val == "yes"
			v.Set(configName, enabled)
		}
	}
}
