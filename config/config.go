package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/caarlos0/env/v6"
	"github.com/juicycleff/frank/gen/designtypes"

	"github.com/spf13/viper"
)

var (
	config *Config
	once   sync.Once
)

// Config represents the application configuration
type Config struct {
	Environment     string `json:"environment" yaml:"environment" mapstructure:"environment" env:"ENVIRONMENT" envDefault:"development"`
	Version         string `json:"version" yaml:"version" mapstructure:"version" env:"VERSION" envDefault:"0.0.0"`
	GenerateSwagger bool   `json:"generate_swagger" yaml:"generate_swagger" mapstructure:"generate_swagger" env:"GENERATE_SWAGGER" envDefault:"false"`
	UseHuma         bool   `json:"useHuma" yaml:"useHuma" mapstructure:"useHuma" env:"USE_HUMA" envDefault:"false"`
	UseGoa          bool   `json:"useGoa" yaml:"useGoa" mapstructure:"useGoa" env:"USE_GOA" envDefault:"true"`
	GitCommit       string `json:"git_commit" yaml:"git_commit" mapstructure:"git_commit" env:"GIT_COMMIT" envDefault:""`
	GitBranch       string `json:"git_branch" yaml:"git_branch" mapstructure:"git_branch" env:"GIT_BRANCH" envDefault:""`
	GitTag          string `json:"git_tag" yaml:"git_tag" mapstructure:"git_tag" env:"GIT_TAG" envDefault:""`
	BuildDate       string `json:"build_date" yaml:"build_date" mapstructure:"build_date" env:"BUILD_DATE" envDefault:""`
	StandaloneMode  bool   `json:"standalone_mode" yaml:"standalone_mode" mapstructure:"standalone_mode" env:"STANDALONE_MODE" envDefault:"false"`
	BasePath        string `json:"base_path" yaml:"base_path" mapstructure:"base_path" env:"BASE_PATH" envDefault:"/"`

	Server       *ServerConfig      `json:"server" yaml:"server" mapstructure:"server"`
	Database     DatabaseConfig     `json:"database" yaml:"database" mapstructure:"database"`
	Auth         AuthConfig         `json:"auth" yaml:"auth" mapstructure:"auth"`
	Email        EmailConfig        `json:"email" yaml:"email" mapstructure:"email"`
	SMS          SMSConfig          `json:"sms" yaml:"sms" mapstructure:"sms"` // Redis configuration
	Redis        RedisConfig        `json:"redis" yaml:"redis" mapstructure:"redis"`
	OAuth        OAuthConfig        `json:"oauth" yaml:"oauth" mapstructure:"oauth"`
	Passkeys     PasskeysConfig     `json:"passkeys" yaml:"passkeys" mapstructure:"passkeys"`
	Webhooks     WebhooksConfig     `json:"webhooks" yaml:"webhooks" mapstructure:"webhooks"`
	Security     SecurityConfig     `json:"security" yaml:"security" mapstructure:"security"`
	Logging      LoggingConfig      `json:"logging" yaml:"logging" mapstructure:"logging"`
	Features     FeaturesConfig     `json:"features" yaml:"features" mapstructure:"features"`
	Templates    TemplatesConfig    `json:"templates" yaml:"templates" mapstructure:"templates"`
	Monitoring   MonitoringConfig   `json:"monitoring" yaml:"monitoring" mapstructure:"monitoring"`
	Organization OrganizationConfig `json:"organization" yaml:"organization" mapstructure:"organization"`
}

func (c *Config) GetServerAddress() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}

// ServerConfig represents server-specific configuration
type ServerConfig struct {
	Host             string        `json:"host" yaml:"host" mapstructure:"host" env:"SERVER_HOST" envDefault:"localhost"`
	Name             string        `json:"name" yaml:"name" mapstructure:"name" env:"SERVER_NAME" envDefault:"Wakflo"`
	Port             int           `json:"port" yaml:"port" mapstructure:"port" env:"SERVER_PORT" envDefault:"8080"`
	BaseURL          string        `json:"base_url" yaml:"base_url" mapstructure:"base_url" env:"SERVER_BASE_URL" envDefault:"http://localhost:8080"`
	ReadTimeout      time.Duration `json:"read_timeout" yaml:"read_timeout" mapstructure:"read_timeout" env:"SERVER_READ_TIMEOUT" envDefault:"5s"`
	WriteTimeout     time.Duration `json:"write_timeout" yaml:"write_timeout" mapstructure:"write_timeout" env:"SERVER_WRITE_TIMEOUT" envDefault:"10s"`
	IdleTimeout      time.Duration `json:"idle_timeout" yaml:"idle_timeout" mapstructure:"idle_timeout" env:"SERVER_IDLE_TIMEOUT" envDefault:"120s"`
	ShutdownTimeout  time.Duration `json:"shutdown_timeout" yaml:"shutdown_timeout" mapstructure:"shutdown_timeout" env:"SERVER_SHUTDOWN_TIMEOUT" envDefault:"30s"`
	TLS              TLSConfig     `json:"tls" yaml:"tls" mapstructure:"tls"`
	GracefulShutdown bool          `json:"graceful_shutdown" yaml:"graceful_shutdown" mapstructure:"graceful_shutdown" env:"SERVER_GRACEFUL_SHUTDOWN" envDefault:"true"`
	EnableHTTP2      bool          `json:"enable_http2" yaml:"enable_http2" mapstructure:"enable_http2" env:"SERVER_ENABLE_HTTP2" envDefault:"true"`
	ShutdownDelay    time.Duration `json:"shutdown_delay" yaml:"shutdown_delay" mapstructure:"shutdown_delay" env:"SERVER_SHUTDOWN_DELAY" envDefault:"5s"`
	TrustedProxies   []string      `json:"trusted_proxies" yaml:"trusted_proxies" mapstructure:"trusted_proxies" env:"SERVER_TRUSTED_PROXIES"`
	DebugMode        bool          `json:"debug_mode" yaml:"debug_mode" mapstructure:"debug_mode" env:"SERVER_DEBUG_MODE" envDefault:"false"`
	LogFormat        string        `json:"log_format" yaml:"log_format" mapstructure:"log_format" env:"SERVER_LOG_FORMAT" envDefault:"json"`
	LogLevel         string        `json:"log_level" yaml:"log_level" mapstructure:"log_level" env:"SERVER_LOG_LEVEL" envDefault:"info"`
	LogOutput        string        `json:"log_output" yaml:"log_output" mapstructure:"log_output" env:"SERVER_LOG_OUTPUT" envDefault:"stdout"`
	LogSQL           bool          `json:"log_sql" yaml:"log_sql" mapstructure:"log_sql" env:"SERVER_LOG_SQL" envDefault:"false"`
	LogSQLFile       string        `json:"log_sql_file" yaml:"log_sql_file" mapstructure:"log_sql_file" env:"SERVER_LOG_SQL_FILE" envDefault:"sql.log"`
}

// TLSConfig represents TLS configuration
type TLSConfig struct {
	Enabled  bool   `json:"enabled" yaml:"enabled" mapstructure:"enabled" env:"TLS_ENABLED" envDefault:"false"`
	CertFile string `json:"cert_file" yaml:"cert_file" mapstructure:"cert_file" env:"TLS_CERT_FILE" envDefault:"./certs/server.crt"`
	KeyFile  string `json:"key_file" yaml:"key_file" mapstructure:"key_file" env:"TLS_KEY_FILE" envDefault:"./certs/server.key"`
}

// DatabaseConfig represents database-specific configuration
type DatabaseConfig struct {
	Driver        string        `json:"driver" yaml:"driver" mapstructure:"driver" env:"DATABASE_DRIVER" envDefault:"postgres"`
	URL           string        `json:"url" yaml:"url" mapstructure:"url" env:"DATABASE_URL"`
	Host          string        `json:"host" yaml:"host" mapstructure:"host" env:"DATABASE_HOST" envDefault:"localhost"`
	Port          int           `json:"port" yaml:"port" mapstructure:"port" env:"DATABASE_PORT" envDefault:"5432"`
	User          string        `json:"user" yaml:"username" mapstructure:"user" env:"DATABASE_USER" envDefault:"postgres"`
	Password      string        `json:"password" yaml:"password" mapstructure:"password" env:"DATABASE_PASSWORD" envDefault:"postgres"`
	Database      string        `json:"database" yaml:"database" mapstructure:"database" env:"DATABASE_NAME" envDefault:"frank"`
	SSLMode       string        `json:"ssl_mode" yaml:"ssl_mode" mapstructure:"ssl_mode" env:"DATABASE_SSL_MODE" envDefault:"disable"`
	MaxOpenConns  int           `json:"max_open_conns" yaml:"max_open_conns" mapstructure:"max_open_conns" env:"DATABASE_MAX_OPEN_CONNS" envDefault:"25"`
	MaxIdleConns  int           `json:"max_idle_conns" yaml:"max_idle_conns" mapstructure:"max_idle_conns" env:"DATABASE_MAX_IDLE_CONNS" envDefault:"25"`
	ConnMaxLife   time.Duration `json:"conn_max_life" yaml:"conn_max_life" mapstructure:"conn_max_life" env:"DATABASE_CONN_MAX_LIFE" envDefault:"5m"`
	DSN           string        `json:"dsn" yaml:"-" mapstructure:"dsn" env:"DATABASE_DSN"`
	AutoMigrate   bool          `json:"auto_migrate" yaml:"auto_migrate" mapstructure:"auto_migrate" env:"DATABASE_AUTO_MIGRATE" envDefault:"true"`
	LogSQL        bool          `json:"log_sql" yaml:"log_sql" mapstructure:"log_sql" env:"DATABASE_LOG_SQL" envDefault:"false"`
	MigrationsDir string        `json:"migrations_dir" yaml:"migrations_dir" mapstructure:"migrations_dir" env:"DATABASE_MIGRATIONS_DIR" envDefault:"./migrations"`
}

func (d *DatabaseConfig) GetAddress() string {
	if d.DSN != "" {
		return d.DSN
	}

	if d.Driver == "sqlite3" || d.Driver == "sqlite" {
		return d.Database
	}

	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?sslmode=%s", d.User, d.Password, d.Host, d.Port, d.Database, d.SSLMode)
}

func (d *DatabaseConfig) GetFullAddress() string {
	if d.DSN != "" {
		return d.DSN
	}

	if d.Driver == "sqlite3" || d.Driver == "sqlite" {
		return d.Database
	}

	return fmt.Sprintf("%s://%s:%s@tcp(%s:%d)/%s?sslmode=%s", d.Driver, d.User, d.Password, d.Host, d.Port, d.Database, d.SSLMode)
}

// AuthConfig represents authentication-specific configuration
type AuthConfig struct {
	// Token configuration
	TokenSecretKey            string        `json:"token_secret_key" yaml:"token_secret_key" mapstructure:"token_secret_key" env:"AUTH_TOKEN_SECRET_KEY"`
	TokenSigningMethod        string        `json:"token_signing_method" yaml:"token_signing_method" mapstructure:"token_signing_method" env:"AUTH_TOKEN_SIGNING_METHOD" envDefault:"HS256"`
	AccessTokenDuration       time.Duration `json:"access_token_duration" yaml:"access_token_duration" mapstructure:"access_token_duration" env:"AUTH_ACCESS_TOKEN_DURATION" envDefault:"15m"`
	RefreshTokenDuration      time.Duration `json:"refresh_token_duration" yaml:"refresh_token_duration" mapstructure:"refresh_token_duration" env:"AUTH_REFRESH_TOKEN_DURATION" envDefault:"720h"` // 30 days
	TokenIssuer               string        `json:"token_issuer" yaml:"token_issuer" mapstructure:"token_issuer" env:"AUTH_TOKEN_ISSUER" envDefault:"frank"`
	TokenAudience             []string      `json:"token_audience" yaml:"token_audience" mapstructure:"token_audience"`
	RememberMeDuration        time.Duration `json:"remember_me_duration" yaml:"remember_me_duration" mapstructure:"remember_me_duration" env:"AUTH_REMEMBER_ME_DURATION" envDefault:"720h"` // 30 days
	VerificationTokenDuration time.Duration `json:"verification_token_duration" yaml:"verification_token_duration" mapstructure:"verification_token_duration" env:"AUTH_VERIFICATION_TOKEN_DURATION" envDefault:"15m"`
	MagicLinkDuration         time.Duration `json:"magic_link_duration" yaml:"magic_link_duration" mapstructure:"magic_link_duration" env:"AUTH_MAGIC_LINK_DURATION" envDefault:"15m"`

	// AllowAPIKey allows API key authentication
	AllowAPIKey bool `json:"allow_api_key" yaml:"allow_api_key" mapstructure:"allow_api_key" env:"AUTH_ALLOW_API_KEY" envDefault:"true"`

	// AllowSession allows session-based authentication
	AllowSession bool `json:"allow_session" yaml:"allow_session" mapstructure:"allow_session" env:"AUTH_ALLOW_SESSION" envDefault:"true"`

	// AllowBearerToken allows bearer token authentication
	AllowBearerToken bool `json:"allow_bearer_token" yaml:"allow_bearer_token" mapstructure:"allow_bearer_token" env:"AUTH_ALLOW_BEARER_TOKEN" envDefault:"true"`

	// Session configuration
	SessionDuration  time.Duration `json:"session_duration" yaml:"session_duration" mapstructure:"session_duration" env:"AUTH_SESSION_DURATION" envDefault:"24h"`
	SessionSecretKey string        `json:"session_secret_key" yaml:"session_secret_key" mapstructure:"session_secret_key" env:"AUTH_SESSION_SECRET_KEY"`
	CookieDomain     string        `json:"cookie_domain" yaml:"cookie_domain" mapstructure:"cookie_domain" env:"AUTH_COOKIE_DOMAIN" envDefault:"localhost"`
	CookieSecure     bool          `json:"cookie_secure" yaml:"cookie_secure" mapstructure:"cookie_secure" env:"AUTH_COOKIE_SECURE" envDefault:"false"`
	CookieHTTPOnly   bool          `json:"cookie_http_only" yaml:"cookie_http_only" mapstructure:"cookie_http_only" env:"AUTH_COOKIE_HTTP_ONLY" envDefault:"true"`
	CookieSameSite   string        `json:"cookie_same_site" yaml:"cookie_same_site" mapstructure:"cookie_same_site" env:"AUTH_COOKIE_SAME_SITE" envDefault:"lax"`

	// Email verification
	RequireEmailVerification bool          `json:"require_email_verification" yaml:"require_email_verification" mapstructure:"require_email_verification" env:"AUTH_REQUIRE_EMAIL_VERIFICATION" envDefault:"true"`
	EmailVerificationExpiry  time.Duration `json:"email_verification_expiry" yaml:"email_verification_expiry" mapstructure:"email_verification_expiry" env:"AUTH_EMAIL_VERIFICATION_EXPIRY" envDefault:"24h"`

	// Default user role
	DefaultUserRole   string `json:"default_user_role" yaml:"default_user_role" mapstructure:"default_user_role" env:"AUTH_DEFAULT_USER_ROLE" envDefault:"user"`
	DefaultAdminRole  string `json:"default_admin_role" yaml:"default_admin_role" mapstructure:"default_admin_role" env:"AUTH_DEFAULT_ADMIN_ROLE" envDefault:"admin"`
	DefaultSuperRole  string `json:"default_super_role" yaml:"default_super_role" mapstructure:"default_super_role" env:"AUTH_DEFAULT_SUPER_ROLE" envDefault:"super"`
	AutoRegisterUsers bool   `json:"auto_register_users" yaml:"auto_register_users" mapstructure:"auto_register_users" env:"AUTH_AUTO_REGISTER_USERS" envDefault:"false"`

	// Rate limiting
	MaxLoginAttempts     int           `json:"max_login_attempts" yaml:"max_login_attempts" mapstructure:"max_login_attempts" env:"AUTH_MAX_LOGIN_ATTEMPTS" envDefault:"5"`
	LoginLockoutDuration time.Duration `json:"login_lockout_duration" yaml:"login_lockout_duration" mapstructure:"login_lockout_duration" env:"AUTH_LOGIN_LOCKOUT_DURATION" envDefault:"15m"`

	PasswordPolicy PasswordPolicy `json:"password_policy" yaml:"password_policy" mapstructure:"password_policy"`

	// CAPTCHA
	EnableCaptcha    bool   `json:"enable_captcha" yaml:"enable_captcha" mapstructure:"enable_captcha" env:"AUTH_ENABLE_CAPTCHA" envDefault:"false"`
	CaptchaSecretKey string `json:"captcha_secret_key" yaml:"captcha_secret_key" mapstructure:"captcha_secret_key" env:"AUTH_CAPTCHA_SECRET_KEY"`
	CaptchaSiteKey   string `json:"captcha_site_key" yaml:"captcha_site_key" mapstructure:"captcha_site_key" env:"AUTH_CAPTCHA_SITE_KEY"`
}

// PasswordPolicy defines password requirements
type PasswordPolicy struct {
	MinLength          int  `json:"password_min_length" yaml:"password_min_length" mapstructure:"password_min_length" env:"AUTH_PASSWORD_MIN_LENGTH" envDefault:"8"`
	MaxLength          int  `json:"password_max_length" yaml:"password_max_length" mapstructure:"password_max_length" env:"AUTH_PASSWORD_MAX_LENGTH" envDefault:"100"`
	RequireUppercase   bool `json:"password_require_uppercase" yaml:"password_require_uppercase" mapstructure:"password_require_uppercase" env:"AUTH_PASSWORD_REQUIRE_UPPERCASE" envDefault:"true"`
	RequireLowercase   bool `json:"password_require_lowercase" yaml:"password_require_lowercase" mapstructure:"password_require_lowercase" env:"AUTH_PASSWORD_REQUIRE_LOWERCASE" envDefault:"true"`
	RequireDigit       bool `json:"password_require_digit" yaml:"password_require_digit" mapstructure:"password_require_digit" env:"AUTH_PASSWORD_REQUIRE_DIGIT" envDefault:"true"`
	RequireSpecial     bool `json:"password_require_special" yaml:"password_require_special" mapstructure:"password_require_special" env:"AUTH_PASSWORD_REQUIRE_SPECIAL" envDefault:"false"`
	MaxReusedPasswords int  `json:"password_max_reused_passwords" yaml:"password_max_reused_passwords" mapstructure:"password_max_reused_passwords" env:"AUTH_PASSWORD_MAX_REUSED_PASSWORDS" envDefault:"3"`
	PreventReuse       bool `json:"password_prevent_reuse" yaml:"password_prevent_reuse" mapstructure:"password_prevent_reuse" env:"AUTH_PASSWORD_PREVENT_REUSE" envDefault:"true"`
	ExpiryDays         int  `json:"password_expiry_days" yaml:"password_expiry_days" mapstructure:"password_expiry_days" env:"AUTH_PASSWORD_EXPIRY_DAYS" envDefault:"90"`
}

// OrganizationConfig defines organization settings
type OrganizationConfig struct {
	DefaultName     string                  `json:"default_name" yaml:"default_name" mapstructure:"default_name" env:"ORG_DEFAULT_NAME" envDefault:"Default"`
	DefaultFeatures []string                `json:"default_features" yaml:"default_features" mapstructure:"default_features" env:"ORG_DEFAULT_FEATURES" envDefault:"email,sms,magic_link"`
	SignupFields    []designtypes.FormField `json:"signup_fields" yaml:"signup_fields" mapstructure:"signup_fields"`
	Verification    OrgVerificationConfig   `json:"verification" yaml:"verification" mapstructure:"verification"`
}

// OrgVerificationConfig defines organization settings
type OrgVerificationConfig struct {
	CodeLength int    `json:"code_length" yaml:"code_length" mapstructure:"code_length" env:"ORG_VERIFICATION_CODE_LENGTH" envDefault:"6"`
	Method     string `json:"method" yaml:"method" mapstructure:"method" env:"ORG_VERIFICATION_METHOD" envDefault:"email"`
}

// EmailConfig represents email-specific configuration
type EmailConfig struct {
	Provider      string            `json:"provider" yaml:"provider" mapstructure:"provider" env:"EMAIL_PROVIDER" envDefault:"provider"`
	FromEmail     string            `json:"from_email" yaml:"from_email" mapstructure:"from_email" env:"EMAIL_FROM_EMAIL" envDefault:"no-reply@example.com"`
	FromName      string            `json:"from_name" yaml:"from_name" mapstructure:"from_name" env:"EMAIL_FROM_NAME" envDefault:"Frank Auth"`
	CustomHeaders map[string]string `json:"custom_headers" yaml:"custom_headers" mapstructure:"custom_headers"`

	// SMTP settings
	SMTP SMTPConfig `json:"smtp" yaml:"smtp" mapstructure:"smtp"`

	// Sendgrid settings
	Sendgrid SendgridConfig `json:"sendgrid" yaml:"sendgrid" mapstructure:"sendgrid"`

	// Mailgun settings
	Mailgun MailgunConfig `json:"mailgun" yaml:"amazon_ses" mapstructure:"amazon_ses"`

	// MailerSend settings
	MailerSend MailerSendConfig `json:"mailer_send" yaml:"mailer_send" mapstructure:"mailer_send"`

	// Resend settings
	Resend ResendConfig `json:"resend" yaml:"resend" mapstructure:"resend"`

	// SNS SES settings
	SES AmazonSESConfig `json:"ses" yaml:"amazon_ses" mapstructure:"amazon_ses"`

	// Postmark configuration
	Postmark PostmarkConfig `json:"postmark" yaml:"postmark" mapstructure:"postmark"`

	// Template settings
	TemplatesDir      string `json:"templates_dir" yaml:"templates_dir" mapstructure:"templates_dir" env:"EMAIL_TEMPLATES_DIR" envDefault:"./templates/email"`
	DefaultLanguage   string `json:"default_language" yaml:"default_language" mapstructure:"default_language" env:"EMAIL_DEFAULT_LANGUAGE" envDefault:"en"`
	EnableRemoteStore bool   `json:"enable_remote_store" yaml:"enable_remote_store" mapstructure:"enable_remote_store" env:"EMAIL_ENABLE_REMOTE_STORE" envDefault:"true"`
}

// SMTPConfig represents SMTP configuration
type SMTPConfig struct {
	Host     string `json:"host" yaml:"host" mapstructure:"host" env:"SMTP_HOST"`
	Port     int    `json:"port" yaml:"port" mapstructure:"port" env:"SMTP_PORT" envDefault:"587"`
	Username string `json:"username" yaml:"username" mapstructure:"username" env:"SMTP_USERNAME"`
	Password string `json:"password" yaml:"password" mapstructure:"password" env:"SMTP_PASSWORD"`
	UseTLS   bool   `json:"use_tls" yaml:"use_tls" mapstructure:"use_tls" env:"SMTP_USE_TLS" envDefault:"false"`
}

// SendgridConfig represents Sendgrid configuration
type SendgridConfig struct {
	APIKey string `json:"api_key" yaml:"api_key" mapstructure:"api_key" env:"SENDGRID_API_KEY"`
}

// MailerSendConfig represents ResendConfig configuration
type MailerSendConfig struct {
	APIKey string `json:"api_key" yaml:"api_key" mapstructure:"api_key" env:"MAILER_SEND_API_KEY"`
}

// ResendConfig represents ResendConfig configuration
type ResendConfig struct {
	APIKey string `json:"api_key" yaml:"api_key" mapstructure:"api_key" env:"RESEND_API_KEY"`
}

// MailgunConfig represents Mailgun configuration
type MailgunConfig struct {
	Domain      string `json:"domain" yaml:"domain" mapstructure:"domain" env:"MAILGUN_DOMAIN"`
	APIKey      string `json:"api_key" yaml:"api_key" mapstructure:"api_key" env:"MAILGUN_API_KEY"`
	APIEndpoint string `json:"api_endpoint" yaml:"api_endpoint" mapstructure:"api_endpoint" env:"MAILGUN_API_ENDPOINT" envDefault:"https://api.mailgun.net/v3"`
}

// AmazonSESConfig represents Amazon SES configuration
type AmazonSESConfig struct {
	Region           string `json:"region" yaml:"region" mapstructure:"region" env:"SES_REGION" envDefault:"us-east-1"`
	AccessKey        string `json:"access_key" yaml:"access_key" mapstructure:"access_key" env:"SES_ACCESS_KEY_ID"`
	SecretKey        string `json:"secret_key" yaml:"secret_key" mapstructure:"secret_key" env:"SES_SECRET_ACCESS_KEY"`
	ConfigurationSet string `json:"configuration_set" yaml:"configuration_set" mapstructure:"configuration_set" env:"CONFIGURATION_SET"`
}

// SMSConfig represents SMS-specific configuration
type SMSConfig struct {
	FromPhone string `json:"from_phone" yaml:"from_phone" yaml:"from_phone" env:"SMS_FROM_PHONE"`
	// Provider specifies which SMS provider to use
	Provider string `yaml:"provider" json:"provider" env:"SMS_PROVIDER" envDefault:"mock" mapstructure:"provider"`
	// FromNumber is the default sender number
	FromNumber string `yaml:"from_number" json:"from_number" env:"SMS_FROM_NUMBER" envDefault:"" mapstructure:"from_number"`
	// VerificationTemplate is the template used for verification SMS messages
	VerificationTemplate string `yaml:"verification_template" json:"verification_template" env:"SMS_VERIFICATION_TEMPLATE" envDefault:"Your verification code is:" mapstructure:"verification_template"`
	// VerificationCodeLength is the length of verification codes
	VerificationCodeLength int `yaml:"verification_code_length" json:"verification_code_length" env:"SMS_VERIFICATION_CODE_LENGTH" envDefault:"6" mapstructure:"verification_code_length"`
	// VerificationCodeExpiry is the expiry time for verification codes
	VerificationCodeExpiry time.Duration `yaml:"verification_code_expiry" json:"verification_code_expiry" env:"SMS_VERIFICATION_CODE_EXPIRY" envDefault:"10m" mapstructure:"verification_code_expiry"`
	// Twilio configuration
	Twilio TwilioConfig `yaml:"twilio" json:"twilio" mapstructure:"twilio"`
	// AWS SNS configuration
	AWS AWSConfig `yaml:"aws" json:"aws" mapstructure:"aws"`
	// MessageBird configuration
	MessageBird MessageBirdConfig `yaml:"messagebird" json:"messagebird" mapstructure:"messagebird"`
	// Vonage (Nexmo) configuration
	Vonage VonageConfig `yaml:"vonage" json:"vonage" mapstructure:"vonage"`
	// SendGrid configuration
	SendGrid SendGridConfig `yaml:"sendgrid" json:"sendgrid" mapstructure:"sendgrid"`
	// Plivo configuration
	Plivo PlivoConfig `yaml:"plivo" json:"plivo" mapstructure:"plivo"`
	// ClickSend configuration
	ClickSend ClickSendConfig `yaml:"clicksend" json:"clicksend" mapstructure:"clicksend"`
	// Sinch configuration
	Sinch SinchConfig `yaml:"sinch" json:"sinch" mapstructure:"sinch"`
	// Infobip configuration
	Infobip InfobipConfig `yaml:"infobip" json:"infobip" mapstructure:"infobip"`
	// Telnyx configuration
	Telnyx TelnyxConfig `yaml:"telnyx" json:"telnyx" mapstructure:"telnyx"`
}

// TwilioConfig represents Twilio configuration
type TwilioConfig struct {
	AccountSID string `json:"account_sid" yaml:"account_sid" mapstructure:"account_sid" env:"TWILIO_ACCOUNT_SID"`
	AuthToken  string `json:"auth_token" yaml:"auth_token" mapstructure:"auth_token" env:"TWILIO_AUTH_TOKEN"`
	ServiceSID string `json:"service_sid" yaml:"service_sid" mapstructure:"service_sid" env:"TWILIO_SERVICE_SID"`
}

// AWSSNSConfig represents SNS SNS configuration
type AWSSNSConfig struct {
	Region    string `json:"region" yaml:"region" mapstructure:"region" env:"SNS_REGION" envDefault:"us-east-1"`
	AccessKey string `json:"access_key_id" yaml:"access_key_id" mapstructure:"access_key_id" env:"SNS_ACCESS_KEY_ID"`
	SecretKey string `json:"secret_access_key" yaml:"secret_access_key" mapstructure:"secret_access_key" env:"SNS_SECRET_ACCESS_KEY"`
}

// AWSConfig contains AWS SNS configuration
type AWSConfig struct {
	AccessKeyID     string `yaml:"access_key_id" json:"access_key_id" env:"SMS_AWS_ACCESS_KEY_ID" envDefault:"" mapstructure:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key" json:"secret_access_key" env:"SMS_AWS_SECRET_ACCESS_KEY" envDefault:"" mapstructure:"secret_access_key"`
	SessionToken    string `yaml:"session_token" json:"session_token" env:"SMS_AWS_SESSION_TOKEN" envDefault:"" mapstructure:"session_token"`
	Region          string `yaml:"region" json:"region" env:"SMS_AWS_REGION" envDefault:"us-east-1" mapstructure:"region"`
}

// MessageBirdConfig contains MessageBird-specific configuration
type MessageBirdConfig struct {
	AccessKey string `yaml:"access_key" json:"access_key" env:"SMS_MESSAGEBIRD_ACCESS_KEY" envDefault:"" mapstructure:"access_key"`
}

// VonageConfig contains Vonage (Nexmo) configuration
type VonageConfig struct {
	APIKey    string `yaml:"api_key" json:"api_key" env:"SMS_VONAGE_API_KEY" envDefault:"" mapstructure:"api_key"`
	APISecret string `yaml:"api_secret" json:"api_secret" env:"SMS_VONAGE_API_SECRET" envDefault:"" mapstructure:"api_secret"`
}

// SendGridConfig contains SendGrid-specific configuration
type SendGridConfig struct {
	APIKey string `yaml:"api_key" json:"api_key" env:"SMS_SENDGRID_API_KEY" envDefault:"" mapstructure:"api_key"`
}

// PlivoConfig contains Plivo-specific configuration
type PlivoConfig struct {
	AuthID    string `yaml:"auth_id" json:"auth_id" env:"SMS_PLIVO_AUTH_ID" envDefault:"" mapstructure:"auth_id"`
	AuthToken string `yaml:"auth_token" json:"auth_token" env:"SMS_PLIVO_AUTH_TOKEN" envDefault:"" mapstructure:"auth_token"`
}

// ClickSendConfig contains ClickSend-specific configuration
type ClickSendConfig struct {
	Username string `yaml:"username" json:"username" env:"SMS_CLICKSEND_USERNAME" envDefault:"" mapstructure:"username"`
	APIKey   string `yaml:"api_key" json:"api_key" env:"SMS_CLICKSEND_API_KEY" envDefault:"" mapstructure:"api_key"`
}

// SinchConfig contains Sinch-specific configuration
type SinchConfig struct {
	ServiceID string `yaml:"service_id" json:"service_id" env:"SMS_SINCH_SERVICE_ID" envDefault:"" mapstructure:"service_id"`
	APIKey    string `yaml:"api_key" json:"api_key" env:"SMS_SINCH_API_KEY" envDefault:"" mapstructure:"api_key"`
	APISecret string `yaml:"api_secret" json:"api_secret" env:"SMS_SINCH_API_SECRET" envDefault:"" mapstructure:"api_secret"`
}

// InfobipConfig contains Infobip-specific configuration
type InfobipConfig struct {
	APIKey  string `yaml:"api_key" json:"api_key" env:"SMS_INFOBIP_API_KEY" envDefault:"" mapstructure:"api_key"`
	BaseURL string `yaml:"base_url" json:"base_url" env:"SMS_INFOBIP_BASE_URL" envDefault:"https://api.infobip.com" mapstructure:"base_url"`
}

// TelnyxConfig contains Telnyx-specific configuration
type TelnyxConfig struct {
	APIKey             string `yaml:"api_key" json:"api_key" env:"SMS_TELNYX_API_KEY" envDefault:"" mapstructure:"api_key"`
	MessagingProfileID string `yaml:"messaging_profile_id" json:"messaging_profile_id" env:"SMS_TELNYX_MESSAGING_PROFILE_ID" envDefault:"" mapstructure:"messaging_profile_id"`
}

type PostmarkConfig struct {
	// ServerToken is the Postmark server token
	ServerToken string `json:"server_token" yaml:"server_token" env:"POSTMARK_SERVER_TOKEN" envDefault:""`

	// AccountToken is the Postmark account token (optional)
	AccountToken string `json:"account_token" yaml:"account_token" env:"POSTMARK_ACCOUNT_TOKEN" envDefault:""`
}

// OAuthConfig represents OAuth-specific configuration
type OAuthConfig struct {
	DefaultScopes    []string                       `mapstructure:"default_scopes" json:"default_scopes" yaml:"default_scopes" env:"OAUTH_DEFAULT_SCOPES"`
	AuthCodeLifetime time.Duration                  `mapstructure:"auth_code_lifetime" json:"auth_code_lifetime" yaml:"auth_code_lifetime" env:"OAUTH_AUTH_CODE_LIFETIME" envDefault:"10m"`
	RefreshLifetime  time.Duration                  `mapstructure:"refresh_lifetime" json:"refresh_lifetime" yaml:"refresh_lifetime" env:"OAUTH_REFRESH_LIFETIME" envDefault:"720h"`
	AccessLifetime   time.Duration                  `mapstructure:"access_lifetime" json:"access_lifetime" yaml:"access_lifetime" env:"OAUTH_ACCESS_LIFETIME" envDefault:"1h"`
	EnforcePKCE      bool                           `mapstructure:"enforce_pkce" json:"enforce_pkce" yaml:"enforce_pkce" env:"OAUTH_ENFORCE_PKCE" envDefault:"false"`
	RequireConsent   bool                           `mapstructure:"require_consent" json:"require_consent" yaml:"require_consent" env:"OAUTH_REQUIRE_CONSENT" envDefault:"true"`
	JWTSigningMethod string                         `mapstructure:"jwt_signing_method" json:"jwt_signing_method" yaml:"jwt_signing_method" env:"OAUTH_JWT_SIGNING_METHOD" envDefault:"HS256"`
	EnablePKCE       bool                           `json:"enable_pkce" yaml:"enable_pkce" mapstructure:"enable_pkce" env:"OAUTH_ENABLE_PKCE" envDefault:"true"`
	RequirePKCE      bool                           `json:"require_pkce" yaml:"require_pkce" mapstructure:"require_pkce" env:"OAUTH_REQUIRE_PKCE" envDefault:"false"`
	EnableOIDC       bool                           `json:"enable_oidc" yaml:"enable_oidc" mapstructure:"enable_oidc" env:"OAUTH_ENABLE_OIDC" envDefault:"true"`
	JWKSPath         string                         `json:"jwks_path" yaml:"jwks_path" mapstructure:"jwks_path" env:"OAUTH_JWKS_PATH" envDefault:"./certs/jwks.json"`
	Providers        map[string]OAuthProviderConfig `json:"providers" yaml:"providers" mapstructure:"providers"`
}

// OAuthProviderConfig represents OAuth provider configuration
type OAuthProviderConfig struct {
	ClientID     string            `json:"client_id" yaml:"client_id" mapstructure:"client_id"`
	ClientSecret string            `json:"client_secret" yaml:"client_secret" mapstructure:"client_secret"`
	RedirectURI  string            `json:"redirect_uri" yaml:"redirect_uri" mapstructure:"redirect_uri"`
	Scopes       []string          `json:"scopes" yaml:"scopes" mapstructure:"scopes"`
	AuthURL      string            `json:"auth_url" yaml:"auth_url" mapstructure:"auth_url"`
	TokenURL     string            `json:"token_url" yaml:"token_url" mapstructure:"token_url"`
	UserInfoURL  string            `json:"user_info_url" yaml:"user_info_url" mapstructure:"user_info_url"`
	FieldMapping map[string]string `json:"field_mapping" yaml:"field_mapping" mapstructure:"field_mapping"`
}

// PasskeysConfig represents WebAuthn/PassKeys configuration
type PasskeysConfig struct {
	RelyingPartyName        string   `mapstructure:"relying_party_name" json:"relying_party_name" yaml:"relying_party_name" env:"PASSKEYS_RELYING_PARTY_NAME" envDefault:"Default Relying Party"`
	RelyingPartyID          string   `mapstructure:"relying_party_id" json:"relying_party_id" yaml:"relying_party_id" env:"PASSKEYS_RELYING_PARTY_ID" envDefault:"example.com"`
	RelyingPartyOrigins     []string `mapstructure:"relying_party_origins" json:"relying_party_origins" yaml:"relying_party_origins" env:"PASSKEYS_RELYING_PARTY_ORIGINS" envDefault:"[]"`
	RPDisplayName           string   `json:"rp_display_name" yaml:"rp_display_name" mapstructure:"rp_display_name" env:"PASSKEYS_RP_DISPLAY_NAME" envDefault:"Frank Auth"`
	RPID                    string   `json:"rp_id" yaml:"rp_id" mapstructure:"rp_id" env:"PASSKEYS_RP_ID"`
	RPOrigins               []string `json:"rp_origins" yaml:"rp_origins" mapstructure:"rp_origins"`
	AttestationTimeout      int      `json:"attestation_timeout" yaml:"attestation_timeout" mapstructure:"attestation_timeout" env:"PASSKEYS_ATTESTATION_TIMEOUT" envDefault:"60000"` // 1 minute in milliseconds
	AssertionTimeout        int      `json:"assertion_timeout" yaml:"assertion_timeout" mapstructure:"assertion_timeout" env:"PASSKEYS_ASSERTION_TIMEOUT" envDefault:"60000"`         // 1 minute in milliseconds
	ConveyancePreference    string   `json:"conveyance_preference" yaml:"conveyance_preference" mapstructure:"conveyance_preference" env:"PASSKEYS_CONVEYANCE_PREFERENCE" envDefault:"direct"`
	AuthenticatorAttachment string   `json:"authenticator_attachment" yaml:"authenticator_attachment" mapstructure:"authenticator_attachment" env:"PASSKEYS_AUTHENTICATOR_ATTACHMENT" envDefault:""`
	UserVerification        string   `json:"user_verification" yaml:"user_verification" mapstructure:"user_verification" env:"PASSKEYS_USER_VERIFICATION" envDefault:"preferred"`
	// UseInMemoryRepository indicates whether to use the in-memory repository for testing
	UseInMemoryRepository bool `json:"use_inmemory_repository" yaml:"use_inmemory_repository" mapstructure:"use_inmemory_repository" env:"PASSKEYS_USE_INMEMORY_REPOSITORY" envDefault:"false"`
	// UseRedisSessionStore indicates whether to use Redis for session storage
	UseRedisSessionStore bool `json:"use_redis_session_store" yaml:"use_redis_session_store" mapstructure:"use_redis_session_store" env:"PASSKEYS_USE_REDIS_SESSION_STORE" envDefault:"true"`
}

// WebhooksConfig represents webhook-specific configuration
type WebhooksConfig struct {
	RetryBackoffFactor float64       `mapstructure:"retry_backoff_factor" json:"retry_backoff_factor" yaml:"retry_backoff_factor" env:"WEBHOOK_RETRY_BACKOFF_FACTOR" envDefault:"2.0"`
	EventTypes         []string      `mapstructure:"event_types" json:"event_types" yaml:"event_types" env:"WEBHOOK_EVENT_TYPES"`
	QueueSize          int           `mapstructure:"queue_size" json:"queue_size" yaml:"queue_size" env:"WEBHOOK_QUEUE_SIZE" envDefault:"100"`
	WorkerCount        int           `mapstructure:"worker_count" json:"worker_count" yaml:"worker_count" env:"WEBHOOK_WORKER_COUNT" envDefault:"4"`
	DefaultRetries     int           `json:"default_retries" yaml:"default_retries" mapstructure:"default_retries" env:"WEBHOOK_DEFAULT_RETRIES" envDefault:"3"`
	DefaultTimeout     time.Duration `json:"default_timeout" yaml:"default_timeout" mapstructure:"default_timeout" env:"WEBHOOK_DEFAULT_TIMEOUT" envDefault:"5s"`
	MaxPayloadSize     int64         `json:"max_payload_size" yaml:"max_payload_size" mapstructure:"max_payload_size" env:"WEBHOOK_MAX_PAYLOAD_SIZE" envDefault:"1048576"` // 1MB
	SigningSecret      string        `json:"signing_secret" yaml:"signing_secret" mapstructure:"signing_secret" env:"WEBHOOK_SIGNING_SECRET"`
	MaxRetryDelay      time.Duration `json:"max_retry_delay" yaml:"max_retry_delay" mapstructure:"max_retry_delay" env:"WEBHOOK_MAX_RETRY_DELAY" envDefault:"5s"`
	MaxConcurrency     int           `json:"max_concurrency" yaml:"max_concurrency" mapstructure:"max_concurrency" env:"WEBHOOK_MAX_CONCURRENCY" envDefault:"10"`
	EnableAsync        bool          `json:"enable_async" yaml:"enable_async" mapstructure:"enable_async" env:"WEBHOOK_ENABLE_ASYNC" envDefault:"true"`
}

// SecurityConfig represents security-specific configuration
type SecurityConfig struct {
	MaxLoginAttempts         int               `mapstructure:"max_login_attempts" json:"max_login_attempts" yaml:"max_login_attempts" env:"SECURITY_MAX_LOGIN_ATTEMPTS" envDefault:"5"`
	LockoutDuration          time.Duration     `mapstructure:"lockout_duration" json:"lockout_duration" yaml:"lockout_duration" env:"SECURITY_LOCKOUT_DURATION" envDefault:"15m"`
	CSRFEnabled              bool              `mapstructure:"csrf_enabled" json:"csrf_enabled" yaml:"csrf_enabled" env:"SECURITY_CSRF_ENABLED" envDefault:"false"`
	CSRFTokenExpiry          time.Duration     `mapstructure:"csrf_token_expiry" json:"csrf_token_expiry" yaml:"csrf_token_expiry" env:"SECURITY_CSRF_TOKEN_EXPIRY" envDefault:"2h"`
	CSRFSecretKey            string            `mapstructure:"csrf_secret_key" json:"csrf_secret_key" yaml:"csrf_secret_key" env:"SECURITY_CSRF_SECRET_KEY" envDefault:"change-me"`
	CSRFCookieName           string            `mapstructure:"csrf_cookie_name" json:"csrf_cookie_name" yaml:"csrf_cookie_name" env:"SECURITY_CSRF_COOKIE_NAME" envDefault:"csrf_token"`
	CSRFHeaderName           string            `mapstructure:"csrf_header_name" json:"csrf_header_name" yaml:"csrf_header_name" env:"SECURITY_CSRF_HEADER_NAME" envDefault:"X-CSRF-Token"`
	IPRateLimit              map[string]string `mapstructure:"ip_rate_limit" json:"ip_rate_limit" yaml:"ip_rate_limit" env:"SECURITY_IP_RATE_LIMIT"`
	ContentTypeOptions       string            `mapstructure:"content_type_options" json:"content_type_options" yaml:"content_type_options" env:"SECURITY_CONTENT_TYPE_OPTIONS" envDefault:"nosniff"`
	ReferrerPolicy           string            `mapstructure:"referrer_policy" json:"referrer_policy" yaml:"referrer_policy" env:"SECURITY_REFERRER_POLICY" envDefault:"no-referrer"`
	AllowedOrigins           []string          `json:"allowed_origins" yaml:"allowed_origins" mapstructure:"allowed_origins"`
	AllowedMethods           []string          `json:"allowed_methods" yaml:"allowed_methods" mapstructure:"allowed_methods"`
	AllowedHeaders           []string          `json:"allowed_headers" yaml:"allowed_headers" mapstructure:"allowed_headers"`
	ExposedHeaders           []string          `json:"exposed_headers" yaml:"exposed_headers" mapstructure:"exposed_headers"`
	AllowCredentials         bool              `json:"allow_credentials" yaml:"allow_credentials" mapstructure:"allow_credentials" env:"SECURITY_ALLOW_CREDENTIALS" envDefault:"true"`
	RateLimitEnabled         bool              `json:"rate_limit_enabled" yaml:"rate_limit_enabled" mapstructure:"rate_limit_enabled" env:"SECURITY_RATE_LIMIT_ENABLED" envDefault:"true"`
	RateLimitPerSecond       float64           `json:"rate_limit_per_second" yaml:"rate_limit_per_second" mapstructure:"rate_limit_per_second" env:"SECURITY_RATE_LIMIT_PER_SECOND" envDefault:"10"`
	RateLimitBurst           int               `json:"rate_limit_burst" yaml:"rate_limit_burst" mapstructure:"rate_limit_burst" env:"SECURITY_RATE_LIMIT_BURST" envDefault:"30"`
	SecHeadersEnabled        bool              `json:"sec_headers_enabled" yaml:"sec_headers_enabled" mapstructure:"sec_headers_enabled" env:"SECURITY_SEC_HEADERS_ENABLED" envDefault:"true"`
	XSSProtection            string            `json:"xss_protection" yaml:"xss_protection" mapstructure:"xss_protection" env:"SECURITY_XSS_PROTECTION" envDefault:"1; mode=block"`
	ContentTypeNosniff       string            `json:"content_type_nosniff" yaml:"content_type_nosniff" mapstructure:"content_type_nosniff" env:"SECURITY_CONTENT_TYPE_NOSNIFF" envDefault:"nosniff"`
	XFrameOptions            string            `json:"x_frame_options" yaml:"x_frame_options" mapstructure:"x_frame_options" env:"SECURITY_X_FRAME_OPTIONS" envDefault:"SAMEORIGIN"`
	HSTSMaxAge               int               `json:"hsts_max_age" yaml:"hsts_max_age" mapstructure:"hsts_max_age" env:"SECURITY_HSTS_MAX_AGE" envDefault:"31536000"`
	HSTSIncludeSubdomains    bool              `json:"hsts_include_subdomains" yaml:"hsts_include_subdomains" mapstructure:"hsts_include_subdomains" env:"SECURITY_HSTS_INCLUDE_SUBDOMAINS" envDefault:"true"`
	ContentSecurityPolicy    string            `json:"content_security_policy" yaml:"content_security_policy" mapstructure:"content_security_policy" env:"SECURITY_CONTENT_SECURITY_POLICY"`
	CSRFProtectionEnabled    bool              `json:"csrf_protection_enabled" yaml:"csrf_protection_enabled" mapstructure:"csrf_protection_enabled" env:"SECURITY_CSRF_PROTECTION_ENABLED" envDefault:"true"`
	CSRFAllowedHosts         []string          `json:"csrf_allowed_hosts" yaml:"csrf_allowed_hosts" mapstructure:"csrf_allowed_hosts"`
	IPGeoLocationEnabled     bool              `json:"ip_geolocation_enabled" yaml:"ip_geolocation_enabled" mapstructure:"ip_geolocation_enabled" env:"SECURITY_IP_GEOLOCATION_ENABLED" envDefault:"false"`
	MaxmindGeoLiteDBPath     string            `json:"maxmind_geolite_db_path" yaml:"maxmind_geolite_db_path" mapstructure:"maxmind_geolite_db_path" env:"SECURITY_MAXMIND_GEOLITE_DATABASE_PATH"`
	MaxmindGeoLiteAccountID  string            `json:"maxmind_geolite_account_id" yaml:"maxmind_geolite_account_id" mapstructure:"maxmind_geolite_account_id" env:"SECURITY_MAXMIND_GEOLITE_ACCOUNT_ID"`
	MaxmindGeoLiteLicenseKey string            `json:"maxmind_geolite_license_key" yaml:"maxmind_geolite_license_key" mapstructure:"maxmind_geolite_license_key" env:"SECURITY_MAXMIND_GEOLITE_LICENSE_KEY"`
	PublicPaths              []string          `json:"public_paths" yaml:"public_paths" mapstructure:"public_paths"`
}

// LoggingConfig represents logging-specific configuration
type LoggingConfig struct {
	MaxFileSize int    `mapstructure:"max_file_size" json:"max_file_size" yaml:"max_file_size" env:"LOG_MAX_FILE_SIZE" envDefault:"200"`
	Level       string `json:"level" yaml:"level" mapstructure:"level" env:"LOG_LEVEL" envDefault:"info"`
	Format      string `json:"format" yaml:"format" mapstructure:"format" env:"LOG_FORMAT" envDefault:"json"`
	Output      string `json:"output" yaml:"output" mapstructure:"output" env:"LOG_OUTPUT" envDefault:"stdout"`
	FilePath    string `json:"file_path" yaml:"file_path" mapstructure:"file_path" env:"LOG_FILE_PATH" envDefault:"./logs/frank.log"`
	MaxSize     int    `json:"max_size" yaml:"max_size" mapstructure:"max_size" env:"LOG_MAX_SIZE" envDefault:"100"` // MB
	MaxBackups  int    `json:"max_backups" yaml:"max_backups" mapstructure:"max_backups" env:"LOG_MAX_BACKUPS" envDefault:"3"`
	MaxAge      int    `json:"max_age" yaml:"max_age" mapstructure:"max_age" env:"LOG_MAX_AGE" envDefault:"28"` // days
	Compress    bool   `json:"compress" yaml:"compress" mapstructure:"compress" env:"LOG_COMPRESS" envDefault:"true"`
	RequestLogs bool   `json:"request_logs" yaml:"request_logs" mapstructure:"request_logs" env:"LOG_REQUEST_LOGS" envDefault:"true"`
}

// FeaturesConfig represents feature flags configuration
type FeaturesConfig struct {
	EnableOAuth2            bool `mapstructure:"enable_oauth2" json:"enable_oauth2" yaml:"enable_oauth2" env:"FEATURE_ENABLE_OAUTH2" envDefault:"false"`
	EnableSSO               bool `mapstructure:"enable_sso" json:"enable_sso" yaml:"enable_sso" env:"FEATURE_ENABLE_SSO" envDefault:"false"`
	EnableEnterpriseSSO     bool `mapstructure:"enable_enterprise_sso" json:"enable_enterprise_sso" yaml:"enable_enterprise_sso" env:"FEATURE_ENABLE_ENTERPRISE_SSO" envDefault:"false"`
	EnableRBAC              bool `mapstructure:"enable_rbac" json:"enable_rbac" yaml:"enable_rbac" env:"FEATURE_ENABLE_RBAC" envDefault:"false"`
	EnableOrganizations     bool `mapstructure:"enable_organizations" json:"enable_organizations" yaml:"enable_organizations" env:"FEATURE_ENABLE_ORGANIZATIONS" envDefault:"false"`
	EnableUserAPI           bool `json:"enable_user_api" yaml:"enable_user_api" mapstructure:"enable_user_api" env:"FEATURE_ENABLE_USER_API" envDefault:"true"`
	EnableOrganizationAPI   bool `json:"enable_organization_api" yaml:"enable_organization_api" mapstructure:"enable_organization_api" env:"FEATURE_ENABLE_ORGANIZATION_API" envDefault:"true"`
	EnableMFA               bool `json:"enable_mfa" yaml:"enable_mfa" mapstructure:"enable_mfa" env:"FEATURE_ENABLE_MFA" envDefault:"true"`
	EnableWebhooks          bool `json:"enable_webhooks" yaml:"enable_webhooks" mapstructure:"enable_webhooks" env:"FEATURE_ENABLE_WEBHOOKS" envDefault:"true"`
	EnablePasswordless      bool `json:"enable_passwordless" yaml:"enable_passwordless" mapstructure:"enable_passwordless" env:"FEATURE_ENABLE_PASSWORDLESS" envDefault:"true"`
	EnablePasskeys          bool `json:"enable_passkeys" yaml:"enable_passkeys" mapstructure:"enable_passkeys" env:"FEATURE_ENABLE_PASSKEYS" envDefault:"true"`
	EnableAPIKeys           bool `json:"enable_api_keys" yaml:"enable_api_keys" mapstructure:"enable_api_keys" env:"FEATURE_ENABLE_API_KEYS" envDefault:"true"`
	EnableAuditLogs         bool `json:"enable_audit_logs" yaml:"enable_audit_logs" mapstructure:"enable_audit_logs" env:"FEATURE_ENABLE_AUDIT_LOGS" envDefault:"true"`
	EnableUserLockout       bool `json:"enable_user_lockout" yaml:"enable_user_lockout" mapstructure:"enable_user_lockout" env:"FEATURE_ENABLE_USER_LOCKOUT" envDefault:"true"`
	EnableUserImpersonation bool `json:"enable_user_impersonation" yaml:"enable_user_impersonation" mapstructure:"enable_user_impersonation" env:"FEATURE_ENABLE_USER_IMPERSONATION" envDefault:"false"`
	EnableFeatureFlags      bool `json:"enable_feature_flags" yaml:"enable_feature_flags" mapstructure:"enable_feature_flags" env:"FEATURE_ENABLE_FEATURE_FLAGS" envDefault:"true"`
}

// TemplatesConfig represents template configuration
type TemplatesConfig struct {
	Path              string `mapstructure:"path"`
	EmailPath         string `mapstructure:"email_path"`
	AuthPath          string `mapstructure:"auth_path"`
	EnableFileWatcher bool   `mapstructure:"enable_file_watcher"`
}

// MFAConfig contains multi-factor authentication configuration
type MFAConfig struct {
	TOTPIssuer        string        `json:"totp_issuer" yaml:"totp_issuer" mapstructure:"totp_issuer" env:"MFA_TOTP_ISSUER" envDefault:"Frank Auth"`
	TOTPDigits        int           `json:"totp_digits" yaml:"totp_digits" mapstructure:"totp_digits" env:"MFA_TOTP_DIGITS" envDefault:"6"`
	TOTPPeriod        uint          `json:"totp_period" yaml:"totp_period" mapstructure:"totp_period" env:"MFA_TOTP_PERIOD" envDefault:"30"`
	TOTPSkew          uint          `json:"totp_skew" yaml:"totp_skew" mapstructure:"totp_skew" env:"MFA_TOTP_SKEW" envDefault:"1"`
	TOTPAlgorithm     string        `json:"totp_algorithm" yaml:"totp_algorithm" mapstructure:"totp_algorithm" env:"MFA_TOTP_ALGORITHM" envDefault:"SHA1"`
	SMSCodeLength     int           `json:"sms_code_length" yaml:"sms_code_length" mapstructure:"sms_code_length" env:"MFA_SMS_CODE_LENGTH" envDefault:"6"`
	SMSCodeExpiry     time.Duration `json:"sms_code_expiry" yaml:"sms_code_expiry" mapstructure:"sms_code_expiry" env:"MFA_SMS_CODE_EXPIRY" envDefault:"10m"`
	EmailCodeLength   int           `json:"email_code_length" yaml:"email_code_length" mapstructure:"email_code_length" env:"MFA_EMAIL_CODE_LENGTH" envDefault:"6"`
	EmailCodeExpiry   time.Duration `json:"email_code_expiry" yaml:"email_code_expiry" mapstructure:"email_code_expiry" env:"MFA_EMAIL_CODE_EXPIRY" envDefault:"10m"`
	BackupCodesCount  int           `json:"backup_codes_count" yaml:"backup_codes_count" mapstructure:"backup_codes_count" env:"MFA_BACKUP_CODES_COUNT" envDefault:"10"`
	BackupCodesLength int           `json:"backup_codes_length" yaml:"backup_codes_length" mapstructure:"backup_codes_length" env:"MFA_BACKUP_CODES_LENGTH" envDefault:"8"`
	EnforceForAdmins  bool          `json:"enforce_for_admins" yaml:"enforce_for_admins" mapstructure:"enforce_for_admins" env:"MFA_ENFORCE_FOR_ADMINS" envDefault:"true"`
	DefaultMethods    []string      `json:"default_methods" yaml:"default_methods" mapstructure:"default_methods" env:"MFA_DEFAULT_METHODS" envDefault:"totp,sms"`
}

// MonitoringConfig represents monitoring configuration
type MonitoringConfig struct {
	MetricsEndpoint   string  `mapstructure:"metrics_endpoint" json:"metrics_endpoint" yaml:"metrics_endpoint" env:"MONITORING_METRICS_ENDPOINT" envDefault:"http://localhost:8080/metrics"`
	JaegerEndpoint    string  `mapstructure:"jaeger_endpoint" json:"jaeger_endpoint" yaml:"jaeger_endpoint" env:"MONITORING_JAEGER_ENDPOINT" envDefault:"http://localhost:14268/api/traces"`
	OTLPEndpoint      string  `mapstructure:"otlp_endpoint" json:"otlp_endpoint" yaml:"otlp_endpoint" env:"MONITORING_OTLP_ENDPOINT" envDefault:"http://localhost:4317"`
	SamplingRate      float64 `mapstructure:"sampling_rate" json:"sampling_rate" yaml:"sampling_rate" env:"MONITORING_SAMPLING_RATE" envDefault:"1.0"`
	Enabled           bool    `json:"enabled" yaml:"enabled" mapstructure:"enabled" env:"MONITORING_ENABLED" envDefault:"false"`
	PrometheusEnabled bool    `json:"prometheus" yaml:"prometheus" mapstructure:"prometheus" env:"MONITORING_PROMETHEUS" envDefault:"true"`
	PrometheusPath    string  `json:"prometheus_path" yaml:"prometheus_path" mapstructure:"prometheus_path" env:"MONITORING_PROMETHEUS_PATH" envDefault:"/metrics"`
	StatsdEnabled     bool    `json:"statsd_enabled" yaml:"statsd_enabled" mapstructure:"statsd_enabled" env:"MONITORING_STATSD_ENABLED" envDefault:"false"`
	StatsdHost        string  `json:"statsd_host" yaml:"statsd_host" mapstructure:"statsd_host" env:"MONITORING_STATSD_HOST" envDefault:"localhost"`
	StatsdPort        int     `json:"statsd_port" yaml:"statsd_port" mapstructure:"statsd_port" env:"MONITORING_STATSD_PORT" envDefault:"8125"`
	StatsdPrefix      string  `json:"statsd_prefix" yaml:"statsd_prefix" mapstructure:"statsd_prefix" env:"MONITORING_STATSD_PREFIX" envDefault:"frank"`
	TracingEnabled    bool    `json:"tracing_enabled" yaml:"tracing_enabled" mapstructure:"tracing_enabled" env:"MONITORING_TRACING_ENABLED" envDefault:"false"`
	TracingProvider   string  `json:"tracing_provider" yaml:"tracing_provider" mapstructure:"tracing_provider" env:"MONITORING_TRACING_PROVIDER" envDefault:"jaeger"`
	TracingEndpoint   string  `json:"tracing_endpoint" yaml:"tracing_endpoint" mapstructure:"tracing_endpoint" env:"MONITORING_TRACING_ENDPOINT"`
	HealthCheckPath   string  `json:"health_check_path" yaml:"health_check_path" mapstructure:"health_check_path" env:"MONITORING_HEALTH_CHECK_PATH" envDefault:"/health"`
	ReadinessPath     string  `json:"readiness_path" yaml:"readiness_path" mapstructure:"readiness_path" env:"MONITORING_READINESS_PATH" envDefault:"/ready"`
}

// Load loads the configuration from environment variables, config files, and defaults
func Load(configPaths ...string) (*Config, error) {
	var loadErr error

	once.Do(func() {
		config = &Config{}
		v := viper.New()

		// Set configuration defaults
		SetDefaults(v)

		// Parse environment variables into the struct
		if err := env.Parse(config); err != nil {
			loadErr = fmt.Errorf("error passring config env: %w", err)
			return
		}

		// Load environment variables
		LoadEnvironment(v)

		// Read configuration files if provided
		if len(configPaths) > 0 {
			for _, path := range configPaths {
				v.AddConfigPath(path)
			}
		} else {
			// Default config paths
			v.AddConfigPath(".")
			v.AddConfigPath("./config")
			v.AddConfigPath("/etc/frank")
		}

		v.SetConfigName("config")
		v.SetConfigType("yaml")

		if err := v.ReadInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
				loadErr = fmt.Errorf("error reading config file: %w", err)
				return
			}
		}

		if err := v.Unmarshal(config); err != nil {
			loadErr = fmt.Errorf("error unmarshaling config: %w", err)
			return
		}

		// Validate required configuration
		if err := validateConfig(config); err != nil {
			loadErr = err
			return
		}
	})

	if loadErr != nil {
		return nil, loadErr
	}

	return config, nil
}

// validateConfig validates the required configuration fields
func validateConfig(config *Config) error {
	if config.Server.Port == 0 {
		return fmt.Errorf("server port is required")
	}

	if config.Auth.SessionSecretKey == "" {
		// Generate a random secret if requested
		secret, err := generateRandomSecret(32)
		if err != nil {
			fmt.Printf("Error generating secret: %v\n", err)
			return fmt.Errorf("session secret key is required")
		}
		config.Auth.SessionSecretKey = secret
		fmt.Printf("Generated Secret Key: %s\n", secret)
	}

	if config.Auth.TokenSecretKey == "" {
		secret, err := generateRandomSecret(32)
		if err != nil {
			fmt.Printf("Error generating secret: %v\n", err)
			return fmt.Errorf("JWT secret key is required")
		}
		config.Auth.SessionSecretKey = secret
		fmt.Printf("Generated JWT Secret Key: %s\n", secret)
	}

	// Validate database configuration if auto-migrate is enabled
	if config.Database.AutoMigrate {
		if config.Database.DSN == "" && (config.Database.Host == "" || config.Database.Database == "") {
			return fmt.Errorf("database DSN or host/dbname are required when auto-migrate is enabled")
		}
	}

	return nil
}

// Get returns the loaded configuration
func Get() *Config {
	if config == nil {
		// If not already loaded, load with defaults
		_, err := Load()
		if err != nil {
			// In case of error, panic as the application cannot run without config
			panic(fmt.Sprintf("failed to load configuration: %v", err))
		}
	}
	return config
}

// GetServerAddress returns the formatted server address
func GetServerAddress() string {
	cfg := Get()
	return fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
}

// IsDevelopment returns true if the application is running in development mode
func IsDevelopment() bool {
	return os.Getenv("GO_ENV") == "development"
}

// IsProduction returns true if the application is running in production mode
func IsProduction() bool {
	return os.Getenv("GO_ENV") == "production"
}

// IsTesting returns true if the application is running in test mode
func IsTesting() bool {
	return os.Getenv("GO_ENV") == "testing"
}

func generateRandomSecret(length int) (string, error) {
	if length == 0 {
		length = 32
	}

	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	// Use URL-safe base64 encoding without padding
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
