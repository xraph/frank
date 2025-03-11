package config

import (
	"time"

	"github.com/spf13/viper"
)

// SetDefaults sets default values for configuration
func SetDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.read_timeout", time.Second*15)
	v.SetDefault("server.write_timeout", time.Second*15)
	v.SetDefault("server.idle_timeout", time.Second*60)
	v.SetDefault("server.shutdown_timeout", time.Second*30)
	v.SetDefault("server.base_url", "http://localhost:8080")
	v.SetDefault("server.trusted_proxies", []string{"127.0.0.1", "::1"})
	v.SetDefault("server.debug_mode", false)

	// TLS defaults
	v.SetDefault("server.tls.enabled", false)
	v.SetDefault("server.tls.cert_file", "")
	v.SetDefault("server.tls.key_file", "")

	// Database defaults
	v.SetDefault("database.driver", "postgres")
	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.user", "postgres")
	v.SetDefault("database.password", "")
	v.SetDefault("database.dbname", "frank")
	v.SetDefault("database.sslmode", "disable")
	v.SetDefault("database.conn_max_lifetime", time.Hour)
	v.SetDefault("database.max_open_conns", 20)
	v.SetDefault("database.max_idle_conns", 10)
	v.SetDefault("database.dsn", "")
	v.SetDefault("database.auto_migrate", true)
	v.SetDefault("database.log_sql", false)

	// Auth defaults
	v.SetDefault("auth.session_duration", time.Hour*24*7)            // 1 week
	v.SetDefault("auth.access_token_duration", time.Minute*15)       // 15 minutes
	v.SetDefault("auth.refresh_token_duration", time.Hour*24*30)     // 30 days
	v.SetDefault("auth.verification_token_duration", time.Minute*15) // 15 minutes
	v.SetDefault("auth.magic_link_duration", time.Minute*10)         // 10 minutes
	v.SetDefault("auth.session_secret_key", "")
	v.SetDefault("auth.jwt_secret_key", "")
	v.SetDefault("auth.cookie_domain", "")
	v.SetDefault("auth.cookie_secure", true)
	v.SetDefault("auth.cookie_httponly", true)
	v.SetDefault("auth.cookie_samesite", "lax")
	v.SetDefault("auth.default_user_role", "user")

	// Password policy defaults
	v.SetDefault("auth.password_policy.min_length", 8)
	v.SetDefault("auth.password_policy.require_uppercase", true)
	v.SetDefault("auth.password_policy.require_lowercase", true)
	v.SetDefault("auth.password_policy.require_digits", true)
	v.SetDefault("auth.password_policy.require_special", true)
	v.SetDefault("auth.password_policy.prevent_reuse", true)
	v.SetDefault("auth.password_policy.max_reused_passwords", 3)
	v.SetDefault("auth.password_policy.expiry_days", 90) // 90 days

	// Email defaults
	v.SetDefault("email.provider", "smtp")
	v.SetDefault("email.from_email", "no-reply@example.com")
	v.SetDefault("email.from_name", "Frank Auth")
	v.SetDefault("email.custom_headers", map[string]string{})

	// SMTP defaults
	v.SetDefault("email.smtp.host", "localhost")
	v.SetDefault("email.smtp.port", 25)
	v.SetDefault("email.smtp.username", "")
	v.SetDefault("email.smtp.password", "")
	v.SetDefault("email.smtp.use_tls", false)

	// SMS defaults
	v.SetDefault("sms.provider", "")
	v.SetDefault("sms.from_phone", "")

	// OAuth defaults
	v.SetDefault("oauth.default_scopes", []string{"email", "profile"})
	v.SetDefault("oauth.auth_code_lifetime", time.Minute*10) // 10 minutes
	v.SetDefault("oauth.refresh_lifetime", time.Hour*24*30)  // 30 days
	v.SetDefault("oauth.access_lifetime", time.Minute*60)    // 60 minutes
	v.SetDefault("oauth.enforce_pkce", true)
	v.SetDefault("oauth.require_consent", true)
	v.SetDefault("oauth.jwt_signing_method", "RS256")

	// PassKeys defaults
	v.SetDefault("passkeys.relying_party_name", "Frank Auth")
	v.SetDefault("passkeys.attestation_timeout", 60000) // 60 seconds in milliseconds
	v.SetDefault("passkeys.assertion_timeout", 60000)   // 60 seconds in milliseconds

	// Webhooks defaults
	v.SetDefault("webhooks.default_retries", 3)
	v.SetDefault("webhooks.default_timeout", time.Second*5)
	v.SetDefault("webhooks.max_payload_size", 1024*1024) // 1MB
	v.SetDefault("webhooks.signing_secret", "")
	v.SetDefault("webhooks.retry_backoff_factor", 2.0)
	v.SetDefault("webhooks.max_retry_delay", time.Hour) // 1 hour
	v.SetDefault("webhooks.event_types", []string{
		"user.created",
		"user.updated",
		"user.deleted",
		"session.created",
		"session.revoked",
		"organization.created",
		"organization.updated",
		"organization.deleted",
		"member.added",
		"member.removed",
		"member.updated",
	})
	v.SetDefault("webhooks.queue_size", 100)
	v.SetDefault("webhooks.worker_count", 5)

	// Security defaults
	v.SetDefault("security.max_login_attempts", 5)
	v.SetDefault("security.lockout_duration", time.Minute*15) // 15 minutes
	v.SetDefault("security.rate_limit_enabled", true)
	v.SetDefault("security.rate_limit_per_second", 10.0)
	v.SetDefault("security.rate_limit_burst", 20)
	v.SetDefault("security.allowed_origins", []string{"*"})
	v.SetDefault("security.allowed_methods", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"})
	v.SetDefault("security.allowed_headers", []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With"})
	v.SetDefault("security.csrf_enabled", true)
	v.SetDefault("security.csrf_token_expiry", time.Hour*24) // 24 hours
	v.SetDefault("security.csrf_secret_key", "")
	v.SetDefault("security.csrf_cookie_name", "csrf_token")
	v.SetDefault("security.csrf_header_name", "X-CSRF-Token")
	v.SetDefault("security.allow_credentials", true)
	v.SetDefault("security.exposed_headers", []string{})
	v.SetDefault("security.sec_headers_enabled", true)
	v.SetDefault("security.x_frame_options", "DENY")
	v.SetDefault("security.content_security_policy", "default-src 'self'")
	v.SetDefault("security.xss_protection", "1; mode=block")
	v.SetDefault("security.content_type_options", "nosniff")
	v.SetDefault("security.referrer_policy", "strict-origin-when-cross-origin")
	v.SetDefault("security.ip_rate_limit", map[string]string{})

	// Logging defaults
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.output", "console")
	v.SetDefault("logging.file_path", "logs/frank.log")
	v.SetDefault("logging.max_file_size", 100) // 100MB
	v.SetDefault("logging.max_backups", 5)
	v.SetDefault("logging.max_age", 30) // 30 days
	v.SetDefault("logging.compress", true)

	// Features defaults
	v.SetDefault("features.enable_oauth2", true)
	v.SetDefault("features.enable_passwordless", true)
	v.SetDefault("features.enable_mfa", true)
	v.SetDefault("features.enable_passkeys", true)
	v.SetDefault("features.enable_sso", true)
	v.SetDefault("features.enable_enterprise_sso", true)
	v.SetDefault("features.enable_webhooks", true)
	v.SetDefault("features.enable_api_keys", true)
	v.SetDefault("features.enable_rbac", true)
	v.SetDefault("features.enable_organizations", true)

	// Templates defaults
	v.SetDefault("templates.path", "./web/templates")
	v.SetDefault("templates.email_path", "./web/templates/email")
	v.SetDefault("templates.auth_path", "./web/templates/auth")
	v.SetDefault("templates.enable_file_watcher", false)

	// Monitoring defaults
	v.SetDefault("monitoring.prometheus_enabled", false)
	v.SetDefault("monitoring.metrics_endpoint", "/metrics")
	v.SetDefault("monitoring.tracing_enabled", false)
	v.SetDefault("monitoring.tracing_provider", "jaeger")
	v.SetDefault("monitoring.jaeger_endpoint", "http://localhost:14268/api/traces")
	v.SetDefault("monitoring.otlp_endpoint", "localhost:4317")
	v.SetDefault("monitoring.sampling_rate", 0.1) // Sample 10% of requests
}
