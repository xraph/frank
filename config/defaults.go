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
	v.SetDefault("server.name", "Wakflo")
	v.SetDefault("server.read_timeout", time.Second*15)
	v.SetDefault("server.write_timeout", time.Second*15)
	v.SetDefault("server.idle_timeout", time.Second*60)
	v.SetDefault("server.shutdown_timeout", time.Second*30)
	v.SetDefault("server.base_url", "http://localhost:8080")
	v.SetDefault("server.trusted_proxies", []string{"127.0.0.1", "::1"})
	v.SetDefault("server.debug_mode", false)

	// TLS defaults
	v.SetDefault("server.tls.enabled", false)
	v.SetDefault("server.tls.cert_file", "./certs/server.crt")
	v.SetDefault("server.tls.key_file", "./certs/server.key")

	// Database defaults
	v.SetDefault("database.driver", "postgres")
	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.user", "postgres")
	v.SetDefault("database.password", "postgres")
	v.SetDefault("database.database", "frank")
	v.SetDefault("database.ssl_mode", "disable")
	v.SetDefault("database.conn_max_life", time.Hour)
	v.SetDefault("database.max_open_conns", 20)
	v.SetDefault("database.max_idle_conns", 10)
	v.SetDefault("database.dsn", "")
	v.SetDefault("database.auto_migrate", true)
	v.SetDefault("database.log_sql", false)
	v.SetDefault("database.migrations_dir", "./migrations")

	// Auth defaults
	v.SetDefault("auth.session_duration", time.Hour*24*7)            // 1 week
	v.SetDefault("auth.access_token_duration", time.Minute*15)       // 15 minutes
	v.SetDefault("auth.refresh_token_duration", time.Hour*24*30)     // 30 days
	v.SetDefault("auth.verification_token_duration", time.Minute*15) // 15 minutes
	v.SetDefault("auth.magic_link_duration", time.Minute*10)         // 10 minutes
	v.SetDefault("auth.session_secret_key", "")
	v.SetDefault("auth.token_secret_key", "")
	v.SetDefault("auth.token_signing_method", "HS256")
	v.SetDefault("auth.token_issuer", "frank")
	v.SetDefault("auth.cookie_domain", "")
	v.SetDefault("auth.cookie_secure", true)
	v.SetDefault("auth.cookie_http_only", true)
	v.SetDefault("auth.cookie_same_site", "lax")
	v.SetDefault("auth.default_user_role", "user")
	v.SetDefault("auth.default_admin_role", "admin")
	v.SetDefault("auth.default_super_role", "super")
	v.SetDefault("auth.require_email_verification", true)
	v.SetDefault("auth.email_verification_expiry", time.Hour*24) // 24 hours
	v.SetDefault("auth.auto_register_users", false)
	v.SetDefault("auth.max_login_attempts", 5)
	v.SetDefault("auth.login_lockout_duration", time.Minute*15) // 15 minutes

	// Password policy defaults
	v.SetDefault("auth.password_policy.password_min_length", 8)
	v.SetDefault("auth.password_policy.password_max_length", 100)
	v.SetDefault("auth.password_policy.password_require_uppercase", true)
	v.SetDefault("auth.password_policy.password_require_lowercase", true)
	v.SetDefault("auth.password_policy.password_require_digit", true)
	v.SetDefault("auth.password_policy.password_require_special", false)
	v.SetDefault("auth.password_policy.password_max_reused_passwords", 3)
	v.SetDefault("auth.password_policy.password_prevent_reuse", true)
	v.SetDefault("auth.password_policy.password_expiry_days", 90) // 90 days

	// Email defaults
	v.SetDefault("email.provider", "smtp")
	v.SetDefault("email.from_email", "no-reply@example.com")
	v.SetDefault("email.from_name", "Frank Auth")
	v.SetDefault("email.templates_dir", "./templates/email")
	v.SetDefault("email.default_language", "en")
	v.SetDefault("email.custom_headers", map[string]string{})

	// SMTP defaults
	v.SetDefault("email.smtp.host", "localhost")
	v.SetDefault("email.smtp.port", 25)
	v.SetDefault("email.smtp.username", "")
	v.SetDefault("email.smtp.password", "")
	v.SetDefault("email.smtp.use_tls", false)

	// SMS defaults
	v.SetDefault("sms.provider", "mock")
	v.SetDefault("sms.from_phone", "+15555555555")
	v.SetDefault("sms.from_number", "")
	v.SetDefault("sms.verification_template", "Your verification code is: {{code}}")
	v.SetDefault("sms.verification_code_length", 6)
	v.SetDefault("sms.verification_code_expiry", time.Minute*10) // 10 minutes

	// Redis defaults
	v.SetDefault("redis.host", "localhost")
	v.SetDefault("redis.port", 6379)
	v.SetDefault("redis.password", "")
	v.SetDefault("redis.database", 0)
	v.SetDefault("redis.max_retries", 3)
	v.SetDefault("redis.min_retry_backoff", time.Millisecond*8)   // 8ms
	v.SetDefault("redis.max_retry_backoff", time.Millisecond*512) // 512ms
	v.SetDefault("redis.dial_timeout", time.Second*5)
	v.SetDefault("redis.read_timeout", time.Second*3)
	v.SetDefault("redis.write_timeout", time.Second*3)
	v.SetDefault("redis.pool_size", 10)
	v.SetDefault("redis.min_idle_conns", 5)
	v.SetDefault("redis.max_idle_conns", 10)
	v.SetDefault("redis.conn_max_idle_time", time.Minute*5)
	v.SetDefault("redis.conn_max_lifetime", time.Hour)

	// OAuth defaults
	v.SetDefault("oauth.default_scopes", []string{"openid", "profile", "email"})
	v.SetDefault("oauth.auth_code_lifetime", time.Minute*10) // 10 minutes
	v.SetDefault("oauth.refresh_lifetime", time.Hour*24*30)  // 30 days
	v.SetDefault("oauth.access_lifetime", time.Hour)         // 60 minutes
	v.SetDefault("oauth.enforce_pkce", true)
	v.SetDefault("oauth.require_consent", true)
	v.SetDefault("oauth.jwt_signing_method", "HS256")
	v.SetDefault("oauth.enable_pkce", true)
	v.SetDefault("oauth.require_pkce", false)
	v.SetDefault("oauth.enable_oidc", true)
	v.SetDefault("oauth.jwks_path", "./certs/jwks.json")

	// PassKeys/WebAuthn defaults
	v.SetDefault("passkeys.relying_party_name", "Frank Auth")
	v.SetDefault("passkeys.relying_party_id", "localhost")
	v.SetDefault("passkeys.relying_party_origins", []string{"http://localhost:8080"})
	v.SetDefault("passkeys.rp_display_name", "Frank Auth")
	v.SetDefault("passkeys.rp_id", "localhost")
	v.SetDefault("passkeys.rp_origins", []string{"http://localhost:8080"})
	v.SetDefault("passkeys.attestation_timeout", 60000) // 60 seconds in milliseconds
	v.SetDefault("passkeys.assertion_timeout", 60000)   // 60 seconds in milliseconds
	v.SetDefault("passkeys.conveyance_preference", "direct")
	v.SetDefault("passkeys.authenticator_attachment", "")
	v.SetDefault("passkeys.user_verification", "preferred")
	v.SetDefault("passkeys.use_inmemory_repository", false)
	v.SetDefault("passkeys.use_redis_session_store", true)

	// Webhooks defaults
	v.SetDefault("webhooks.default_retries", 3)
	v.SetDefault("webhooks.default_timeout", time.Second*5)
	v.SetDefault("webhooks.max_payload_size", 1024*1024) // 1MB
	v.SetDefault("webhooks.signing_secret", "")
	v.SetDefault("webhooks.retry_backoff_factor", 2.0)
	v.SetDefault("webhooks.max_retry_delay", time.Second*5)
	v.SetDefault("webhooks.max_concurrency", 10)
	v.SetDefault("webhooks.enable_async", true)
	v.SetDefault("webhooks.event_types", []string{
		"user.created",
		"user.updated",
		"user.deleted",
		"user.login",
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
	v.SetDefault("webhooks.worker_count", 4)

	// Security defaults
	v.SetDefault("security.max_login_attempts", 5)
	v.SetDefault("security.lockout_duration", time.Minute*15) // 15 minutes
	v.SetDefault("security.rate_limit_enabled", true)
	v.SetDefault("security.rate_limit_per_second", 10.0)
	v.SetDefault("security.rate_limit_burst", 30)
	v.SetDefault("security.allowed_origins", []string{"http://localhost:3000", "http://localhost:8080"})
	v.SetDefault("security.allowed_methods", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"})
	v.SetDefault("security.allowed_headers", []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"})
	v.SetDefault("security.exposed_headers", []string{"X-CSRF-Token"})
	v.SetDefault("security.allow_credentials", true)
	v.SetDefault("security.csrf_enabled", true)
	v.SetDefault("security.csrf_token_expiry", time.Hour*2) // 2 hours
	v.SetDefault("security.csrf_secret_key", "")
	v.SetDefault("security.csrf_cookie_name", "csrf_token")
	v.SetDefault("security.csrf_header_name", "X-CSRF-Token")
	v.SetDefault("security.sec_headers_enabled", true)
	v.SetDefault("security.xss_protection", "1; mode=block")
	v.SetDefault("security.content_type_nosniff", "nosniff")
	v.SetDefault("security.x_frame_options", "SAMEORIGIN")
	v.SetDefault("security.content_type_options", "nosniff")
	v.SetDefault("security.referrer_policy", "no-referrer")
	v.SetDefault("security.hsts_max_age", 31536000)
	v.SetDefault("security.hsts_include_subdomains", true)
	v.SetDefault("security.content_security_policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline';")
	v.SetDefault("security.csrf_protection_enabled", true)
	v.SetDefault("security.csrf_allowed_hosts", []string{"localhost"})
	v.SetDefault("security.ip_geolocation_enabled", false)
	v.SetDefault("security.ip_rate_limit", map[string]string{})
	v.SetDefault("security.public_paths", []string{
		"/swagger",
	})

	// Logging defaults
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.output", "stdout")
	v.SetDefault("logging.file_path", "./logs/frank.log")
	v.SetDefault("logging.max_size", 100) // 100MB
	v.SetDefault("logging.max_backups", 3)
	v.SetDefault("logging.max_age", 28) // 28 days
	v.SetDefault("logging.compress", true)
	v.SetDefault("logging.request_logs", true)

	// Features defaults
	v.SetDefault("features.enable_oauth2", true)
	v.SetDefault("features.enable_sso", true)
	v.SetDefault("features.enable_enterprise_sso", false)
	v.SetDefault("features.enable_rbac", true)
	v.SetDefault("features.enable_organizations", true)
	v.SetDefault("features.enable_user_api", true)
	v.SetDefault("features.enable_organization_api", true)
	v.SetDefault("features.enable_mfa", true)
	v.SetDefault("features.enable_webhooks", true)
	v.SetDefault("features.enable_passwordless", true)
	v.SetDefault("features.enable_passkeys", true)
	v.SetDefault("features.enable_api_keys", true)
	v.SetDefault("features.enable_audit_logs", true)
	v.SetDefault("features.enable_user_lockout", true)
	v.SetDefault("features.enable_user_impersonation", false)
	v.SetDefault("features.enable_feature_flags", true)

	// Templates defaults
	v.SetDefault("templates.path", "./templates")
	v.SetDefault("templates.email_path", "./templates/email")
	v.SetDefault("templates.auth_path", "./templates/auth")
	v.SetDefault("templates.enable_file_watcher", true)

	// Monitoring defaults
	v.SetDefault("monitoring.enabled", true)
	v.SetDefault("monitoring.prometheus", true)
	v.SetDefault("monitoring.prometheus_path", "/metrics")
	v.SetDefault("monitoring.statsd_enabled", false)
	v.SetDefault("monitoring.statsd_host", "localhost")
	v.SetDefault("monitoring.statsd_port", 8125)
	v.SetDefault("monitoring.statsd_prefix", "frank")
	v.SetDefault("monitoring.tracing_enabled", false)
	v.SetDefault("monitoring.tracing_provider", "jaeger")
	v.SetDefault("monitoring.jaeger_endpoint", "http://localhost:14268/api/traces")
	v.SetDefault("monitoring.otlp_endpoint", "http://localhost:4317")
	v.SetDefault("monitoring.sampling_rate", 0.1) // Sample 10% of requests
	v.SetDefault("monitoring.health_check_path", "/health")
	v.SetDefault("monitoring.readiness_path", "/ready")
}
