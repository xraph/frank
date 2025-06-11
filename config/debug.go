package config

import (
	"fmt"
	"os"
	"strings"
)

// DebugConfig prints current configuration values for debugging
func DebugConfig() {
	cfg := Get()
	fmt.Println("=== Configuration Debug ===")

	// Server config
	fmt.Printf("Server Host: %s\n", cfg.Server.Host)
	fmt.Printf("Server Port: %d\n", cfg.Server.Port)
	fmt.Printf("Server Base URL: %s\n", cfg.Server.BaseURL)

	// Database config
	fmt.Printf("Database Host: %s\n", cfg.Database.Host)
	fmt.Printf("Database Port: %d\n", cfg.Database.Port)
	fmt.Printf("Database User: %s\n", cfg.Database.User)
	fmt.Printf("Database Name: %s\n", cfg.Database.Database)
	fmt.Printf("Database DSN: %s\n", cfg.Database.DSN)

	// Auth config
	fmt.Printf("Auth Token Secret Key: %s\n", maskSecret(cfg.Auth.TokenSecretKey))
	fmt.Printf("Auth Session Secret Key: %s\n", maskSecret(cfg.Auth.SessionSecretKey))
	fmt.Printf("Auth Access Token Duration: %s\n", cfg.Auth.AccessTokenDuration)

	// Redis config
	fmt.Printf("Redis Host: %s\n", cfg.Redis.Host)
	fmt.Printf("Redis Port: %d\n", cfg.Redis.Port)
	fmt.Printf("Redis Database: %d\n", cfg.Redis.Database)

	// Email config
	fmt.Printf("Email Provider: %s\n", cfg.Email.Provider)
	fmt.Printf("Email From: %s\n", cfg.Email.FromEmail)

	// Feature flags
	fmt.Printf("Enable OAuth2: %t\n", cfg.Features.EnableOAuth2)
	fmt.Printf("Enable Passwordless: %t\n", cfg.Features.EnablePasswordless)
	fmt.Printf("Enable MFA: %t\n", cfg.Features.EnableMFA)
	fmt.Printf("Enable Passkeys: %t\n", cfg.Features.EnablePasskeys)

	fmt.Println("=== End Configuration Debug ===")
}

// DebugEnvironmentVariables prints all relevant environment variables
func DebugEnvironmentVariables() {
	fmt.Println("=== Environment Variables Debug ===")

	envVars := []string{
		"DATABASE_HOST", "DB_HOST",
		"DATABASE_PORT", "DB_PORT",
		"DATABASE_USER", "DB_USER",
		"DATABASE_PASSWORD", "DB_PASSWORD",
		"DATABASE_NAME", "DB_NAME",
		"DATABASE_DSN",
		"SERVER_HOST", "SERVER_PORT", "PORT",
		"AUTH_TOKEN_SECRET_KEY", "TOKEN_SECRET_KEY",
		"AUTH_SESSION_SECRET_KEY", "SESSION_SECRET_KEY",
		"REDIS_HOST", "REDIS_PORT", "REDIS_DATABASE", "REDIS_DB",
		"EMAIL_PROVIDER", "EMAIL_FROM_EMAIL",
		"FEATURE_ENABLE_OAUTH2", "ENABLE_OAUTH2",
		"FEATURE_ENABLE_MFA", "ENABLE_MFA",
		"LOG_LEVEL", "ENVIRONMENT", "ENV", "GO_ENV",
	}

	for _, envVar := range envVars {
		if value := os.Getenv(envVar); value != "" {
			if strings.Contains(strings.ToLower(envVar), "secret") ||
				strings.Contains(strings.ToLower(envVar), "password") ||
				strings.Contains(strings.ToLower(envVar), "key") {
				fmt.Printf("%s=%s\n", envVar, maskSecret(value))
			} else {
				fmt.Printf("%s=%s\n", envVar, value)
			}
		}
	}

	fmt.Println("=== End Environment Variables Debug ===")
}

// maskSecret masks sensitive information for logging
func maskSecret(secret string) string {
	if len(secret) <= 8 {
		return "***"
	}
	return secret[:4] + "***" + secret[len(secret)-4:]
}
