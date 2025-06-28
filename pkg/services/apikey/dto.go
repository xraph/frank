package apikey

import (
	"github.com/rs/xid"
	"github.com/xraph/frank/pkg/model"
)

// Configuration options for various operations
type CreateOptions struct {
	UserID         *xid.ID
	OrganizationID *xid.ID
	SkipAudit      bool
}

type GetOptions struct {
	UserID         *xid.ID
	OrganizationID *xid.ID
	IncludeUsage   bool
	IncludeUser    bool
	IncludeOrg     bool
}

type UpdateOptions struct {
	UserID         *xid.ID
	OrganizationID *xid.ID
	SkipAudit      bool
}

type DeleteOptions struct {
	UserID         *xid.ID
	OrganizationID *xid.ID
	SkipAudit      bool
	Reason         string
}

type RotateOptions struct {
	UserID         *xid.ID
	OrganizationID *xid.ID
	SkipAudit      bool
}

type DeactivateOptions struct {
	UserID         *xid.ID
	OrganizationID *xid.ID
	SkipAudit      bool
}

type ActivateOptions struct {
	UserID         *xid.ID
	OrganizationID *xid.ID
	SkipAudit      bool
}

type BulkOptions struct {
	UserID         *xid.ID
	OrganizationID *xid.ID
	SkipAudit      bool
}

type StatsOptions struct {
	OrganizationID *xid.ID
	UserID         *xid.ID
	TimeRange      string
}

type ActivityOptions struct {
	OrganizationID *xid.ID
	UserID         *xid.ID
}

type ExportOptions struct {
	OrganizationID *xid.ID
	UserID         *xid.ID
}

// Constants for API key generation
const (
	// Public key prefixes
	PublicKeyTestPrefix = "pk_test_"
	PublicKeyLivePrefix = "pk_live_"

	// Secret key prefixes
	SecretKeyTestPrefix = "sk_test_"
	SecretKeyLivePrefix = "sk_live_"

	// Legacy prefix (deprecated)
	APIKeyPrefix = "frank_sk_"

	// Key generation settings
	KeyLength    = 32
	MinKeyLength = 16
	MaxKeyLength = 64

	// Rate limit defaults
	DefaultRequestsPerMinute = 1000
	DefaultRequestsPerHour   = 60000
	DefaultRequestsPerDay    = 1440000
	DefaultBurstLimit        = 100
)

// Key type validation
var (
	ValidKeyTypes = []model.APIKeyType{
		model.APIKeyTypeServer,
		model.APIKeyTypeClient,
		model.APIKeyTypeAdmin,
	}

	ValidEnvironments = []model.Environment{
		model.EnvironmentTest,
		model.EnvironmentLive,
		model.EnvironmentDevelopment,
		model.EnvironmentStaging,
		model.EnvironmentProduction,
	}

	// Public key prefixes
	PublicKeyPrefixes = []string{
		PublicKeyTestPrefix,
		PublicKeyLivePrefix,
	}

	// Secret key prefixes
	SecretKeyPrefixes = []string{
		SecretKeyTestPrefix,
		SecretKeyLivePrefix,
	}

	// All key prefixes (including legacy)
	AllKeyPrefixes = []string{
		PublicKeyTestPrefix,
		PublicKeyLivePrefix,
		SecretKeyTestPrefix,
		SecretKeyLivePrefix,
		APIKeyPrefix, // Legacy support
	}
)

// IsValidKeyType Helper functions for key validation
func IsValidKeyType(keyType model.APIKeyType) bool {
	for _, validType := range ValidKeyTypes {
		if keyType == validType {
			return true
		}
	}
	return false
}

func IsValidEnvironment(environment model.Environment) bool {
	for _, validEnv := range ValidEnvironments {
		if environment == validEnv {
			return true
		}
	}
	return false
}

func IsPublicKey(key string) bool {
	for _, prefix := range PublicKeyPrefixes {
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

func IsSecretKey(key string) bool {
	for _, prefix := range SecretKeyPrefixes {
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

func IsLegacyKey(key string) bool {
	return len(key) > len(APIKeyPrefix) && key[:len(APIKeyPrefix)] == APIKeyPrefix
}

func IsValidAPIKey(key string) bool {
	return IsPublicKey(key) || IsSecretKey(key) || IsLegacyKey(key)
}

func GetKeyEnvironment(key string) model.Environment {
	switch {
	case len(key) > len(PublicKeyTestPrefix) && key[:len(PublicKeyTestPrefix)] == PublicKeyTestPrefix:
		return model.EnvironmentTest
	case len(key) > len(PublicKeyLivePrefix) && key[:len(PublicKeyLivePrefix)] == PublicKeyLivePrefix:
		return model.EnvironmentLive
	case len(key) > len(SecretKeyTestPrefix) && key[:len(SecretKeyTestPrefix)] == SecretKeyTestPrefix:
		return model.EnvironmentTest
	case len(key) > len(SecretKeyLivePrefix) && key[:len(SecretKeyLivePrefix)] == SecretKeyLivePrefix:
		return model.EnvironmentLive
	case IsLegacyKey(key):
		return model.EnvironmentTest // Default for legacy keys
	default:
		return ""
	}
}

func GetKeyType(key string) string {
	switch {
	case IsPublicKey(key):
		return "public"
	case IsSecretKey(key):
		return "secret"
	case IsLegacyKey(key):
		return "legacy"
	default:
		return "unknown"
	}
}

// Validation errors
const (
	ErrInvalidKeyType      = "invalid API key type"
	ErrInvalidEnvironment  = "invalid environment"
	ErrInvalidKeyFormat    = "invalid API key format"
	ErrPublicKeyNotAllowed = "public key cannot be used for authentication"
	ErrSecretKeyRequired   = "secret key required for authentication"
	ErrLegacyKeyDeprecated = "legacy API key format is deprecated"
)

// Key generation settings by environment
type KeyGenerationSettings struct {
	PublicPrefix  string
	SecretPrefix  string
	Environment   model.Environment
	DefaultLength int
}

var KeySettingsByEnvironment = map[model.Environment]KeyGenerationSettings{
	model.EnvironmentTest: {
		PublicPrefix:  PublicKeyTestPrefix,
		SecretPrefix:  SecretKeyTestPrefix,
		Environment:   model.EnvironmentTest,
		DefaultLength: KeyLength,
	},
	model.EnvironmentLive: {
		PublicPrefix:  PublicKeyLivePrefix,
		SecretPrefix:  SecretKeyLivePrefix,
		Environment:   model.EnvironmentLive,
		DefaultLength: KeyLength,
	},
	model.EnvironmentDevelopment: {
		PublicPrefix:  PublicKeyTestPrefix,
		SecretPrefix:  SecretKeyTestPrefix,
		Environment:   model.EnvironmentDevelopment,
		DefaultLength: KeyLength,
	},
	model.EnvironmentStaging: {
		PublicPrefix:  PublicKeyTestPrefix,
		SecretPrefix:  SecretKeyTestPrefix,
		Environment:   model.EnvironmentStaging,
		DefaultLength: KeyLength,
	},
	model.EnvironmentProduction: {
		PublicPrefix:  PublicKeyLivePrefix,
		SecretPrefix:  SecretKeyLivePrefix,
		Environment:   model.EnvironmentProduction,
		DefaultLength: KeyLength,
	},
}

// GetKeySettings Get key generation settings for an environment
func GetKeySettings(environment model.Environment) KeyGenerationSettings {
	if settings, exists := KeySettingsByEnvironment[environment]; exists {
		return settings
	}
	// Default to test environment
	return KeySettingsByEnvironment[model.EnvironmentTest]
}
