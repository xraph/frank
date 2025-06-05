package organization

import (
	"context"
	"fmt"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/featureflag"
	"github.com/juicycleff/frank/pkg/errors"
)

// FeaturesManager manages organization features
type FeaturesManager struct {
	repo       Repository
	client     *ent.Client
	config     *config.Config
	featureMap map[string]FeatureDetails
}

// FeatureDetails contains information about a feature
type FeatureDetails struct {
	Key         string
	Name        string
	Description string
	Component   string
	IsPremium   bool
	Settings    map[string]SettingDefinition
}

// SettingDefinition defines a setting for a feature
type SettingDefinition struct {
	Type        string // "boolean", "string", "number", "select"
	Default     interface{}
	Description string
	Options     []string // For "select" type
	Required    bool
}

// NewFeaturesManager creates a new features manager
func NewFeaturesManager(repo Repository, client *ent.Client, cfg *config.Config) *FeaturesManager {
	manager := &FeaturesManager{
		repo:       repo,
		client:     client,
		config:     cfg,
		featureMap: make(map[string]FeatureDetails),
	}

	// Register default features
	manager.registerDefaultFeatures()

	return manager
}

// registerDefaultFeatures registers the default features
func (m *FeaturesManager) registerDefaultFeatures() {
	// OAuth2 feature
	m.featureMap["oauth2"] = FeatureDetails{
		Key:         "oauth2",
		Name:        "OAuth 2.0",
		Description: "OAuth 2.0 authentication and authorization",
		Component:   "oauth2",
		IsPremium:   false,
		Settings: map[string]SettingDefinition{
			"enforce_pkce": {
				Type:        "boolean",
				Default:     true,
				Description: "Enforce PKCE (Proof Key for Code Exchange)",
			},
			"token_lifetime": {
				Type:        "number",
				Default:     3600,
				Description: "Access token lifetime in seconds",
			},
			"refresh_token_lifetime": {
				Type:        "number",
				Default:     2592000, // 30 days
				Description: "Refresh token lifetime in seconds",
			},
		},
	}

	// Passwordless feature
	m.featureMap["passwordless"] = FeatureDetails{
		Key:         "passwordless",
		Name:        "Passwordless",
		Description: "Passwordless authentication with magic links and OTPs",
		Component:   "passwordless",
		IsPremium:   false,
		Settings: map[string]SettingDefinition{
			"allow_email": {
				Type:        "boolean",
				Default:     true,
				Description: "Allow email-based passwordless authentication",
			},
			"allow_sms": {
				Type:        "boolean",
				Default:     true,
				Description: "Allow SMS-based passwordless authentication",
			},
			"magic_link_lifetime": {
				Type:        "number",
				Default:     600, // 10 minutes
				Description: "Magic link lifetime in seconds",
			},
			"otp_lifetime": {
				Type:        "number",
				Default:     300, // 5 minutes
				Description: "One-time password lifetime in seconds",
			},
		},
	}

	// MFA feature
	m.featureMap["mfa"] = FeatureDetails{
		Key:         "mfa",
		Name:        "Multi-Factor Authentication",
		Description: "Strengthen security with multi-factor authentication",
		Component:   "mfa",
		IsPremium:   false,
		Settings: map[string]SettingDefinition{
			"allow_totp": {
				Type:        "boolean",
				Default:     true,
				Description: "Allow TOTP (Time-based One-Time Password) authentication",
			},
			"allow_sms": {
				Type:        "boolean",
				Default:     true,
				Description: "Allow SMS-based multi-factor authentication",
			},
			"allow_email": {
				Type:        "boolean",
				Default:     true,
				Description: "Allow email-based multi-factor authentication",
			},
			"require_mfa": {
				Type:        "boolean",
				Default:     false,
				Description: "Require MFA for all users",
			},
		},
	}

	// Passkeys feature
	m.featureMap["passkeys"] = FeatureDetails{
		Key:         "passkeys",
		Name:        "Passkeys (WebAuthn)",
		Description: "Passwordless authentication with FIDO2/WebAuthn",
		Component:   "passkeys",
		IsPremium:   false,
		Settings: map[string]SettingDefinition{
			"user_verification": {
				Type:        "select",
				Default:     "preferred",
				Description: "User verification requirement",
				Options:     []string{"discouraged", "preferred", "required"},
			},
			"attestation": {
				Type:        "select",
				Default:     "none",
				Description: "Attestation conveyance preference",
				Options:     []string{"none", "indirect", "direct"},
			},
		},
	}

	// SSO feature
	m.featureMap["sso"] = FeatureDetails{
		Key:         "sso",
		Name:        "Single Sign-On",
		Description: "Authenticate users via external identity providers",
		Component:   "sso",
		IsPremium:   true,
		Settings: map[string]SettingDefinition{
			"allow_multiple_connections": {
				Type:        "boolean",
				Default:     true,
				Description: "Allow multiple SSO connections per user",
			},
			"force_sso_for_domain": {
				Type:        "boolean",
				Default:     false,
				Description: "Force SSO for users with organization domain",
			},
		},
	}

	// Enterprise SSO feature
	m.featureMap["enterprise_sso"] = FeatureDetails{
		Key:         "enterprise_sso",
		Name:        "Enterprise SSO",
		Description: "Advanced SSO with SAML and custom OIDC providers",
		Component:   "enterprise",
		IsPremium:   true,
		Settings: map[string]SettingDefinition{
			"allow_saml": {
				Type:        "boolean",
				Default:     true,
				Description: "Allow SAML authentication",
			},
			"allow_custom_oidc": {
				Type:        "boolean",
				Default:     true,
				Description: "Allow custom OIDC providers",
			},
			"enforce_domain_restriction": {
				Type:        "boolean",
				Default:     true,
				Description: "Enforce domain restrictions for SSO",
			},
		},
	}

	// Webhooks feature
	m.featureMap["webhooks"] = FeatureDetails{
		Key:         "webhooks",
		Name:        "Webhooks",
		Description: "Receive event notifications via webhooks",
		Component:   "webhooks",
		IsPremium:   false,
		Settings: map[string]SettingDefinition{
			"max_retries": {
				Type:        "number",
				Default:     3,
				Description: "Maximum number of retry attempts",
			},
			"signing_algorithm": {
				Type:        "select",
				Default:     "sha256",
				Description: "Webhook signature algorithm",
				Options:     []string{"sha256", "sha512"},
			},
		},
	}

	// API Keys feature
	m.featureMap["api_keys"] = FeatureDetails{
		Key:         "api_keys",
		Name:        "API Keys",
		Description: "Machine-to-machine authentication with API keys",
		Component:   "api_keys",
		IsPremium:   false,
		Settings: map[string]SettingDefinition{
			"max_keys_per_org": {
				Type:        "number",
				Default:     100,
				Description: "Maximum number of API keys per organization",
			},
			"default_key_expiry": {
				Type:        "number",
				Default:     31536000, // 1 year in seconds
				Description: "Default API key expiry in seconds",
			},
		},
	}
}

// EnsureDefaultFeatureFlagsExist ensures that all default feature flags exist in the database
func (m *FeaturesManager) EnsureDefaultFeatureFlagsExist(ctx context.Context) error {
	for key, details := range m.featureMap {
		// Check if feature flag already exists
		exists, err := m.client.FeatureFlag.
			Query().
			Where(featureflag.Key(key)).
			Exist(ctx)

		if err != nil {
			return errors.Wrap(errors.CodeDatabaseError, err, "failed to check feature flag existence")
		}

		if !exists {
			// Feature flag doesn't exist, create it
			_, err = m.client.FeatureFlag.
				Create().
				SetName(details.Name).
				SetKey(key).
				SetDescription(details.Description).
				SetComponent(featureflag.Component(details.Component)).
				SetIsPremium(details.IsPremium).
				// Default enabled state based on config
				SetEnabled(m.isFeatureEnabledInConfig(key)).
				Save(ctx)

			if err != nil {
				return errors.Wrap(errors.CodeDatabaseError, err, "failed to create feature flag")
			}
		}
	}

	return nil
}

// isFeatureEnabledInConfig checks if a feature is enabled in the config
func (m *FeaturesManager) isFeatureEnabledInConfig(key string) bool {
	switch key {
	case "oauth2":
		return m.config.Features.EnableOAuth2
	case "passwordless":
		return m.config.Features.EnablePasswordless
	case "mfa":
		return m.config.Features.EnableMFA
	case "passkeys":
		return m.config.Features.EnablePasskeys
	case "sso":
		return m.config.Features.EnableSSO
	case "enterprise_sso":
		return m.config.Features.EnableEnterpriseSSO
	case "webhooks":
		return m.config.Features.EnableWebhooks
	case "api_keys":
		return m.config.Features.EnableAPIKeys
	default:
		return false
	}
}

// GetFeatureDetails returns details for a specific feature
func (m *FeaturesManager) GetFeatureDetails(key string) (FeatureDetails, error) {
	details, ok := m.featureMap[key]
	if !ok {
		return FeatureDetails{}, fmt.Errorf("feature not found: %s", key)
	}
	return details, nil
}

// GetAllFeatureDetails returns details for all features
func (m *FeaturesManager) GetAllFeatureDetails() map[string]FeatureDetails {
	return m.featureMap
}

// IsFeatureAllowedForPlan checks if a feature is allowed for a specific plan
func (m *FeaturesManager) IsFeatureAllowedForPlan(feature, plan string) bool {
	details, ok := m.featureMap[feature]
	if !ok {
		return false
	}

	// Premium features are only available for paid plans
	if details.IsPremium {
		return plan != "free"
	}

	// Non-premium features are available for all plans
	return true
}

// ValidateSettings validates feature settings against the defined schema
func (m *FeaturesManager) ValidateSettings(feature string, settings map[string]interface{}) error {
	details, ok := m.featureMap[feature]
	if !ok {
		return fmt.Errorf("unknown feature: %s", feature)
	}

	// Check for required settings
	for settingKey, definition := range details.Settings {
		if definition.Required {
			if _, exists := settings[settingKey]; !exists {
				return fmt.Errorf("missing required setting: %s", settingKey)
			}
		}
	}

	// Validate each setting
	for settingKey, value := range settings {
		definition, ok := details.Settings[settingKey]
		if !ok {
			return fmt.Errorf("unknown setting: %s", settingKey)
		}

		// Type validation
		switch definition.Type {
		case "boolean":
			if _, ok := value.(bool); !ok {
				return fmt.Errorf("setting %s must be a boolean", settingKey)
			}
		case "string":
			if _, ok := value.(string); !ok {
				return fmt.Errorf("setting %s must be a string", settingKey)
			}
		case "number":
			// JSON numbers could be float64 or int
			_, ok1 := value.(float64)
			_, ok2 := value.(int)
			if !ok1 && !ok2 {
				return fmt.Errorf("setting %s must be a number", settingKey)
			}
		case "select":
			strValue, ok := value.(string)
			if !ok {
				return fmt.Errorf("setting %s must be a string", settingKey)
			}

			// Check if value is in options
			valid := false
			for _, option := range definition.Options {
				if strValue == option {
					valid = true
					break
				}
			}

			if !valid {
				return fmt.Errorf("setting %s must be one of: %v", settingKey, definition.Options)
			}
		}
	}

	return nil
}

// GetDefaultSettings returns default settings for a feature
func (m *FeaturesManager) GetDefaultSettings(feature string) map[string]interface{} {
	details, ok := m.featureMap[feature]
	if !ok {
		return nil
	}

	defaults := make(map[string]interface{})
	for key, definition := range details.Settings {
		defaults[key] = definition.Default
	}

	return defaults
}

// MergeSettings merges custom settings with defaults
func (m *FeaturesManager) MergeSettings(feature string, custom map[string]interface{}) map[string]interface{} {
	defaults := m.GetDefaultSettings(feature)

	// If no custom settings, return defaults
	if custom == nil {
		return defaults
	}

	// Merge custom settings with defaults
	result := make(map[string]interface{})
	for key, value := range defaults {
		result[key] = value
	}

	for key, value := range custom {
		result[key] = value
	}

	return result
}
