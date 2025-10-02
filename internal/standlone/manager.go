package standalone

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/rs/xid"
	"github.com/xraph/frank/config"
	"github.com/xraph/frank/pkg/contexts"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
	"github.com/xraph/frank/pkg/services/apikey"
	"github.com/xraph/frank/pkg/services/organization"
)

// Manager handles standalone mode initialization
type Manager struct {
	config        *config.Config
	orgService    organization.Service
	apiKeyService apikey.Service
	logger        logging.Logger
}

// Context holds the initialized standalone resources
type Context struct {
	Organization *model.Organization
	APIKey       *model.APIKey
	PublicKey    string
	SecretKey    string
}

// NewManager creates a new standalone manager
func NewManager(
	cfg *config.Config,
	orgService organization.Service,
	apiKeyService apikey.Service,
	logger logging.Logger,
) *Manager {
	return &Manager{
		config:        cfg,
		orgService:    orgService,
		apiKeyService: apiKeyService,
		logger:        logger.Named("standalone"),
	}
}

// Initialize sets up standalone mode resources
func (sm *Manager) Initialize(ctx context.Context) (*Context, error) {
	if !sm.config.Standalone.Enabled {
		return nil, nil
	}

	sm.logger.Info("Initializing standalone mode",
		logging.String("org_name", sm.config.Standalone.OrganizationName),
		logging.String("org_slug", sm.config.Standalone.OrganizationSlug),
	)

	// Get or create organization
	org, err := sm.getOrCreateOrganization(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get/create organization: %w", err)
	}

	// Generate or validate API keys
	publicKey := sm.config.Standalone.PublicKey
	secretKey := sm.config.Standalone.SecretKey

	if publicKey == "" || secretKey == "" {
		if !sm.config.Standalone.AutoGenerate {
			return nil, fmt.Errorf("standalone mode requires public_key and secret_key or auto_generate=true")
		}
		publicKey, secretKey, err = sm.generateAPIKeys()
		if err != nil {
			return nil, fmt.Errorf("failed to generate API keys: %w", err)
		}
		sm.logger.Warn("Generated new API keys for standalone mode",
			logging.String("public_key", publicKey),
			logging.String("secret_key", secretKey),
		)
	}

	// Get or create API key
	apiKey, err := sm.getOrCreateAPIKey(ctx, org, publicKey, secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get/create API key: %w", err)
	}

	sm.logger.Info("Standalone mode initialized successfully",
		logging.String("org_id", org.ID.String()),
		logging.String("org_slug", org.Slug),
		logging.String("public_key", publicKey),
	)

	return &Context{
		Organization: org,
		APIKey:       apiKey,
		PublicKey:    publicKey,
		SecretKey:    secretKey,
	}, nil
}

func (sm *Manager) getOrCreateOrganization(ctx context.Context) (*model.Organization, error) {
	// Try to find existing organization using service
	org, err := sm.orgService.GetOrganizationBySlug(ctx, sm.config.Standalone.OrganizationSlug)
	if err == nil {
		// Validate it's a platform organization
		if org.OrgType != model.OrgTypePlatform {
			return nil, fmt.Errorf("existing organization '%s' is not a platform organization", org.Slug)
		}
		sm.logger.Info("Found existing standalone organization",
			logging.String("org_id", org.ID.String()))
		return org, nil
	}

	// If not found, create new organization
	if !errors.IsNotFound(err) {
		return nil, fmt.Errorf("error querying organization: %w", err)
	}

	sm.logger.Info("Creating new standalone organization")

	createReq := model.CreateOrganizationPlatformRequest{
		Name:              sm.config.Standalone.OrganizationName,
		Slug:              sm.config.Standalone.OrganizationSlug,
		OrgType:           model.OrgTypePlatform,
		Plan:              "standalone",
		ExternalUserLimit: 1000000, // Effectively unlimited
		EndUserLimit:      1000000, // Effectively unlimited
		EnableAuthService: true,
		CreateTrialPeriod: false,
		Metadata: map[string]interface{}{
			"standalone": true,
			"created_by": "system",
		},
	}

	org, err = sm.orgService.CreatePlatformOrganization(ctx, createReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create organization: %w", err)
	}

	return org, nil
}

func (sm *Manager) createStandaloneContext(ctx context.Context, org *model.Organization) context.Context {
	// Create context with organization
	ctxWithOrg := contexts.WithOrganizationID(ctx, org.ID)

	// Use nil user ID for system operations
	systemUserID := xid.NilID()
	ctxWithOrg = contexts.WithUserID(ctxWithOrg, systemUserID)

	return ctxWithOrg
}

func (sm *Manager) getOrCreateAPIKey(ctx context.Context, org *model.Organization, publicKey, secretKey string) (*model.APIKey, error) {
	// Try to find existing API key using service
	apiKey, err := sm.apiKeyService.GetAPIKeyByPublicKey(ctx, publicKey)
	if err == nil {
		// Validate and update if needed
		if apiKey.OrganizationID != org.ID {
			sm.logger.Info("Updating existing API key organization",
				logging.String("key_id", apiKey.ID.String()),
				logging.String("old_org_id", apiKey.OrganizationID.String()),
				logging.String("new_org_id", org.ID.String()),
			)

			// Update using service
			updateReq := &model.UpdateAPIKeyRequest{
				Active: true,
			}
			apiKey, err = sm.apiKeyService.UpdateAPIKey(ctx, apiKey.ID, updateReq)
			if err != nil {
				return nil, fmt.Errorf("failed to update API key: %w", err)
			}
		}

		sm.logger.Info("Found existing standalone API key",
			logging.String("key_id", apiKey.ID.String()))
		return apiKey, nil
	}

	// If not found, create new API key
	if !errors.IsNotFound(err) {
		return nil, fmt.Errorf("error querying API key: %w", err)
	}

	sm.logger.Info("Creating new standalone API key",
		logging.String("org_id", org.ID.String()),
		logging.String("public_key", publicKey),
	)

	createReq := &model.CreateAPIKeyRequest{
		Name:        "Standalone Mode API Key",
		Type:        model.APIKeyTypeServer,
		Environment: model.EnvironmentLive,
		Permissions: []string{"*"}, // Full permissions
		Scopes:      []string{"*"}, // All scopes
		Metadata: map[string]interface{}{
			"standalone":      true,
			"created_by":      "system",
			"description":     "Auto-generated API key for standalone mode",
			"organization_id": org.ID.String(),
		},
	}

	// Use the new method with predefined keys
	// No need to set context, the service will extract org ID from metadata
	response, err := sm.apiKeyService.CreateAPIKeyWithKeys(contexts.WithOrganizationID(ctx, org.ID), createReq, publicKey, secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create API key: %w", err)
	}

	sm.logger.Info("Standalone API key created with configured keys",
		logging.String("key_id", response.APIKey.ID.String()),
		logging.String("public_key", publicKey),
	)

	return &response.APIKey, nil
}

// createStandaloneAPIKey creates an API key with predefined public/secret keys
// This is a special case for standalone mode
func (sm *Manager) createStandaloneAPIKey(
	ctx context.Context,
	orgID xid.ID,
	req *model.CreateAPIKeyRequest,
	publicKey, secretKey string,
) (*model.CreateAPIKeyResponse, error) {
	// We need to create the API key through the service but with our specific keys
	// This requires either:
	// 1. Adding a special method to the API key service for standalone mode
	// 2. Or directly creating it (not ideal but acceptable for bootstrap)

	// For now, we'll call the regular service method and note this limitation
	// In a production system, you might want to add a CreateStandaloneAPIKey method to the service

	response, err := sm.apiKeyService.CreateAPIKey(ctx, req)
	if err != nil {
		return nil, err
	}

	sm.logger.Warn("API key created with auto-generated keys instead of configured keys",
		logging.String("configured_public_key", publicKey),
		logging.String("generated_public_key", response.PublicKey),
	)

	return response, nil
}

func (sm *Manager) generateAPIKeys() (publicKey, secretKey string, err error) {
	// Generate public key with prefix
	publicBytes := make([]byte, 16)
	if _, err := rand.Read(publicBytes); err != nil {
		return "", "", err
	}
	publicKey = "pk_standalone_" + base64.RawURLEncoding.EncodeToString(publicBytes)

	// Generate secret key with prefix
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", "", err
	}
	secretKey = "sk_standalone_" + base64.RawURLEncoding.EncodeToString(secretBytes)

	return publicKey, secretKey, nil
}

// GetStandaloneOrganization retrieves the standalone organization
func (sm *Manager) GetStandaloneOrganization(ctx context.Context) (*model.Organization, error) {
	org, err := sm.orgService.GetOrganizationBySlug(ctx, sm.config.Standalone.OrganizationSlug)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, fmt.Errorf("standalone organization not found")
		}
		return nil, fmt.Errorf("failed to get standalone organization: %w", err)
	}

	if org.OrgType != model.OrgTypePlatform {
		return nil, fmt.Errorf("organization '%s' is not a platform organization", org.Slug)
	}

	return org, nil
}

// ValidateStandaloneAPIKey validates an API key in standalone mode
func (sm *Manager) ValidateStandaloneAPIKey(ctx context.Context, publicKey, secretKey string) (*model.APIKey, error) {
	validateReq := &model.ValidateAPIKeyRequest{
		SecretKey: secretKey,
	}

	response, err := sm.apiKeyService.ValidateAPIKey(ctx, validateReq)
	if err != nil {
		return nil, fmt.Errorf("failed to validate API key: %w", err)
	}

	if !response.Valid {
		return nil, fmt.Errorf("invalid API key: %s", response.Error)
	}

	// Get full API key details
	apiKey, err := sm.apiKeyService.GetAPIKey(ctx, response.KeyID, &apikey.GetOptions{
		IncludeOrg:  true,
		IncludeUser: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get API key: %w", err)
	}

	// Verify it belongs to the standalone organization
	standalonOrg, err := sm.GetStandaloneOrganization(ctx)
	if err != nil {
		return nil, err
	}

	if apiKey.OrganizationID != standalonOrg.ID {
		return nil, fmt.Errorf("API key does not belong to standalone organization")
	}

	return apiKey, nil
}
