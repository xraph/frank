package sso

import (
	"context"

	"github.com/rs/xid"
	"github.com/xraph/frank/internal/repository"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
)

// ProviderCatalogService manages the SSO provider catalog
type ProviderCatalogService interface {
	// Catalog management
	SeedProviderCatalog(ctx context.Context) error
	GetAvailableProviders(ctx context.Context) ([]model.ProviderTemplate, error)
	ListProviderTemplates(ctx context.Context, params model.ProviderCatalogListRequest) (*model.PaginatedOutput[model.ProviderTemplate], error)
	GetProviderTemplate(ctx context.Context, templateKey string) (*model.ProviderTemplate, error)

	// Organization provider management
	EnableProviderForOrganization(ctx context.Context, req model.EnableProviderBody) (*model.IdentityProvider, error)
	GetOrganizationProviders(ctx context.Context, orgID xid.ID) ([]model.OrganizationProvider, error)
	ConfigureProvider(ctx context.Context, providerID xid.ID, config model.ProviderConfiguration) (*model.IdentityProvider, error)
}

// providerCatalogService implements the provider catalog
type providerCatalogService struct {
	logger          logging.Logger
	catalogRepo     repository.ProviderCatalogRepository
	providerRepo    repository.IdentityProviderRepository
	orgProviderRepo repository.OrganizationProviderRepository
	ssoService      Service
}

// NewProviderCatalogService creates a new provider catalog service
func NewProviderCatalogService(
	repo repository.Repository,
	ssoService Service,
	logger logging.Logger,
) ProviderCatalogService {
	return &providerCatalogService{
		logger:          logger,
		catalogRepo:     repo.ProviderCatalog(),
		providerRepo:    repo.IdentityProvider(),
		orgProviderRepo: repo.OrganizationProvider(),
		ssoService:      ssoService,
	}
}

// SeedProviderCatalog seeds the database with popular provider templates
func (s *providerCatalogService) SeedProviderCatalog(ctx context.Context) error {
	s.logger.Info("Seeding SSO provider catalog")

	// Define popular providers with enhanced metadata
	popularProviders := []model.ProviderTemplate{
		{
			Key:         "google",
			Name:        "Google",
			DisplayName: "Sign in with Google",
			Type:        "oidc",
			Protocol:    "openid_connect",
			IconURL:     "https://developers.google.com/identity/images/g-logo.png",
			Category:    "social",
			Popular:     true,
			Active:      true,
			Description: "Sign in with your Google account",
			ConfigTemplate: map[string]any{
				"issuer":      "https://accounts.google.com",
				"authUrl":     "https://accounts.google.com/o/oauth2/v2/auth",
				"tokenUrl":    "https://oauth2.googleapis.com/token",
				"userInfoUrl": "https://www.googleapis.com/oauth2/v2/userinfo",
				"jwksUrl":     "https://www.googleapis.com/oauth2/v3/certs",
				"scopes":      []string{"openid", "email", "profile"},
			},
			RequiredFields:    []string{"clientId", "clientSecret"},
			SupportedFeatures: []string{"auto_discovery", "pkce", "id_token"},
		},
		{
			Key:         "microsoft",
			Name:        "Microsoft",
			DisplayName: "Sign in with Microsoft",
			Type:        "oidc",
			Protocol:    "openid_connect",
			IconURL:     "https://learn.microsoft.com/en-us/azure/active-directory/develop/media/howto-add-branding-in-azure-ad-apps/ms-symbollockup_mssymbol_19.png",
			Category:    "enterprise",
			Popular:     true,
			Active:      true,
			Description: "Sign in with your Microsoft account or Azure AD",
			ConfigTemplate: map[string]any{
				"issuer":      "https://login.microsoftonline.com/common/v2.0",
				"authUrl":     "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
				"tokenUrl":    "https://login.microsoftonline.com/common/oauth2/v2.0/token",
				"userInfoUrl": "https://graph.microsoft.com/v1.0/me",
				"jwksUrl":     "https://login.microsoftonline.com/common/discovery/v2.0/keys",
				"scopes":      []string{"openid", "email", "profile"},
			},
			RequiredFields:    []string{"clientId", "clientSecret"},
			SupportedFeatures: []string{"auto_discovery", "pkce", "id_token", "tenant_specific"},
		},
		{
			Key:         "github",
			Name:        "GitHub",
			DisplayName: "Sign in with GitHub",
			Type:        "oauth2",
			Protocol:    "oauth2",
			IconURL:     "https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png",
			Category:    "developer",
			Popular:     true,
			Active:      true,
			Description: "Sign in with your GitHub account",
			ConfigTemplate: map[string]any{
				"authUrl":     "https://github.com/login/oauth/authorize",
				"tokenUrl":    "https://github.com/login/oauth/access_token",
				"userInfoUrl": "https://api.github.com/user",
				"scopes":      []string{"user:email"},
			},
			RequiredFields:    []string{"clientId", "clientSecret"},
			SupportedFeatures: []string{"organizations", "teams"},
		},
		{
			Key:         "gitlab",
			Name:        "GitLab",
			DisplayName: "Sign in with GitLab",
			Type:        "oidc",
			Protocol:    "openid_connect",
			IconURL:     "https://about.gitlab.com/images/press/logo/png/gitlab-icon-rgb.png",
			Category:    "developer",
			Popular:     true,
			Active:      true,
			Description: "Sign in with your GitLab account",
			ConfigTemplate: map[string]any{
				"issuer":      "https://gitlab.com",
				"authUrl":     "https://gitlab.com/oauth/authorize",
				"tokenUrl":    "https://gitlab.com/oauth/token",
				"userInfoUrl": "https://gitlab.com/oauth/userinfo",
				"scopes":      []string{"openid", "email", "profile"},
			},
			RequiredFields:    []string{"clientId", "clientSecret"},
			SupportedFeatures: []string{"groups", "projects"},
		},
		{
			Key:         "discord",
			Name:        "Discord",
			DisplayName: "Sign in with Discord",
			Type:        "oauth2",
			Protocol:    "oauth2",
			IconURL:     "https://assets-global.website-files.com/6257adef93867e50d84d30e2/636e0a6ca814282eca7172c6_icon_clyde_white_RGB.svg",
			Category:    "social",
			Popular:     false,
			Active:      true,
			Description: "Sign in with your Discord account",
			ConfigTemplate: map[string]any{
				"authUrl":     "https://discord.com/api/oauth2/authorize",
				"tokenUrl":    "https://discord.com/api/oauth2/token",
				"userInfoUrl": "https://discord.com/api/users/@me",
				"scopes":      []string{"identify", "email"},
			},
			RequiredFields:    []string{"clientId", "clientSecret"},
			SupportedFeatures: []string{"guilds", "connections"},
		},
		{
			Key:         "apple",
			Name:        "Apple",
			DisplayName: "Sign in with Apple",
			Type:        "oidc",
			Protocol:    "openid_connect",
			IconURL:     "https://developer.apple.com/assets/elements/icons/sign-in-with-apple/sign-in-with-apple.svg",
			Category:    "social",
			Popular:     true,
			Active:      true,
			Description: "Sign in with your Apple ID",
			ConfigTemplate: map[string]any{
				"issuer":   "https://appleid.apple.com",
				"authUrl":  "https://appleid.apple.com/auth/authorize",
				"tokenUrl": "https://appleid.apple.com/auth/token",
				"jwksUrl":  "https://appleid.apple.com/auth/keys",
				"scopes":   []string{"name", "email"},
			},
			RequiredFields:    []string{"clientId", "keyId", "teamId", "privateKey"},
			SupportedFeatures: []string{"privacy_focused", "jwt_client_auth"},
		},
		{
			Key:         "saml_generic",
			Name:        "Generic SAML",
			DisplayName: "SAML 2.0 Provider",
			Type:        "saml",
			Protocol:    "saml2",
			IconURL:     "https://upload.wikimedia.org/wikipedia/commons/thumb/6/68/SAML_Logo.svg/256px-SAML_Logo.svg.png",
			Category:    "enterprise",
			Popular:     true,
			Active:      true,
			Description: "Configure any SAML 2.0 compliant identity provider",
			ConfigTemplate: map[string]any{
				"nameIdFormat":        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
				"wantAssertionSigned": true,
				"signRequests":        false,
			},
			RequiredFields:    []string{"ssoUrl", "entityId", "certificate"},
			SupportedFeatures: []string{"metadata_import", "attribute_mapping", "encryption"},
		},
	}

	// Seed each provider template
	for _, template := range popularProviders {
		if err := s.catalogRepo.UpsertTemplate(ctx, template); err != nil {
			s.logger.Error("Failed to seed provider template",
				logging.String("provider", template.Key),
				logging.Error(err))
			continue
		}
		s.logger.Debug("Seeded provider template", logging.String("provider", template.Key))
	}

	s.logger.Info("Successfully seeded SSO provider catalog",
		logging.Int("count", len(popularProviders)))

	return nil
}

// GetAvailableProviders returns all available provider templates
func (s *providerCatalogService) GetAvailableProviders(ctx context.Context) ([]model.ProviderTemplate, error) {
	templates, err := s.catalogRepo.ListTemplates(ctx, repository.ListTemplatesParams{
		IncludeInactive: false,
	})
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get provider templates")
	}

	return templates.Data, nil
}

func (s *providerCatalogService) ListProviderTemplates(ctx context.Context, params model.ProviderCatalogListRequest) (*model.PaginatedOutput[model.ProviderTemplate], error) {
	reqParams := repository.ListTemplatesParams{
		PaginationParams: params.PaginationParams,
		Category:         params.Category,
		Type:             params.Type,
		IncludeInactive:  false,
		Search:           params.Search,
	}
	if params.IncludeInactive.IsSet {
		reqParams.IncludeInactive = params.IncludeInactive.Value
	}
	if params.Popular.IsSet {
		reqParams.Popular = &params.Popular.Value
	}

	templates, err := s.catalogRepo.ListTemplates(ctx, reqParams)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get provider templates")
	}

	return templates, nil
}

// GetProviderTemplate returns a specific provider template
func (s *providerCatalogService) GetProviderTemplate(ctx context.Context, templateKey string) (*model.ProviderTemplate, error) {
	template, err := s.catalogRepo.GetTemplateByKey(ctx, templateKey)
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "provider template not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get provider template")
	}

	return template, nil
}

// EnableProviderForOrganization enables a provider template for an organization
func (s *providerCatalogService) EnableProviderForOrganization(ctx context.Context, req model.EnableProviderBody) (*model.IdentityProvider, error) {
	s.logger.Info("Enabling provider for organization",
		logging.String("template", req.TemplateKey),
		logging.String("org_id", req.OrganizationID.String()))

	// Get the provider template
	template, err := s.GetProviderTemplate(ctx, req.TemplateKey)
	if err != nil {
		return nil, err
	}

	// Validate required configuration
	if err := s.validateRequiredConfig(template, req.Config); err != nil {
		return nil, errors.Wrap(err, errors.CodeInvalidInput, "invalid provider configuration")
	}

	// Merge template config with provided config
	finalConfig := s.mergeConfigs(template.ConfigTemplate, req.Config)

	// Create the identity provider
	createReq := model.CreateIdentityProviderRequest{
		Name:             req.CustomName,
		Type:             template.Type,
		Protocol:         template.Protocol,
		Domain:           req.Domain,
		AutoProvision:    req.AutoProvision,
		DefaultRole:      req.DefaultRole,
		AttributeMapping: req.AttributeMapping,
		Config:           finalConfig,
		IconURL:          template.IconURL,
		ButtonText:       req.CustomButtonText,
	}

	// Use custom name or fallback to template display name
	if createReq.Name == "" {
		createReq.Name = template.DisplayName
	}

	if createReq.ButtonText == "" {
		createReq.ButtonText = template.DisplayName
	}

	// Create the provider through the main SSO service
	provider, err := s.ssoService.CreateProvider(ctx, req.OrganizationID, createReq)
	if err != nil {
		return nil, err
	}

	// Track the relationship between template and organization provider
	orgProvider := repository.CreateOrganizationProviderInput{
		OrganizationID: req.OrganizationID,
		ProviderID:     provider.ID,
		TemplateKey:    req.TemplateKey,
		CustomConfig:   req.Config,
		EnabledAt:      provider.CreatedAt,
	}

	if _, err := s.orgProviderRepo.Create(ctx, orgProvider); err != nil {
		s.logger.Warn("Failed to create organization provider relationship", logging.Error(err))
		// Don't fail the main operation for this
	}

	return provider, nil
}

// GetOrganizationProviders returns all providers configured for an organization
func (s *providerCatalogService) GetOrganizationProviders(ctx context.Context, orgID xid.ID) ([]model.OrganizationProvider, error) {
	orgProviders, err := s.orgProviderRepo.ListByOrganization(ctx, orgID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get organization providers")
	}

	return orgProviders, nil
}

// ConfigureProvider updates provider configuration
func (s *providerCatalogService) ConfigureProvider(ctx context.Context, providerID xid.ID, config model.ProviderConfiguration) (*model.IdentityProvider, error) {
	// Get existing provider
	_, err := s.ssoService.GetProvider(ctx, providerID)
	if err != nil {
		return nil, err
	}

	// Update the provider
	updateReq := model.UpdateIdentityProviderRequest{
		Config:           config.Config,
		Domain:           config.Domain,
		AutoProvision:    config.AutoProvision,
		DefaultRole:      config.DefaultRole,
		AttributeMapping: config.AttributeMapping,
		Enabled:          config.Enabled,
	}

	return s.ssoService.UpdateProvider(ctx, providerID, updateReq)
}

// Helper methods

// validateRequiredConfig validates that all required fields are provided
func (s *providerCatalogService) validateRequiredConfig(template *model.ProviderTemplate, config map[string]any) error {
	// Validate required fields
	for _, fieldName := range template.RequiredFields {
		value, exists := config[fieldName]
		if !exists {
			return errors.Newf(errors.CodeInvalidInput, "required field missing: %s", fieldName)
		}

		// Check for empty values based on type
		switch v := value.(type) {
		case string:
			if v == "" {
				return errors.Newf(errors.CodeInvalidInput, "required field cannot be empty: %s", fieldName)
			}
		case []string:
			if len(v) == 0 {
				return errors.Newf(errors.CodeInvalidInput, "required field cannot be empty: %s", fieldName)
			}
		case []any:
			if len(v) == 0 {
				return errors.Newf(errors.CodeInvalidInput, "required field cannot be empty: %s", fieldName)
			}
		case nil:
			return errors.Newf(errors.CodeInvalidInput, "required field cannot be null: %s", fieldName)
		}
	}

	return nil
}

// mergeConfigs merges template config with user config, prioritizing user config
func (s *providerCatalogService) mergeConfigs(templateConfig, userConfig map[string]any) map[string]any {
	// OnStart with a copy of template config
	merged := make(map[string]any)

	// Copy template config
	for key, value := range templateConfig {
		merged[key] = value
	}

	// Override with user config values
	for key, value := range userConfig {
		// Skip nil values
		if value == nil {
			continue
		}

		// Skip empty strings
		if strVal, ok := value.(string); ok && strVal == "" {
			continue
		}

		// Skip empty slices
		if sliceVal, ok := value.([]string); ok && len(sliceVal) == 0 {
			continue
		}
		if sliceVal, ok := value.([]any); ok && len(sliceVal) == 0 {
			continue
		}

		merged[key] = value
	}

	return merged
}

// Validation helpers for specific config types

// validateOIDCConfig validates OIDC-specific configuration
func (s *providerCatalogService) validateOIDCConfig(config map[string]any) error {
	// Check for auto-discovery
	if issuer, hasIssuer := config["issuer"].(string); hasIssuer && issuer != "" {
		// For auto-discovery, we only need issuer and client credentials
		if _, hasClientID := config["clientId"].(string); !hasClientID {
			return errors.New(errors.CodeInvalidInput, "clientId is required for OIDC")
		}
		if _, hasClientSecret := config["clientSecret"].(string); !hasClientSecret {
			return errors.New(errors.CodeInvalidInput, "clientSecret is required for OIDC")
		}
		return nil
	}

	// Manual configuration requires more fields
	requiredFields := []string{"clientId", "clientSecret", "authUrl", "tokenUrl"}
	for _, field := range requiredFields {
		if value, exists := config[field].(string); !exists || value == "" {
			return errors.Newf(errors.CodeInvalidInput, "required OIDC field missing or empty: %s", field)
		}
	}

	return nil
}

// validateSAMLConfig validates SAML-specific configuration
func (s *providerCatalogService) validateSAMLConfig(config map[string]any) error {
	requiredFields := []string{"ssoUrl", "entityId", "certificate"}
	for _, field := range requiredFields {
		if value, exists := config[field].(string); !exists || value == "" {
			return errors.Newf(errors.CodeInvalidInput, "required SAML field missing or empty: %s", field)
		}
	}

	return nil
}

// validateOAuth2Config validates OAuth2-specific configuration
func (s *providerCatalogService) validateOAuth2Config(config map[string]any) error {
	requiredFields := []string{"clientId", "clientSecret", "authUrl", "tokenUrl"}
	for _, field := range requiredFields {
		if value, exists := config[field].(string); !exists || value == "" {
			return errors.Newf(errors.CodeInvalidInput, "required OAuth2 field missing or empty: %s", field)
		}
	}

	return nil
}

// Helper functions for config extraction

// getStringFromConfig safely extracts a string value from config
func getStringFromConfig(config map[string]any, key string) string {
	if value, exists := config[key]; exists {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}

// getStringSliceFromConfig safely extracts a string slice from config
func getStringSliceFromConfig(config map[string]any, key string) []string {
	if value, exists := config[key]; exists {
		if slice, ok := value.([]string); ok {
			return slice
		}
		if slice, ok := value.([]any); ok {
			result := make([]string, 0, len(slice))
			for _, item := range slice {
				if str, ok := item.(string); ok {
					result = append(result, str)
				}
			}
			return result
		}
	}
	return nil
}

// getBoolFromConfig safely extracts a boolean value from config
func getBoolFromConfig(config map[string]any, key string) bool {
	if value, exists := config[key]; exists {
		if b, ok := value.(bool); ok {
			return b
		}
	}
	return false
}

// ConfigExtractor provides methods to extract typed values from config maps
type ConfigExtractor struct {
	config map[string]any
}

// NewConfigExtractor creates a new config extractor
func NewConfigExtractor(config map[string]any) *ConfigExtractor {
	return &ConfigExtractor{config: config}
}

// String extracts a string value
func (e *ConfigExtractor) String(key string) string {
	return getStringFromConfig(e.config, key)
}

// StringSlice extracts a string slice value
func (e *ConfigExtractor) StringSlice(key string) []string {
	return getStringSliceFromConfig(e.config, key)
}

// Bool extracts a boolean value
func (e *ConfigExtractor) Bool(key string) bool {
	return getBoolFromConfig(e.config, key)
}

// Has checks if a key exists in the config
func (e *ConfigExtractor) Has(key string) bool {
	_, exists := e.config[key]
	return exists
}

// Get returns the raw value for a key
func (e *ConfigExtractor) Get(key string) (any, bool) {
	value, exists := e.config[key]
	return value, exists
}
