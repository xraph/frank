package sso

import (
	"context"
	"reflect"
	"strings"
	"time"

	"github.com/juicycleff/frank/internal/model"
	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
)

// ProviderCatalogService manages the SSO provider catalog
type ProviderCatalogService interface {
	// Catalog management
	SeedProviderCatalog(ctx context.Context) error
	GetAvailableProviders(ctx context.Context) ([]model.ProviderTemplate, error)
	GetProviderTemplate(ctx context.Context, templateKey string) (*model.ProviderTemplate, error)

	// Organization provider management
	EnableProviderForOrganization(ctx context.Context, req model.EnableProviderRequest) (*model.IdentityProvider, error)
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
	logger logging.Logger,
	catalogRepo repository.ProviderCatalogRepository,
	providerRepo repository.IdentityProviderRepository,
	orgProviderRepo repository.OrganizationProviderRepository,
	ssoService Service,
) ProviderCatalogService {
	return &providerCatalogService{
		logger:          logger,
		catalogRepo:     catalogRepo,
		providerRepo:    providerRepo,
		orgProviderRepo: orgProviderRepo,
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
			Description: "Sign in with your Google account",
			ConfigTemplate: model.IdentityProviderConfig{
				Issuer:      "https://accounts.google.com",
				AuthURL:     "https://accounts.google.com/o/oauth2/v2/auth",
				TokenURL:    "https://oauth2.googleapis.com/token",
				UserInfoURL: "https://www.googleapis.com/oauth2/v2/userinfo",
				JWKSUrl:     "https://www.googleapis.com/oauth2/v3/certs",
				Scopes:      []string{"openid", "email", "profile"},
			},
			RequiredFields:    []string{"client_id", "client_secret"},
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
			Description: "Sign in with your Microsoft account or Azure AD",
			ConfigTemplate: model.IdentityProviderConfig{
				Issuer:      "https://login.microsoftonline.com/common/v2.0",
				AuthURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
				TokenURL:    "https://login.microsoftonline.com/common/oauth2/v2.0/token",
				UserInfoURL: "https://graph.microsoft.com/v1.0/me",
				JWKSUrl:     "https://login.microsoftonline.com/common/discovery/v2.0/keys",
				Scopes:      []string{"openid", "email", "profile"},
			},
			RequiredFields:    []string{"client_id", "client_secret"},
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
			Description: "Sign in with your GitHub account",
			ConfigTemplate: model.IdentityProviderConfig{
				AuthURL:     "https://github.com/login/oauth/authorize",
				TokenURL:    "https://github.com/login/oauth/access_token",
				UserInfoURL: "https://api.github.com/user",
				Scopes:      []string{"user:email"},
			},
			RequiredFields:    []string{"client_id", "client_secret"},
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
			Description: "Sign in with your GitLab account",
			ConfigTemplate: model.IdentityProviderConfig{
				Issuer:       "https://gitlab.com",
				AuthURL:      "https://gitlab.com/oauth/authorize",
				NameIDFormat: "https://gitlab.com/oauth/token",
				UserInfoURL:  "https://gitlab.com/oauth/userinfo",
				Scopes:       []string{"openid", "email", "profile"},
			},
			RequiredFields:    []string{"client_id", "client_secret"},
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
			Description: "Sign in with your Discord account",
			ConfigTemplate: model.IdentityProviderConfig{
				AuthURL:     "https://discord.com/api/oauth2/authorize",
				TokenURL:    "https://discord.com/api/oauth2/token",
				UserInfoURL: "https://discord.com/api/users/@me",
				Scopes:      []string{"identify", "email"},
			},
			RequiredFields:    []string{"client_id", "client_secret"},
			SupportedFeatures: []string{"guilds", "connections"},
		},
		{
			Key:         "facebook",
			Name:        "Facebook",
			DisplayName: "Sign in with Facebook",
			Type:        "oauth2",
			Protocol:    "oauth2",
			IconURL:     "https://upload.wikimedia.org/wikipedia/en/0/04/Facebook_f_logo_%282021%29.svg",
			Category:    "social",
			Popular:     false,
			Description: "Sign in with your Facebook account",
			ConfigTemplate: model.IdentityProviderConfig{
				AuthURL:     "https://www.facebook.com/v18.0/dialog/oauth",
				TokenURL:    "https://graph.facebook.com/v18.0/oauth/access_token",
				UserInfoURL: "https://graph.facebook.com/me?fields=id,name,email,first_name,last_name,picture",
				Scopes:      []string{"email", "public_profile"},
			},
			RequiredFields:    []string{"client_id", "client_secret"},
			SupportedFeatures: []string{"pages", "groups"},
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
			Description: "Sign in with your Apple ID",
			ConfigTemplate: model.IdentityProviderConfig{
				Issuer:   "https://appleid.apple.com",
				AuthURL:  "https://appleid.apple.com/auth/authorize",
				TokenURL: "https://appleid.apple.com/auth/token",
				JWKSUrl:  "https://appleid.apple.com/auth/keys",
				Scopes:   []string{"name", "email"},
			},
			RequiredFields:    []string{"client_id", "key_id", "team_id", "private_key"},
			SupportedFeatures: []string{"privacy_focused", "jwt_client_auth"},
		},
		{
			Key:         "linkedin",
			Name:        "LinkedIn",
			DisplayName: "Sign in with LinkedIn",
			Type:        "oauth2",
			Protocol:    "oauth2",
			IconURL:     "https://upload.wikimedia.org/wikipedia/commons/c/ca/LinkedIn_logo_initials.png",
			Category:    "professional",
			Popular:     false,
			Description: "Sign in with your LinkedIn account",
			ConfigTemplate: model.IdentityProviderConfig{
				AuthURL:     "https://www.linkedin.com/oauth/v2/authorization",
				TokenURL:    "https://www.linkedin.com/oauth/v2/accessToken",
				UserInfoURL: "https://api.linkedin.com/v2/people/~:(id,firstName,lastName,emailAddress)",
				Scopes:      []string{"r_liteprofile", "r_emailaddress"},
			},
			RequiredFields:    []string{"client_id", "client_secret"},
			SupportedFeatures: []string{"company_data", "professional_network"},
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
			Description: "Configure any SAML 2.0 compliant identity provider",
			ConfigTemplate: model.IdentityProviderConfig{
				NameIDFormat:        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
				WantAssertionSigned: true,
				SignRequests:        false,
			},
			RequiredFields:    []string{"sso_url", "entity_id", "certificate"},
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
func (s *providerCatalogService) EnableProviderForOrganization(ctx context.Context, req model.EnableProviderRequest) (*model.IdentityProvider, error) {
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
		Config:           &config.Config,
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
func (s *providerCatalogService) validateRequiredConfig(template *model.ProviderTemplate, config model.IdentityProviderConfig) error {
	configValue := reflect.ValueOf(config)
	configType := reflect.TypeOf(config)

	// Create a map of JSON field names to struct field values
	fieldMap := make(map[string]interface{})

	for i := 0; i < configValue.NumField(); i++ {
		field := configType.Field(i)
		jsonTag := field.Tag.Get("json")

		// Extract field name from JSON tag (remove omitempty, etc.)
		jsonFieldName := strings.Split(jsonTag, ",")[0]
		if jsonFieldName == "" {
			jsonFieldName = field.Name
		}

		fieldValue := configValue.Field(i)
		if fieldValue.IsValid() && fieldValue.CanInterface() {
			fieldMap[jsonFieldName] = fieldValue.Interface()
		}
	}

	// Validate required fields
	for _, fieldName := range template.RequiredFields {
		value, exists := fieldMap[fieldName]
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
		}
	}

	return nil
}

// Alternative manual approach (more explicit, better performance)
func (s *providerCatalogService) validateRequiredConfigManual(template *model.ProviderTemplate, config model.IdentityProviderConfig) error {
	// Create field mapping from JSON names to values
	fieldValues := map[string]interface{}{
		"clientId":           config.ClientID,
		"clientSecret":       config.ClientSecret,
		"authUrl":            config.AuthURL,
		"tokenUrl":           config.TokenURL,
		"userInfoUrl":        config.UserInfoURL,
		"jwksUrl":            config.JWKSUrl,
		"scopes":             config.Scopes,
		"entityId":           config.EntityID,
		"ssoUrl":             config.SSOUrl,
		"sloUrl":             config.SLOUrl,
		"certificate":        config.Certificate,
		"signatureAlgorithm": config.SignatureAlgorithm,
		"nameIdFormat":       config.NameIDFormat,
		"issuer":             config.Issuer,
		"audience":           config.Audience,
		"algorithm":          config.Algorithm,
	}

	for _, fieldName := range template.RequiredFields {
		value, exists := fieldValues[fieldName]
		if !exists {
			return errors.Newf(errors.CodeInvalidInput, "required field missing: %s", fieldName)
		}

		// Check for empty values
		switch v := value.(type) {
		case string:
			if v == "" {
				return errors.Newf(errors.CodeInvalidInput, "required field cannot be empty: %s", fieldName)
			}
		case []string:
			if len(v) == 0 {
				return errors.Newf(errors.CodeInvalidInput, "required field cannot be empty: %s", fieldName)
			}
		}
	}

	return nil
}

// Helper function to get field value by JSON tag name
func (s *providerCatalogService) getFieldValueByJSONTag(config model.IdentityProviderConfig, jsonFieldName string) (interface{}, bool) {
	configValue := reflect.ValueOf(config)
	configType := reflect.TypeOf(config)

	for i := 0; i < configValue.NumField(); i++ {
		field := configType.Field(i)
		jsonTag := field.Tag.Get("json")

		// Extract field name from JSON tag
		tagName := strings.Split(jsonTag, ",")[0]
		if tagName == jsonFieldName {
			fieldValue := configValue.Field(i)
			if fieldValue.IsValid() && fieldValue.CanInterface() {
				return fieldValue.Interface(), true
			}
		}
	}

	return nil, false
}

// mergeConfigs merges template config with user config, prioritizing user config
func (s *providerCatalogService) mergeConfigs(templateConfig, userConfig model.IdentityProviderConfig) model.IdentityProviderConfig {
	// Start with template config
	merged := templateConfig

	// Override with non-empty user config values
	if userConfig.ClientID != "" {
		merged.ClientID = userConfig.ClientID
	}
	if userConfig.ClientSecret != "" {
		merged.ClientSecret = userConfig.ClientSecret
	}
	if userConfig.AuthURL != "" {
		merged.AuthURL = userConfig.AuthURL
	}
	if userConfig.TokenURL != "" {
		merged.TokenURL = userConfig.TokenURL
	}
	if userConfig.UserInfoURL != "" {
		merged.UserInfoURL = userConfig.UserInfoURL
	}
	if userConfig.JWKSUrl != "" {
		merged.JWKSUrl = userConfig.JWKSUrl
	}
	if len(userConfig.Scopes) > 0 {
		merged.Scopes = userConfig.Scopes
	}
	if userConfig.EntityID != "" {
		merged.EntityID = userConfig.EntityID
	}
	if userConfig.SSOUrl != "" {
		merged.SSOUrl = userConfig.SSOUrl
	}
	if userConfig.SLOUrl != "" {
		merged.SLOUrl = userConfig.SLOUrl
	}
	if userConfig.Certificate != "" {
		merged.Certificate = userConfig.Certificate
	}
	if userConfig.SignatureAlgorithm != "" {
		merged.SignatureAlgorithm = userConfig.SignatureAlgorithm
	}
	if userConfig.NameIDFormat != "" {
		merged.NameIDFormat = userConfig.NameIDFormat
	}
	if userConfig.Issuer != "" {
		merged.Issuer = userConfig.Issuer
	}
	if userConfig.Audience != "" {
		merged.Audience = userConfig.Audience
	}
	if userConfig.Algorithm != "" {
		merged.Algorithm = userConfig.Algorithm
	}

	return merged
}

// mergeConfigsReflection alternative approach using reflection (more generic but slightly more complex)
func (s *providerCatalogService) mergeConfigsReflection(templateConfig, userConfig model.IdentityProviderConfig) model.IdentityProviderConfig {
	merged := templateConfig

	templateVal := reflect.ValueOf(&merged).Elem()
	userVal := reflect.ValueOf(userConfig)

	for i := 0; i < templateVal.NumField(); i++ {
		templateField := templateVal.Field(i)
		userField := userVal.Field(i)

		// For strings, check if non-empty
		if templateField.Kind() == reflect.String && userField.String() != "" {
			templateField.SetString(userField.String())
		}
		// For slices, check if non-empty
		if templateField.Kind() == reflect.Slice && userField.Len() > 0 {
			templateField.Set(userField)
		}
	}

	return merged
}

// Additional model types for the catalog system

// Extended model types for provider catalog
type ProviderTemplate struct {
	Key               string                 `json:"key"`
	Name              string                 `json:"name"`
	DisplayName       string                 `json:"displayName"`
	Type              string                 `json:"type"`
	Protocol          string                 `json:"protocol"`
	IconURL           string                 `json:"iconUrl"`
	Category          string                 `json:"category"`
	Popular           bool                   `json:"popular"`
	Description       string                 `json:"description"`
	ConfigTemplate    map[string]interface{} `json:"configTemplate"`
	RequiredFields    []string               `json:"requiredFields"`
	SupportedFeatures []string               `json:"supportedFeatures"`
	Documentation     string                 `json:"documentation,omitempty"`
	SetupGuideURL     string                 `json:"setupGuideUrl,omitempty"`
}

type EnableProviderRequest struct {
	OrganizationID   xid.ID                 `json:"organizationId"`
	TemplateKey      string                 `json:"templateKey"`
	CustomName       string                 `json:"customName,omitempty"`
	CustomButtonText string                 `json:"customButtonText,omitempty"`
	Config           map[string]interface{} `json:"config"`
	Domain           string                 `json:"domain,omitempty"`
	AutoProvision    bool                   `json:"autoProvision"`
	DefaultRole      string                 `json:"defaultRole,omitempty"`
	AttributeMapping map[string]string      `json:"attributeMapping,omitempty"`
}

type OrganizationProvider struct {
	ID             xid.ID                  `json:"id"`
	OrganizationID xid.ID                  `json:"organizationId"`
	ProviderID     xid.ID                  `json:"providerId"`
	TemplateKey    string                  `json:"templateKey"`
	Provider       *model.IdentityProvider `json:"provider"`
	Template       *ProviderTemplate       `json:"template"`
	CustomConfig   map[string]interface{}  `json:"customConfig"`
	EnabledAt      time.Time               `json:"enabledAt"`
	LastUsed       *time.Time              `json:"lastUsed,omitempty"`
	UsageCount     int                     `json:"usageCount"`
}

type ProviderConfiguration struct {
	Config           map[string]interface{} `json:"config"`
	Domain           string                 `json:"domain,omitempty"`
	AutoProvision    bool                   `json:"autoProvision"`
	DefaultRole      string                 `json:"defaultRole,omitempty"`
	AttributeMapping map[string]string      `json:"attributeMapping,omitempty"`
	Enabled          bool                   `json:"enabled"`
}

// Service initialization helper
func InitializeProviderCatalog(ctx context.Context, catalogService ProviderCatalogService) error {
	return catalogService.SeedProviderCatalog(ctx)
}
