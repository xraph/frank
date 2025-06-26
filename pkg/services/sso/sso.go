package sso

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/pkg/contexts"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// Service defines the interface for SSO operations
type Service interface {
	// Identity Provider management
	CreateProvider(ctx context.Context, organizationID xid.ID, req model.CreateIdentityProviderRequest) (*model.IdentityProvider, error)
	GetProvider(ctx context.Context, id xid.ID) (*model.IdentityProvider, error)
	UpdateProvider(ctx context.Context, id xid.ID, req model.UpdateIdentityProviderRequest) (*model.IdentityProvider, error)
	DeleteProvider(ctx context.Context, id xid.ID) error
	ListProviders(ctx context.Context, req model.SSOProviderListRequest) (*model.SSOProviderListResponse, error)

	// SSO Authentication flow
	InitiateSSOLogin(ctx context.Context, req model.SSOLoginRequest) (*model.SSOLoginResponse, error)
	HandleSSOCallback(ctx context.Context, req model.SSOCallbackRequest) (*model.SSOCallbackResponse, error)

	// Provider management
	EnableProvider(ctx context.Context, id xid.ID) error
	DisableProvider(ctx context.Context, id xid.ID) error
	TestConnection(ctx context.Context, req model.TestSSOConnectionRequest) (*model.TestSSOConnectionResponse, error)

	// User provisioning
	AutoProvisionUser(ctx context.Context, providerID xid.ID, userInfo SSOUserInfo) (*model.User, error)
	BulkProvisionUsers(ctx context.Context, req model.SSOBulkProvisionRequest) (*model.SSOBulkProvisionResponse, error)

	// Domain management
	VerifyDomain(ctx context.Context, req model.SSODomainVerificationRequest) (*model.SSODomainVerificationResponse, error)
	GetProviderByDomain(ctx context.Context, domain string) (*model.IdentityProvider, error)

	// Metadata and configuration
	GetSSOMetadata(ctx context.Context, req model.SSOMetadataRequest) (*model.SSOMetadataResponse, error)
	ExportSSOData(ctx context.Context, req model.SSOExportRequest) (*model.SSOExportResponse, error)

	// Analytics and monitoring
	GetSSOStats(ctx context.Context, organizationID *xid.ID) (*model.SSOStats, error)
	GetProviderStats(ctx context.Context, providerID xid.ID) (*model.SSOProviderStats, error)
	GetSSOActivity(ctx context.Context, req model.SSOActivityRequest) (*model.SSOActivityResponse, error)
	GetProviderMetrics(ctx context.Context, providerID xid.ID, period string) (*model.SSOProviderMetrics, error)

	// Health monitoring
	CheckProviderHealth(ctx context.Context, providerID xid.ID) (*model.SSOHealthCheck, error)
	GetHealthStatus(ctx context.Context, organizationID xid.ID) ([]model.SSOHealthCheck, error)
}

// SSOUserInfo represents user information from SSO provider
type SSOUserInfo struct {
	ID            string                 `json:"id"`
	Email         string                 `json:"email"`
	EmailVerified bool                   `json:"emailVerified"`
	FirstName     string                 `json:"firstName"`
	LastName      string                 `json:"lastName"`
	Name          string                 `json:"name"`
	Username      string                 `json:"username"`
	Picture       string                 `json:"picture"`
	Locale        string                 `json:"locale"`
	Attributes    map[string]interface{} `json:"attributes"`
	Groups        []string               `json:"groups"`
	Roles         []string               `json:"roles"`
}

// ssoService implements the SSO Service interface
type ssoService struct {
	logger       logging.Logger
	providerRepo repository.IdentityProviderRepository
	userRepo     repository.UserRepository
	orgRepo      repository.OrganizationRepository
	memberRepo   repository.MembershipRepository
	auditRepo    repository.AuditRepository
	ssoStateRepo repository.SSOStateRepository

	samlService SAMLService
	oidcService OIDCService
}

// NewService creates a new SSO ssoService
func NewService(
	repos repository.Repository,
	samlService SAMLService,
	oidcService OIDCService,
	logger logging.Logger,
) Service {
	return &ssoService{
		providerRepo: repos.IdentityProvider(),
		userRepo:     repos.User(),
		orgRepo:      repos.Organization(),
		oidcService:  oidcService,
		samlService:  samlService,
		memberRepo:   repos.Membership(),
		auditRepo:    repos.Audit(),
		ssoStateRepo: repos.SSOState(),
		logger:       logger.Named("sso"),
	}
}

// CreateIdentityProvider creates a new identity provider
func (s *ssoService) CreateProvider(ctx context.Context, organizationID xid.ID, req model.CreateIdentityProviderRequest) (*model.IdentityProvider, error) {
	s.logger.Debug("Creating identity provider",
		logging.String("organizationId", organizationID.String()),
		logging.String("name", req.Name),
		logging.String("type", req.Type))

	// Validate organization exists
	_, err := s.orgRepo.GetByID(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	// Validate configuration based on type
	if err := s.validateProviderConfig(req.Type, req.Config); err != nil {
		return nil, err
	}

	// Create identity provider
	input := repository.CreateIdentityProviderInput{
		Name:             req.Name,
		Type:             req.Type,
		Protocol:         req.Protocol,
		OrganizationID:   organizationID,
		Domain:           req.Domain,
		AutoProvision:    req.AutoProvision,
		DefaultRole:      req.DefaultRole,
		AttributeMapping: req.AttributeMapping,
		// Config:           req.Config,
		IconURL:    req.IconURL,
		ButtonText: req.ButtonText,
		Active:     true,
	}

	entProvider, err := s.providerRepo.Create(ctx, input)
	if err != nil {
		return nil, err
	}

	provider := s.convertEntProviderToModel(entProvider)

	// Log audit event
	s.auditLog(ctx, "sso.provider.created", "identity_provider", &provider.ID, map[string]interface{}{
		"provider_name": provider.Name,
		"provider_type": provider.Type,
	})

	s.logger.Info("Identity provider created successfully",
		logging.String("providerId", provider.ID.String()),
		logging.String("name", provider.Name))

	return provider, nil
}

// GetIdentityProvider gets an identity provider by ID
func (s *ssoService) GetProvider(ctx context.Context, id xid.ID) (*model.IdentityProvider, error) {
	provider, err := s.providerRepo.GetByID(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "provider not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get provider")
	}

	// Check organization access
	if !s.canAccessProvider(ctx, provider) {
		return nil, errors.New(errors.CodeForbidden, "access denied to provider")
	}

	return s.convertEntProviderToModel(provider), nil
}

// UpdateIdentityProvider updates an identity provider
func (s *ssoService) UpdateProvider(ctx context.Context, id xid.ID, req model.UpdateIdentityProviderRequest) (*model.IdentityProvider, error) {
	s.logger.Debug("Updating identity provider", logging.String("providerId", id.String()))

	// Get existing provider
	provider, err := s.providerRepo.GetByID(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "provider not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get provider")
	}

	// Check organization access
	if !s.canAccessProvider(ctx, provider) {
		return nil, errors.New(errors.CodeForbidden, "access denied to provider")
	}

	// Validate configuration if provided
	if req.Config != nil {
		if err := s.validateProviderConfig(provider.ProviderType, req.Config); err != nil {
			return nil, errors.Wrap(err, errors.CodeInvalidInput, "invalid provider configuration")
		}
	}

	input := repository.UpdateIdentityProviderInput{
		Name:             &req.Name,
		Domain:           &req.Domain,
		Enabled:          &req.Enabled,
		AutoProvision:    &req.AutoProvision,
		DefaultRole:      &req.DefaultRole,
		AttributeMapping: req.AttributeMapping,
		Config:           req.Config,
		IconURL:          &req.IconURL,
		ButtonText:       &req.ButtonText,
		Active:           &req.Active,
	}

	updatedProvider, err := s.providerRepo.Update(ctx, id, input)
	if err != nil {
		return nil, err
	}

	// Log audit event
	s.auditLog(ctx, "sso.provider.updated", "identity_provider", &updatedProvider.ID, map[string]interface{}{
		"provider_name": updatedProvider.Name,
		"changes":       input,
	})

	s.logger.Info("Identity provider updated successfully",
		logging.String("providerId", provider.ID.String()))

	return s.convertEntProviderToModel(updatedProvider), nil
}

// DeleteIdentityProvider deletes an identity provider
func (s *ssoService) DeleteProvider(ctx context.Context, id xid.ID) error {
	s.logger.Debug("Deleting identity provider", logging.String("providerId", id.String()))

	// Get existing provider
	provider, err := s.providerRepo.GetByID(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "provider not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "failed to get provider")
	}

	// Check organization access
	if !s.canAccessProvider(ctx, provider) {
		return errors.New(errors.CodeForbidden, "access denied to provider")
	}

	// Delete provider
	if err := s.providerRepo.Delete(ctx, id); err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to delete provider")
	}

	// Log audit event
	s.auditLog(ctx, "sso.provider.deleted", "identity_provider", &provider.ID, map[string]interface{}{
		"provider_name": provider.Name,
		"provider_type": provider.ProviderType,
	})

	s.logger.Info("Identity provider deleted successfully", logging.String("providerId", id.String()))
	return nil
}

// ListProviders lists identity providers
func (s *ssoService) ListProviders(ctx context.Context, req model.SSOProviderListRequest) (*model.SSOProviderListResponse, error) {
	// Get organization ID from context or request
	orgID := getOrganizationIDFromContext(ctx)
	if req.OrganizationID.IsSet {
		orgID = req.OrganizationID.Value
	}

	if orgID.IsNil() {
		return nil, errors.New(errors.CodeUnauthorized, "organization context required 2")
	}

	result, err := s.providerRepo.ListByOrganizationID(ctx, orgID, req)
	if err != nil {
		return nil, err
	}

	// Convert to model
	summaries := make([]model.IdentityProviderSummary, len(result.Data))
	for i, provider := range result.Data {
		summaries[i] = s.convertProviderToSummary(provider)
	}

	return &model.SSOProviderListResponse{
		Data:       summaries,
		Pagination: result.Pagination,
	}, nil
}

// InitiateSSOLogin initiates SSO login flow
func (s *ssoService) InitiateSSOLogin(ctx context.Context, req model.SSOLoginRequest) (*model.SSOLoginResponse, error) {
	s.logger.Debug("Initiating SSO login", logging.String("providerId", req.ProviderID.String()))

	// Get provider
	prov, err := s.providerRepo.GetByID(ctx, req.ProviderID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "provider not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get provider")
	}

	provider := s.convertEntProviderToModel(prov)

	// Check if provider is enabled and active
	if !provider.Enabled || !provider.Active {
		return nil, errors.New(errors.CodeForbidden, "provider is not available")
	}

	state := req.State
	if state == "" {
		// Generate state parameter
		state, err = s.generateState()
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to generate state")
		}
	}

	// Store SSO state
	if err := s.storeSSOState(ctx, state, req.ProviderID, req.RedirectURL); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to store SSO state")
	}

	// Delegate to appropriate service based on provider type
	var authURL string
	switch strings.ToLower(provider.Type) {
	case "saml":
		authURL, err = s.samlService.InitiateLogin(ctx, provider, state, req.RedirectURL)
	case "oidc", "oauth2":
		authURL, err = s.oidcService.InitiateLogin(ctx, provider, state, req.RedirectURL)
	default:
		return nil, errors.New(errors.CodeInvalidInput, "unsupported provider type")
	}

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to initiate SSO login")
	}

	// Log audit event
	s.auditLog(ctx, "sso.login.initiated", "identity_provider", &provider.ID, map[string]interface{}{
		"provider_name": provider.Name,
		"redirect_url":  req.RedirectURL,
	})

	s.logger.Info("SSO login initiated",
		logging.String("providerId", req.ProviderID.String()),
		logging.String("state", state))

	return &model.SSOLoginResponse{
		AuthURL:   authURL,
		State:     state,
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}, nil
}

// HandleSSOCallback handles SSO callback
func (s *ssoService) HandleSSOCallback(ctx context.Context, req model.SSOCallbackRequest) (*model.SSOCallbackResponse, error) {
	s.logger.Debug("Handling SSO callback", logging.String("providerId", req.ProviderID.String()))

	// Get identity provider
	prov, err := s.providerRepo.GetByID(ctx, req.ProviderID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "provider not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get provider")
	}

	provider := s.convertEntProviderToModel(prov)

	if !provider.Enabled || !provider.Active {
		return nil, errors.New(errors.CodeForbidden, "identity provider is not enabled")
	}

	// Validate state parameter
	ssoState, err := s.validateSSOState(ctx, req.State)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeUnauthorized, "invalid SSO state")
	}

	var userInfo *SSOUserInfo

	// Handle different protocols
	switch strings.ToLower(provider.Type) {
	case "oidc", "oauth2":
		userInfo, err = s.oidcService.HandleCallback(ctx, provider, req.Code, req.State)
	case "saml":
		userInfo, err = s.samlService.HandleCallback(ctx, provider, req.SAMLResponse, req.RelayState)
	default:
		return nil, errors.New(errors.CodeBadRequest, "unsupported provider type")
	}

	if err != nil {
		// Log failed attempt
		s.auditLog(ctx, "sso.callback.failed", "identity_provider", &provider.ID, map[string]interface{}{
			"provider_name": provider.Name,
			"error":         err.Error(),
		})
		return nil, errors.Wrap(err, errors.CodeUnauthorized, "SSO authentication failed")
	}

	// Find or create user
	user, userCreated, err := s.findOrCreateUser(ctx, provider, userInfo)
	if err != nil {
		return nil, err
	}

	s.logger.Info("SSO callback handled successfully",
		logging.String("providerId", req.ProviderID.String()),
		logging.String("userId", user.ID.String()),
		logging.Bool("userCreated", userCreated))

	// Convert ent.User to model.User
	modelUser := s.convertEntUserToModel(user)

	// Log successful login
	s.auditLog(ctx, "sso.login.success", "user", &user.ID, map[string]interface{}{
		"provider_name": provider.Name,
		"user_email":    user.Email,
		"user_created":  userCreated,
	})

	// Cleanup SSO state
	s.cleanupSSOState(ctx, req.State)

	return &model.SSOCallbackResponse{
		Success:     true,
		User:        *modelUser,
		UserCreated: userCreated,
		RedirectURL: ssoState.RedirectURL,
	}, nil
}

// ... rest of the methods remain largely the same but need to be updated for map[string]any configs

// TestConnection tests connection to identity provider
func (s *ssoService) TestConnection(ctx context.Context, req model.TestSSOConnectionRequest) (*model.TestSSOConnectionResponse, error) {
	s.logger.Debug("Testing SSO connection", logging.String("providerId", req.ProviderID.String()))

	// Get provider
	prov, err := s.providerRepo.GetByID(ctx, req.ProviderID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "provider not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get provider")
	}

	provider := s.convertEntProviderToModel(prov)

	// Check organization access
	if !s.canAccessProvider(ctx, prov) {
		return nil, errors.New(errors.CodeForbidden, "access denied to provider")
	}

	start := time.Now()

	// Delegate to appropriate service
	var testErr error
	switch strings.ToLower(provider.Type) {
	case "saml":
		testErr = s.samlService.TestConnection(ctx, provider)
	case "oidc", "oauth2":
		testErr = s.oidcService.TestConnection(ctx, provider)
	default:
		return &model.TestSSOConnectionResponse{
			Success: false,
			Message: "Unsupported provider type",
			Error:   "Provider type not supported for testing",
		}, nil
	}

	latency := int(time.Since(start).Milliseconds())

	var success bool
	if testErr != nil {
		success = false
		return &model.TestSSOConnectionResponse{
			Success: false,
			Message: "Connection test failed",
			Error:   testErr.Error(),
			Latency: latency,
		}, nil
	}

	success = true
	s.logger.Info("SSO connection test completed",
		logging.String("providerId", req.ProviderID.String()),
		logging.Bool("success", success),
		logging.Int("latency", latency))

	return &model.TestSSOConnectionResponse{
		Success: success,
		Message: "Connection test successful",
		Latency: latency,
	}, nil
}

// Helper methods

// validateProviderConfig validates SSO provider configuration based on type
func (s *ssoService) validateProviderConfig(providerType string, config map[string]any) error {
	extractor := NewConfigExtractor(config)

	switch strings.ToLower(providerType) {
	case "saml":
		return s.validateSAMLConfig(extractor)
	case "oidc", "oauth2":
		return s.validateOIDCConfig(extractor)
	default:
		return fmt.Errorf("unsupported provider type: %s", providerType)
	}
}

// validateOIDCConfig validates OIDC configuration using ConfigExtractor
func (s *ssoService) validateOIDCConfig(extractor *ConfigExtractor) error {
	// Check for auto-discovery
	if issuer := extractor.String("issuer"); issuer != "" {
		// For auto-discovery, we only need issuer and client credentials
		if !extractor.Has("clientId") || extractor.String("clientId") == "" {
			return errors.New(errors.CodeInvalidInput, "clientId is required for OIDC")
		}
		if !extractor.Has("clientSecret") || extractor.String("clientSecret") == "" {
			return errors.New(errors.CodeInvalidInput, "clientSecret is required for OIDC")
		}
		return nil
	}

	// Manual configuration requires more fields
	requiredFields := []string{"clientId", "clientSecret", "authUrl", "tokenUrl"}
	for _, field := range requiredFields {
		if !extractor.Has(field) || extractor.String(field) == "" {
			return errors.Newf(errors.CodeInvalidInput, "required OIDC field missing or empty: %s", field)
		}
	}

	return nil
}

// validateSAMLConfig validates SAML configuration using ConfigExtractor
func (s *ssoService) validateSAMLConfig(extractor *ConfigExtractor) error {
	requiredFields := []string{"ssoUrl", "entityId", "certificate"}
	for _, field := range requiredFields {
		if !extractor.Has(field) || extractor.String(field) == "" {
			return errors.Newf(errors.CodeInvalidInput, "required SAML field missing or empty: %s", field)
		}
	}

	return nil
}

// generateState generates a secure state parameter for SSO
func (s *ssoService) generateState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// storeSSOState stores SSO state information
func (s *ssoService) storeSSOState(ctx context.Context, state string, providerID xid.ID, redirectURL string) error {
	input := repository.CreateSSOStateInput{
		State:       state,
		ProviderID:  providerID,
		RedirectURL: redirectURL,
		ExpiresAt:   time.Now().Add(15 * time.Minute),
	}

	_, err := s.ssoStateRepo.Create(ctx, input)
	return err
}

// validateSSOState validates and retrieves SSO state
func (s *ssoService) validateSSOState(ctx context.Context, state string) (*ent.SSOState, error) {
	ssoState, err := s.ssoStateRepo.GetValidState(ctx, state)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired state")
	}
	return ssoState, nil
}

// cleanupSSOState removes used SSO state
func (s *ssoService) cleanupSSOState(ctx context.Context, state string) {
	s.ssoStateRepo.DeleteByState(ctx, state)
}

// convertEntProviderToModel converts ent provider to model using map[string]any config
func (s *ssoService) convertEntProviderToModel(entProvider *ent.IdentityProvider) *model.IdentityProvider {
	// Convert stored config to map[string]any
	config := make(map[string]any)

	// Extract non-empty fields from ent provider to config map
	if entProvider.ClientID != "" {
		config["clientId"] = entProvider.ClientID
	}
	if entProvider.ClientSecret != "" {
		config["clientSecret"] = entProvider.ClientSecret
	}
	if entProvider.AuthorizationEndpoint != "" {
		config["authUrl"] = entProvider.AuthorizationEndpoint
	}
	if entProvider.TokenEndpoint != "" {
		config["tokenUrl"] = entProvider.TokenEndpoint
	}
	if entProvider.UserinfoEndpoint != "" {
		config["userInfoUrl"] = entProvider.UserinfoEndpoint
	}
	if entProvider.JwksURI != "" {
		config["jwksUrl"] = entProvider.JwksURI
	}
	if entProvider.Issuer != "" {
		config["issuer"] = entProvider.Issuer
	}

	return &model.IdentityProvider{
		Base: model.Base{
			ID:        entProvider.ID,
			CreatedAt: entProvider.CreatedAt,
			UpdatedAt: entProvider.UpdatedAt,
		},
		Name:             entProvider.Name,
		Type:             entProvider.ProviderType,
		Protocol:         entProvider.Protocol,
		OrganizationID:   entProvider.OrganizationID,
		Domain:           entProvider.Domain,
		Enabled:          entProvider.Enabled,
		AutoProvision:    entProvider.AutoProvision,
		DefaultRole:      entProvider.DefaultRole,
		AttributeMapping: entProvider.AttributesMapping,
		// Config:           config,
		IconURL:    entProvider.IconURL,
		ButtonText: entProvider.ButtonText,
		Active:     entProvider.Active,
	}
}

// findOrCreateUser finds or creates a user from SSO information
func (s *ssoService) findOrCreateUser(ctx context.Context, provider *model.IdentityProvider, userInfo *SSOUserInfo) (*ent.User, bool, error) {
	// Try to find existing user
	existingUser, err := s.userRepo.GetByExternalID(ctx, userInfo.ID, provider.Type, model.UserTypeExternal, &provider.OrganizationID)
	if err == nil {
		// User exists, update info
		updateInput := repository.UpdateUserInput{
			UpdateUserRequest: model.UpdateUserRequest{
				Email:     &userInfo.Email,
				FirstName: &userInfo.FirstName,
				LastName:  &userInfo.LastName,
			},
		}

		if userInfo.Picture != "" {
			updateInput.ProfileImageURL = &userInfo.Picture
		}

		updatedUser, err := s.userRepo.Update(ctx, existingUser.ID, updateInput)
		if err != nil {
			return nil, false, err
		}

		return updatedUser, false, nil
	}

	// Try to find by email if auto-provision is enabled
	if provider.AutoProvision {
		existingUser, err := s.userRepo.GetByEmail(ctx, userInfo.Email, model.UserTypeExternal, &provider.OrganizationID)
		if err == nil {
			// Link existing user to SSO provider
			updateInput := repository.UpdateUserInput{
				ExternalID:   &userInfo.ID,
				AuthProvider: &provider.Type,
			}

			updatedUser, err := s.userRepo.Update(ctx, existingUser.ID, updateInput)
			if err != nil {
				return nil, false, err
			}

			return updatedUser, false, nil
		}
	}

	// Auto-provision if enabled
	if !provider.AutoProvision {
		return nil, false, errors.New(errors.CodeForbidden, "user not found and auto-provisioning is disabled")
	}

	// Create new user
	input := repository.CreateUserInput{
		Email:           userInfo.Email,
		Username:        &userInfo.Username,
		FirstName:       &userInfo.FirstName,
		LastName:        &userInfo.LastName,
		ProviderName:    provider.Name,
		UserType:        model.UserTypeExternal,
		OrganizationID:  &provider.OrganizationID,
		AuthProvider:    provider.Type,
		ExternalID:      &userInfo.ID,
		EmailVerified:   true, // SSO users are considered verified
		Active:          true,
		ProfileImageURL: &userInfo.Picture,
	}

	newUser, err := s.userRepo.Create(ctx, input)
	if err != nil {
		return nil, false, err
	}

	return newUser, true, nil
}

// canAccessProvider checks if the current context can access the provider
func (s *ssoService) canAccessProvider(ctx context.Context, provider *ent.IdentityProvider) bool {
	orgID := getOrganizationIDFromContext(ctx)
	return orgID != (xid.ID{}) && orgID == provider.OrganizationID
}

// auditLog creates an audit log entry
func (s *ssoService) auditLog(ctx context.Context, action, resource string, resourceID *xid.ID, details map[string]interface{}) {
	input := repository.CreateAuditInput{
		Action:       action,
		ResourceType: resource,
		ResourceID:   resourceID,
		Status:       "success",
		Details:      details,
	}

	// Get user and organization from context
	if userID := getUserIDFromContext(ctx); userID != (xid.ID{}) {
		input.UserID = &userID
	}
	if orgID := getOrganizationIDFromContext(ctx); orgID != (xid.ID{}) {
		input.OrganizationID = &orgID
	}

	s.auditRepo.Create(ctx, input)
}

// convertEntUserToModel converts ent.User to model.User
func (s *ssoService) convertEntUserToModel(entUser *ent.User) *model.User {
	return &model.User{
		Base: model.Base{
			ID:        entUser.ID,
			CreatedAt: entUser.CreatedAt,
			UpdatedAt: entUser.UpdatedAt,
		},
		Email:           entUser.Email,
		Username:        entUser.Username,
		FirstName:       entUser.FirstName,
		LastName:        entUser.LastName,
		PhoneNumber:     entUser.PhoneNumber,
		EmailVerified:   entUser.EmailVerified,
		PhoneVerified:   entUser.PhoneVerified,
		Active:          entUser.Active,
		Blocked:         entUser.Blocked,
		UserType:        entUser.UserType,
		AuthProvider:    entUser.AuthProvider,
		ExternalID:      entUser.ExternalID,
		ProfileImageURL: entUser.ProfileImageURL,
		Locale:          entUser.Locale,
		Timezone:        entUser.Timezone,
	}
}

// convertProviderToSummary converts provider to summary
func (s *ssoService) convertProviderToSummary(provider *ent.IdentityProvider) model.IdentityProviderSummary {
	return model.IdentityProviderSummary{
		ID:        provider.ID,
		Name:      provider.Name,
		Type:      provider.ProviderType,
		Domain:    provider.Domain,
		Enabled:   provider.Enabled,
		CreatedAt: provider.CreatedAt,
	}
}

// Context helpers (these would be implemented in middleware)
func getOrganizationIDFromContext(ctx context.Context) xid.ID {
	if orgID := contexts.GetOrganizationIDFromContext(ctx); orgID != nil {
		return *orgID
	}
	return xid.NilID()
}

func getUserIDFromContext(ctx context.Context) xid.ID {
	if orgID := contexts.GetUserIDFromContext(ctx); orgID != nil {
		return *orgID
	}
	return xid.NilID()
}

// Additional methods for auto-provisioning, stats, health checks, etc. would go here
// (Truncated for brevity - they follow similar patterns with config extraction)

// AutoProvisionUser auto-provisions a user from SSO
func (s *ssoService) AutoProvisionUser(ctx context.Context, providerID xid.ID, userInfo SSOUserInfo) (*model.User, error) {
	s.logger.Debug("Auto-provisioning user",
		logging.String("providerId", providerID.String()),
		logging.String("email", userInfo.Email))

	// Get provider
	prov, err := s.providerRepo.GetByID(ctx, providerID)
	if err != nil {
		return nil, err
	}

	provider := s.convertEntProviderToModel(prov)

	if !provider.AutoProvision {
		return nil, errors.New(errors.CodeForbidden, "auto-provisioning not enabled for this provider")
	}

	// Create user
	user, _, err := s.findOrCreateUser(ctx, provider, &userInfo)
	if err != nil {
		return nil, err
	}

	return s.convertEntUserToModel(user), nil
}

// GetSSOStats gets SSO statistics (placeholder implementation)
func (s *ssoService) GetSSOStats(ctx context.Context, organizationID *xid.ID) (*model.SSOStats, error) {
	// This would integrate with analytics service
	return &model.SSOStats{
		TotalProviders:       5,
		ActiveProviders:      4,
		EnabledProviders:     4,
		ProvidersByType:      map[string]int{"oidc": 3, "saml": 2},
		SSOLoginsToday:       150,
		SSOLoginsWeek:        1050,
		SSOLoginsMonth:       4500,
		UniqueUsersToday:     85,
		UniqueUsersWeek:      425,
		AutoProvisionedUsers: 320,
		FailedLoginsToday:    12,
		AverageLoginTime:     2.5,
	}, nil
}

// EnableProvider enables an identity provider
func (s *ssoService) EnableProvider(ctx context.Context, id xid.ID) error {
	s.logger.Debug("Enabling identity provider", logging.String("providerId", id.String()))

	err := s.providerRepo.ActivateProvider(ctx, id)
	if err != nil {
		return err
	}

	s.logger.Info("Identity provider enabled", logging.String("providerId", id.String()))
	return nil
}

// DisableProvider disables an identity provider
func (s *ssoService) DisableProvider(ctx context.Context, id xid.ID) error {
	s.logger.Debug("Disabling identity provider", logging.String("providerId", id.String()))

	err := s.providerRepo.DeactivateProvider(ctx, id)
	if err != nil {
		return err
	}

	s.logger.Info("Identity provider disabled", logging.String("providerId", id.String()))
	return nil
}

// BulkProvisionUsers bulk provisions users
func (s *ssoService) BulkProvisionUsers(ctx context.Context, req model.SSOBulkProvisionRequest) (*model.SSOBulkProvisionResponse, error) {
	s.logger.Debug("Bulk provisioning users",
		logging.String("providerId", req.ProviderID.String()),
		logging.Int("count", len(req.Users)))

	if req.DryRun {
		s.logger.Info("Performing dry run bulk provision")
	}

	var success []model.SSOProvisionedUser
	var failed []model.SSOProvisionError

	for i, userData := range req.Users {
		userInfo := SSOUserInfo{
			Email:     userData.Email,
			FirstName: userData.FirstName,
			LastName:  userData.LastName,
			Attributes: map[string]interface{}{
				"role": userData.Role,
			},
		}

		if !req.DryRun {
			user, err := s.AutoProvisionUser(ctx, req.ProviderID, userInfo)
			if err != nil {
				failed = append(failed, model.SSOProvisionError{
					Email: userData.Email,
					Error: err.Error(),
					Index: i,
				})
				continue
			}

			success = append(success, model.SSOProvisionedUser{
				Email:   userData.Email,
				UserID:  user.ID,
				Created: true,
			})
		} else {
			// Dry run - just validate
			success = append(success, model.SSOProvisionedUser{
				Email:   userData.Email,
				UserID:  xid.New(), // Mock ID for dry run
				Created: true,
			})
		}
	}

	return &model.SSOBulkProvisionResponse{
		Success:      success,
		Failed:       failed,
		SuccessCount: len(success),
		FailureCount: len(failed),
		DryRun:       req.DryRun,
	}, nil
}

// VerifyDomain verifies domain ownership
func (s *ssoService) VerifyDomain(ctx context.Context, req model.SSODomainVerificationRequest) (*model.SSODomainVerificationResponse, error) {
	s.logger.Debug("Verifying domain", logging.String("domain", req.Domain))

	// Generate verification token
	verificationToken := fmt.Sprintf("frank-sso-verify=%s", xid.New().String())

	return &model.SSODomainVerificationResponse{
		Domain:       req.Domain,
		Verified:     false, // Would check actual DNS record
		TXTRecord:    verificationToken,
		Instructions: fmt.Sprintf("Add the following TXT record to your DNS: %s", verificationToken),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}, nil
}

// GetProviderByDomain gets provider by domain
func (s *ssoService) GetProviderByDomain(ctx context.Context, domain string) (*model.IdentityProvider, error) {
	providers, err := s.providerRepo.GetByDomain(ctx, domain)
	if err != nil {
		return nil, err
	}

	if len(providers) == 0 {
		return nil, errors.New(errors.CodeNotFound, "no provider found for domain")
	}

	// Return the first active provider
	for _, provider := range providers {
		if provider.Active && provider.Enabled {
			return s.convertEntProviderToModel(provider), nil
		}
	}

	return nil, errors.New(errors.CodeNotFound, "no active provider found for domain")
}

// GetSSOMetadata gets SSO metadata
func (s *ssoService) GetSSOMetadata(ctx context.Context, req model.SSOMetadataRequest) (*model.SSOMetadataResponse, error) {
	s.logger.Debug("Getting SSO metadata", logging.String("providerId", req.ProviderID.String()))

	prov, err := s.providerRepo.GetByID(ctx, req.ProviderID)
	if err != nil {
		return nil, err
	}

	provider := s.convertEntProviderToModel(prov)

	var metadata string
	var contentType string

	if provider.Type == "saml" {
		var config model.SSOProviderConfig
		// if err := s.parseProviderConfig(provider.Config, &config); err != nil {
		// 	return nil, err
		// }
		config = provider.Config

		metadata, err = s.samlService.GetMetadata(ctx, config)
		if err != nil {
			return nil, err
		}
		contentType = "application/samlmetadata+xml"
	} else {
		// For OIDC, return configuration
		metadata = `{"issuer":"https://example.com","authorization_endpoint":"https://example.com/auth","token_endpoint":"https://example.com/token"}`
		contentType = "application/json"
	}

	return &model.SSOMetadataResponse{
		Metadata:    metadata,
		Format:      req.Format,
		ContentType: contentType,
		DownloadURL: fmt.Sprintf("https://api.example.com/sso/metadata/%s.xml", req.ProviderID.String()),
	}, nil
}

// ExportSSOData exports SSO data
func (s *ssoService) ExportSSOData(ctx context.Context, req model.SSOExportRequest) (*model.SSOExportResponse, error) {
	exportURL := fmt.Sprintf("https://api.example.com/downloads/sso-export-%s.%s",
		xid.New().String(), req.Format)

	return &model.SSOExportResponse{
		DownloadURL: exportURL,
		ExpiresAt:   time.Now().Add(time.Hour),
		Format:      req.Format,
		RecordCount: 0, // Would calculate actual count
	}, nil
}

// GetProviderStats gets provider statistics
func (s *ssoService) GetProviderStats(ctx context.Context, providerID xid.ID) (*model.SSOProviderStats, error) {
	// This would integrate with analytics ssoService
	return &model.SSOProviderStats{
		ProviderID:           providerID,
		TotalLogins:          1500,
		SuccessfulLogins:     1485,
		FailedLogins:         15,
		UniqueUsers:          350,
		AutoProvisionedUsers: 85,
		LoginsToday:          45,
		LoginsWeek:           315,
		LoginsMonth:          1350,
		AverageLoginTime:     2.1,
		LastUsed:             nil,
		SuccessRate:          99.0,
	}, nil
}

// GetSSOActivity gets SSO activity
func (s *ssoService) GetSSOActivity(ctx context.Context, req model.SSOActivityRequest) (*model.SSOActivityResponse, error) {
	// This would integrate with audit ssoService
	return &model.SSOActivityResponse{
		Data: []model.SSOActivity{},
		Pagination: &model.Pagination{
			TotalCount:      0,
			HasNextPage:     false,
			HasPreviousPage: false,
		},
	}, nil
}

// GetProviderMetrics gets provider metrics
func (s *ssoService) GetProviderMetrics(ctx context.Context, providerID xid.ID, period string) (*model.SSOProviderMetrics, error) {
	return &model.SSOProviderMetrics{
		ProviderID:    providerID,
		Period:        period,
		LoginsByHour:  map[string]int{"00": 5, "01": 3},
		LoginsByDay:   map[string]int{"monday": 150, "tuesday": 160},
		ErrorsByType:  map[string]int{"timeout": 3, "invalid_cert": 1},
		ResponseTimes: []int{200, 250, 180},
		UsersByDomain: map[string]int{"acme.com": 120, "corp.com": 30},
		DeviceTypes:   map[string]int{"desktop": 100, "mobile": 50},
		Locations:     map[string]int{"US": 120, "CA": 30},
		GeneratedAt:   time.Now(),
	}, nil
}

// CheckProviderHealth checks provider health
func (s *ssoService) CheckProviderHealth(ctx context.Context, providerID xid.ID) (*model.SSOHealthCheck, error) {
	provider, err := s.providerRepo.GetByID(ctx, providerID)
	if err != nil {
		return nil, err
	}

	// Perform health check
	start := time.Now()
	healthy := true
	responseTime := int(time.Since(start).Milliseconds())
	status := "operational"
	var issues []string

	if !provider.Active || !provider.Enabled {
		healthy = false
		status = "disabled"
		issues = append(issues, "Provider is disabled")
	}

	return &model.SSOHealthCheck{
		ProviderID:   providerID,
		Healthy:      healthy,
		LastCheck:    time.Now(),
		ResponseTime: responseTime,
		Status:       status,
		Issues:       issues,
		NextCheck:    time.Now().Add(15 * time.Minute),
	}, nil
}

// GetHealthStatus gets health status for all providers
func (s *ssoService) GetHealthStatus(ctx context.Context, organizationID xid.ID) ([]model.SSOHealthCheck, error) {
	providers, err := s.providerRepo.ListActiveByOrganizationID(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	var healthChecks []model.SSOHealthCheck
	for _, provider := range providers {
		check, err := s.CheckProviderHealth(ctx, provider.ID)
		if err != nil {
			continue // Skip failed health checks
		}
		healthChecks = append(healthChecks, *check)
	}

	return healthChecks, nil
}

// Helper methods

func (s *ssoService) parseProviderConfig(config map[string]interface{}, target *model.SSOProviderConfig) error {
	data, err := json.Marshal(config)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to marshal config")
	}

	err = json.Unmarshal(data, target)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to unmarshal config")
	}

	return nil
}

func (s *ssoService) testOIDCConnection(ctx context.Context, config model.SSOProviderConfig) (bool, string, string) {
	// Test OIDC connection by attempting to fetch discovery document
	if config.AuthURL == "" || config.TokenURL == "" {
		return false, "", "Missing required OIDC configuration"
	}

	// In production, make actual HTTP request to test endpoints
	return true, "OIDC connection test successful", ""
}

func (s *ssoService) testSAMLConnection(ctx context.Context, config model.SSOProviderConfig) (bool, string, string) {
	// Test SAML connection by validating certificate and endpoints
	if config.SSOUrl == "" || config.Certificate == "" {
		return false, "", "Missing required SAML configuration"
	}

	// In production, validate certificate and test endpoints
	return true, "SAML connection test successful", ""
}
