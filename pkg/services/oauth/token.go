package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// ClientService defines the interface for OAuth client management
type ClientService interface {
	// Client CRUD
	CreateClient(ctx context.Context, req model.CreateOAuthClientRequest) (*model.CreateOAuthClientResponse, error)
	GetClient(ctx context.Context, id xid.ID) (*model.OAuthClient, error)
	GetClientByClientID(ctx context.Context, clientID string) (*model.OAuthClient, error)
	UpdateClient(ctx context.Context, id xid.ID, req model.UpdateOAuthClientRequest) (*model.OAuthClient, error)
	DeleteClient(ctx context.Context, id xid.ID) error
	ListClients(ctx context.Context, req model.OAuthClientListRequest) (*model.OAuthClientListResponse, error)

	// Client Management
	RegenerateClientSecret(ctx context.Context, id xid.ID) (*model.RegenerateClientSecretResponse, error)
	ActivateClient(ctx context.Context, id xid.ID) error
	DeactivateClient(ctx context.Context, id xid.ID) error

	// Client Validation
	ValidateClientConfig(ctx context.Context, req model.CreateOAuthClientRequest) error
	ValidateRedirectURIs(redirectURIs []string) error
	ValidateAllowedOrigins(origins []string) error

	// Client Statistics
	GetClientStats(ctx context.Context, id xid.ID) (*model.OAuthClientStats, error)
	GetClientUsage(ctx context.Context, id xid.ID, days int) (*model.OAuthClientStats, error)

	// Bulk Operations
	BulkRevokeClientTokens(ctx context.Context, req model.BulkRevokeTokensRequest) (*model.BulkRevokeTokensResponse, error)
}

// clientService implements ClientService
type clientService struct {
	oauthRepo repository.OAuthRepository
	logger    logging.Logger
}

// NewClientService creates a new OAuth client service
func NewClientService(
	oauthRepo repository.OAuthRepository,
	logger logging.Logger,
) ClientService {
	return &clientService{
		oauthRepo: oauthRepo,
		logger:    logger.Named("oauth.client"),
	}
}

// CreateClient creates a new OAuth client
func (s *clientService) CreateClient(ctx context.Context, req model.CreateOAuthClientRequest) (*model.CreateOAuthClientResponse, error) {
	s.logger.Info("Creating OAuth client", logging.String("name", req.ClientName))

	// Validate request
	if err := s.ValidateClientConfig(ctx, req); err != nil {
		return nil, err
	}

	// Get organization from context
	orgID, ok := ctx.Value("organization_id").(xid.ID)
	if !ok {
		return nil, errors.New(errors.CodeBadRequest, "Organization context required")
	}

	// Generate client ID and secret
	clientID, err := s.generateClientID()
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to generate client ID")
	}

	var clientSecret string
	if !req.Public {
		clientSecret, err = s.generateClientSecret()
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to generate client secret")
		}
	}

	// Set defaults
	if len(req.AllowedGrantTypes) == 0 {
		req.AllowedGrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if req.TokenExpirySeconds == 0 {
		req.TokenExpirySeconds = 3600 // 1 hour
	}
	if req.RefreshTokenExpirySeconds == 0 {
		req.RefreshTokenExpirySeconds = 2592000 // 30 days
	}
	if req.AuthCodeExpirySeconds == 0 {
		req.AuthCodeExpirySeconds = 600 // 10 minutes
	}

	// Create client input
	input := repository.CreateOAuthClientInput{
		ClientID:                  clientID,
		ClientSecret:              clientSecret,
		ClientName:                req.ClientName,
		ClientDescription:         req.ClientDescription,
		ClientURI:                 req.ClientURI,
		LogoURI:                   req.LogoURI,
		RedirectURIs:              req.RedirectURIs,
		PostLogoutRedirectURIs:    req.PostLogoutRedirectURIs,
		OrganizationID:            &orgID,
		Public:                    req.Public,
		Active:                    true,
		AllowedCORSOrigins:        req.AllowedCORSOrigins,
		AllowedGrantTypes:         req.AllowedGrantTypes,
		TokenExpirySeconds:        req.TokenExpirySeconds,
		RefreshTokenExpirySeconds: req.RefreshTokenExpirySeconds,
		AuthCodeExpirySeconds:     req.AuthCodeExpirySeconds,
		RequiresPKCE:              req.RequiresPKCE,
		RequiresConsent:           req.RequiresConsent,
	}

	client, err := s.oauthRepo.CreateClient(ctx, input)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to create OAuth client")
	}

	// Assign scopes if specified
	if len(req.ScopeNames) > 0 {
		for _, scopeName := range req.ScopeNames {
			scope, err := s.oauthRepo.GetScopeByName(ctx, scopeName)
			if err != nil {
				s.logger.Warn("Scope not found", logging.String("scope", scopeName))
				continue
			}
			// Here you would typically create a client-scope relationship
			// This depends on your schema design
			_ = scope
		}
	}

	s.logger.Info("OAuth client created successfully",
		logging.String("client_id", clientID),
		logging.String("name", req.ClientName))

	// Convert to model
	modelClient := s.convertToModel(client)

	return &model.CreateOAuthClientResponse{
		Client:       *modelClient,
		ClientSecret: clientSecret,
	}, nil
}

// GetClient retrieves an OAuth client by ID
func (s *clientService) GetClient(ctx context.Context, id xid.ID) (*model.OAuthClient, error) {
	client, err := s.oauthRepo.GetClientByID(ctx, id)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "OAuth client not found")
	}

	return s.convertToModel(client), nil
}

// GetClientByClientID retrieves an OAuth client by client ID
func (s *clientService) GetClientByClientID(ctx context.Context, clientID string) (*model.OAuthClient, error) {
	client, err := s.oauthRepo.GetClientByClientID(ctx, clientID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "OAuth client not found")
	}

	return s.convertToModel(client), nil
}

// UpdateClient updates an OAuth client
func (s *clientService) UpdateClient(ctx context.Context, id xid.ID, req model.UpdateOAuthClientRequest) (*model.OAuthClient, error) {
	s.logger.Info("Updating OAuth client", logging.String("id", id.String()))

	// Get existing client to validate ownership
	existingClient, err := s.oauthRepo.GetClientByID(ctx, id)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "OAuth client not found")
	}

	// Validate organization ownership
	orgID, ok := ctx.Value("organization_id").(xid.ID)
	if ok && !existingClient.OrganizationID.IsNil() && existingClient.OrganizationID != orgID {
		return nil, errors.New(errors.CodeForbidden, "Access denied")
	}

	// Validate redirect URIs if being updated
	if len(req.RedirectURIs) > 0 {
		if err := s.ValidateRedirectURIs(req.RedirectURIs); err != nil {
			return nil, err
		}
	}

	// Validate CORS origins if being updated
	if len(req.AllowedCORSOrigins) > 0 {
		if err := s.ValidateAllowedOrigins(req.AllowedCORSOrigins); err != nil {
			return nil, err
		}
	}

	// Create update input
	input := repository.UpdateOAuthClientInput{
		ClientName:                &req.ClientName,
		ClientDescription:         &req.ClientDescription,
		ClientURI:                 &req.ClientURI,
		LogoURI:                   &req.LogoURI,
		RedirectURIs:              req.RedirectURIs,
		PostLogoutRedirectURIs:    req.PostLogoutRedirectURIs,
		AllowedCORSOrigins:        req.AllowedCORSOrigins,
		AllowedGrantTypes:         req.AllowedGrantTypes,
		TokenExpirySeconds:        &req.TokenExpirySeconds,
		RefreshTokenExpirySeconds: &req.RefreshTokenExpirySeconds,
		AuthCodeExpirySeconds:     &req.AuthCodeExpirySeconds,
		RequiresPKCE:              &req.RequiresPKCE,
		RequiresConsent:           &req.RequiresConsent,
		Active:                    &req.Active,
	}

	updatedClient, err := s.oauthRepo.UpdateClient(ctx, id, input)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to update OAuth client")
	}

	s.logger.Info("OAuth client updated successfully", logging.String("id", id.String()))

	return s.convertToModel(updatedClient), nil
}

// DeleteClient deletes an OAuth client
func (s *clientService) DeleteClient(ctx context.Context, id xid.ID) error {
	s.logger.Info("Deleting OAuth client", logging.String("id", id.String()))

	// Get existing client to validate ownership
	existingClient, err := s.oauthRepo.GetClientByID(ctx, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeNotFound, "OAuth client not found")
	}

	// Validate organization ownership
	orgID, ok := ctx.Value("organization_id").(xid.ID)
	if ok && !existingClient.OrganizationID.IsNil() && existingClient.OrganizationID != orgID {
		return errors.New(errors.CodeForbidden, "Access denied")
	}

	// Revoke all tokens for this client
	if err := s.oauthRepo.RevokeAllClientTokens(ctx, id); err != nil {
		s.logger.Warn("Failed to revoke client tokens", logging.Error(err))
	}

	// Delete the client
	if err := s.oauthRepo.DeleteClient(ctx, id); err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to delete OAuth client")
	}

	s.logger.Info("OAuth client deleted successfully", logging.String("id", id.String()))
	return nil
}

// ListClients lists OAuth clients with pagination and filtering
func (s *clientService) ListClients(ctx context.Context, req model.OAuthClientListRequest) (*model.OAuthClientListResponse, error) {
	// Convert request to repository parameters
	params := repository.ListOAuthClientsParams{
		PaginationParams: req.PaginationParams,
	}

	if req.Public.IsSet {
		params.Public = &req.Public.Value
	}
	if req.Active.IsSet {
		params.Active = &req.Active.Value
	}
	if req.Search != "" {
		params.Search = &req.Search
	}
	if req.OrganizationID.IsSet {
		params.OrganizationID = &req.OrganizationID.Value
	}

	// If no organization specified in request, use context
	if params.OrganizationID == nil {
		if orgID, ok := ctx.Value("organization_id").(xid.ID); ok {
			params.OrganizationID = &orgID
		}
	}

	result, err := s.oauthRepo.ListClients(ctx, params)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list OAuth clients")
	}

	// Convert to summaries
	summaries := make([]model.OAuthClientSummary, len(result.Data))
	for i, client := range result.Data {
		summaries[i] = s.convertToSummary(client)
	}

	return &model.OAuthClientListResponse{
		Data:       summaries,
		Pagination: result.Pagination,
	}, nil
}

// RegenerateClientSecret generates a new client secret
func (s *clientService) RegenerateClientSecret(ctx context.Context, id xid.ID) (*model.RegenerateClientSecretResponse, error) {
	s.logger.Info("Regenerating client secret", logging.String("id", id.String()))

	// Get existing client
	existingClient, err := s.oauthRepo.GetClientByID(ctx, id)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "OAuth client not found")
	}

	// Validate organization ownership
	orgID, ok := ctx.Value("organization_id").(xid.ID)
	if ok && !existingClient.OrganizationID.IsNil() && existingClient.OrganizationID != orgID {
		return nil, errors.New(errors.CodeForbidden, "Access denied")
	}

	// Cannot regenerate secret for public clients
	if existingClient.Public {
		return nil, errors.New(errors.CodeBadRequest, "Cannot regenerate secret for public client")
	}

	// Generate new secret
	newSecret, err := s.generateClientSecret()
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to generate client secret")
	}

	// Update client with new secret
	input := repository.UpdateOAuthClientInput{
		ClientSecret: &newSecret,
	}

	_, err = s.oauthRepo.UpdateClient(ctx, id, input)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to update client secret")
	}

	// Revoke all existing tokens (forcing re-authentication)
	if err := s.oauthRepo.RevokeAllClientTokens(ctx, id); err != nil {
		s.logger.Warn("Failed to revoke client tokens after secret regeneration", logging.Error(err))
	}

	s.logger.Info("Client secret regenerated successfully", logging.String("id", id.String()))

	return &model.RegenerateClientSecretResponse{
		ClientSecret: newSecret,
		Message:      "Client secret regenerated successfully. All existing tokens have been revoked.",
	}, nil
}

// ActivateClient activates an OAuth client
func (s *clientService) ActivateClient(ctx context.Context, id xid.ID) error {
	return s.updateClientStatus(ctx, id, true)
}

// DeactivateClient deactivates an OAuth client
func (s *clientService) DeactivateClient(ctx context.Context, id xid.ID) error {
	return s.updateClientStatus(ctx, id, false)
}

// ValidateClientConfig validates OAuth client configuration
func (s *clientService) ValidateClientConfig(ctx context.Context, req model.CreateOAuthClientRequest) error {
	if req.ClientName == "" {
		return errors.New(errors.CodeBadRequest, "Client name is required")
	}

	if len(req.RedirectURIs) == 0 {
		return errors.New(errors.CodeBadRequest, "At least one redirect URI is required")
	}

	if err := s.ValidateRedirectURIs(req.RedirectURIs); err != nil {
		return err
	}

	if len(req.AllowedCORSOrigins) > 0 {
		if err := s.ValidateAllowedOrigins(req.AllowedCORSOrigins); err != nil {
			return err
		}
	}

	// Validate grant types
	for _, grantType := range req.AllowedGrantTypes {
		if !s.isValidGrantType(grantType) {
			return errors.Newf(errors.CodeBadRequest, "Invalid grant type: %s", grantType)
		}
	}

	// Validate token expiry settings
	if req.TokenExpirySeconds < 0 || req.TokenExpirySeconds > 86400 { // Max 24 hours
		return errors.New(errors.CodeBadRequest, "Token expiry must be between 0 and 86400 seconds")
	}

	if req.RefreshTokenExpirySeconds < 0 || req.RefreshTokenExpirySeconds > 31536000 { // Max 1 year
		return errors.New(errors.CodeBadRequest, "Refresh token expiry must be between 0 and 31536000 seconds")
	}

	return nil
}

// ValidateRedirectURIs validates redirect URIs
func (s *clientService) ValidateRedirectURIs(redirectURIs []string) error {
	if len(redirectURIs) == 0 {
		return errors.New(errors.CodeBadRequest, "At least one redirect URI is required")
	}

	for _, uri := range redirectURIs {
		if err := s.validateRedirectURI(uri); err != nil {
			return errors.Wrapf(err, errors.CodeBadRequest, "Invalid redirect URI: %s", uri)
		}
	}

	return nil
}

// ValidateAllowedOrigins validates CORS origins
func (s *clientService) ValidateAllowedOrigins(origins []string) error {
	for _, origin := range origins {
		if err := s.validateOrigin(origin); err != nil {
			return errors.Wrapf(err, errors.CodeBadRequest, "Invalid CORS origin: %s", origin)
		}
	}

	return nil
}

// GetClientStats returns client statistics
func (s *clientService) GetClientStats(ctx context.Context, id xid.ID) (*model.OAuthClientStats, error) {
	stats, err := s.oauthRepo.GetClientUsageStats(ctx, id, 30) // Last 30 days
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get client stats")
	}

	return &model.OAuthClientStats{
		TotalTokens:             stats.TotalTokens,
		ActiveTokens:            stats.ActiveTokens,
		TotalAuthorizations:     stats.TotalAuthorizations,
		LastUsed:                stats.LastUsed,
		TokensThisMonth:         stats.TokensThisMonth,
		AuthorizationsThisMonth: stats.AuthorizationsThisMonth,
		UniqueUsers:             stats.UniqueUsers,
		SuccessRate:             stats.SuccessRate,
	}, nil
}

// GetClientUsage returns client usage statistics
func (s *clientService) GetClientUsage(ctx context.Context, id xid.ID, days int) (*model.OAuthClientStats, error) {
	stats, err := s.oauthRepo.GetClientUsageStats(ctx, id, days)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get client usage")
	}

	return &model.OAuthClientStats{
		TotalTokens:             stats.TotalTokens,
		ActiveTokens:            stats.ActiveTokens,
		TotalAuthorizations:     stats.TotalAuthorizations,
		LastUsed:                stats.LastUsed,
		TokensThisMonth:         stats.TokensThisMonth,
		AuthorizationsThisMonth: stats.AuthorizationsThisMonth,
		UniqueUsers:             stats.UniqueUsers,
		SuccessRate:             stats.SuccessRate,
	}, nil
}

// BulkRevokeClientTokens revokes tokens for multiple clients
func (s *clientService) BulkRevokeClientTokens(ctx context.Context, req model.BulkRevokeTokensRequest) (*model.BulkRevokeTokensResponse, error) {
	s.logger.Info("Bulk revoking client tokens", logging.String("reason", req.Reason))

	var revokedCount int
	var err error

	if req.ClientID != nil {
		err = s.oauthRepo.RevokeAllClientTokens(ctx, *req.ClientID)
		if err == nil {
			revokedCount = 1 // Simplified count
		}
	} else if req.UserID != nil {
		err = s.oauthRepo.RevokeAllUserTokens(ctx, *req.UserID)
		if err == nil {
			revokedCount = 1 // Simplified count
		}
	} else {
		return nil, errors.New(errors.CodeBadRequest, "Either client_id or user_id must be specified")
	}

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to revoke tokens")
	}

	s.logger.Info("Bulk token revocation completed", logging.Int("count", revokedCount))

	return &model.BulkRevokeTokensResponse{
		RevokedCount: revokedCount,
		Message:      fmt.Sprintf("%d tokens revoked successfully", revokedCount),
	}, nil
}

// Helper methods

func (s *clientService) updateClientStatus(ctx context.Context, id xid.ID, active bool) error {
	status := "activated"
	if !active {
		status = "deactivated"
	}

	s.logger.Info("Updating client status",
		logging.String("id", id.String()),
		logging.String("status", status))

	// Get existing client to validate ownership
	existingClient, err := s.oauthRepo.GetClientByID(ctx, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeNotFound, "OAuth client not found")
	}

	// Validate organization ownership
	orgID, ok := ctx.Value("organization_id").(xid.ID)
	if ok && !existingClient.OrganizationID.IsNil() && existingClient.OrganizationID != orgID {
		return errors.New(errors.CodeForbidden, "Access denied")
	}

	input := repository.UpdateOAuthClientInput{
		Active: &active,
	}

	_, err = s.oauthRepo.UpdateClient(ctx, id, input)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, fmt.Sprintf("Failed to %s client", status))
	}

	// If deactivating, revoke all tokens
	if !active {
		if err := s.oauthRepo.RevokeAllClientTokens(ctx, id); err != nil {
			s.logger.Warn("Failed to revoke client tokens during deactivation", logging.Error(err))
		}
	}

	s.logger.Info("Client status updated successfully",
		logging.String("id", id.String()),
		logging.String("status", status))

	return nil
}

func (s *clientService) generateClientID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "client_" + base64.RawURLEncoding.EncodeToString(bytes), nil
}

func (s *clientService) generateClientSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "secret_" + base64.RawURLEncoding.EncodeToString(bytes), nil
}

func (s *clientService) validateRedirectURI(uri string) error {
	parsed, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("invalid URL format")
	}

	// Must have a scheme
	if parsed.Scheme == "" {
		return fmt.Errorf("missing URL scheme")
	}

	// Allow http for localhost during development
	if parsed.Scheme == "http" && !s.isLocalhost(parsed.Host) {
		return fmt.Errorf("http scheme only allowed for localhost")
	}

	// Must not have fragment
	if parsed.Fragment != "" {
		return fmt.Errorf("fragments not allowed in redirect URIs")
	}

	return nil
}

func (s *clientService) validateOrigin(origin string) error {
	parsed, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("invalid URL format")
	}

	if parsed.Scheme == "" {
		return fmt.Errorf("missing URL scheme")
	}

	if parsed.Path != "" && parsed.Path != "/" {
		return fmt.Errorf("origins cannot have paths")
	}

	return nil
}

func (s *clientService) isLocalhost(host string) bool {
	localhostPatterns := []string{
		"localhost",
		"127.0.0.1",
		"::1",
	}

	for _, pattern := range localhostPatterns {
		if strings.HasPrefix(host, pattern) {
			return true
		}
	}

	return false
}

func (s *clientService) isValidGrantType(grantType string) bool {
	validGrantTypes := []string{
		"authorization_code",
		"client_credentials",
		"refresh_token",
		"urn:ietf:params:oauth:grant-type:device_code",
	}

	for _, valid := range validGrantTypes {
		if grantType == valid {
			return true
		}
	}

	return false
}

func (s *clientService) convertToModel(client *ent.OAuthClient) *model.OAuthClient {
	return &model.OAuthClient{
		Base: model.Base{
			ID:        client.ID,
			CreatedAt: client.CreatedAt,
			UpdatedAt: client.UpdatedAt,
		},
		ClientID:                  client.ClientID,
		ClientName:                client.ClientName,
		ClientDescription:         client.ClientDescription,
		ClientURI:                 client.ClientURI,
		LogoURI:                   client.LogoURI,
		RedirectURIs:              client.RedirectUris,
		PostLogoutRedirectURIs:    client.PostLogoutRedirectUris,
		OrganizationID:            &client.OrganizationID,
		Public:                    client.Public,
		Active:                    client.Active,
		AllowedCORSOrigins:        client.AllowedCorsOrigins,
		AllowedGrantTypes:         client.AllowedGrantTypes,
		TokenExpirySeconds:        client.TokenExpirySeconds,
		RefreshTokenExpirySeconds: client.RefreshTokenExpirySeconds,
		AuthCodeExpirySeconds:     client.AuthCodeExpirySeconds,
		RequiresPKCE:              client.RequiresPkce,
		RequiresConsent:           client.RequiresConsent,
		ClientSecret:              client.ClientSecret,
	}
}

func (s *clientService) convertToSummary(client *ent.OAuthClient) model.OAuthClientSummary {
	return model.OAuthClientSummary{
		ID:         client.ID,
		ClientID:   client.ClientID,
		ClientName: client.ClientName,
		LogoURI:    client.LogoURI,
		Public:     client.Public,
		Active:     client.Active,
		CreatedAt:  client.CreatedAt,
		// TokenCount, LastUsed would need to be calculated separately
	}
}
