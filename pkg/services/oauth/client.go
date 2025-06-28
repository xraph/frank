package oauth

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/rs/xid"
	"github
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/internal/repository"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
	"github.com/rs/xid"
)

// TokenService defines the interface for OAuth token management
type TokenService interface {
	// Token Validation
	ValidateAccessToken(ctx context.Context, token string) (*model.OAuthToken, error)
	ValidateRefreshToken(ctx context.Context, token string) (*model.OAuthToken, error)
	ValidateTokenScopes(ctx context.Context, token string, requiredScopes []string) error

	// Token Information
	GetTokenInfo(ctx context.Context, tokenID xid.ID) (*model.OAuthToken, error)
	GetTokenByAccessToken(ctx context.Context, accessToken string) (*model.OAuthToken, error)
	ListTokens(ctx context.Context, req model.OAuthTokenListRequest) (*model.OAuthTokenListResponse, error)
	ListUserTokens(ctx context.Context, userID xid.ID, req model.OAuthTokenListRequest) (*model.OAuthTokenListResponse, error)
	ListClientTokens(ctx context.Context, clientID xid.ID, req model.OAuthTokenListRequest) (*model.OAuthTokenListResponse, error)

	// Token Management
	RevokeToken(ctx context.Context, tokenID xid.ID) error
	RevokeTokenByValue(ctx context.Context, token string) error
	RevokeAllUserTokens(ctx context.Context, userID xid.ID) error
	RevokeAllClientTokens(ctx context.Context, clientID xid.ID) error
	ExtendTokenExpiry(ctx context.Context, tokenID xid.ID, additionalSeconds int) error

	// Token Analytics
	GetTokenStats(ctx context.Context, userID *xid.ID, clientID *xid.ID, days int) (*model.TokenUsageStats, error)
	GetTokenUsageByClient(ctx context.Context, orgID xid.ID, days int) (map[string]*model.TokenUsageStats, error)
	GetTokenUsageByUser(ctx context.Context, orgID xid.ID, days int) (map[string]*model.TokenUsageStats, error)

	// Token Cleanup
	CleanupExpiredTokens(ctx context.Context) (int, error)
	CleanupRevokedTokens(ctx context.Context, olderThan time.Duration) (int, error)

	// Token Introspection
	IntrospectToken(ctx context.Context, token string, clientID string) (*model.IntrospectTokenResponse, error)

	// Scope Management
	ValidateScopes(ctx context.Context, scopes []string) error
	GetScopesByNames(ctx context.Context, scopeNames []string) ([]*ent.OAuthScope, error)
	ExpandScopes(ctx context.Context, scopes []string) ([]string, error)
}

// tokenService implements TokenService
type tokenService struct {
	oauthRepo repository.OAuthRepository
	userRepo  repository.UserRepository
	logger    logging.Logger
}

// NewTokenService creates a new OAuth token service
func NewTokenService(
	oauthRepo repository.OAuthRepository,
	userRepo repository.UserRepository,
	logger logging.Logger,
) TokenService {
	return &tokenService{
		oauthRepo: oauthRepo,
		userRepo:  userRepo,
		logger:    logger.Named("oauth.token"),
	}
}

// ValidateAccessToken validates an access token and returns token information
func (s *tokenService) ValidateAccessToken(ctx context.Context, token string) (*model.OAuthToken, error) {
	s.logger.Debug("Validating access token", logging.String("token_prefix", s.getTokenPrefix(token)))

	entToken, err := s.oauthRepo.ValidateAccessToken(ctx, token)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeUnauthorized, "Invalid access token")
	}

	// Check if token is expired
	if time.Now().After(entToken.ExpiresAt) {
		return nil, errors.New(errors.CodeUnauthorized, "Token expired")
	}

	// Check if token is revoked
	if entToken.Revoked {
		return nil, errors.New(errors.CodeUnauthorized, "Token revoked")
	}

	return s.convertToModel(entToken), nil
}

// ValidateRefreshToken validates a refresh token
func (s *tokenService) ValidateRefreshToken(ctx context.Context, token string) (*model.OAuthToken, error) {
	s.logger.Debug("Validating refresh token", logging.String("token_prefix", s.getTokenPrefix(token)))

	entToken, err := s.oauthRepo.ValidateRefreshToken(ctx, token)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeUnauthorized, "Invalid refresh token")
	}

	// Check if refresh token is expired
	if entToken.RefreshTokenExpiresAt != nil && time.Now().After(*entToken.RefreshTokenExpiresAt) {
		return nil, errors.New(errors.CodeUnauthorized, "Refresh token expired")
	}

	// Check if token is revoked
	if entToken.Revoked {
		return nil, errors.New(errors.CodeUnauthorized, "Token revoked")
	}

	return s.convertToModel(entToken), nil
}

// ValidateTokenScopes validates that a token has the required scopes
func (s *tokenService) ValidateTokenScopes(ctx context.Context, token string, requiredScopes []string) error {
	if len(requiredScopes) == 0 {
		return nil // No scopes required
	}

	modelToken, err := s.ValidateAccessToken(ctx, token)
	if err != nil {
		return err
	}

	// Check if token has all required scopes
	tokenScopes := make(map[string]bool)
	for _, scope := range modelToken.ScopeNames {
		tokenScopes[scope] = true
	}

	for _, requiredScope := range requiredScopes {
		if !tokenScopes[requiredScope] {
			return errors.Newf(errors.CodeForbidden, "Missing required scope: %s", requiredScope)
		}
	}

	return nil
}

// GetTokenInfo returns token information by ID
func (s *tokenService) GetTokenInfo(ctx context.Context, tokenID xid.ID) (*model.OAuthToken, error) {
	entToken, err := s.oauthRepo.GetTokenByID(ctx, tokenID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Token not found")
	}

	return s.convertToModel(entToken), nil
}

// GetTokenByAccessToken returns token information by access token value
func (s *tokenService) GetTokenByAccessToken(ctx context.Context, accessToken string) (*model.OAuthToken, error) {
	entToken, err := s.oauthRepo.GetTokenByAccessToken(ctx, accessToken)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Token not found")
	}

	return s.convertToModel(entToken), nil
}

// ListTokens lists tokens with pagination and filtering
func (s *tokenService) ListTokens(ctx context.Context, req model.OAuthTokenListRequest) (*model.OAuthTokenListResponse, error) {
	params := repository.ListOAuthTokensParams{
		PaginationParams: req.PaginationParams,
	}

	if req.Revoked.IsSet {
		params.Revoked = &req.Revoked.Value
	}
	if req.Expired.IsSet {
		params.Expired = &req.Expired.Value
	}
	if req.ClientID.IsSet {
		params.ClientID = &req.ClientID.Value
	}
	if req.UserID.IsSet {
		params.UserID = &req.UserID.Value
	}
	if req.OrganizationID.IsSet {
		params.OrganizationID = &req.OrganizationID.Value
	}
	if req.Scope != "" {
		params.Scope = &req.Scope
	}

	result, err := s.oauthRepo.ListTokens(ctx, params)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list tokens")
	}

	// Convert to summaries
	summaries := make([]model.OAuthTokenSummary, len(result.Data))
	for i, token := range result.Data {
		summaries[i] = s.convertToSummary(token)
	}

	return &model.OAuthTokenListResponse{
		Data:       summaries,
		Pagination: result.Pagination,
	}, nil
}

// ListUserTokens lists tokens for a specific user
func (s *tokenService) ListUserTokens(ctx context.Context, userID xid.ID, req model.OAuthTokenListRequest) (*model.OAuthTokenListResponse, error) {
	params := repository.ListOAuthTokensParams{
		PaginationParams: req.PaginationParams,
		UserID:           &userID,
	}

	if req.Revoked.IsSet {
		params.Revoked = &req.Revoked.Value
	}
	if req.Expired.IsSet {
		params.Expired = &req.Expired.Value
	}
	if req.ClientID.IsSet {
		params.ClientID = &req.ClientID.Value
	}
	// if req.UserID.IsSet {
	// 	params.UserID = &req.UserID.Value
	// }
	if req.OrganizationID.IsSet {
		params.OrganizationID = &req.OrganizationID.Value
	}
	if req.Scope != "" {
		params.Scope = &req.Scope
	}

	result, err := s.oauthRepo.ListUserTokens(ctx, userID, params)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list user tokens")
	}

	// Convert to summaries
	summaries := make([]model.OAuthTokenSummary, len(result.Data))
	for i, token := range result.Data {
		summaries[i] = s.convertToSummary(token)
	}

	return &model.OAuthTokenListResponse{
		Data:       summaries,
		Pagination: result.Pagination,
	}, nil
}

// ListClientTokens lists tokens for a specific client
func (s *tokenService) ListClientTokens(ctx context.Context, clientID xid.ID, req model.OAuthTokenListRequest) (*model.OAuthTokenListResponse, error) {
	params := repository.ListOAuthTokensParams{
		PaginationParams: req.PaginationParams,
		ClientID:         &clientID,
	}

	if req.Revoked.IsSet {
		params.Revoked = &req.Revoked.Value
	}
	if req.Expired.IsSet {
		params.Expired = &req.Expired.Value
	}
	// if req.ClientID.IsSet {
	// 	params.ClientID = &req.ClientID.Value
	// }
	if req.UserID.IsSet {
		params.UserID = &req.UserID.Value
	}
	if req.OrganizationID.IsSet {
		params.OrganizationID = &req.OrganizationID.Value
	}
	if req.Scope != "" {
		params.Scope = &req.Scope
	}

	result, err := s.oauthRepo.ListClientTokens(ctx, clientID, params)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to list client tokens")
	}

	// Convert to summaries
	summaries := make([]model.OAuthTokenSummary, len(result.Data))
	for i, token := range result.Data {
		summaries[i] = s.convertToSummary(token)
	}

	return &model.OAuthTokenListResponse{
		Data:       summaries,
		Pagination: result.Pagination,
	}, nil
}

// RevokeToken revokes a token by ID
func (s *tokenService) RevokeToken(ctx context.Context, tokenID xid.ID) error {
	s.logger.Info("Revoking token", logging.String("token_id", tokenID.String()))

	if err := s.oauthRepo.DeleteToken(ctx, tokenID); err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to revoke token")
	}

	s.logger.Info("Token revoked successfully", logging.String("token_id", tokenID.String()))
	return nil
}

// RevokeTokenByValue revokes a token by its value
func (s *tokenService) RevokeTokenByValue(ctx context.Context, token string) error {
	s.logger.Info("Revoking token by value", logging.String("token_prefix", s.getTokenPrefix(token)))

	if err := s.oauthRepo.RevokeToken(ctx, token); err != nil {
		// Try as refresh token
		if err := s.oauthRepo.RevokeTokenByRefreshToken(ctx, token); err != nil {
			return errors.Wrap(err, errors.CodeNotFound, "Token not found")
		}
	}

	s.logger.Info("Token revoked successfully")
	return nil
}

// RevokeAllUserTokens revokes all tokens for a user
func (s *tokenService) RevokeAllUserTokens(ctx context.Context, userID xid.ID) error {
	s.logger.Info("Revoking all user tokens", logging.String("user_id", userID.String()))

	if err := s.oauthRepo.RevokeAllUserTokens(ctx, userID); err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to revoke user tokens")
	}

	s.logger.Info("All user tokens revoked", logging.String("user_id", userID.String()))
	return nil
}

// RevokeAllClientTokens revokes all tokens for a client
func (s *tokenService) RevokeAllClientTokens(ctx context.Context, clientID xid.ID) error {
	s.logger.Info("Revoking all client tokens", logging.String("client_id", clientID.String()))

	if err := s.oauthRepo.RevokeAllClientTokens(ctx, clientID); err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to revoke client tokens")
	}

	s.logger.Info("All client tokens revoked", logging.String("client_id", clientID.String()))
	return nil
}

// ExtendTokenExpiry extends the expiration time of a token
func (s *tokenService) ExtendTokenExpiry(ctx context.Context, tokenID xid.ID, additionalSeconds int) error {
	s.logger.Info("Extending token expiry",
		logging.String("token_id", tokenID.String()),
		logging.Int("additional_seconds", additionalSeconds))

	// Get current token
	entToken, err := s.oauthRepo.GetTokenByAccessToken(ctx, tokenID.String())
	if err != nil {
		return errors.Wrap(err, errors.CodeNotFound, "Token not found")
	}

	// Calculate new expiry
	newExpiry := entToken.ExpiresAt.Add(time.Duration(additionalSeconds) * time.Second)

	// Update token
	input := repository.UpdateOAuthTokenInput{
		ExpiresAt: &newExpiry,
	}

	_, err = s.oauthRepo.UpdateToken(ctx, tokenID, input)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to extend token expiry")
	}

	s.logger.Info("Token expiry extended",
		logging.String("token_id", tokenID.String()),
		logging.Time("new_expiry", newExpiry))

	return nil
}

// GetTokenStats returns token usage statistics
func (s *tokenService) GetTokenStats(ctx context.Context, userID *xid.ID, clientID *xid.ID, days int) (*model.TokenUsageStats, error) {
	stats, err := s.oauthRepo.GetTokenUsageStats(ctx, userID, clientID, days)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to get token stats")
	}

	return &model.TokenUsageStats{
		ActiveTokens:    stats.ActiveTokens,
		RevokedTokens:   stats.RevokedTokens,
		ClientBreakdown: stats.ClientBreakdown,
		ScopeBreakdown:  stats.ScopeBreakdown,
		DailyBreakdown:  []model.OAuthDailyUsage{},
		ExpiredTokens:   stats.ExpiredTokens,
		TotalTokens:     stats.TotalTokens,
	}, nil
}

// GetTokenUsageByClient returns token usage grouped by client
func (s *tokenService) GetTokenUsageByClient(ctx context.Context, orgID xid.ID, days int) (map[string]*model.TokenUsageStats, error) {
	// This would require custom repository method
	// For now, return empty map
	return make(map[string]*model.TokenUsageStats), nil
}

// GetTokenUsageByUser returns token usage grouped by user
func (s *tokenService) GetTokenUsageByUser(ctx context.Context, orgID xid.ID, days int) (map[string]*model.TokenUsageStats, error) {
	// This would require custom repository method
	// For now, return empty map
	return make(map[string]*model.TokenUsageStats), nil
}

// CleanupExpiredTokens removes expired tokens
func (s *tokenService) CleanupExpiredTokens(ctx context.Context) (int, error) {
	s.logger.Info("Starting cleanup of expired tokens")

	count, err := s.oauthRepo.CleanupExpiredTokens(ctx)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternalServer, "Failed to cleanup expired tokens")
	}

	if count > 0 {
		s.logger.Info("Expired tokens cleaned up", logging.Int("count", count))
	}

	return count, nil
}

// CleanupRevokedTokens removes old revoked tokens
func (s *tokenService) CleanupRevokedTokens(ctx context.Context, olderThan time.Duration) (int, error) {
	s.logger.Info("Starting cleanup of revoked tokens", logging.Duration("older_than", olderThan))

	// This would require a custom repository method
	// For now, return 0
	return 0, nil
}

// IntrospectToken provides RFC 7662 token introspection
func (s *tokenService) IntrospectToken(ctx context.Context, token string, clientID string) (*model.IntrospectTokenResponse, error) {
	s.logger.Debug("Introspecting token",
		logging.String("token_prefix", s.getTokenPrefix(token)),
		logging.String("client_id", clientID))

	// Validate the token
	entToken, err := s.oauthRepo.ValidateAccessToken(ctx, token)
	if err != nil {
		// Return inactive response per RFC
		return &model.IntrospectTokenResponse{Active: false}, nil
	}

	// Check if token is expired
	if time.Now().After(entToken.ExpiresAt) {
		return &model.IntrospectTokenResponse{Active: false}, nil
	}

	// Check if token is revoked
	if entToken.Revoked {
		return &model.IntrospectTokenResponse{Active: false}, nil
	}

	// Get user information if token has a user
	var username string
	if entToken.UserID != xid.NilID() {
		user, err := s.userRepo.GetByID(ctx, entToken.UserID)
		if err == nil {
			username = user.Email
		}
	}

	// Build response
	response := &model.IntrospectTokenResponse{
		Active:    true,
		Scope:     strings.Join(entToken.ScopeNames, " "),
		ClientID:  clientID,
		Username:  username,
		TokenType: entToken.TokenType,
		ExpiresAt: entToken.ExpiresAt.Unix(),
		IssuedAt:  entToken.CreatedAt.Unix(),
		Subject:   entToken.UserID.String(),
	}

	return response, nil
}

// ValidateScopes validates that all provided scopes exist and are available
func (s *tokenService) ValidateScopes(ctx context.Context, scopes []string) error {
	if len(scopes) == 0 {
		return nil
	}

	for _, scopeName := range scopes {
		_, err := s.oauthRepo.GetScopeByName(ctx, scopeName)
		if err != nil {
			return errors.Newf(errors.CodeBadRequest, "Invalid scope: %s", scopeName)
		}
	}

	return nil
}

// GetScopesByNames returns scope entities by their names
func (s *tokenService) GetScopesByNames(ctx context.Context, scopeNames []string) ([]*ent.OAuthScope, error) {
	var scopes []*ent.OAuthScope

	for _, name := range scopeNames {
		scope, err := s.oauthRepo.GetScopeByName(ctx, name)
		if err != nil {
			return nil, errors.Wrapf(err, errors.CodeNotFound, "Scope not found: %s", name)
		}
		scopes = append(scopes, scope)
	}

	return scopes, nil
}

// ExpandScopes expands scope names to include implied scopes
func (s *tokenService) ExpandScopes(ctx context.Context, scopes []string) ([]string, error) {
	// For now, just return the original scopes
	// In a full implementation, this would handle scope hierarchies and implications
	expandedScopes := make([]string, len(scopes))
	copy(expandedScopes, scopes)

	// Remove duplicates
	scopeMap := make(map[string]bool)
	var result []string
	for _, scope := range expandedScopes {
		if !scopeMap[scope] {
			scopeMap[scope] = true
			result = append(result, scope)
		}
	}

	return result, nil
}

// Helper methods

func (s *tokenService) getTokenPrefix(token string) string {
	if len(token) > 8 {
		return token[:8] + "..."
	}
	return token
}

func (s *tokenService) convertToModel(entToken *ent.OAuthToken) *model.OAuthToken {
	modelToken := &model.OAuthToken{
		Base: model.Base{
			ID:        entToken.ID,
			CreatedAt: entToken.CreatedAt,
			UpdatedAt: entToken.UpdatedAt,
		},
		TokenType:             entToken.TokenType,
		ClientID:              entToken.ClientID,
		UserID:                entToken.UserID,
		OrganizationID:        &entToken.OrganizationID,
		ScopeNames:            entToken.ScopeNames,
		ExpiresIn:             entToken.ExpiresIn,
		ExpiresAt:             entToken.ExpiresAt,
		RefreshTokenExpiresAt: entToken.RefreshTokenExpiresAt,
		Revoked:               entToken.Revoked,
		RevokedAt:             entToken.RevokedAt,
		IPAddress:             entToken.IPAddress,
		UserAgent:             entToken.UserAgent,
	}

	return modelToken
}

func (s *tokenService) convertToSummary(entToken *ent.OAuthToken) model.OAuthTokenSummary {
	// Get client name - would need to be joined in the query
	clientName := "Unknown Client"

	// Get user email - would need to be joined in the query
	userEmail := "Unknown User"

	return model.OAuthTokenSummary{
		ID:         entToken.ID,
		ClientName: clientName,
		UserEmail:  userEmail,
		ScopeNames: entToken.ScopeNames,
		ExpiresAt:  entToken.ExpiresAt,
		Revoked:    entToken.Revoked,
		CreatedAt:  entToken.CreatedAt,
	}
}

// TokenMetadata represents additional token metadata
type TokenMetadata struct {
	DeviceInfo   map[string]interface{} `json:"device_info,omitempty"`
	LocationInfo map[string]interface{} `json:"location_info,omitempty"`
	SessionInfo  map[string]interface{} `json:"session_info,omitempty"`
	CustomClaims map[string]interface{} `json:"custom_claims,omitempty"`
}

// EnrichTokenWithMetadata adds metadata to a token
func (s *tokenService) EnrichTokenWithMetadata(ctx context.Context, tokenID xid.ID, metadata TokenMetadata) error {
	s.logger.Debug("Enriching token with metadata", logging.String("token_id", tokenID.String()))

	// Convert metadata to JSON
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to marshal metadata")
	}

	// This would require extending the token schema to include a metadata field
	// For now, just log the operation
	s.logger.Debug("Token metadata would be stored",
		logging.String("token_id", tokenID.String()),
		logging.String("metadata", string(metadataBytes)))

	return nil
}

// GetTokenMetadata retrieves token metadata
func (s *tokenService) GetTokenMetadata(ctx context.Context, tokenID xid.ID) (*TokenMetadata, error) {
	// This would retrieve metadata from the token record
	// For now, return empty metadata
	return &TokenMetadata{}, nil
}

// RevokeTokensMatchingPattern revokes tokens matching a specific pattern
func (s *tokenService) RevokeTokensMatchingPattern(ctx context.Context, pattern string, reason string) (int, error) {
	s.logger.Info("Revoking tokens matching pattern",
		logging.String("pattern", pattern),
		logging.String("reason", reason))

	// This would require a custom repository method with pattern matching
	// For now, return 0
	return 0, nil
}

// GetTokenAuditLog returns audit log for token operations
func (s *tokenService) GetTokenAuditLog(ctx context.Context, tokenID xid.ID) ([]TokenAuditEntry, error) {
	// This would return audit entries for token operations
	// For now, return empty slice
	return []TokenAuditEntry{}, nil
}

// TokenAuditEntry represents an audit log entry for token operations
type TokenAuditEntry struct {
	ID        xid.ID    `json:"id"`
	TokenID   xid.ID    `json:"token_id"`
	Action    string    `json:"action"`
	UserID    *xid.ID   `json:"user_id,omitempty"`
	IPAddress string    `json:"ip_address,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	Details   string    `json:"details,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}
