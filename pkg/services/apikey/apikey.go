package apikey

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/rs/xid"
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/internal/repository"
	"github.com/xraph/frank/pkg/contexts"
	contexts2 "github.com/xraph/frank/pkg/contexts"
	"github.com/xraph/frank/pkg/crypto"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
	"github.com/xraph/frank/pkg/services/activity"
	"github.com/xraph/frank/pkg/services/audit"
	"github.com/xraph/frank/pkg/services/rbac"
)

// Service defines the API key service interface
type Service interface {
	// Core CRUD operations
	CreateAPIKey(ctx context.Context, req *model.CreateAPIKeyRequest) (*model.CreateAPIKeyResponse, error)
	GetAPIKey(ctx context.Context, keyID xid.ID, opts *GetOptions) (*model.APIKey, error)
	GetAPIKeyByPublicKey(ctx context.Context, publicKey string) (*model.APIKey, error)
	GetAPIKeyBySecretKey(ctx context.Context, secretKey string) (*model.APIKey, error)
	UpdateAPIKey(ctx context.Context, keyID xid.ID, req *model.UpdateAPIKeyRequest) (*model.APIKey, error)
	DeleteAPIKey(ctx context.Context, keyID xid.ID, opts *DeleteOptions) error
	ListAPIKeys(ctx context.Context, req *model.APIKeyListRequest) (*model.APIKeyListResponse, error)

	// Key management operations
	RotateAPIKey(ctx context.Context, keyID xid.ID, req *model.RotateAPIKeyRequest) (*model.RotateAPIKeyResponse, error)
	ValidateAPIKey(ctx context.Context, req *model.ValidateAPIKeyRequest) (*model.ValidateAPIKeyResponse, error)
	DeactivateAPIKey(ctx context.Context, keyID xid.ID, reason string, opts *DeactivateOptions) error
	ActivateAPIKey(ctx context.Context, keyID xid.ID, opts *ActivateOptions) error
	AuthenticateAPIKey(ctx context.Context, secretKey string) (*model.APIKey, error)

	// Bulk operations
	BulkAPIKeyOperation(ctx context.Context, req *model.BulkAPIKeyOperationRequest, opts *BulkOptions) (*model.BulkAPIKeyOperationResponse, error)

	// Analytics and reporting
	RecordAPIKeyUsage(ctx context.Context, keyID xid.ID, endpoint, method string, statusCode int, responseTime int) error
	GetAPIKeyStats(ctx context.Context, orgID *xid.ID) (*model.APIKeyStats, error)
	GetAPIKeyUsage(ctx context.Context, keyID xid.ID) (*model.APIKeyUsage, error)
	GetAPIKeyActivity(ctx context.Context, req *model.APIKeyActivityRequest) (*model.APIKeyActivityResponse, error)

	// Export functionality
	ExportAPIKeyData(ctx context.Context, req *model.APIKeyExportRequest, opts *ExportOptions) (*model.APIKeyExportResponse, error)

	// Utility methods
	CheckAPIKeyPermissions(ctx context.Context, keyID xid.ID, requiredPermissions []string) error

	// Rate limiting
	CheckRateLimit(ctx context.Context, keyID xid.ID, endpoint string) (*model.RateLimitInfo, error)
	UpdateRateLimit(ctx context.Context, keyID xid.ID, endpoint string) error
}

// service implements the Service interface
type service struct {
	repo            repository.Repository
	logger          logging.Logger
	crypto          crypto.Util
	auditService    audit.Service
	activityService activity.Service
	rbacService     rbac.Service
}

// NewService creates a new API key service
func NewService(
	repo repository.Repository,
	crypto crypto.Util,
	auditService audit.Service,
	activityService activity.Service,
	rbacService rbac.Service,
	logger logging.Logger,
) Service {
	return &service{
		repo:            repo,
		logger:          logger,
		crypto:          crypto,
		auditService:    auditService,
		activityService: activityService,
		rbacService:     rbacService,
	}
}

// CreateAPIKey creates a new API key with both public and secret keys
func (s *service) CreateAPIKey(ctx context.Context, req *model.CreateAPIKeyRequest) (*model.CreateAPIKeyResponse, error) {
	// Validate request
	if err := s.validateCreateRequest(ctx, req); err != nil {
		return nil, err
	}

	// Set defaults
	if req.Type == "" {
		req.Type = model.APIKeyTypeServer
	}
	if req.Environment == "" {
		req.Environment = "test"
	}

	// Validate permissions exist and are applicable
	if err := s.validatePermissions(ctx, req.Permissions); err != nil {
		return nil, errors.Newf(errors.CodeInvalidInput, "invalid permissions: %v", err)
	}

	// Generate key pair
	publicKey, secretKey, err := s.generateAPIKeyPair(string(req.Type), string(req.Environment))
	if err != nil {
		return nil, errors.Newf(errors.CodeInternalServer, "failed to generate API key pair: %v", err)
	}

	// Hash the secret key
	hashedSecretKey, err := s.hashAPIKey(secretKey)
	if err != nil {
		return nil, errors.Newf(errors.CodeInternalServer, "failed to hash secret key: %v", err)
	}

	// Get current user and organization from context
	userID, organizationID, err := s.getContextInfo(ctx)
	if err != nil {
		s.logger.Error("Failed to get context info", logging.Error(err))
		return nil, err
	}

	// Set default rate limits if not provided
	if req.RateLimits == nil {
		req.RateLimits = &model.APIKeyRateLimits{
			RequestsPerMinute: DefaultRequestsPerMinute,
			RequestsPerHour:   DefaultRequestsPerHour,
			RequestsPerDay:    DefaultRequestsPerDay,
			BurstLimit:        DefaultBurstLimit,
		}
	}

	// Create API key model
	createReq := repository.CreateApiKeyInput{
		Name:            req.Name,
		PublicKey:       publicKey,
		SecretKey:       secretKey,
		HashedSecretKey: hashedSecretKey,
		UserID:          *userID,
		OrganizationID:  *organizationID,
		Type:            req.Type,
		Environment:     req.Environment,
		Active:          true,
		Permissions:     req.Permissions,
		Scopes:          req.Scopes,
		Metadata:        req.Metadata,
		ExpiresAt:       req.ExpiresAt,
		IPWhitelist:     req.IPWhitelist,
		RateLimits:      req.RateLimits,
	}

	// Save to database
	keyModel, err := s.repo.APIKey().Create(ctx, createReq)
	if err != nil {
		return nil, errors.Newf(errors.CodeInternalServer, "failed to create API key: %v", err)
	}

	// Audit the action
	if s.auditService != nil {
		auditReq := audit.AuditEvent{
			OrganizationID: organizationID,
			UserID:         userID,
			Action:         "apikey.create",
			Resource:       "apikey",
			ResourceID:     &keyModel.ID,
			Status:         "success",
			Details: map[string]interface{}{
				"name":        req.Name,
				"type":        req.Type,
				"environment": req.Environment,
				"permissions": req.Permissions,
				"scopes":      req.Scopes,
				"public_key":  publicKey,
			},
			RiskLevel: "medium",
			Tags:      []string{"apikey", "security"},
		}

		if err := s.auditService.LogEvent(ctx, auditReq); err != nil {
			s.logger.Warn("failed to create audit log", logging.Error(err))
		}
	}

	s.logger.Info("API key created successfully",
		logging.String("keyId", keyModel.ID.String()),
		logging.String("name", req.Name),
		logging.String("type", string(req.Type)),
		logging.String("environment", string(req.Environment)),
		logging.String("publicKey", publicKey),
	)

	// Log the creation
	if err = s.logAPIKeyEvent(ctx, keyModel.ID, "api_key_created", map[string]interface{}{
		"key_name":    req.Name,
		"key_type":    req.Type,
		"environment": req.Environment,
		"public_key":  publicKey,
	}); err != nil {
		s.logger.Warn("Failed to log API key creation", logging.Error(err))
	}

	response := &model.CreateAPIKeyResponse{
		APIKey:    *convertEntToApiKeyDTO(keyModel),
		PublicKey: publicKey,
		SecretKey: secretKey,
		Warning:   "Store the secret key securely. It will not be shown again.",
	}

	// Remove sensitive data from the response
	response.APIKey.HashedSecretKey = ""
	response.APIKey.SecretKey = ""

	return response, nil
}

// GetAPIKey retrieves an API key by ID
func (s *service) GetAPIKey(ctx context.Context, keyID xid.ID, opts *GetOptions) (*model.APIKey, error) {
	if opts == nil {
		opts = &GetOptions{}
	}

	// Get API key from database
	apiKeyEnt, err := s.repo.APIKey().GetByID(ctx, keyID)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "API key not found")
		}
		return nil, errors.Newf(errors.CodeInternalServer, "failed to get API key: %v", err)
	}

	apiKey := convertEntToApiKeyDTO(apiKeyEnt)

	// Check organization access
	if opts.OrganizationID != nil && !apiKey.OrganizationID.IsNil() &&
		apiKey.OrganizationID != *opts.OrganizationID {
		return nil, errors.New(errors.CodeForbidden, "access denied to API key")
	}

	// Check user access
	if opts.UserID != nil && !apiKey.UserID.IsNil() &&
		apiKey.UserID != *opts.UserID {
		return nil, errors.New(errors.CodeForbidden, "access denied to API key")
	}

	// Load related data if requested
	if opts.IncludeUsage {
		usage, err := s.getAPIKeyUsage(ctx, keyID)
		if err != nil {
			s.logger.Warn("failed to load API key usage", logging.Error(err))
		} else {
			apiKey.Usage = usage
		}
	}

	if opts.IncludeUser && !apiKey.UserID.IsNil() {
		user, err := s.repo.User().GetByID(ctx, apiKey.UserID)
		if err != nil {
			s.logger.Warn("failed to load API key user", logging.Error(err))
		} else {
			apiKey.User = &model.UserSummary{
				ID:              user.ID,
				Email:           user.Email,
				FirstName:       user.FirstName,
				LastName:        user.LastName,
				ProfileImageURL: user.ProfileImageURL,
			}
		}
	}

	if opts.IncludeOrg && !apiKey.OrganizationID.IsNil() {
		org, err := s.repo.Organization().GetByID(ctx, apiKey.OrganizationID)
		if err != nil {
			s.logger.Warn("failed to load API key organization", logging.Error(err))
		} else {
			apiKey.Organization = &model.OrganizationSummary{
				ID:   org.ID,
				Name: org.Name,
				Slug: org.Slug,
			}
		}
	}

	// Remove sensitive data
	apiKey.HashedSecretKey = ""
	apiKey.SecretKey = ""

	return apiKey, nil
}

// GetAPIKeyByPublicKey retrieves an API key by its public key
func (s *service) GetAPIKeyByPublicKey(ctx context.Context, publicKey string) (*model.APIKey, error) {
	s.logger.Debug("Getting API key by public key")

	apiKey, err := s.repo.APIKey().GetByPublicKey(ctx, publicKey)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "API key not found")
		}
		s.logger.Error("Failed to get API key by public key", logging.Error(err))
		return nil, errors.New(errors.CodeInternalServer, "failed to get API key")
	}

	result := convertEntToApiKeyDTO(apiKey)
	// Remove sensitive data
	result.HashedSecretKey = ""
	result.SecretKey = ""

	return result, nil
}

// GetAPIKeyBySecretKey retrieves an API key by its secret key value
func (s *service) GetAPIKeyBySecretKey(ctx context.Context, secretKey string) (*model.APIKey, error) {
	s.logger.Debug("Getting API key by secret key")

	// Hash the provided secret key
	hashedSecretKey, err := s.hashAPIKey(secretKey)
	if err != nil {
		return nil, errors.New(errors.CodeBadRequest, "invalid secret key format")
	}

	apiKey, err := s.repo.APIKey().GetByHashedSecretKey(ctx, hashedSecretKey)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "API key not found")
		}
		s.logger.Error("Failed to get API key by secret key", logging.Error(err))
		return nil, errors.New(errors.CodeInternalServer, "failed to get API key")
	}

	result := convertEntToApiKeyDTO(apiKey)
	// Remove sensitive data
	result.HashedSecretKey = ""
	result.SecretKey = ""

	return result, nil
}

// AuthenticateAPIKey authenticates a secret key and returns the key if valid
func (s *service) AuthenticateAPIKey(ctx context.Context, secretKey string) (*model.APIKey, error) {
	req := &model.ValidateAPIKeyRequest{SecretKey: secretKey}

	response, err := s.ValidateAPIKey(ctx, req)
	if err != nil {
		return nil, err
	}

	if !response.Valid {
		return nil, errors.New(errors.CodeUnauthorized, response.Error)
	}

	return s.GetAPIKey(ctx, response.KeyID, nil)
}

// ValidateAPIKey validates a secret key and returns its details
func (s *service) ValidateAPIKey(ctx context.Context, req *model.ValidateAPIKeyRequest) (*model.ValidateAPIKeyResponse, error) {
	s.logger.Debug("Validating API key")

	// Get API key by secret key
	apiKey, err := s.GetAPIKeyBySecretKey(ctx, req.SecretKey)
	if err != nil {
		return &model.ValidateAPIKeyResponse{
			Valid: false,
			Error: "invalid API key",
		}, nil
	}

	// Check if key is active
	if !apiKey.Active {
		return &model.ValidateAPIKeyResponse{
			Valid: false,
			Error: "API key is inactive",
		}, nil
	}

	// Check expiration
	if apiKey.ExpiresAt != nil && time.Now().After(*apiKey.ExpiresAt) {
		return &model.ValidateAPIKeyResponse{
			Valid: false,
			Error: "API key has expired",
		}, nil
	}

	// Check IP whitelist
	if len(apiKey.IPWhitelist) > 0 && req.IPAddress != "" {
		if !s.isIPAllowed(req.IPAddress, apiKey.IPWhitelist) {
			return &model.ValidateAPIKeyResponse{
				Valid: false,
				Error: "IP address not allowed",
			}, nil
		}
	}

	// Check rate limits
	rateLimitInfo, err := s.CheckRateLimit(ctx, apiKey.ID, req.Endpoint)
	if err != nil {
		s.logger.Warn("Failed to check rate limit", logging.Error(err))
	}

	// Update last used timestamp and record activity
	go func() {
		// Update last used timestamp
		if err := s.updateLastUsed(context.Background(), apiKey.ID); err != nil {
			s.logger.Warn("Failed to update last used timestamp", logging.Error(err))
		}

		// Record validation activity
		if err := s.activityService.RecordActivity(context.Background(), &activity.ActivityRecord{
			ID:             xid.New(),
			ResourceType:   "api_key",
			ResourceID:     apiKey.ID,
			UserID:         &apiKey.UserID,
			OrganizationID: &apiKey.OrganizationID,
			Action:         "key_validated",
			Category:       "api",
			Source:         "api",
			IPAddress:      req.IPAddress,
			UserAgent:      req.UserAgent,
			Success:        true,
			Timestamp:      time.Now(),
			Metadata: map[string]interface{}{
				"endpoint":    req.Endpoint,
				"method":      req.Method,
				"public_key":  apiKey.PublicKey,
				"environment": apiKey.Environment,
			},
			Tags: []string{"validation", "api_key"},
		}); err != nil {
			s.logger.Warn("Failed to record key validation activity", logging.Error(err))
		}
	}()

	return &model.ValidateAPIKeyResponse{
		Valid:          true,
		KeyID:          apiKey.ID,
		PublicKey:      apiKey.PublicKey,
		UserID:         apiKey.UserID,
		OrganizationID: apiKey.OrganizationID,
		Type:           apiKey.Type,
		Environment:    apiKey.Environment,
		Permissions:    apiKey.Permissions,
		Scopes:         apiKey.Scopes,
		RateLimitInfo:  rateLimitInfo,
		ExpiresAt:      apiKey.ExpiresAt,
	}, nil
}

// RotateAPIKey rotates an API key by creating a new key pair and marking the old one as inactive
func (s *service) RotateAPIKey(ctx context.Context, keyID xid.ID, req *model.RotateAPIKeyRequest) (*model.RotateAPIKeyResponse, error) {
	s.logger.Info("Rotating API key", logging.String("key_id", keyID.String()))

	// Get existing API key
	existingKey, err := s.repo.APIKey().GetByID(ctx, keyID)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "API key not found")
		}
		return nil, errors.New(errors.CodeInternalServer, "failed to get API key")
	}

	// Generate new key pair
	newPublicKey, newSecretKey, err := s.generateAPIKeyPair(string(existingKey.Type), string(existingKey.Environment))
	if err != nil {
		return nil, errors.New(errors.CodeInternalServer, "failed to generate new API key pair")
	}

	// Hash the new secret key
	newHashedSecretKey, err := s.hashAPIKey(newSecretKey)
	if err != nil {
		return nil, errors.New(errors.CodeInternalServer, "failed to hash new secret key")
	}

	// Create new API key
	newAPIKey := &model.APIKey{
		Base: model.Base{
			ID:        xid.New(),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		Name:            existingKey.Name,
		PublicKey:       newPublicKey,
		SecretKey:       newSecretKey,
		HashedSecretKey: newHashedSecretKey,
		UserID:          existingKey.UserID,
		OrganizationID:  existingKey.OrganizationID,
		Type:            existingKey.Type,
		Environment:     existingKey.Environment,
		Active:          true,
		Permissions:     existingKey.Permissions,
		Scopes:          existingKey.Scopes,
		Metadata:        existingKey.Metadata,
		ExpiresAt:       req.ExpiresAt,
		IPWhitelist:     existingKey.IPWhitelist,
		RateLimits:      &existingKey.RateLimits,
	}

	// Save new key and deactivate old key in transaction
	if err := s.repo.APIKey().RotateKey(ctx, existingKey.ID, newAPIKey); err != nil {
		s.logger.Error("Failed to rotate API key", logging.Error(err))
		return nil, errors.New(errors.CodeInternalServer, "failed to rotate API key")
	}

	// Audit the action
	if s.auditService != nil {
		auditReq := audit.AuditEvent{
			OrganizationID: &existingKey.OrganizationID,
			UserID:         &existingKey.UserID,
			Action:         "apikey.rotate",
			Resource:       "apikey",
			ResourceID:     &req.KeyID,
			Status:         "success",
			Details: map[string]interface{}{
				"old_key_id":     req.KeyID.String(),
				"new_key_id":     newAPIKey.ID.String(),
				"old_public_key": existingKey.PublicKey,
				"new_public_key": newPublicKey,
				"reason":         req.Reason,
			},
			RiskLevel: "high",
			Tags:      []string{"apikey", "security", "rotation"},
		}

		if err := s.auditService.LogEvent(ctx, auditReq); err != nil {
			s.logger.Warn("failed to create audit log", logging.Error(err))
		}
	}

	// Log the rotation
	if err := s.logAPIKeyEvent(ctx, keyID, "api_key_rotated", map[string]interface{}{
		"old_key_id":     existingKey.ID.String(),
		"new_key_id":     newAPIKey.ID.String(),
		"old_public_key": existingKey.PublicKey,
		"new_public_key": newPublicKey,
		"reason":         req.Reason,
	}); err != nil {
		s.logger.Warn("Failed to log API key rotation", logging.Error(err))
	}

	s.logger.Info("API key rotated successfully",
		logging.String("oldKeyId", req.KeyID.String()),
		logging.String("newKeyId", newAPIKey.ID.String()),
		logging.String("oldPublicKey", existingKey.PublicKey),
		logging.String("newPublicKey", newPublicKey),
		logging.String("reason", req.Reason),
	)

	return &model.RotateAPIKeyResponse{
		NewPublicKey: newPublicKey,
		NewSecretKey: newSecretKey,
		OldKeyID:     existingKey.ID,
		NewKeyID:     newAPIKey.ID,
		ExpiresAt:    newAPIKey.ExpiresAt,
		Warning:      "Update your applications with the new secret key. Old key will be deactivated.",
	}, nil
}

// generateAPIKeyPair generates a public/secret key pair
func (s *service) generateAPIKeyPair(keyType, environment string) (publicKey, secretKey string, err error) {
	// Generate random bytes for both keys
	publicBytes := make([]byte, KeyLength)
	secretBytes := make([]byte, KeyLength)

	if _, err := rand.Read(publicBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate public key bytes: %v", err)
	}

	if _, err := rand.Read(secretBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate secret key bytes: %v", err)
	}

	// Create key prefixes based on type and environment
	var publicPrefix, secretPrefix string

	switch strings.ToLower(environment) {
	case "live", "production":
		publicPrefix = "pk_live_"
		secretPrefix = "sk_live_"
	default: // test, development, etc.
		publicPrefix = "pk_test_"
		secretPrefix = "sk_test_"
	}

	// Generate the keys
	publicKey = publicPrefix + hex.EncodeToString(publicBytes)
	secretKey = secretPrefix + hex.EncodeToString(secretBytes)

	return publicKey, secretKey, nil
}

// hashAPIKey hashes an API key for storage
func (s *service) hashAPIKey(key string) (string, error) {
	if s.crypto == nil {
		return "", fmt.Errorf("crypto utility not available")
	}

	hash := s.crypto.Hasher().HashAPIKey(key)
	return hash, nil
}

// UpdateAPIKey updates an existing API key
func (s *service) UpdateAPIKey(ctx context.Context, keyID xid.ID, req *model.UpdateAPIKeyRequest) (*model.APIKey, error) {
	// Get existing API key
	existingKey, err := s.GetAPIKey(ctx, keyID, nil)
	if err != nil {
		return nil, err
	}

	// Validate permissions if being updated
	if req.Permissions != nil {
		if err := s.validatePermissions(ctx, req.Permissions); err != nil {
			return nil, errors.Newf(errors.CodeInvalidInput, "invalid permissions: %v", err)
		}
	}

	// Prepare changes map for audit
	updatedKey := existingKey
	changes := make(map[string]interface{})
	updateInput := repository.UpdateApiKeyInput{}

	// Update fields
	if req.Name != "" && req.Name != existingKey.Name {
		changes["name"] = map[string]interface{}{
			"from": existingKey.Name,
			"to":   req.Name,
		}
		updateInput.Name = &req.Name
	}

	if req.Active != existingKey.Active {
		changes["active"] = map[string]interface{}{
			"from": existingKey.Active,
			"to":   req.Active,
		}
		updateInput.Active = &req.Active
	}

	if req.Permissions != nil {
		changes["permissions"] = map[string]interface{}{
			"from": existingKey.Permissions,
			"to":   req.Permissions,
		}
		updateInput.Permissions = req.Permissions
	}

	if req.Scopes != nil {
		changes["scopes"] = map[string]interface{}{
			"from": existingKey.Scopes,
			"to":   req.Scopes,
		}
		updateInput.Scopes = req.Scopes
	}

	if req.ExpiresAt != nil {
		changes["expires_at"] = map[string]interface{}{
			"from": existingKey.ExpiresAt,
			"to":   req.ExpiresAt,
		}
		updateInput.ExpiresAt = req.ExpiresAt
	}

	if req.IPWhitelist != nil {
		changes["ip_whitelist"] = map[string]interface{}{
			"from": existingKey.IPWhitelist,
			"to":   req.IPWhitelist,
		}
		updateInput.IPWhitelist = &req.IPWhitelist
	}

	if req.RateLimits != nil {
		changes["rate_limits"] = map[string]interface{}{
			"from": existingKey.RateLimits,
			"to":   req.RateLimits,
		}
		updateInput.RateLimits = req.RateLimits
	}

	if req.Metadata != nil {
		changes["metadata"] = map[string]interface{}{
			"from": existingKey.Metadata,
			"to":   req.Metadata,
		}
		updateInput.Metadata = req.Metadata
	}

	// Update in database
	if _, err := s.repo.APIKey().Update(ctx, existingKey.ID, updateInput); err != nil {
		return nil, errors.Newf(errors.CodeInternalServer, "failed to update API key: %v", err)
	}

	// Audit the action
	if s.auditService != nil && len(changes) > 0 {
		auditReq := audit.AuditEvent{
			OrganizationID: &existingKey.OrganizationID,
			UserID:         &existingKey.UserID,
			Action:         "apikey.update",
			Resource:       "apikey",
			ResourceID:     &keyID,
			Status:         "success",
			Changes:        changes,
			Details: map[string]interface{}{
				"name":        existingKey.Name,
				"type":        existingKey.Type,
				"environment": existingKey.Environment,
				"public_key":  existingKey.PublicKey,
			},
			RiskLevel: "medium",
			Tags:      []string{"apikey", "security"},
		}

		if err := s.auditService.LogEvent(ctx, auditReq); err != nil {
			s.logger.Warn("failed to create audit log", logging.Error(err))
		}
	}

	// Log the update
	if err := s.logAPIKeyEvent(ctx, keyID, "api_key_updated", map[string]interface{}{
		"key_name":   updatedKey.Name,
		"public_key": updatedKey.PublicKey,
		"changes":    changes,
	}); err != nil {
		s.logger.Warn("Failed to log API key update", logging.Error(err))
	}

	s.logger.Info("API key updated successfully",
		logging.String("keyId", keyID.String()),
		logging.String("name", existingKey.Name),
		logging.String("publicKey", existingKey.PublicKey),
	)

	return existingKey, nil
}

// ----

// DeleteAPIKey deletes an API key
func (s *service) DeleteAPIKey(ctx context.Context, keyID xid.ID, opts *DeleteOptions) error {
	if opts == nil {
		opts = &DeleteOptions{}
	}

	// Get existing API key for audit purposes
	existingKey, err := s.GetAPIKey(ctx, keyID, &GetOptions{
		UserID:         opts.UserID,
		OrganizationID: opts.OrganizationID,
	})
	if err != nil {
		return err
	}

	// Delete from database
	if err := s.repo.APIKey().Delete(ctx, keyID); err != nil {
		return errors.Newf(errors.CodeInternalServer, "failed to delete API key: %v", err)
	}

	// Audit the action
	if !opts.SkipAudit && s.auditService != nil {
		auditReq := audit.AuditEvent{
			OrganizationID: opts.OrganizationID,
			UserID:         opts.UserID,
			Action:         "apikey.delete",
			Resource:       "apikey",
			ResourceID:     &keyID,
			Status:         "success",
			Details: map[string]interface{}{
				"name":   existingKey.Name,
				"type":   existingKey.Type,
				"reason": opts.Reason,
			},
			RiskLevel: "high",
			Tags:      []string{"apikey", "security", "deletion"},
		}

		if err := s.auditService.LogEvent(ctx, auditReq); err != nil {
			s.logger.Warn("failed to create audit log", logging.Error(err))
		}
	}

	// Log the deletion
	if err := s.logAPIKeyEvent(ctx, keyID, "api_key_deleted", map[string]interface{}{
		"key_name": existingKey.Name,
		"key_type": existingKey.Type,
	}); err != nil {
		s.logger.Warn("Failed to log API key deletion", logging.Error(err))
	}

	s.logger.Info("API key deleted successfully",
		logging.String("keyId", keyID.String()),
		logging.String("name", existingKey.Name),
		logging.String("reason", opts.Reason),
	)

	return nil
}

// ListAPIKeys lists API keys with filtering and pagination
func (s *service) ListAPIKeys(ctx context.Context, req *model.APIKeyListRequest) (*model.APIKeyListResponse, error) {
	opts := repository.ListAPIKeyParams{
		PaginationParams: req.PaginationParams,
		Search:           req.Search,
		Scopes:           req.Scopes,
		Permission:       req.Permission,
		Type:             req.Type,
		Environment:      model.EnvironmentTest,
	}

	// Apply organization and user filters from options
	if req.OrganizationID.IsSet {
		opts.OrganizationID = &req.OrganizationID.Value
	}
	if req.UserID.IsSet {
		opts.UserID = &req.UserID.Value
	}
	if req.Active.IsSet {
		opts.Active = &req.Active.Value
	}
	if req.Used.IsSet {
		opts.Active = &req.Used.Value
	}

	// Get API keys from repository
	apiKeys, err := s.repo.APIKey().List(ctx, opts)
	if err != nil {
		return nil, errors.Newf(errors.CodeInternalServer, "failed to list API keys: %v", err)
	}

	// Convert to summaries and optionally include usage data
	summaries := make([]model.APIKeySummary, len(apiKeys.Data))
	for i, key := range apiKeys.Data {
		summaries[i] = s.convertToAPIKeySummary(key)

		// Include usage data if requested
		if opts.IncludeUsage {
			if usage, err := s.getAPIKeyUsage(ctx, key.ID); err == nil {
				summaries[i].UsageCount = usage.TotalRequests
			}
		}
	}

	return &model.APIKeyListResponse{
		Data:       summaries,
		Pagination: apiKeys.Pagination,
	}, nil
}

// DeactivateAPIKey deactivates an API key
func (s *service) DeactivateAPIKey(ctx context.Context, keyID xid.ID, reason string, opts *DeactivateOptions) error {
	if opts == nil {
		opts = &DeactivateOptions{}
	}

	// Get existing API key
	existingKey, err := s.GetAPIKey(ctx, keyID, &GetOptions{
		UserID:         opts.UserID,
		OrganizationID: opts.OrganizationID,
	})
	if err != nil {
		return err
	}

	if !existingKey.Active {
		return errors.New(errors.CodeBadRequest, "API key is already inactive")
	}

	// Update API key
	if err := s.repo.APIKey().SetActive(ctx, keyID, false); err != nil {
		s.logger.Error("Failed to deactivate API key", logging.Error(err))
		return errors.New(errors.CodeInternalServer, "failed to deactivate API key")
	}

	// Log the deactivation
	if err := s.logAPIKeyEvent(ctx, keyID, "api_key_deactivated", nil); err != nil {
		s.logger.Warn("Failed to log API key deactivation", logging.Error(err))
	}

	// Audit the action
	if !opts.SkipAudit && s.auditService != nil {
		auditReq := audit.AuditEvent{
			OrganizationID: opts.OrganizationID,
			UserID:         opts.UserID,
			Action:         "apikey.deactivate",
			Resource:       "apikey",
			ResourceID:     &keyID,
			Status:         "success",
			Details: map[string]interface{}{
				"name":   existingKey.Name,
				"reason": reason,
			},
			RiskLevel: "medium",
			Tags:      []string{"apikey", "security", "deactivation"},
		}

		if err := s.auditService.LogEvent(ctx, auditReq); err != nil {
			s.logger.Warn("failed to create audit log", logging.Error(err))
		}
	}

	s.logger.Info("API key deactivated successfully",
		logging.String("keyId", keyID.String()),
		logging.String("reason", reason),
	)

	return nil
}

// ActivateAPIKey activates an API key
func (s *service) ActivateAPIKey(ctx context.Context, keyID xid.ID, opts *ActivateOptions) error {
	if opts == nil {
		opts = &ActivateOptions{}
	}

	// Get existing API key
	existingKey, err := s.GetAPIKey(ctx, keyID, &GetOptions{
		UserID:         opts.UserID,
		OrganizationID: opts.OrganizationID,
	})
	if err != nil {
		return err
	}

	if existingKey.Active {
		return errors.New(errors.CodeBadRequest, "API key is already active")
	}

	// Check if key is expired
	if existingKey.ExpiresAt != nil && existingKey.ExpiresAt.Before(time.Now()) {
		return errors.New(errors.CodeBadRequest, "Cannot activate expired API key")
	}

	// Update API key
	if err := s.repo.APIKey().SetActive(ctx, keyID, true); err != nil {
		s.logger.Error("Failed to activate API key", logging.Error(err))
		return errors.New(errors.CodeInternalServer, "failed to activate API key")
	}

	// Audit the action
	if !opts.SkipAudit && s.auditService != nil {
		auditReq := audit.AuditEvent{
			OrganizationID: opts.OrganizationID,
			UserID:         opts.UserID,
			Action:         "apikey.activate",
			Resource:       "apikey",
			ResourceID:     &keyID,
			Status:         "success",
			Details: map[string]interface{}{
				"name": existingKey.Name,
			},
			RiskLevel: "medium",
			Tags:      []string{"apikey", "security", "activation"},
		}

		if err := s.auditService.LogEvent(ctx, auditReq); err != nil {
			s.logger.Warn("failed to create audit log", logging.Error(err))
		}
	}

	s.logger.Info("API key activated successfully",
		logging.String("keyId", keyID.String()),
	)

	// Log the activation
	if err := s.logAPIKeyEvent(ctx, keyID, "api_key_activated", nil); err != nil {
		s.logger.Warn("Failed to log API key activation", logging.Error(err))
	}

	return nil
}

// BulkAPIKeyOperation performs bulk operations on API keys
func (s *service) BulkAPIKeyOperation(ctx context.Context, req *model.BulkAPIKeyOperationRequest, opts *BulkOptions) (*model.BulkAPIKeyOperationResponse, error) {
	if opts == nil {
		opts = &BulkOptions{}
	}

	if len(req.KeyIDs) == 0 {
		return nil, errors.New(errors.CodeBadRequest, "no API key IDs provided")
	}

	response := &model.BulkAPIKeyOperationResponse{
		Success: make([]xid.ID, 0),
		Failed:  make([]xid.ID, 0),
		Errors:  make([]string, 0),
	}

	for _, keyID := range req.KeyIDs {
		var err error

		switch req.Operation {
		case "activate":
			err = s.ActivateAPIKey(ctx, keyID, &ActivateOptions{
				UserID:         opts.UserID,
				OrganizationID: opts.OrganizationID,
				SkipAudit:      true, // We'll audit the bulk operation
			})
		case "deactivate":
			err = s.DeactivateAPIKey(ctx, keyID, req.Reason, &DeactivateOptions{
				UserID:         opts.UserID,
				OrganizationID: opts.OrganizationID,
				SkipAudit:      true, // We'll audit the bulk operation
			})
		case "delete":
			err = s.DeleteAPIKey(ctx, keyID, &DeleteOptions{
				UserID:         opts.UserID,
				OrganizationID: opts.OrganizationID,
				SkipAudit:      true, // We'll audit the bulk operation
				Reason:         req.Reason,
			})
		case "extend":
			if req.ExpiresAt == nil {
				err = errors.New(errors.CodeBadRequest, "expires_at is required for extend operation")
			} else {
				_, err = s.UpdateAPIKey(ctx, keyID, &model.UpdateAPIKeyRequest{
					ExpiresAt: req.ExpiresAt,
				})
			}
		default:
			err = errors.New(errors.CodeBadRequest, "invalid operation: %s", req.Operation)
		}

		if err != nil {
			response.Failed = append(response.Failed, keyID)
			response.Errors = append(response.Errors, err.Error())
		} else {
			response.Success = append(response.Success, keyID)
		}
	}

	response.SuccessCount = len(response.Success)
	response.FailureCount = len(response.Failed)

	// Audit the bulk operation
	if !opts.SkipAudit && s.auditService != nil {
		auditReq := audit.AuditEvent{
			OrganizationID: opts.OrganizationID,
			UserID:         opts.UserID,
			Action:         fmt.Sprintf("apikey.bulk_%s", req.Operation),
			Resource:       "apikey",
			Status:         "success",
			Details: map[string]interface{}{
				"operation":     req.Operation,
				"total_keys":    len(req.KeyIDs),
				"success_count": response.SuccessCount,
				"failure_count": response.FailureCount,
				"reason":        req.Reason,
			},
			RiskLevel: "high",
			Tags:      []string{"apikey", "bulk", "security"},
		}

		if err := s.auditService.LogEvent(ctx, auditReq); err != nil {
			s.logger.Warn("failed to create audit log", logging.Error(err))
		}
	}

	// Log bulk operation
	if err := s.logAPIKeyEvent(ctx, xid.ID{}, "bulk_api_key_operation", map[string]interface{}{
		"operation":  req.Operation,
		"total_keys": len(req.KeyIDs),
		"successful": response.SuccessCount,
		"failed":     response.FailureCount,
		"reason":     req.Reason,
	}); err != nil {
		s.logger.Warn("Failed to log bulk operation", logging.Error(err))
	}

	return response, nil
}

// GetAPIKeyStats returns statistics about API keys
func (s *service) GetAPIKeyStats(ctx context.Context, organizationID *xid.ID) (*model.APIKeyStats, error) {
	// Get basic API key counts from repository
	stats := &model.APIKeyStats{
		KeysByType:   make(map[model.APIKeyType]int),
		TopEndpoints: []model.EndpointUsage{},
	}

	// Get API key counts
	listReq := &model.APIKeyListRequest{
		PaginationParams: model.PaginationParams{
			Limit: 1000, // Get a large number to count properly
		},
	}
	if organizationID != nil {
		listReq.OrganizationID = model.OptionalParam[xid.ID]{Value: *organizationID, IsSet: true}
	}

	apiKeys, err := s.ListAPIKeys(ctx, listReq)
	if err != nil {
		s.logger.Error("Failed to list API keys for stats", logging.Error(err))
		return nil, errors.New(errors.CodeInternalServer, "failed to get API key stats")
	}

	// Process API key counts
	stats.TotalKeys = len(apiKeys.Data)
	expiredCount := 0
	keysByType := make(map[model.APIKeyType]int)
	uniqueUsers := make(map[xid.ID]bool)

	for _, key := range apiKeys.Data {
		if key.Active {
			stats.ActiveKeys++
		}

		if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
			expiredCount++
		}

		keysByType[key.Type]++

		// Track unique users (if this is a user-scoped key)
		// Note: This is a simplified version - in the real implementation,
		// you'd need to get the full API key details to access UserID
	}

	stats.ExpiredKeys = expiredCount
	stats.KeysByType = keysByType
	stats.UniqueUsers = len(uniqueUsers)

	// Get activity statistics using the generic activity service
	activityStatsReq := &activity.ActivityStatsRequest{
		ResourceType:   "api_key",
		OrganizationID: organizationID,
		StartDate:      func() *time.Time { t := time.Now().AddDate(0, 0, -30); return &t }(), // Last 30 days
	}

	activityStats, err := s.activityService.GetActivityStats(ctx, activityStatsReq)
	if err != nil {
		s.logger.Warn("Failed to get activity stats", logging.Error(err))
		// Don't fail the whole request - just return basic stats
		return stats, nil
	}

	// Populate activity-based statistics
	stats.TotalRequests = activityStats.TotalActivities
	stats.AverageSuccessRate = activityStats.SuccessRate
	stats.ErrorRate = 100 - activityStats.SuccessRate

	// Get time-based request counts
	now := time.Now()
	today := now.Truncate(24 * time.Hour)
	weekStart := today.AddDate(0, 0, -int(today.Weekday()))
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())

	// Get requests for different time periods
	todayStats, err := s.activityService.GetActivityStats(ctx, &activity.ActivityStatsRequest{
		ResourceType:   "api_key",
		OrganizationID: organizationID,
		StartDate:      &today,
	})
	if err == nil {
		stats.RequestsToday = todayStats.TotalActivities
	}

	weekStats, err := s.activityService.GetActivityStats(ctx, &activity.ActivityStatsRequest{
		ResourceType:   "api_key",
		OrganizationID: organizationID,
		StartDate:      &weekStart,
	})
	if err == nil {
		stats.RequestsWeek = weekStats.TotalActivities
	}

	monthStats, err := s.activityService.GetActivityStats(ctx, &activity.ActivityStatsRequest{
		ResourceType:   "api_key",
		OrganizationID: organizationID,
		StartDate:      &monthStart,
	})
	if err == nil {
		stats.RequestsMonth = monthStats.TotalActivities
	}

	// Get top endpoints from activity stats
	stats.TopEndpoints = make([]model.EndpointUsage, len(activityStats.TopEndpoints))
	for i, endpoint := range activityStats.TopEndpoints {
		stats.TopEndpoints[i] = model.EndpointUsage{
			Endpoint:        endpoint.Endpoint,
			Method:          endpoint.Method,
			RequestCount:    endpoint.RequestCount,
			SuccessRate:     endpoint.SuccessRate,
			AvgResponseTime: int(endpoint.AvgResponseTime),
		}
	}

	// Get keys created this week/month
	weeklyKeys := 0
	monthlyKeys := 0
	for _, key := range apiKeys.Data {
		if key.CreatedAt.After(weekStart) {
			weeklyKeys++
		}
		if key.CreatedAt.After(monthStart) {
			monthlyKeys++
		}
	}
	stats.KeysCreatedWeek = weeklyKeys
	stats.KeysCreatedMonth = monthlyKeys

	return stats, nil
}

// RecordAPIKeyUsage records API key usage for analytics
func (s *service) RecordAPIKeyUsage(ctx context.Context, keyID xid.ID, endpoint, method string, statusCode int, responseTime int) error {
	// Get API key for additional context
	apiKey, err := s.GetAPIKey(ctx, keyID, nil)
	if err != nil {
		s.logger.Warn("Failed to get API key for usage recording",
			logging.String("key_id", keyID.String()),
			logging.Error(err))
		// Don't return error - usage recording shouldn't fail the main operation
	}

	ipAddress, _ := contexts2.GetIPAddressFromContext(ctx)
	userAgent, _ := contexts2.GetUserAgentFromContext(ctx)

	// Record using generic activity service
	return s.activityService.RecordAPIActivity(ctx, &activity.APIActivityRecord{
		KeyID:        keyID,
		Endpoint:     endpoint,
		Method:       method,
		StatusCode:   statusCode,
		ResponseTime: responseTime,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		Success:      statusCode >= 200 && statusCode < 300,
		Timestamp:    time.Now(),
		// Add additional context if API key was retrieved
		UserID: func() *xid.ID {
			if apiKey != nil {
				return &apiKey.UserID
			}
			return nil
		}(),
		OrganizationID: func() *xid.ID {
			if apiKey != nil {
				return &apiKey.OrganizationID
			}
			return nil
		}(),
	})
}

// GetAPIKeyUsage retrieves usage statistics for an API key
func (s *service) GetAPIKeyUsage(ctx context.Context, keyID xid.ID) (*model.APIKeyUsage, error) {
	return s.getAPIKeyUsage(ctx, keyID)
}

// GetAPIKeyActivity returns activity for API keys
func (s *service) GetAPIKeyActivity(ctx context.Context, req *model.APIKeyActivityRequest) (*model.APIKeyActivityResponse, error) {
	// Convert API key activity request to generic activity request
	activityReq := &activity.GetActivitiesRequest{
		PaginationParams: req.PaginationParams,
		ResourceType:     "api_key",
		Action:           req.Action,
	}

	// Set resource ID if specific key is requested
	if req.KeyID.IsSet {
		activityReq.ResourceID = &req.KeyID.Value
	}

	if req.EndDate.IsSet {
		activityReq.EndDate = &req.EndDate.Value
	}

	if req.StartDate.IsSet {
		activityReq.StartDate = &req.StartDate.Value
	}

	if req.Success.IsSet {
		activityReq.Success = &req.Success.Value
	}

	// Set endpoint filter if specified
	if req.Endpoint != "" {
		activityReq.Endpoint = req.Endpoint
	}

	// Set method filter if specified
	if req.Method != "" {
		activityReq.Method = req.Method
	}

	// Set status code filter if specified
	if req.StatusCode != 0 {
		activityReq.StatusCode = req.StatusCode
	}

	// Set IP address filter if specified
	if req.IPAddress != "" {
		activityReq.IPAddress = req.IPAddress
	}

	// Get activities from generic service
	result, err := s.activityService.GetActivities(ctx, activityReq)
	if err != nil {
		s.logger.Error("Failed to get API key activities", logging.Error(err))
		return nil, errors.New(errors.CodeInternalServer, "failed to get API key activities")
	}

	// Convert generic activities to API key activities
	activities := make([]model.APIKeyActivity, len(result.Data))
	for i, genericActivity := range result.Data {
		activities[i] = model.APIKeyActivity{
			ID:           genericActivity.ID,
			KeyID:        genericActivity.ResourceID,
			Action:       genericActivity.Action,
			Endpoint:     genericActivity.Endpoint,
			Method:       genericActivity.Method,
			StatusCode:   genericActivity.StatusCode,
			ResponseTime: genericActivity.ResponseTime,
			IPAddress:    genericActivity.IPAddress,
			UserAgent:    genericActivity.UserAgent,
			Success:      genericActivity.Success,
			Error:        genericActivity.Error,
			Timestamp:    genericActivity.Timestamp,
			Metadata:     genericActivity.Metadata,
		}
	}

	return &model.APIKeyActivityResponse{
		Data:       activities,
		Pagination: result.Pagination,
	}, nil
}

// ExportAPIKeyData exports API key data
func (s *service) ExportAPIKeyData(ctx context.Context, req *model.APIKeyExportRequest, opts *ExportOptions) (*model.APIKeyExportResponse, error) {
	s.logger.Info("Exporting API keys", logging.String("format", req.Format))

	// Create export job
	exportID := xid.New()
	downloadURL := fmt.Sprintf("/api/v1/exports/%s", exportID.String())

	// Start export process (implementation would depend on your export system)
	// For now, return a mock response
	return &model.APIKeyExportResponse{
		ExportID:    exportID,
		Status:      "processing",
		DownloadURL: downloadURL,
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		Format:      req.Format,
		KeyCount:    len(req.KeyIDs),
	}, nil
}

// CheckRateLimit checks if API key is within rate limits
func (s *service) CheckRateLimit(ctx context.Context, keyID xid.ID, endpoint string) (*model.RateLimitInfo, error) {
	// Implementation would depend on your rate limiting system (Redis, etc.)
	// For now, return a mock response
	return &model.RateLimitInfo{
		Limit:     100,
		Remaining: 85,
		Reset:     int(time.Now().Add(time.Hour).Unix()),
		Window:    3600,
	}, nil
}

// UpdateRateLimit updates rate limit counters
func (s *service) UpdateRateLimit(ctx context.Context, keyID xid.ID, endpoint string) error {
	// Implementation would update rate limit counters
	// This would typically use Redis or similar
	return nil
}

// generateAPIKey generates a new API key
func (s *service) generateAPIKey(keyType string) (string, error) {
	// Generate random bytes
	bytes := make([]byte, KeyLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %v", err)
	}

	// Encode to hex
	key := APIKeyPrefix + hex.EncodeToString(bytes)

	return key, nil
}

// CheckAPIKeyPermissions checks if an API key has the required permissions
func (s *service) CheckAPIKeyPermissions(ctx context.Context, keyID xid.ID, requiredPermissions []string) error {
	apiKey, err := s.GetAPIKey(ctx, keyID, &GetOptions{})
	if err != nil {
		return err
	}

	if !apiKey.Active {
		return errors.New(errors.CodeForbidden, "API key is inactive")
	}

	// Check if key is expired
	if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(time.Now()) {
		return errors.New(errors.CodeForbidden, "API key is expired")
	}

	// Check permissions
	apiKeyPermMap := make(map[string]bool)
	for _, granted := range apiKey.Permissions {
		apiKeyPermMap[granted] = true
	}

	var missingPermissions []string
	for _, required := range requiredPermissions {
		if !apiKeyPermMap[required] {
			missingPermissions = append(missingPermissions, required)
		}
	}

	if len(missingPermissions) > 0 {
		return errors.Newf(errors.CodeForbidden, "insufficient permissions: missing %v", missingPermissions)
	}

	return nil
}

// getContextInfo extracts user and organization info from context
func (s *service) getContextInfo(ctx context.Context) (*xid.ID, *xid.ID, error) {
	userId := contexts2.GetUserIDFromContext(ctx)
	orgId := contexts.GetOrganizationIDFromContext(ctx)
	if userId == nil || orgId == nil {
		return nil, nil, errors.New(errors.CodeUnauthorized, "user and organization not found in context")
	}
	return userId, orgId, nil
}

// logAPIKeyEvent logs an API key event for audit purposes
func (s *service) logAPIKeyEvent(ctx context.Context, keyID xid.ID, action string, details map[string]interface{}) error {
	// Get user and organization context
	userID, organizationID, err := s.getContextInfo(ctx)
	if err != nil {
		s.logger.Warn("Failed to get context for audit logging", logging.Error(err))
		return nil
	}

	activityRecord := &activity.ActivityRecord{
		ID:             xid.New(),
		ResourceType:   "api_key",
		ResourceID:     keyID,
		UserID:         userID,
		OrganizationID: organizationID,
		Action:         action,
		Category:       "audit", // Mark as audit category
		Source:         "system",
		Success:        true,
		Timestamp:      time.Now(),
		Metadata:       details,
		Tags:           []string{"audit", "api_key", "security"},
		// Set longer expiration for audit activities (2 years for compliance)
		ExpiresAt: func() *time.Time { t := time.Now().AddDate(2, 0, 0); return &t }(),
	}

	return s.activityService.RecordActivity(ctx, activityRecord)
}

// updateLastUsed updates the last used timestamp for an API key
func (s *service) updateLastUsed(ctx context.Context, keyID xid.ID) error {
	return s.repo.APIKey().UpdateLastUsed(ctx, keyID)
}

type endpointMetrics struct {
	Endpoint          string
	Method            string
	RequestCount      int
	SuccessCount      int
	TotalResponseTime int64
	ResponseTimeCount int
}

// getAPIKeyUsage retrieves usage statistics for an API key
func (s *service) getAPIKeyUsage(ctx context.Context, keyID xid.ID) (*model.APIKeyUsage, error) {
	// Get activities for this API key
	activities, err := s.activityService.GetResourceActivities(ctx, "api_key", keyID, &activity.ActivityQueryOptions{
		Limit: 10000, // Get a large number for accurate statistics
	})
	if err != nil {
		s.logger.Error("Failed to get API key activities", logging.Error(err))
		return nil, errors.New(errors.CodeInternalServer, "failed to get API key activities")
	}

	// Calculate usage statistics
	usage := &model.APIKeyUsage{
		TotalRequests:    len(activities),
		PopularEndpoints: []model.EndpointUsage{},
		ErrorsByCode:     make(map[string]int),
	}

	if len(activities) == 0 {
		return usage, nil
	}

	// Process activities for statistics
	var successfulRequests int
	var totalResponseTime int64
	var responseTimeCount int
	endpointStats := make(map[string]*endpointMetrics)
	errorsByCode := make(map[string]int)

	// Time periods for filtering
	now := time.Now()
	today := now.Truncate(24 * time.Hour)
	weekStart := today.AddDate(0, 0, -int(today.Weekday()))
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())

	for _, act := range activities {
		// Count successful requests
		if act.Success {
			successfulRequests++
		} else {
			// Count errors by status code
			if act.StatusCode > 0 {
				errorsByCode[fmt.Sprintf("%d", act.StatusCode)]++
			}
		}

		// Track response times
		if act.ResponseTime > 0 {
			totalResponseTime += int64(act.ResponseTime)
			responseTimeCount++
		}

		// Track endpoint usage
		if act.Endpoint != "" {
			key := fmt.Sprintf("%s:%s", act.Method, act.Endpoint)
			if endpointStats[key] == nil {
				endpointStats[key] = &endpointMetrics{
					Endpoint: act.Endpoint,
					Method:   act.Method,
				}
			}
			endpointStats[key].RequestCount++
			if act.Success {
				endpointStats[key].SuccessCount++
			}
			if act.ResponseTime > 0 {
				endpointStats[key].TotalResponseTime += int64(act.ResponseTime)
				endpointStats[key].ResponseTimeCount++
			}
		}

		// Count requests by time period
		if act.Timestamp.After(today) {
			usage.RequestsToday++
		}
		if act.Timestamp.After(weekStart) {
			usage.RequestsWeek++
		}
		if act.Timestamp.After(monthStart) {
			usage.RequestsMonth++
		}

		// Track last used
		if usage.LastUsed == nil || act.Timestamp.After(*usage.LastUsed) {
			usage.LastUsed = &act.Timestamp
		}
	}

	// Calculate derived statistics
	usage.SuccessfulRequests = successfulRequests
	usage.ErrorRequests = usage.TotalRequests - successfulRequests

	if usage.TotalRequests > 0 {
		usage.SuccessRate = float64(successfulRequests) / float64(usage.TotalRequests) * 100
	}

	// Convert endpoint stats to popular endpoints (top 5)
	type endpointWithStats struct {
		stats model.EndpointUsage
		count int
	}

	var endpointList []endpointWithStats
	for _, metrics := range endpointStats {
		successRate := float64(0)
		if metrics.RequestCount > 0 {
			successRate = float64(metrics.SuccessCount) / float64(metrics.RequestCount) * 100
		}

		avgResponseTime := 0
		if metrics.ResponseTimeCount > 0 {
			avgResponseTime = int(metrics.TotalResponseTime / int64(metrics.ResponseTimeCount))
		}

		endpointList = append(endpointList, endpointWithStats{
			stats: model.EndpointUsage{
				Endpoint:        metrics.Endpoint,
				Method:          metrics.Method,
				RequestCount:    metrics.RequestCount,
				SuccessRate:     successRate,
				AvgResponseTime: avgResponseTime,
			},
			count: metrics.RequestCount,
		})
	}

	// Sort by request count and take top 5
	// Simple bubble sort for small datasets
	for i := 0; i < len(endpointList); i++ {
		for j := i + 1; j < len(endpointList); j++ {
			if endpointList[i].count < endpointList[j].count {
				endpointList[i], endpointList[j] = endpointList[j], endpointList[i]
			}
		}
	}

	// Take top 5 endpoints
	maxEndpoints := 5
	if len(endpointList) < maxEndpoints {
		maxEndpoints = len(endpointList)
	}

	for i := 0; i < maxEndpoints; i++ {
		usage.PopularEndpoints = append(usage.PopularEndpoints, endpointList[i].stats)
	}

	usage.ErrorsByCode = errorsByCode

	return usage, nil
}

// getRateLimitInfo gets current rate limit information for an API key
func (s *service) getRateLimitInfo(ctx context.Context, keyID xid.ID, limits *model.APIKeyRateLimits) *model.RateLimitInfo {
	if limits == nil {
		return nil
	}

	// This would typically check current usage against Redis or similar
	// For now, return a placeholder
	return &model.RateLimitInfo{
		Limit:     limits.RequestsPerMinute,
		Remaining: limits.RequestsPerMinute - 10, // Placeholder
		Reset:     int(time.Now().Add(time.Minute).Unix()),
		Window:    60,
	}
}

func convertEntToApiKeyDTO(key *ent.ApiKey) *model.APIKey {

	newKey := &model.APIKey{
		Base: model.Base{
			ID:        key.ID,
			CreatedAt: key.CreatedAt,
			UpdatedAt: key.UpdatedAt,
		},
		Name:            key.Name,
		PublicKey:       key.PublicKey,
		SecretKey:       key.SecretKey,
		HashedSecretKey: key.HashedSecretKey,
		Type:            key.Type,
		Environment:     key.Environment,
		Active:          key.Active,
		Permissions:     key.Permissions,
		Scopes:          key.Scopes,
		Metadata:        key.Metadata,
		ExpiresAt:       key.ExpiresAt,
		IPWhitelist:     key.IPWhitelist,
		LastUsed:        key.LastUsed,

		// Legacy support
		Key:       key.Key,
		HashedKey: key.HashedKey,

		RateLimits: &key.RateLimits,
	}

	if !key.OrganizationID.IsNil() {
		newKey.OrganizationID = key.OrganizationID
	}
	if !key.UserID.IsNil() {
		newKey.UserID = key.UserID
	}

	// Handle relationships
	if key.Edges.User != nil {
		newKey.User = &model.UserSummary{
			ID:              key.Edges.User.ID,
			Email:           key.Edges.User.Email,
			FirstName:       key.Edges.User.FirstName,
			LastName:        key.Edges.User.LastName,
			ProfileImageURL: key.Edges.User.ProfileImageURL,
		}
	}

	if key.Edges.Organization != nil {
		newKey.Organization = &model.OrganizationSummary{
			ID:   key.Edges.Organization.ID,
			Name: key.Edges.Organization.Name,
			Slug: key.Edges.Organization.Slug,
		}
	}

	return newKey
}
