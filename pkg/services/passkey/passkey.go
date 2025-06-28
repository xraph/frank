package passkey

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/xid"
	"github
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/internal/repository"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
	"github.com/rs/xid"
)

// Service defines the interface for passkey operations
type Service interface {
	// Registration operations
	BeginRegistration(ctx context.Context, req model.PasskeyRegistrationBeginRequest) (*model.PasskeyRegistrationBeginResponse, error)
	FinishRegistration(ctx context.Context, req model.PasskeyRegistrationFinishRequest) (*model.PasskeyRegistrationFinishResponse, error)

	// Authentication operations
	BeginAuthentication(ctx context.Context, req model.PasskeyAuthenticationBeginRequest) (*model.PasskeyAuthenticationBeginResponse, error)
	FinishAuthentication(ctx context.Context, req model.PasskeyAuthenticationFinishRequest) (*model.PasskeyAuthenticationFinishResponse, error)

	// Management operations
	CreatePasskey(ctx context.Context, userID xid.ID, req model.CreatePasskeyRequest) (*model.Passkey, error)
	GetPasskey(ctx context.Context, id xid.ID) (*model.Passkey, error)
	UpdatePasskey(ctx context.Context, id xid.ID, req model.UpdatePasskeyRequest) (*model.Passkey, error)
	DeletePasskey(ctx context.Context, id xid.ID) error
	ListPasskeys(ctx context.Context, req model.PasskeyListRequest) (*model.PasskeyListResponse, error)

	// User passkey operations
	GetUserPasskeys(ctx context.Context, userID xid.ID, activeOnly bool) ([]*model.PasskeySummary, error)
	DeactivateUserPasskeys(ctx context.Context, userID xid.ID) error
	BulkDeletePasskeys(ctx context.Context, req model.BulkDeletePasskeysRequest) (*model.BulkDeletePasskeysResponse, error)

	// Verification and validation
	VerifyPasskey(ctx context.Context, req model.PasskeyVerificationRequest) (*model.PasskeyVerificationResponse, error)
	ValidateCredentialID(ctx context.Context, credentialID string) (*model.Passkey, error)

	// Analytics and reporting
	GetPasskeyStats(ctx context.Context, userID *xid.ID) (*model.PasskeyStats, error)
	GetPasskeyActivity(ctx context.Context, req model.PasskeyActivityRequest) (*model.PasskeyActivityResponse, error)
	ExportPasskeyData(ctx context.Context, req model.PasskeyExportRequest) (*model.PasskeyExportResponse, error)

	// Discovery and capability
	DiscoverPasskeys(ctx context.Context, req model.PasskeyDiscoveryRequest) (*model.PasskeyDiscoveryResponse, error)
	UpdateBackupState(ctx context.Context, req model.PasskeyBackupRequest) (*model.PasskeyBackupResponse, error)

	// Maintenance operations
	CleanupUnusedPasskeys(ctx context.Context, days int) (int, error)
	GetUnusedPasskeys(ctx context.Context, userID xid.ID, days int) ([]*model.PasskeySummary, error)
}

// service implements the Service interface
type service struct {
	repo     repository.PasskeyRepository
	userRepo repository.UserRepository
	webauthn WebAuthnService
	logger   logging.Logger
}

// NewService creates a new passkey service
func NewService(
	repo repository.PasskeyRepository,
	userRepo repository.UserRepository,
	webauthn WebAuthnService,
	logger logging.Logger,
) Service {
	return &service{
		repo:     repo,
		userRepo: userRepo,
		webauthn: webauthn,
		logger:   logger.Named("passkey"),
	}
}

// BeginRegistration starts the passkey registration process
func (s *service) BeginRegistration(ctx context.Context, req model.PasskeyRegistrationBeginRequest) (*model.PasskeyRegistrationBeginResponse, error) {
	s.logger.Debug("Beginning passkey registration", logging.String("username", req.Username))

	// Create WebAuthn registration options
	options, sessionData, err := s.webauthn.BeginRegistration(ctx, WebAuthnBeginRegistrationRequest{
		Username:           req.Username,
		DisplayName:        req.DisplayName,
		RequireResidentKey: req.RequireResidentKey,
		UserVerification:   req.UserVerification,
		AttestationType:    req.AttestationType,
		AuthenticatorType:  req.AuthenticatorType,
	})
	if err != nil {
		s.logger.Error("Failed to begin WebAuthn registration", logging.Error(err))
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to begin passkey registration")
	}

	return &model.PasskeyRegistrationBeginResponse{
		Options:   options,
		Challenge: sessionData.Challenge,
		SessionID: sessionData.SessionID,
		ExpiresAt: sessionData.ExpiresAt,
	}, nil
}

// FinishRegistration completes the passkey registration process
func (s *service) FinishRegistration(ctx context.Context, req model.PasskeyRegistrationFinishRequest) (*model.PasskeyRegistrationFinishResponse, error) {
	s.logger.Debug("Finishing passkey registration", logging.String("sessionId", req.SessionID))

	// Complete WebAuthn registration
	credential, err := s.webauthn.FinishRegistration(ctx, WebAuthnFinishRegistrationRequest{
		SessionID: req.SessionID,
		Response:  req.Response,
	})
	if err != nil {
		s.logger.Error("Failed to finish WebAuthn registration", logging.Error(err))
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to finish passkey registration")
	}

	// Get user from the credential (this would be stored during BeginRegistration)
	userID, err := s.getUserFromSession(ctx, req.SessionID)
	if err != nil {
		return nil, err
	}

	// Create passkey record
	passkey, err := s.CreatePasskey(ctx, userID, model.CreatePasskeyRequest{
		Name:           req.Name,
		CredentialID:   credential.CredentialID,
		PublicKey:      credential.PublicKey,
		DeviceType:     &credential.DeviceType,
		AAGUID:         &credential.AAGUID,
		Transports:     credential.Transports,
		Attestation:    credential.Attestation,
		BackupEligible: credential.BackupEligible,
		BackupState:    credential.BackupState,
	})
	if err != nil {
		return nil, err
	}

	s.logger.Info("Passkey registration completed successfully",
		logging.String("userId", userID.String()),
		logging.String("passkeyId", passkey.ID.String()))

	return &model.PasskeyRegistrationFinishResponse{
		Success: true,
		Passkey: *passkey,
		Message: "Passkey registered successfully",
	}, nil
}

// BeginAuthentication starts the passkey authentication process
func (s *service) BeginAuthentication(ctx context.Context, req model.PasskeyAuthenticationBeginRequest) (*model.PasskeyAuthenticationBeginResponse, error) {
	s.logger.Debug("Beginning passkey authentication", logging.String("username", req.Username))

	// Get user passkeys if username provided
	var allowCredentials []string
	if req.Username != "" {
		user, err := s.userRepo.GetByEmail(ctx, req.Username, "", nil) // Get any user type for auth
		if err != nil {
			if !errors.IsNotFound(err) {
				return nil, err
			}
			// User not found, continue with empty credentials (for privacy)
		} else {
			passkeys, err := s.repo.GetActivePasskeys(ctx, user.ID)
			if err != nil {
				return nil, err
			}

			for _, pk := range passkeys {
				allowCredentials = append(allowCredentials, pk.CredentialID)
			}
		}
	}

	// Create WebAuthn authentication options
	options, sessionData, err := s.webauthn.BeginAuthentication(ctx, WebAuthnBeginAuthenticationRequest{
		Username:         req.Username,
		AllowCredentials: allowCredentials,
		UserVerification: req.UserVerification,
	})
	if err != nil {
		s.logger.Error("Failed to begin WebAuthn authentication", logging.Error(err))
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to begin passkey authentication")
	}

	return &model.PasskeyAuthenticationBeginResponse{
		Options:   options,
		Challenge: sessionData.Challenge,
		SessionID: sessionData.SessionID,
		ExpiresAt: sessionData.ExpiresAt,
	}, nil
}

// FinishAuthentication completes the passkey authentication process
func (s *service) FinishAuthentication(ctx context.Context, req model.PasskeyAuthenticationFinishRequest) (*model.PasskeyAuthenticationFinishResponse, error) {
	s.logger.Debug("Finishing passkey authentication", logging.String("sessionId", req.SessionID))

	// Complete WebAuthn authentication
	result, err := s.webauthn.FinishAuthentication(ctx, WebAuthnFinishAuthenticationRequest{
		SessionID: req.SessionID,
		Response:  req.Response,
	})
	if err != nil {
		s.logger.Error("Failed to finish WebAuthn authentication", logging.Error(err))
		return nil, errors.Wrap(err, errors.CodeUnauthorized, "passkey authentication failed")
	}

	// Get passkey and user
	passkey, err := s.repo.GetByCredentialID(ctx, result.CredentialID)
	if err != nil {
		return nil, err
	}

	user, err := s.userRepo.GetByID(ctx, passkey.UserID)
	if err != nil {
		return nil, err
	}

	// Update passkey usage
	err = s.repo.UpdateSignCount(ctx, result.CredentialID, result.SignCount)
	if err != nil {
		s.logger.Error("Failed to update sign count", logging.Error(err))
		// Don't fail authentication for this
	}

	err = s.repo.UpdateLastUsed(ctx, result.CredentialID)
	if err != nil {
		s.logger.Error("Failed to update last used", logging.Error(err))
		// Don't fail authentication for this
	}

	s.logger.Info("Passkey authentication completed successfully",
		logging.String("userId", user.ID.String()),
		logging.String("passkeyId", passkey.ID.String()))

	// Convert ent.User to model.User
	modelUser := s.convertEntUserToModel(user)

	return &model.PasskeyAuthenticationFinishResponse{
		Success: true,
		User:    *modelUser,
		Message: "Authentication successful",
		// AccessToken and RefreshToken would be generated by auth service
	}, nil
}

// CreatePasskey creates a new passkey
func (s *service) CreatePasskey(ctx context.Context, userID xid.ID, req model.CreatePasskeyRequest) (*model.Passkey, error) {
	s.logger.Debug("Creating passkey", logging.String("userId", userID.String()))

	// Check if credential ID already exists
	exists, err := s.repo.ExistsByCredentialID(ctx, req.CredentialID)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, errors.New(errors.CodeConflict, "passkey with this credential ID already exists")
	}

	// Create passkey
	input := repository.CreatePasskeyInput{
		UserID:         userID,
		Name:           req.Name,
		CredentialID:   req.CredentialID,
		PublicKey:      req.PublicKey,
		DeviceType:     req.DeviceType,
		AAGUID:         req.AAGUID,
		Transports:     req.Transports,
		Attestation:    req.Attestation,
		UserAgent:      req.UserAgent,
		IPAddress:      req.IPAddress,
		BackupEligible: req.BackupEligible,
		BackupState:    req.BackupState,
		Active:         true,
	}

	entPasskey, err := s.repo.Create(ctx, input)
	if err != nil {
		return nil, err
	}

	passkey := s.convertEntPasskeyToModel(entPasskey)

	s.logger.Info("Passkey created successfully",
		logging.String("passkeyId", passkey.ID.String()))

	return passkey, nil
}

// GetPasskey retrieves a passkey by ID
func (s *service) GetPasskey(ctx context.Context, id xid.ID) (*model.Passkey, error) {
	entPasskey, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	return s.convertEntPasskeyToModel(entPasskey), nil
}

// UpdatePasskey updates a passkey
func (s *service) UpdatePasskey(ctx context.Context, id xid.ID, req model.UpdatePasskeyRequest) (*model.Passkey, error) {
	s.logger.Debug("Updating passkey", logging.String("passkeyId", id.String()))

	input := repository.UpdatePasskeyInput{
		Name:   &req.Name,
		Active: &req.Active,
	}

	entPasskey, err := s.repo.Update(ctx, id, input)
	if err != nil {
		return nil, err
	}

	passkey := s.convertEntPasskeyToModel(entPasskey)

	s.logger.Info("Passkey updated successfully",
		logging.String("passkeyId", passkey.ID.String()))

	return passkey, nil
}

// DeletePasskey deletes a passkey
func (s *service) DeletePasskey(ctx context.Context, id xid.ID) error {
	s.logger.Debug("Deleting passkey", logging.String("passkeyId", id.String()))

	err := s.repo.Delete(ctx, id)
	if err != nil {
		return err
	}

	s.logger.Info("Passkey deleted successfully", logging.String("passkeyId", id.String()))
	return nil
}

// ListPasskeys lists passkeys with filtering and pagination
func (s *service) ListPasskeys(ctx context.Context, req model.PasskeyListRequest) (*model.PasskeyListResponse, error) {
	params := repository.ListPasskeysParams{
		PaginationParams: req.PaginationParams,
		DeviceType:       req.DeviceType,
		Search:           req.Search,
	}

	if req.UserID.IsSet {
		params.UserID = &req.UserID.Value
	}
	if req.Active.IsSet {
		params.Active = &req.Active.Value
	}

	result, err := s.repo.List(ctx, params)
	if err != nil {
		return nil, err
	}

	// Convert to summaries
	summaries := make([]model.PasskeySummary, len(result.Data))
	for i, entPasskey := range result.Data {
		summaries[i] = model.PasskeySummary{
			ID:          entPasskey.ID,
			Name:        entPasskey.Name,
			DeviceType:  entPasskey.DeviceType,
			Active:      entPasskey.Active,
			LastUsed:    entPasskey.LastUsed,
			CreatedAt:   entPasskey.CreatedAt,
			BackupState: entPasskey.BackupState,
			SignCount:   entPasskey.SignCount,
		}
	}

	return &model.PasskeyListResponse{
		Data:       summaries,
		Pagination: result.Pagination,
	}, nil
}

// GetUserPasskeys gets all passkeys for a user
func (s *service) GetUserPasskeys(ctx context.Context, userID xid.ID, activeOnly bool) ([]*model.PasskeySummary, error) {
	entPasskeys, err := s.repo.GetUserPasskeys(ctx, userID, activeOnly)
	if err != nil {
		return nil, err
	}

	summaries := make([]*model.PasskeySummary, len(entPasskeys))
	for i, entPasskey := range entPasskeys {
		summaries[i] = &model.PasskeySummary{
			ID:          entPasskey.ID,
			Name:        entPasskey.Name,
			DeviceType:  entPasskey.DeviceType,
			Active:      entPasskey.Active,
			LastUsed:    entPasskey.LastUsed,
			CreatedAt:   entPasskey.CreatedAt,
			BackupState: entPasskey.BackupState,
			SignCount:   entPasskey.SignCount,
		}
	}

	return summaries, nil
}

// DeactivateUserPasskeys deactivates all passkeys for a user
func (s *service) DeactivateUserPasskeys(ctx context.Context, userID xid.ID) error {
	s.logger.Debug("Deactivating user passkeys", logging.String("userId", userID.String()))

	err := s.repo.DeactivateAllUserPasskeys(ctx, userID)
	if err != nil {
		return err
	}

	s.logger.Info("User passkeys deactivated", logging.String("userId", userID.String()))
	return nil
}

// BulkDeletePasskeys deletes multiple passkeys
func (s *service) BulkDeletePasskeys(ctx context.Context, req model.BulkDeletePasskeysRequest) (*model.BulkDeletePasskeysResponse, error) {
	s.logger.Debug("Bulk deleting passkeys", logging.Int("count", len(req.PasskeyIDs)))

	err := s.repo.BulkDelete(ctx, req.PasskeyIDs)
	if err != nil {
		return &model.BulkDeletePasskeysResponse{
			DeletedCount: 0,
			Failed:       req.PasskeyIDs,
			Errors:       []string{err.Error()},
		}, err
	}

	s.logger.Info("Bulk deleted passkeys", logging.Int("count", len(req.PasskeyIDs)))

	return &model.BulkDeletePasskeysResponse{
		DeletedCount: len(req.PasskeyIDs),
		Failed:       []xid.ID{},
		Errors:       []string{},
	}, nil
}

// VerifyPasskey verifies a passkey credential
func (s *service) VerifyPasskey(ctx context.Context, req model.PasskeyVerificationRequest) (*model.PasskeyVerificationResponse, error) {
	passkey, err := s.repo.GetByCredentialID(ctx, req.CredentialID)
	if err != nil {
		if errors.IsNotFound(err) {
			return &model.PasskeyVerificationResponse{
				Valid: false,
				Error: "Passkey not found",
			}, nil
		}
		return nil, err
	}

	if !passkey.Active {
		return &model.PasskeyVerificationResponse{
			Valid: false,
			Error: "Passkey is not active",
		}, nil
	}

	// Verify with WebAuthn service
	valid, err := s.webauthn.VerifyCredential(ctx, WebAuthnVerifyCredentialRequest{
		CredentialID: req.CredentialID,
		Challenge:    req.Challenge,
		Origin:       req.Origin,
		PublicKey:    passkey.PublicKey,
	})
	if err != nil {
		return &model.PasskeyVerificationResponse{
			Valid: false,
			Error: err.Error(),
		}, nil
	}

	if !valid {
		return &model.PasskeyVerificationResponse{
			Valid: false,
			Error: "Invalid signature",
		}, nil
	}

	// Update sign count
	newSignCount := passkey.SignCount + 1
	err = s.repo.UpdateSignCount(ctx, req.CredentialID, newSignCount)
	if err != nil {
		s.logger.Error("Failed to update sign count", logging.Error(err))
	}

	return &model.PasskeyVerificationResponse{
		Valid:     true,
		PasskeyID: passkey.ID,
		UserID:    passkey.UserID,
		SignCount: newSignCount,
	}, nil
}

// ValidateCredentialID validates a credential ID
func (s *service) ValidateCredentialID(ctx context.Context, credentialID string) (*model.Passkey, error) {
	entPasskey, err := s.repo.ValidateCredentialID(ctx, credentialID)
	if err != nil {
		return nil, err
	}

	return s.convertEntPasskeyToModel(entPasskey), nil
}

// GetPasskeyStats gets passkey statistics
func (s *service) GetPasskeyStats(ctx context.Context, userID *xid.ID) (*model.PasskeyStats, error) {
	repoStats, err := s.repo.GetPasskeyStats(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Convert repository stats to model stats
	return &model.PasskeyStats{
		TotalPasskeys:  repoStats.TotalPasskeys,
		ActivePasskeys: repoStats.ActivePasskeys,
		// PlatformPasskeys:  repoStats.PlatformPasskeys,
		// RoamingPasskeys:   repoStats.RoamingPasskeys,
		// BackedUpPasskeys:  repoStats.BackedUpPasskeys,
		// PasskeysUsedToday: repoStats.PasskeysUsedToday,
		// PasskeysUsedWeek:  repoStats.PasskeysUsedWeek,
		// PasskeysThisMonth: repoStats.PasskeysThisMonth,
		// UniqueUsers:       repoStats.UniqueUsers,
		// AveragePerUser:    repoStats.AveragePerUser,
	}, nil
}

// GetPasskeyActivity gets passkey activity logs
func (s *service) GetPasskeyActivity(ctx context.Context, req model.PasskeyActivityRequest) (*model.PasskeyActivityResponse, error) {
	// This would typically integrate with audit service
	// For now, return empty response
	return &model.PasskeyActivityResponse{
		Data: []model.PasskeyActivity{},
		Pagination: &model.Pagination{
			TotalCount:      0,
			HasNextPage:     false,
			HasPreviousPage: false,
		},
	}, nil
}

// ExportPasskeyData exports passkey data
func (s *service) ExportPasskeyData(ctx context.Context, req model.PasskeyExportRequest) (*model.PasskeyExportResponse, error) {
	// Generate export URL (this would typically be handled by a file service)
	exportURL := fmt.Sprintf("https://api.example.com/downloads/passkeys-export-%s.%s",
		xid.New().String(), req.Format)

	return &model.PasskeyExportResponse{
		DownloadURL: exportURL,
		ExpiresAt:   time.Now().Add(time.Hour),
		Format:      req.Format,
		RecordCount: 0, // Would be calculated based on actual data
	}, nil
}

// DiscoverPasskeys discovers available passkeys for a user
func (s *service) DiscoverPasskeys(ctx context.Context, req model.PasskeyDiscoveryRequest) (*model.PasskeyDiscoveryResponse, error) {
	var count int

	if req.Username != "" {
		user, err := s.userRepo.GetByEmail(ctx, req.Username, "", nil)
		if err != nil {
			if !errors.IsNotFound(err) {
				return nil, err
			}
		} else {
			hasPasskeys, err := s.repo.UserHasActivePasskeys(ctx, user.ID)
			if err != nil {
				return nil, err
			}
			if hasPasskeys {
				passkeys, err := s.repo.GetActivePasskeys(ctx, user.ID)
				if err != nil {
					return nil, err
				}
				count = len(passkeys)
			}
		}
	}

	return &model.PasskeyDiscoveryResponse{
		Available:        count > 0,
		Count:            count,
		PlatformSupport:  true, // Would check actual platform support
		RoamingSupport:   true,
		ConditionalUI:    true,
		SupportedMethods: []string{"platform", "roaming"},
	}, nil
}

// UpdateBackupState updates backup state for passkeys
func (s *service) UpdateBackupState(ctx context.Context, req model.PasskeyBackupRequest) (*model.PasskeyBackupResponse, error) {
	s.logger.Debug("Updating passkey backup state", logging.Int("count", len(req.PasskeyIDs)))

	updated := 0
	var failed []xid.ID
	var errs []string

	for _, id := range req.PasskeyIDs {
		input := repository.UpdatePasskeyInput{
			BackupState: &req.BackupState,
		}

		_, err := s.repo.Update(ctx, id, input)
		if err != nil {
			failed = append(failed, id)
			errs = append(errs, err.Error())
		} else {
			updated++
		}
	}

	return &model.PasskeyBackupResponse{
		UpdatedCount: updated,
		Failed:       failed,
		Errors:       errs,
	}, nil
}

// CleanupUnusedPasskeys removes unused passkeys
func (s *service) CleanupUnusedPasskeys(ctx context.Context, days int) (int, error) {
	s.logger.Debug("Cleaning up unused passkeys", logging.Int("days", days))

	count, err := s.repo.CleanupUnusedPasskeys(ctx, days)
	if err != nil {
		return 0, err
	}

	s.logger.Info("Cleaned up unused passkeys", logging.Int("count", count))
	return count, nil
}

// GetUnusedPasskeys gets unused passkeys for a user
func (s *service) GetUnusedPasskeys(ctx context.Context, userID xid.ID, days int) ([]*model.PasskeySummary, error) {
	entPasskeys, err := s.repo.GetUnusedPasskeys(ctx, userID, days)
	if err != nil {
		return nil, err
	}

	summaries := make([]*model.PasskeySummary, len(entPasskeys))
	for i, entPasskey := range entPasskeys {
		summaries[i] = &model.PasskeySummary{
			ID:          entPasskey.ID,
			Name:        entPasskey.Name,
			DeviceType:  entPasskey.DeviceType,
			Active:      entPasskey.Active,
			LastUsed:    entPasskeys[i].LastUsed,
			CreatedAt:   entPasskey.CreatedAt,
			BackupState: entPasskey.BackupState,
			SignCount:   entPasskey.SignCount,
		}
	}

	return summaries, nil
}

// Helper methods

func (s *service) getUserFromSession(ctx context.Context, sessionID string) (xid.ID, error) {
	// This would typically retrieve user ID from session storage
	// For now, return error indicating not implemented
	return xid.ID{}, errors.New(errors.CodeNotImplemented, "session management not implemented")
}

func (s *service) convertEntPasskeyToModel(entPasskey *ent.Passkey) *model.Passkey {
	transports := entPasskey.Transports

	attestation := entPasskey.Attestation

	return &model.Passkey{
		Base: model.Base{
			ID:        entPasskey.ID,
			CreatedAt: entPasskey.CreatedAt,
			UpdatedAt: entPasskey.UpdatedAt,
		},
		UserID:         entPasskey.UserID,
		Name:           entPasskey.Name,
		CredentialID:   entPasskey.CredentialID,
		PublicKey:      entPasskey.PublicKey,
		SignCount:      entPasskey.SignCount,
		Active:         entPasskey.Active,
		DeviceType:     entPasskey.DeviceType,
		AAGUID:         entPasskey.Aaguid,
		LastUsed:       entPasskey.LastUsed,
		Transports:     transports,
		Attestation:    attestation,
		UserAgent:      entPasskey.UserAgent,
		IPAddress:      entPasskey.IPAddress,
		BackupEligible: entPasskey.BackupEligible,
		BackupState:    entPasskey.BackupState,
	}
}

func (s *service) convertEntUserToModel(entUser *ent.User) *model.User {
	return &model.User{
		Base: model.Base{
			ID:        entUser.ID,
			CreatedAt: entUser.CreatedAt,
			UpdatedAt: entUser.UpdatedAt,
		},
		Email:         entUser.Email,
		Username:      entUser.Username,
		FirstName:     entUser.FirstName,
		LastName:      entUser.LastName,
		PhoneNumber:   entUser.PhoneNumber,
		EmailVerified: entUser.EmailVerified,
		PhoneVerified: entUser.PhoneVerified,
		Active:        entUser.Active,
		Blocked:       entUser.Blocked,
	}
}
