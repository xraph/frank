package mfa

import (
	"context"
	"time"

	"github.com/rs/xid"
	"github.co
	"github.com/xraph/frank/config"
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/internal/repository"
	"github.com/xraph/frank/pkg/data"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
	"github.com/rs/xid"
)

// Service defines the interface for MFA operations
type Service interface {
	// MFA method management
	EnableMFA(ctx context.Context, userID xid.ID, method string, config map[string]interface{}) (*model.MFA, error)
	DisableMFA(ctx context.Context, userID xid.ID, method string) error
	ListUserMFAMethods(ctx context.Context, userID xid.ID) ([]*model.MFA, error)
	GetMFAMethod(ctx context.Context, id xid.ID) (*model.MFA, error)
	UpdateMFAMethod(ctx context.Context, id xid.ID, config map[string]interface{}) (*model.MFA, error)

	// GetMFAMethodByUserAndType Get MFA method by user and type (for setup verification)
	GetMFAMethodByUserAndType(ctx context.Context, userID xid.ID, method string) (*model.MFA, error)

	// HasVerifiedMFA Check if user has any verified MFA methods
	HasVerifiedMFA(ctx context.Context, userID xid.ID) (bool, error)

	// GetUnverifiedMFAMethods Get unverified MFA methods for user
	GetUnverifiedMFAMethods(ctx context.Context, userID xid.ID) ([]*model.MFA, error)

	// TOTP operations
	SetupTOTP(ctx context.Context, userID xid.ID) (*model.TOTPSetupResponse, error)
	VerifyTOTP(ctx context.Context, userID xid.ID, code string) (*model.MFAVerifyResponse, error)
	DisableTOTP(ctx context.Context, userID xid.ID) error

	// SMS operations
	SetupSMS(ctx context.Context, userID xid.ID, input model.SetupSMSRequest) (*model.SetupSMSResponse, error)
	SendSMSCode(ctx context.Context, userID xid.ID) (*model.SMSCodeResponse, error)
	VerifySMSCode(ctx context.Context, userID xid.ID, code string) (*model.MFAVerifyResponse, error)
	DisableSMS(ctx context.Context, userID xid.ID) error

	// Email operations
	SetupEmail(ctx context.Context, userID xid.ID, email string) (*model.EmailMFASetupResponse, error)
	SendEmailCode(ctx context.Context, userID xid.ID) (*model.EmailCodeResponse, error)
	VerifyEmailCode(ctx context.Context, userID xid.ID, code string) (*model.MFAVerifyResponse, error)
	DisableEmailMFA(ctx context.Context, userID xid.ID) error

	// Backup codes
	GenerateBackupCodes(ctx context.Context, userID xid.ID, input *model.GenerateBackupCodesRequest) (*model.MFABackCodes, error)
	VerifyBackupCode(ctx context.Context, userID xid.ID, code string) (*model.MFAVerifyResponse, error)
	RegenerateBackupCodes(ctx context.Context, userID xid.ID, input *model.GenerateBackupCodesRequest) (*model.MFABackCodes, error)

	// MFA verification flow
	RequiresMFA(ctx context.Context, userID xid.ID) (bool, []string, error)
	VerifyMFA(ctx context.Context, userID xid.ID, method, code string) (*model.MFAVerifyResponse, error)

	// MFA session management
	CreateMFAChallenge(ctx context.Context, userID xid.ID) (*model.MFAChallengeResponse, error)
	ValidateMFAChallenge(ctx context.Context, challengeID string, method, code string) (*model.MFAVerifyResponse, error)

	// Recovery operations
	DisableAllMFA(ctx context.Context, userID xid.ID) error
	GetRecoveryOptions(ctx context.Context, userID xid.ID) (*model.MFARecoveryOptions, error)

	SessionStore() SessionStore
}

// Dependencies
type TOTPService interface {
	GenerateSecret(ctx context.Context, userID xid.ID, issuer, accountName string) (*model.TOTPSecret, error)
	GenerateQRCode(ctx context.Context, secret *model.TOTPSecret) ([]byte, error)
	ValidateCode(ctx context.Context, secret, code string) (bool, error)
	GetBackupCodes(ctx context.Context, userID xid.ID) ([]string, error)
	GenerateBackupCodes(ctx context.Context, userID xid.ID, count int) ([]string, error)
	ValidateBackupCode(ctx context.Context, userID xid.ID, code string) (bool, error)
}

type SMSService interface {
	SendVerificationCode(ctx context.Context, phoneNumber string, code string) error
	GenerateCode(ctx context.Context, length int) (string, error)
}

// service implements the MFA Service interface
type service struct {
	repo     repository.MFARepository
	userRepo repository.UserRepository
	totpSvc  TOTPService
	store    SessionStore
	smsSvc   SMSService
	logger   logging.Logger
}

// NewService creates a new MFA service
func NewService(
	repo repository.Repository,
	dataClient *data.Clients,
	provider sms.Provider,
	logger logging.Logger,
	cfg *config.Config,
) Service {
	totpSvc := NewTOTPService(cfg.Auth.TokenIssuer, logger)
	smsSvc := NewSMSService(provider, &cfg.SMS, logger)

	var store SessionStore
	if dataClient != nil && cfg.Redis.Enabled && dataClient.Redis != nil {
		store = NewRedisSessionStore(dataClient)
	} else {
		// Fallback to in-memory store (not recommended for production)
		store = NewInMemorySessionStore()
		logger.Warn("Using in-memory MFA session store - not recommended for production")
	}

	return &service{
		repo:     repo.MFA(),
		userRepo: repo.User(),
		totpSvc:  totpSvc,
		smsSvc:   smsSvc,
		store:    store,
		logger:   logger.Named("mfa"),
	}
}

func (s *service) SessionStore() SessionStore {
	return s.store
}

// EnableMFA enables MFA for a user with the specified method
func (s *service) EnableMFA(ctx context.Context, userID xid.ID, method string, config map[string]interface{}) (*model.MFA, error) {
	s.logger.Debug("Enabling MFA",
		logging.String("userId", userID.String()),
		logging.String("method", method))

	// Check if user exists
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Check if MFA method already exists
	existing, err := s.repo.GetByUserIDAndMethod(ctx, userID, method)
	if err != nil && !errors.IsNotFound(err) {
		return nil, err
	}
	if existing != nil {
		return nil, errors.New(errors.CodeConflict, "MFA method already enabled for user")
	}

	// Create MFA record
	input := repository.CreateMFAInput{
		UserID:   userID,
		Method:   method,
		Metadata: config,
		Active:   true,
		Verified: false,
		Secret:   config["secret"].(string),
		Email:    &user.Email,
	}

	entMFA, err := s.repo.Create(ctx, input)
	if err != nil {
		return nil, err
	}

	mfa := s.convertEntMFAToModel(entMFA)

	s.logger.Info("MFA enabled successfully",
		logging.String("userId", userID.String()),
		logging.String("method", method),
		logging.String("mfaId", mfa.ID.String()))

	return mfa, nil
}

// DisableMFA disables MFA for a user with the specified method
func (s *service) DisableMFA(ctx context.Context, userID xid.ID, method string) error {
	s.logger.Debug("Disabling MFA",
		logging.String("userId", userID.String()),
		logging.String("method", method))

	err := s.repo.DeactivateMethodByUserID(ctx, userID, method)
	if err != nil {
		return err
	}

	s.logger.Info("MFA disabled successfully",
		logging.String("userId", userID.String()),
		logging.String("method", method))

	return nil
}

// ListUserMFAMethods lists all MFA methods for a user
func (s *service) ListUserMFAMethods(ctx context.Context, userID xid.ID) ([]*model.MFA, error) {
	entMFAs, err := s.repo.ListActiveByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	mfas := make([]*model.MFA, len(entMFAs))
	for i, entMFA := range entMFAs {
		mfas[i] = s.convertEntMFAToModel(entMFA)
	}

	return mfas, nil
}

// GetMFAMethod gets an MFA method by ID
func (s *service) GetMFAMethod(ctx context.Context, id xid.ID) (*model.MFA, error) {
	entMFA, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	return s.convertEntMFAToModel(entMFA), nil
}

// UpdateMFAMethod updates an MFA method configuration
func (s *service) UpdateMFAMethod(ctx context.Context, id xid.ID, metadata map[string]interface{}) (*model.MFA, error) {
	s.logger.Debug("Updating MFA method", logging.String("mfaId", id.String()))

	input := repository.UpdateMFAInput{
		Metadata: metadata,
	}

	entMFA, err := s.repo.Update(ctx, id, input)
	if err != nil {
		return nil, err
	}

	mfa := s.convertEntMFAToModel(entMFA)

	s.logger.Info("MFA method updated successfully", logging.String("mfaId", id.String()))

	return mfa, nil
}

// SetupTOTP sets up TOTP for a user
func (s *service) SetupTOTP(ctx context.Context, userID xid.ID) (*model.TOTPSetupResponse, error) {
	s.logger.Debug("Setting up TOTP", logging.String("userId", userID.String()))

	// Get user information
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Generate TOTP secret
	secret, err := s.totpSvc.GenerateSecret(ctx, userID, "Frank Auth", user.Email)
	if err != nil {
		return nil, err
	}

	// Generate QR code
	qrCode, err := s.totpSvc.GenerateQRCode(ctx, secret)
	if err != nil {
		return nil, err
	}

	// Store TOTP configuration
	config := map[string]interface{}{
		"secret":      secret.Secret,
		"issuer":      secret.Issuer,
		"accountName": secret.AccountName,
	}

	mfa, err := s.EnableMFA(ctx, userID, "totp", config)
	if err != nil {
		return nil, err
	}

	return &model.TOTPSetupResponse{
		Secret:      secret.Secret,
		QRCode:      string(qrCode),
		BackupURL:   secret.URL,
		BackupCodes: []string{}, // Will be generated after verification
		MethodID:    mfa.ID,
	}, nil
}

// VerifyTOTP verifies a TOTP code
func (s *service) VerifyTOTP(ctx context.Context, userID xid.ID, code string) (*model.MFAVerifyResponse, error) {
	s.logger.Debug("Verifying TOTP", logging.String("userId", userID.String()))

	// Get TOTP MFA record
	mfa, err := s.repo.GetByUserIDAndMethod(ctx, userID, "totp")
	if err != nil {
		return nil, err
	}

	if !mfa.Active {
		return nil, errors.New(errors.CodeBadRequest, "TOTP is not active")
	}

	// Extract secret from config
	secret, ok := mfa.Metadata["secret"].(string)
	if !ok {
		return nil, errors.New(errors.CodeInternalServer, "invalid TOTP configuration")
	}

	// Validate code
	valid, err := s.totpSvc.ValidateCode(ctx, secret, code)
	if err != nil {
		return nil, err
	}

	if !valid {
		return &model.MFAVerifyResponse{
			Success: false,
			Method:  "totp",
			Message: "Invalid TOTP code",
		}, nil
	}

	// Mark as verified if first time
	if !mfa.Verified {
		err = s.repo.MarkAsVerified(ctx, mfa.ID)
		if err != nil {
			s.logger.Error("Failed to mark TOTP as verified", logging.Error(err))
		}
	}

	// Update last used
	err = s.repo.UpdateLastUsed(ctx, mfa.ID)
	if err != nil {
		s.logger.Error("Failed to update last used", logging.Error(err))
	}

	s.logger.Info("TOTP verified successfully", logging.String("userId", userID.String()))

	return &model.MFAVerifyResponse{
		Success: true,
		Method:  "totp",
		Message: "TOTP verification successful",
	}, nil
}

// DisableTOTP disables TOTP for a user
func (s *service) DisableTOTP(ctx context.Context, userID xid.ID) error {
	return s.DisableMFA(ctx, userID, "totp")
}

// SetupSMS sets up SMS MFA for a user
func (s *service) SetupSMS(ctx context.Context, userID xid.ID, input model.SetupSMSRequest) (*model.SetupSMSResponse, error) {
	s.logger.Debug("Setting up SMS MFA",
		logging.String("userId", userID.String()),
		logging.String("phone", input.PhoneNumber))

	// Store SMS configuration
	config := map[string]interface{}{
		"phoneNumber": input.PhoneNumber,
		"name":        input.Name,
	}

	mfa, err := s.EnableMFA(ctx, userID, "sms", config)
	if err != nil {
		return nil, err
	}

	// Send verification code
	code, err := s.smsSvc.GenerateCode(ctx, 6)
	if err != nil {
		return nil, err
	}

	err = s.smsSvc.SendVerificationCode(ctx, input.PhoneNumber, code)
	if err != nil {
		return nil, err
	}

	// Store the code temporarily (in production, use Redis with expiry)
	config["verificationCode"] = code
	config["codeExpiry"] = time.Now().Add(10 * time.Minute)

	_, err = s.UpdateMFAMethod(ctx, mfa.ID, config)
	if err != nil {
		return nil, err
	}

	return &model.SetupSMSResponse{
		PhoneNumber: input.PhoneNumber,
		Message:     "Verification code sent to your phone",
		MethodID:    mfa.ID,
	}, nil
}

// SendSMSCode sends an SMS verification code
func (s *service) SendSMSCode(ctx context.Context, userID xid.ID) (*model.SMSCodeResponse, error) {
	s.logger.Debug("Sending SMS code", logging.String("userId", userID.String()))

	// Get SMS MFA record
	mfa, err := s.repo.GetByUserIDAndMethod(ctx, userID, "sms")
	if err != nil {
		return nil, err
	}

	if !mfa.Active {
		return nil, errors.New(errors.CodeBadRequest, "SMS MFA is not active")
	}

	// Extract phone number
	phoneNumber, ok := mfa.Metadata["phoneNumber"].(string)
	if !ok {
		return nil, errors.New(errors.CodeInternalServer, "invalid SMS configuration")
	}

	// Generate and send code
	code, err := s.smsSvc.GenerateCode(ctx, 6)
	if err != nil {
		return nil, err
	}

	err = s.smsSvc.SendVerificationCode(ctx, phoneNumber, code)
	if err != nil {
		return nil, err
	}

	// Store the code temporarily
	config := mfa.Metadata
	config["verificationCode"] = code
	config["codeExpiry"] = time.Now().Add(10 * time.Minute)

	_, err = s.UpdateMFAMethod(ctx, mfa.ID, config)
	if err != nil {
		return nil, err
	}

	return &model.SMSCodeResponse{
		Message:   "Verification code sent",
		ExpiresIn: 600, // 10 minutes
	}, nil
}

// VerifySMSCode verifies an SMS code
func (s *service) VerifySMSCode(ctx context.Context, userID xid.ID, code string) (*model.MFAVerifyResponse, error) {
	s.logger.Debug("Verifying SMS code", logging.String("userId", userID.String()))

	// Get SMS MFA record
	mfa, err := s.repo.GetByUserIDAndMethod(ctx, userID, "sms")
	if err != nil {
		return nil, err
	}

	if !mfa.Active {
		return nil, errors.New(errors.CodeBadRequest, "SMS MFA is not active")
	}

	// Check stored code and expiry
	storedCode, ok := mfa.Metadata["verificationCode"].(string)
	if !ok {
		return &model.MFAVerifyResponse{
			Success: false,
			Method:  "sms",
			Message: "No verification code found",
		}, nil
	}

	expiryTime, ok := mfa.Metadata["codeExpiry"].(time.Time)
	if !ok || time.Now().After(expiryTime) {
		return &model.MFAVerifyResponse{
			Success: false,
			Method:  "sms",
			Message: "Verification code expired",
		}, nil
	}

	if storedCode != code {
		return &model.MFAVerifyResponse{
			Success: false,
			Method:  "sms",
			Message: "Invalid verification code",
		}, nil
	}

	// Mark as verified if first time
	if !mfa.Verified {
		err = s.repo.MarkAsVerified(ctx, mfa.ID)
		if err != nil {
			s.logger.Error("Failed to mark SMS as verified", logging.Error(err))
		}
	}

	// Update last used
	err = s.repo.UpdateLastUsed(ctx, mfa.ID)
	if err != nil {
		s.logger.Error("Failed to update last used", logging.Error(err))
	}

	// Clear the verification code
	config := mfa.Metadata
	delete(config, "verificationCode")
	delete(config, "codeExpiry")
	_, err = s.UpdateMFAMethod(ctx, mfa.ID, config)
	if err != nil {
		s.logger.Error("Failed to clear verification code", logging.Error(err))
	}

	s.logger.Info("SMS code verified successfully", logging.String("userId", userID.String()))

	return &model.MFAVerifyResponse{
		Success: true,
		Method:  "sms",
		Message: "SMS verification successful",
	}, nil
}

// DisableSMS disables SMS MFA for a user
func (s *service) DisableSMS(ctx context.Context, userID xid.ID) error {
	return s.DisableMFA(ctx, userID, "sms")
}

func (s *service) GetMFAMethodByUserAndType(ctx context.Context, userID xid.ID, method string) (*model.MFA, error) {
	entMFA, err := s.repo.GetByUserIDAndMethod(ctx, userID, method)
	if err != nil {
		return nil, err
	}

	return s.convertEntMFAToModel(entMFA), nil
}

func (s *service) HasVerifiedMFA(ctx context.Context, userID xid.ID) (bool, error) {
	requiresMFA, _, err := s.RequiresMFA(ctx, userID)
	return requiresMFA, err
}

func (s *service) GetUnverifiedMFAMethods(ctx context.Context, userID xid.ID) ([]*model.MFA, error) {
	allMethods, err := s.ListUserMFAMethods(ctx, userID)
	if err != nil {
		return nil, err
	}

	var unverified []*model.MFA
	for _, method := range allMethods {
		if !method.Verified {
			unverified = append(unverified, method)
		}
	}

	return unverified, nil
}

// SetupEmail sets up email MFA for a user
func (s *service) SetupEmail(ctx context.Context, userID xid.ID, email string) (*model.EmailMFASetupResponse, error) {
	s.logger.Debug("Setting up email MFA",
		logging.String("userId", userID.String()),
		logging.String("email", email))

	// Store email configuration
	config := map[string]interface{}{
		"email": email,
	}

	mfa, err := s.EnableMFA(ctx, userID, "email", config)
	if err != nil {
		return nil, err
	}

	return &model.EmailMFASetupResponse{
		Email:    email,
		Message:  "Email MFA setup completed",
		MethodID: mfa.ID,
	}, nil
}

// SendEmailCode sends an email verification code
func (s *service) SendEmailCode(ctx context.Context, userID xid.ID) (*model.EmailCodeResponse, error) {
	s.logger.Debug("Sending email code", logging.String("userId", userID.String()))

	// Get email MFA record
	mfa, err := s.repo.GetByUserIDAndMethod(ctx, userID, "email")
	if err != nil {
		return nil, err
	}

	if !mfa.Active {
		return nil, errors.New(errors.CodeBadRequest, "Email MFA is not active")
	}

	// Generate code
	code, err := s.smsSvc.GenerateCode(ctx, 6) // Reuse SMS service for code generation
	if err != nil {
		return nil, err
	}

	// Store the code temporarily
	config := mfa.Metadata
	config["verificationCode"] = code
	config["codeExpiry"] = time.Now().Add(10 * time.Minute)

	_, err = s.UpdateMFAMethod(ctx, mfa.ID, config)
	if err != nil {
		return nil, err
	}

	// In production, send email here using email service
	s.logger.Info("Email code generated",
		logging.String("userId", userID.String()),
		logging.String("code", code)) // Remove in production

	return &model.EmailCodeResponse{
		Message:   "Verification code sent to your email",
		ExpiresIn: 600, // 10 minutes
	}, nil
}

// VerifyEmailCode verifies an email code
func (s *service) VerifyEmailCode(ctx context.Context, userID xid.ID, code string) (*model.MFAVerifyResponse, error) {
	s.logger.Debug("Verifying email code", logging.String("userId", userID.String()))

	// Get email MFA record
	mfa, err := s.repo.GetByUserIDAndMethod(ctx, userID, "email")
	if err != nil {
		return nil, err
	}

	if !mfa.Active {
		return nil, errors.New(errors.CodeBadRequest, "Email MFA is not active")
	}

	// Check stored code and expiry
	storedCode, ok := mfa.Metadata["verificationCode"].(string)
	if !ok {
		return &model.MFAVerifyResponse{
			Success: false,
			Method:  "email",
			Message: "No verification code found",
		}, nil
	}

	expiryTime, ok := mfa.Metadata["codeExpiry"].(time.Time)
	if !ok || time.Now().After(expiryTime) {
		return &model.MFAVerifyResponse{
			Success: false,
			Method:  "email",
			Message: "Verification code expired",
		}, nil
	}

	if storedCode != code {
		return &model.MFAVerifyResponse{
			Success: false,
			Method:  "email",
			Message: "Invalid verification code",
		}, nil
	}

	// Mark as verified if first time
	if !mfa.Verified {
		err = s.repo.MarkAsVerified(ctx, mfa.ID)
		if err != nil {
			s.logger.Error("Failed to mark email MFA as verified", logging.Error(err))
		}
	}

	// Update last used
	err = s.repo.UpdateLastUsed(ctx, mfa.ID)
	if err != nil {
		s.logger.Error("Failed to update last used", logging.Error(err))
	}

	// Clear the verification code
	config := mfa.Metadata
	delete(config, "verificationCode")
	delete(config, "codeExpiry")
	_, err = s.UpdateMFAMethod(ctx, mfa.ID, config)
	if err != nil {
		s.logger.Error("Failed to clear verification code", logging.Error(err))
	}

	s.logger.Info("Email code verified successfully", logging.String("userId", userID.String()))

	return &model.MFAVerifyResponse{
		Success: true,
		Method:  "email",
		Message: "Email verification successful",
	}, nil
}

// DisableEmailMFA disables email MFA for a user
func (s *service) DisableEmailMFA(ctx context.Context, userID xid.ID) error {
	return s.DisableMFA(ctx, userID, "email")
}

// GenerateBackupCodes generates backup codes for a user
func (s *service) GenerateBackupCodes(ctx context.Context, userID xid.ID, input *model.GenerateBackupCodesRequest) (*model.MFABackCodes, error) {
	s.logger.Debug("Generating backup codes", logging.String("userId", userID.String()))

	count := 10
	if input.Count > 0 {
		count = input.Count
	}

	// Generate backup codes using TOTP service
	codes, err := s.totpSvc.GenerateBackupCodes(ctx, userID, count)
	if err != nil {
		return nil, err
	}

	return &model.MFABackCodes{
		Codes:   codes,
		Message: "Backup codes generated successfully. Store them in a safe place.",
	}, nil
}

// VerifyBackupCode verifies a backup code
func (s *service) VerifyBackupCode(ctx context.Context, userID xid.ID, code string) (*model.MFAVerifyResponse, error) {
	s.logger.Debug("Verifying backup code", logging.String("userId", userID.String()))

	valid, err := s.totpSvc.ValidateBackupCode(ctx, userID, code)
	if err != nil {
		return nil, err
	}

	if !valid {
		return &model.MFAVerifyResponse{
			Success: false,
			Method:  "backup_code",
			Message: "Invalid backup code",
		}, nil
	}

	s.logger.Info("Backup code verified successfully", logging.String("userId", userID.String()))

	return &model.MFAVerifyResponse{
		Success: true,
		Method:  "backup_code",
		Message: "Backup code verification successful",
	}, nil
}

// RegenerateBackupCodes regenerates backup codes for a user
func (s *service) RegenerateBackupCodes(ctx context.Context, userID xid.ID, input *model.GenerateBackupCodesRequest) (*model.MFABackCodes, error) {
	s.logger.Debug("Regenerating backup codes", logging.String("userId", userID.String()))

	// Generate new backup codes
	codes, err := s.totpSvc.GenerateBackupCodes(ctx, userID, input.Count)
	if err != nil {
		return nil, err
	}

	return &model.MFABackCodes{
		Codes:   codes,
		Message: "New backup codes generated. Previous codes are no longer valid.",
	}, nil
}

// RequiresMFA checks if a user requires MFA
func (s *service) RequiresMFA(ctx context.Context, userID xid.ID) (bool, []string, error) {
	mfas, err := s.ListUserMFAMethods(ctx, userID)
	if err != nil {
		return false, nil, err
	}

	if len(mfas) == 0 {
		return false, nil, nil
	}

	// Check for verified MFA methods
	var methods []string
	hasVerified := false

	for _, mfa := range mfas {
		if mfa.Verified && mfa.Active {
			methods = append(methods, mfa.Method)
			hasVerified = true
		}
	}

	return hasVerified, methods, nil
}

// VerifyMFA verifies MFA using any available method
func (s *service) VerifyMFA(ctx context.Context, userID xid.ID, method, code string) (*model.MFAVerifyResponse, error) {
	switch method {
	case "totp":
		return s.VerifyTOTP(ctx, userID, code)
	case "sms":
		return s.VerifySMSCode(ctx, userID, code)
	case "email":
		return s.VerifyEmailCode(ctx, userID, code)
	case "backup_code":
		return s.VerifyBackupCode(ctx, userID, code)
	default:
		return nil, errors.New(errors.CodeBadRequest, "unsupported MFA method")
	}
}

// CreateMFAChallenge creates an MFA challenge for verification
func (s *service) CreateMFAChallenge(ctx context.Context, userID xid.ID) (*model.MFAChallengeResponse, error) {
	s.logger.Debug("Creating MFA challenge", logging.String("userId", userID.String()))

	requiresMFA, methods, err := s.RequiresMFA(ctx, userID)
	if err != nil {
		return nil, err
	}

	if !requiresMFA {
		return &model.MFAChallengeResponse{
			Required: false,
			Methods:  []string{},
		}, nil
	}

	challengeID := xid.New().String()

	return &model.MFAChallengeResponse{
		ChallengeID: challengeID,
		Required:    true,
		Methods:     methods,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}, nil
}

// ValidateMFAChallenge validates an MFA challenge response
func (s *service) ValidateMFAChallenge(ctx context.Context, challengeID string, method, code string) (*model.MFAVerifyResponse, error) {
	s.logger.Debug("Validating MFA challenge",
		logging.String("challengeId", challengeID),
		logging.String("method", method))

	// In production, validate the challenge ID and expiry
	// For now, we'll skip challenge validation and proceed with MFA verification

	// Extract user ID from challenge (would be stored with challenge)
	// For now, we'll need the user ID to be passed separately or stored differently
	return nil, errors.New(errors.CodeNotImplemented, "MFA challenge validation not fully implemented")
}

// DisableAllMFA disables all MFA methods for a user (recovery function)
func (s *service) DisableAllMFA(ctx context.Context, userID xid.ID) error {
	s.logger.Debug("Disabling all MFA methods", logging.String("userId", userID.String()))

	err := s.repo.DeactivateByUserID(ctx, userID)
	if err != nil {
		return err
	}

	s.logger.Info("All MFA methods disabled", logging.String("userId", userID.String()))
	return nil
}

// GetRecoveryOptions gets MFA recovery options for a user
func (s *service) GetRecoveryOptions(ctx context.Context, userID xid.ID) (*model.MFARecoveryOptions, error) {
	mfas, err := s.ListUserMFAMethods(ctx, userID)
	if err != nil {
		return nil, err
	}

	var options []string
	hasBackupCodes := false

	for _, mfa := range mfas {
		if mfa.Verified && mfa.Active {
			options = append(options, mfa.Method)
		}
	}

	// Check if user has backup codes
	codes, err := s.totpSvc.GetBackupCodes(ctx, userID)
	if err == nil && len(codes) > 0 {
		hasBackupCodes = true
		options = append(options, "backup_code")
	}

	return &model.MFARecoveryOptions{
		Available:      len(options) > 0,
		Methods:        options,
		HasBackupCodes: hasBackupCodes,
		ContactSupport: len(options) == 0, // If no recovery options, suggest contacting support
	}, nil
}

// Helper methods

func (s *service) convertEntMFAToModel(entMFA *ent.MFA) *model.MFA {
	return &model.MFA{
		Base: model.Base{
			ID:        entMFA.ID,
			CreatedAt: entMFA.CreatedAt,
			UpdatedAt: entMFA.UpdatedAt,
		},
		UserID:      entMFA.UserID,
		Method:      entMFA.Method,
		Active:      entMFA.Active,
		Verified:    entMFA.Verified,
		LastUsed:    entMFA.LastUsed,
		Name:        "",
		Secret:      entMFA.Secret,
		Email:       entMFA.Email,
		PhoneNumber: entMFA.PhoneNumber,
		Metadata:    entMFA.Metadata,
		BackupCodes: entMFA.BackupCodes,
		// Config:   entMFA.Config,
	}
}
