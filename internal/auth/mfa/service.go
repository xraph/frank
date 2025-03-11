package mfa

import (
	"context"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/mfa"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// Method represents the type of MFA method
type Method string

const (
	// MethodTOTP represents Time-based One-Time Password authentication
	MethodTOTP Method = "totp"

	// MethodSMS represents SMS-based authentication
	MethodSMS Method = "sms"

	// MethodEmail represents email-based authentication
	MethodEmail Method = "email"

	// MethodBackupCodes represents backup codes authentication
	MethodBackupCodes Method = "backup_codes"
)

// Service defines the interface for multi-factor authentication operations
type Service interface {
	EnableTOTP(ctx context.Context, userID string, email string) (*TOTPSecret, error)
	VerifyTOTP(ctx context.Context, userID, code string) (bool, error)
	DisableTOTP(ctx context.Context, userID string) error

	EnableSMS(ctx context.Context, userID, phoneNumber string) error
	SendSMSCode(ctx context.Context, userID string) (time.Time, error)
	VerifySMSCode(ctx context.Context, userID, code string) (bool, error)
	DisableSMS(ctx context.Context, userID string) error

	EnableEmail(ctx context.Context, userID, email string) error
	SendEmailCode(ctx context.Context, userID string) (time.Time, error)
	VerifyEmailCode(ctx context.Context, userID, code string) (bool, error)
	DisableEmail(ctx context.Context, userID string) error

	EnableBackupCodes(ctx context.Context, userID string) ([]string, error)
	VerifyBackupCode(ctx context.Context, userID, code string) (bool, error)
	GetRemainingBackupCodes(ctx context.Context, userID string) (int, error)
	DisableBackupCodes(ctx context.Context, userID string) error

	GetEnabledMethods(ctx context.Context, userID string) ([]string, error)
	IsAnyMethodEnabled(ctx context.Context, userID string) (bool, error)
	DisableAllMethods(ctx context.Context, userID string) error
}

// serviceImpl implements the Service interface
type serviceImpl struct {
	client         *ent.Client
	config         *config.Config
	logger         logging.Logger
	totpProvider   *TOTPProvider
	smsProvider    *SMSProvider
	emailProvider  *EmailProvider
	backupProvider *BackupCodesProvider
}

// NewService creates a new MFA service
func NewService(client *ent.Client, cfg *config.Config, logger logging.Logger) Service {
	// Create the TOTP provider
	totpConfig := DefaultTOTPConfig()
	totpConfig.Issuer = cfg.Auth.DefaultUserRole

	// Create the SMS provider
	smsConfig := DefaultSMSCodeConfig()
	smsProvider := GetSMSProvider(cfg, logger)

	// Create the Email provider
	emailConfig := DefaultEmailCodeConfig()
	emailProvider := GetEmailProvider(cfg, logger)

	// Create backup codes provider
	backupConfig := DefaultBackupCodesConfig()

	return &serviceImpl{
		client:         client,
		config:         cfg,
		logger:         logger,
		totpProvider:   NewTOTPProvider(totpConfig),
		smsProvider:    NewSMSProvider(smsConfig, smsProvider, logger),
		emailProvider:  NewEmailProvider(emailConfig, emailProvider, logger),
		backupProvider: NewBackupCodesProvider(backupConfig),
	}
}

// EnableTOTP enables TOTP for a user
func (s *serviceImpl) EnableTOTP(ctx context.Context, userID string, email string) (*TOTPSecret, error) {
	// Generate a new TOTP secret
	secret, err := s.totpProvider.GenerateSecret(email)
	if err != nil {
		return nil, err
	}

	// Check if TOTP is already set up for this user
	exists, err := s.client.MFA.Query().
		Where(
			mfa.UserID(userID),
			mfa.Method(string(MethodTOTP)),
		).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check for existing TOTP")
	}

	// If TOTP is already set up, update it
	if exists {
		_, err = s.client.MFA.Update().
			Where(
				mfa.UserID(userID),
				mfa.Method(string(MethodTOTP)),
			).
			SetSecret(secret.Secret).
			SetVerified(false).
			Save(ctx)
	} else {
		// Otherwise, create a new MFA record
		_, err = s.client.MFA.Create().
			SetUserID(userID).
			SetMethod(string(MethodTOTP)).
			SetSecret(secret.Secret).
			SetVerified(false).
			SetActive(true).
			Save(ctx)
	}

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to save TOTP secret")
	}

	return secret, nil
}

// VerifyTOTP verifies a TOTP code
func (s *serviceImpl) VerifyTOTP(ctx context.Context, userID, code string) (bool, error) {
	// Get the user's TOTP method
	mfaMethod, err := s.client.MFA.Query().
		Where(
			mfa.UserID(userID),
			mfa.Method(string(MethodTOTP)),
			mfa.Active(true),
		).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return false, errors.New(errors.CodeNotFound, "TOTP not set up for this user")
		}
		return false, errors.Wrap(errors.CodeDatabaseError, err, "failed to retrieve TOTP method")
	}

	// Verify the code
	valid, err := s.totpProvider.Verify(mfaMethod.Secret, code)
	if err != nil {
		return false, err
	}

	// If this is the first successful verification, mark it as verified
	if valid && !mfaMethod.Verified {
		_, err = s.client.MFA.UpdateOne(mfaMethod).
			SetVerified(true).
			SetLastUsed(time.Now()).
			Save(ctx)

		if err != nil {
			s.logger.Error("Failed to update TOTP verification status",
				logging.String("user_id", userID),
				logging.Error(err),
			)
		}
	}

	// If verification is successful, update the last used timestamp
	if valid {
		_, err = s.client.MFA.UpdateOne(mfaMethod).
			SetLastUsed(time.Now()).
			Save(ctx)

		if err != nil {
			s.logger.Error("Failed to update TOTP last used timestamp",
				logging.String("user_id", userID),
				logging.Error(err),
			)
		}
	}

	return valid, nil
}

// DisableTOTP disables TOTP for a user
func (s *serviceImpl) DisableTOTP(ctx context.Context, userID string) error {
	_, err := s.client.MFA.Update().
		Where(
			mfa.UserID(userID),
			mfa.Method(string(MethodTOTP)),
		).
		SetActive(false).
		Save(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to disable TOTP")
	}

	return nil
}

// EnableSMS enables SMS-based MFA for a user
func (s *serviceImpl) EnableSMS(ctx context.Context, userID, phoneNumber string) error {
	// Check if the phone number is already registered
	exists, err := s.client.MFA.Query().
		Where(
			mfa.UserID(userID),
			mfa.Method(string(MethodSMS)),
		).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to check for existing SMS MFA")
	}

	// If SMS MFA is already set up, update it
	if exists {
		_, err = s.client.MFA.Update().
			Where(
				mfa.UserID(userID),
				mfa.Method(string(MethodSMS)),
			).
			SetPhoneNumber(phoneNumber).
			SetVerified(false).
			SetActive(true).
			Save(ctx)
	} else {
		// Otherwise, create a new MFA record
		_, err = s.client.MFA.Create().
			SetUserID(userID).
			SetMethod(string(MethodSMS)).
			SetPhoneNumber(phoneNumber).
			SetSecret(""). // Will be filled with a verification code
			SetVerified(false).
			SetActive(true).
			Save(ctx)
	}

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to save SMS MFA")
	}

	return nil
}

// SendSMSCode sends a verification code via SMS
func (s *serviceImpl) SendSMSCode(ctx context.Context, userID string) (time.Time, error) {
	// Get the user's SMS method
	mfaMethod, err := s.client.MFA.Query().
		Where(
			mfa.UserID(userID),
			mfa.Method(string(MethodSMS)),
			mfa.Active(true),
		).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return time.Time{}, errors.New(errors.CodeNotFound, "SMS MFA not set up for this user")
		}
		return time.Time{}, errors.Wrap(errors.CodeDatabaseError, err, "failed to retrieve SMS method")
	}

	// Generate and send the code
	code, expiresAt, err := s.smsProvider.SendVerificationCode(ctx, mfaMethod.PhoneNumber)
	if err != nil {
		return time.Time{}, err
	}

	// Update the secret with the new code
	_, err = s.client.MFA.UpdateOne(mfaMethod).
		SetSecret(code).
		Save(ctx)

	if err != nil {
		return time.Time{}, errors.Wrap(errors.CodeDatabaseError, err, "failed to save SMS code")
	}

	return expiresAt, nil
}

// VerifySMSCode verifies an SMS verification code
func (s *serviceImpl) VerifySMSCode(ctx context.Context, userID, code string) (bool, error) {
	// Get the user's SMS method
	mfaMethod, err := s.client.MFA.Query().
		Where(
			mfa.UserID(userID),
			mfa.Method(string(MethodSMS)),
			mfa.Active(true),
		).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return false, errors.New(errors.CodeNotFound, "SMS MFA not set up for this user")
		}
		return false, errors.Wrap(errors.CodeDatabaseError, err, "failed to retrieve SMS method")
	}

	// Calculate expiration time
	expiresAt := mfaMethod.UpdatedAt.Add(s.smsProvider.config.CodeExpiry)

	// Verify the code
	valid, err := s.smsProvider.VerifyCode(code, mfaMethod.Secret, expiresAt)
	if err != nil {
		return false, err
	}

	// If this is the first successful verification, mark it as verified
	if valid && !mfaMethod.Verified {
		_, err = s.client.MFA.UpdateOne(mfaMethod).
			SetVerified(true).
			SetLastUsed(time.Now()).
			Save(ctx)

		if err != nil {
			s.logger.Error("Failed to update SMS verification status",
				logging.String("user_id", userID),
				logging.Error(err),
			)
		}
	}

	// If verification is successful, update the last used timestamp
	if valid {
		_, err = s.client.MFA.UpdateOne(mfaMethod).
			SetLastUsed(time.Now()).
			Save(ctx)

		if err != nil {
			s.logger.Error("Failed to update SMS last used timestamp",
				logging.String("user_id", userID),
				logging.Error(err),
			)
		}
	}

	return valid, nil
}

// DisableSMS disables SMS-based MFA for a user
func (s *serviceImpl) DisableSMS(ctx context.Context, userID string) error {
	_, err := s.client.MFA.Update().
		Where(
			mfa.UserID(userID),
			mfa.Method(string(MethodSMS)),
		).
		SetActive(false).
		Save(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to disable SMS MFA")
	}

	return nil
}

// EnableEmail enables email-based MFA for a user
func (s *serviceImpl) EnableEmail(ctx context.Context, userID, email string) error {
	// Check if email MFA is already set up
	exists, err := s.client.MFA.Query().
		Where(
			mfa.UserID(userID),
			mfa.Method(string(MethodEmail)),
		).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to check for existing email MFA")
	}

	// If email MFA is already set up, update it
	if exists {
		_, err = s.client.MFA.Update().
			Where(
				mfa.UserID(userID),
				mfa.Method(string(MethodEmail)),
			).
			SetEmail(email).
			SetVerified(false).
			SetActive(true).
			Save(ctx)
	} else {
		// Otherwise, create a new MFA record
		_, err = s.client.MFA.Create().
			SetUserID(userID).
			SetMethod(string(MethodEmail)).
			SetEmail(email).
			SetSecret(""). // Will be filled with a verification code
			SetVerified(false).
			SetActive(true).
			Save(ctx)
	}

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to save email MFA")
	}

	return nil
}

// SendEmailCode sends a verification code via email
func (s *serviceImpl) SendEmailCode(ctx context.Context, userID string) (time.Time, error) {
	// Get the user's email method
	mfaMethod, err := s.client.MFA.Query().
		Where(
			mfa.UserID(userID),
			mfa.Method(string(MethodEmail)),
			mfa.Active(true),
		).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return time.Time{}, errors.New(errors.CodeNotFound, "Email MFA not set up for this user")
		}
		return time.Time{}, errors.Wrap(errors.CodeDatabaseError, err, "failed to retrieve email method")
	}

	// Generate and send the code
	code, expiresAt, err := s.emailProvider.SendVerificationCode(ctx, mfaMethod.Email)
	if err != nil {
		return time.Time{}, err
	}

	// Update the secret with the new code
	_, err = s.client.MFA.UpdateOne(mfaMethod).
		SetSecret(code).
		Save(ctx)

	if err != nil {
		return time.Time{}, errors.Wrap(errors.CodeDatabaseError, err, "failed to save email code")
	}

	return expiresAt, nil
}

// VerifyEmailCode verifies an email verification code
func (s *serviceImpl) VerifyEmailCode(ctx context.Context, userID, code string) (bool, error) {
	// Get the user's email method
	mfaMethod, err := s.client.MFA.Query().
		Where(
			mfa.UserID(userID),
			mfa.Method(string(MethodEmail)),
			mfa.Active(true),
		).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return false, errors.New(errors.CodeNotFound, "Email MFA not set up for this user")
		}
		return false, errors.Wrap(errors.CodeDatabaseError, err, "failed to retrieve email method")
	}

	// Calculate expiration time
	expiresAt := mfaMethod.UpdatedAt.Add(s.emailProvider.config.CodeExpiry)

	// Verify the code
	valid, err := s.emailProvider.VerifyCode(code, mfaMethod.Secret, expiresAt)
	if err != nil {
		return false, err
	}

	// If this is the first successful verification, mark it as verified
	if valid && !mfaMethod.Verified {
		_, err = s.client.MFA.UpdateOne(mfaMethod).
			SetVerified(true).
			SetLastUsed(time.Now()).
			Save(ctx)

		if err != nil {
			s.logger.Error("Failed to update email verification status",
				logging.String("user_id", userID),
				logging.Error(err),
			)
		}
	}

	// If verification is successful, update the last used timestamp
	if valid {
		_, err = s.client.MFA.UpdateOne(mfaMethod).
			SetLastUsed(time.Now()).
			Save(ctx)

		if err != nil {
			s.logger.Error("Failed to update email last used timestamp",
				logging.String("user_id", userID),
				logging.Error(err),
			)
		}
	}

	return valid, nil
}

// DisableEmail disables email-based MFA for a user
func (s *serviceImpl) DisableEmail(ctx context.Context, userID string) error {
	_, err := s.client.MFA.Update().
		Where(
			mfa.UserID(userID),
			mfa.Method(string(MethodEmail)),
		).
		SetActive(false).
		Save(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to disable email MFA")
	}

	return nil
}

// EnableBackupCodes enables backup codes for a user
func (s *serviceImpl) EnableBackupCodes(ctx context.Context, userID string) ([]string, error) {
	// Generate backup codes
	backupSet, err := s.backupProvider.GenerateBackupCodeSet()
	if err != nil {
		return nil, err
	}

	// Check if backup codes are already set up
	exists, err := s.client.MFA.Query().
		Where(
			mfa.UserID(userID),
			mfa.Method(string(MethodBackupCodes)),
		).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check for existing backup codes")
	}

	// If backup codes are already set up, update them
	if exists {
		_, err = s.client.MFA.Update().
			Where(
				mfa.UserID(userID),
				mfa.Method(string(MethodBackupCodes)),
			).
			SetBackupCodes(backupSet.HashedCodes).
			SetVerified(true).
			SetActive(true).
			Save(ctx)
	} else {
		// Otherwise, create a new MFA record
		_, err = s.client.MFA.Create().
			SetUserID(userID).
			SetMethod(string(MethodBackupCodes)).
			SetBackupCodes(backupSet.HashedCodes).
			SetVerified(true). // Backup codes are verified by default
			SetActive(true).
			Save(ctx)
	}

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to save backup codes")
	}

	return backupSet.PlainCodes, nil
}

// VerifyBackupCode verifies a backup code
func (s *serviceImpl) VerifyBackupCode(ctx context.Context, userID, code string) (bool, error) {
	// Get the user's backup codes
	mfaMethod, err := s.client.MFA.Query().
		Where(
			mfa.UserID(userID),
			mfa.Method(string(MethodBackupCodes)),
			mfa.Active(true),
		).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return false, errors.New(errors.CodeNotFound, "Backup codes not set up for this user")
		}
		return false, errors.Wrap(errors.CodeDatabaseError, err, "failed to retrieve backup codes")
	}

	// Verify the code
	valid, index := s.backupProvider.VerifyCode(code, mfaMethod.BackupCodes)
	if !valid {
		return false, nil
	}

	// If the code is valid, remove it from the list
	hashedCodes := s.backupProvider.RemoveUsedCode(mfaMethod.BackupCodes, index)

	// Update the backup codes
	_, err = s.client.MFA.UpdateOne(mfaMethod).
		SetBackupCodes(hashedCodes).
		SetLastUsed(time.Now()).
		Save(ctx)

	if err != nil {
		return false, errors.Wrap(errors.CodeDatabaseError, err, "failed to update backup codes")
	}

	return true, nil
}

// GetRemainingBackupCodes gets the number of remaining backup codes
func (s *serviceImpl) GetRemainingBackupCodes(ctx context.Context, userID string) (int, error) {
	// Get the user's backup codes
	mfaMethod, err := s.client.MFA.Query().
		Where(
			mfa.UserID(userID),
			mfa.Method(string(MethodBackupCodes)),
			mfa.Active(true),
		).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return 0, errors.New(errors.CodeNotFound, "Backup codes not set up for this user")
		}
		return 0, errors.Wrap(errors.CodeDatabaseError, err, "failed to retrieve backup codes")
	}

	return len(mfaMethod.BackupCodes), nil
}

// DisableBackupCodes disables backup codes for a user
func (s *serviceImpl) DisableBackupCodes(ctx context.Context, userID string) error {
	_, err := s.client.MFA.Update().
		Where(
			mfa.UserID(userID),
			mfa.Method(string(MethodBackupCodes)),
		).
		SetActive(false).
		Save(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to disable backup codes")
	}

	return nil
}

// GetEnabledMethods gets the list of enabled MFA methods for a user
func (s *serviceImpl) GetEnabledMethods(ctx context.Context, userID string) ([]string, error) {
	methods, err := s.client.MFA.Query().
		Where(
			mfa.UserID(userID),
			mfa.Active(true),
			mfa.Verified(true),
		).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to retrieve MFA methods")
	}

	var enabledMethods []string
	for _, method := range methods {
		enabledMethods = append(enabledMethods, method.Method)
	}

	return enabledMethods, nil
}

// IsAnyMethodEnabled checks if any MFA method is enabled for a user
func (s *serviceImpl) IsAnyMethodEnabled(ctx context.Context, userID string) (bool, error) {
	exists, err := s.client.MFA.Query().
		Where(
			mfa.UserID(userID),
			mfa.Active(true),
			mfa.Verified(true),
		).
		Exist(ctx)

	if err != nil {
		return false, errors.Wrap(errors.CodeDatabaseError, err, "failed to check for MFA methods")
	}

	return exists, nil
}

// DisableAllMethods disables all MFA methods for a user
func (s *serviceImpl) DisableAllMethods(ctx context.Context, userID string) error {
	_, err := s.client.MFA.Update().
		Where(
			mfa.UserID(userID),
		).
		SetActive(false).
		Save(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to disable all MFA methods")
	}

	return nil
}
