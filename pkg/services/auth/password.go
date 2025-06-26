package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/pkg/contexts"
	"github.com/juicycleff/frank/pkg/crypto"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/juicycleff/frank/pkg/services/notification"
	"github.com/juicycleff/frank/pkg/services/user"
	"github.com/rs/xid"
)

// PasswordService defines the interface for password operations
type PasswordService interface {
	// Password management
	HashPassword(password string) (string, error)
	VerifyPassword(password, hash string) bool
	ValidatePasswordStrength(password string) error
	GenerateSecurePassword(length int) (string, error)

	// Password reset
	InitiatePasswordReset(ctx context.Context, req model.PasswordResetRequest) (*model.PasswordResetResponse, error)
	ConfirmPasswordReset(ctx context.Context, req model.PasswordResetConfirmRequest) (*model.PasswordResetConfirmResponse, error)
	ValidatePasswordResetToken(ctx context.Context, token string) (*model.ValidateTokenResponse, error)

	// Password change
	ChangePassword(ctx context.Context, userID xid.ID, req model.ChangePasswordRequest) error
	SetPassword(ctx context.Context, userID xid.ID, req model.SetPasswordRequest) error

	// Password history and validation
	CheckPasswordHistory(ctx context.Context, userID xid.ID, newPassword string) error
	IsPasswordExpired(ctx context.Context, userID xid.ID) (bool, error)
	GetPasswordPolicy(ctx context.Context, organizationID *xid.ID) (*model.PasswordPolicy, error)

	// Temporary passwords
	GenerateTemporaryPassword(ctx context.Context, userID xid.ID) (string, error)
	IsTemporaryPassword(ctx context.Context, userID xid.ID) (bool, error)
}

// passwordService implements the PasswordService interface
type passwordService struct {
	userRepo            repository.UserRepository
	verificationRepo    repository.VerificationRepository
	auditRepo           repository.AuditRepository
	notificationService notification.Service
	userService         user.Service
	sessionService      SessionService
	logger              logging.Logger
	crypto              crypto.Util
	config              *PasswordConfig
}

// PasswordConfig holds password-related configuration
type PasswordConfig struct {
	MinLength          int
	MaxLength          int
	RequireUppercase   bool
	RequireLowercase   bool
	RequireDigit       bool
	RequireSpecial     bool
	MaxReusedPasswords int
	PreventReuse       bool
	ExpiryDays         int
	BcryptCost         int
	ResetTokenExpiry   time.Duration
}

// NewPasswordService creates a new password service
func NewPasswordService(
	repos repository.Repository,
	userService user.Service,
	notificationService notification.Service,
	sessionService SessionService,
	crypto crypto.Util,
	logger logging.Logger,
	cfg *config.AuthConfig,
) PasswordService {
	mcfg := &PasswordConfig{
		MinLength:          cfg.PasswordPolicy.MinLength,
		MaxLength:          cfg.PasswordPolicy.MaxLength,
		RequireUppercase:   cfg.PasswordPolicy.RequireUppercase,
		RequireLowercase:   cfg.PasswordPolicy.RequireLowercase,
		RequireDigit:       cfg.PasswordPolicy.RequireDigit,
		RequireSpecial:     cfg.PasswordPolicy.RequireSpecial,
		MaxReusedPasswords: cfg.PasswordPolicy.MaxReusedPasswords,
		PreventReuse:       cfg.PasswordPolicy.PreventReuse,
		ExpiryDays:         cfg.PasswordPolicy.ExpiryDays,
		BcryptCost:         cfg.PasswordPolicy.BcryptCost,
		ResetTokenExpiry:   cfg.RefreshTokenDuration,
	}
	if mcfg == nil {
		mcfg = defaultPasswordConfig()
	}

	return &passwordService{
		userRepo:            repos.User(),
		userService:         userService,
		verificationRepo:    repos.Verification(),
		auditRepo:           repos.Audit(),
		notificationService: notificationService,
		sessionService:      sessionService,
		crypto:              crypto,
		logger:              logger,
		config:              mcfg,
	}
}

// defaultPasswordConfig returns default password configuration
func defaultPasswordConfig() *PasswordConfig {
	return &PasswordConfig{
		MinLength:          8,
		MaxLength:          100,
		RequireUppercase:   true,
		RequireLowercase:   true,
		RequireDigit:       true,
		RequireSpecial:     false,
		MaxReusedPasswords: 3,
		PreventReuse:       true,
		ExpiryDays:         90,
		BcryptCost:         12,
		ResetTokenExpiry:   15 * time.Minute,
	}
}

// HashPassword hashes a password using bcrypt
func (s *passwordService) HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New(errors.CodeBadRequest, "password cannot be empty")
	}

	hash, err := s.crypto.PasswordHasher().HashPassword(password)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternalServer, "failed to hash password")
	}

	return hash, nil
}

// VerifyPassword verifies a password against its hash
func (s *passwordService) VerifyPassword(password, hash string) bool {
	if password == "" || hash == "" {
		return false
	}

	err := s.crypto.PasswordHasher().VerifyPassword(password, hash)
	return err == nil
}

// ValidatePasswordStrength validates password against policy
func (s *passwordService) ValidatePasswordStrength(password string) error {
	if len(password) < s.config.MinLength {
		return errors.New(errors.CodePasswordTooWeak,
			fmt.Sprintf("password must be at least %d characters long", s.config.MinLength))
	}

	if len(password) > s.config.MaxLength {
		return errors.New(errors.CodePasswordTooWeak,
			fmt.Sprintf("password must be at most %d characters long", s.config.MaxLength))
	}

	// Check for required character types
	var hasUpper, hasLower, hasDigit, hasSpecial bool

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case isSpecialCharacter(char):
			hasSpecial = true
		}
	}

	if s.config.RequireUppercase && !hasUpper {
		return errors.New(errors.CodePasswordTooWeak, "password must contain at least one uppercase letter")
	}

	if s.config.RequireLowercase && !hasLower {
		return errors.New(errors.CodePasswordTooWeak, "password must contain at least one lowercase letter")
	}

	if s.config.RequireDigit && !hasDigit {
		return errors.New(errors.CodePasswordTooWeak, "password must contain at least one digit")
	}

	if s.config.RequireSpecial && !hasSpecial {
		return errors.New(errors.CodePasswordTooWeak, "password must contain at least one special character")
	}

	// Check for common patterns
	if err := s.checkCommonPatterns(password); err != nil {
		return err
	}

	return nil
}

// GenerateSecurePassword generates a cryptographically secure password
func (s *passwordService) GenerateSecurePassword(length int) (string, error) {
	if length < 8 {
		length = 12 // Default to 12 characters
	}

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+"

	password := make([]byte, length)
	for i := range password {
		randomIndex, err := s.secureRandomInt(len(charset))
		if err != nil {
			return "", errors.Wrap(err, errors.CodeInternalServer, "failed to generate secure password")
		}
		password[i] = charset[randomIndex]
	}

	// Ensure generated password meets policy requirements
	generatedPassword := string(password)
	if err := s.ValidatePasswordStrength(generatedPassword); err != nil {
		// Retry once if generated password doesn't meet policy
		return s.GenerateSecurePassword(length)
	}

	return generatedPassword, nil
}

// InitiatePasswordReset starts the password reset process
func (s *passwordService) InitiatePasswordReset(ctx context.Context, req model.PasswordResetRequest) (*model.PasswordResetResponse, error) {
	if req.Email == "" {
		return nil, errors.New(errors.CodeBadRequest, "email is required")
	}

	// Find user by email (don't reveal if user exists for security)
	user, err := s.findUserByEmail(ctx, req.Email)
	if err != nil {
		s.logger.Error("failed to find user for password reset", logging.Error(err))
	}

	// Always return success to prevent email enumeration
	response := &model.PasswordResetResponse{
		Success: true,
		Message: "Password reset email sent",
	}

	// Only send email if user exists
	if user != nil {
		// Generate reset token
		resetToken, err := s.generateResetToken()
		if err != nil {
			s.logger.Error("failed to generate reset token", logging.Error(err))
			return response, nil
		}

		// Store verification record
		expiresAt := time.Now().Add(s.config.ResetTokenExpiry)
		verificationInput := repository.CreateVerificationInput{
			UserID:    user.ID,
			Email:     req.Email,
			Token:     resetToken,
			Type:      "password_reset",
			ExpiresAt: expiresAt,
			Used:      false,
			Metadata: map[string]interface{}{
				"redirect_url": req.RedirectURL,
				"ip_address":   s.getIPFromContext(ctx),
				"user_agent":   s.getUserAgentFromContext(ctx),
			},
		}

		_, err = s.verificationRepo.Create(ctx, verificationInput)
		if err != nil {
			s.logger.Error("failed to create password reset verification", logging.Error(err))
			return response, nil
		}

		// Send password reset email
		err = s.notificationService.Email().SendPasswordResetEmail(ctx, user, resetToken, req.RedirectURL)
		if err != nil {
			return nil, err
		}

		// Audit log
		s.auditPasswordResetInitiated(ctx, user.ID, req.Email)

		// Return token for development/testing
		response.Token = resetToken
	}

	return response, nil
}

// ConfirmPasswordReset completes the password reset process
func (s *passwordService) ConfirmPasswordReset(ctx context.Context, req model.PasswordResetConfirmRequest) (*model.PasswordResetConfirmResponse, error) {
	if req.Token == "" {
		return nil, errors.New(errors.CodeBadRequest, "reset token is required")
	}

	if req.NewPassword == "" {
		return nil, errors.New(errors.CodeBadRequest, "new password is required")
	}

	// Validate new password strength
	if err := s.ValidatePasswordStrength(req.NewPassword); err != nil {
		return nil, err
	}

	// Get and validate reset token
	verification, err := s.verificationRepo.GetValidToken(ctx, req.Token)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeUnauthorized, "invalid or expired reset token")
	}

	if verification.Type != "password_reset" {
		return nil, errors.New(errors.CodeBadRequest, "invalid token type")
	}

	if verification.UserID.IsNil() {
		return nil, errors.New(errors.CodeInternalServer, "invalid verification record")
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, verification.UserID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "user not found")
	}

	// Check password history if enabled
	if s.config.PreventReuse {
		if err := s.CheckPasswordHistory(ctx, user.ID, req.NewPassword); err != nil {
			return nil, err
		}
	}

	// Hash new password
	newPasswordHash, err := s.HashPassword(req.NewPassword)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to hash new password")
	}

	// Update user password
	err = s.userRepo.UpdatePassword(ctx, user.ID, newPasswordHash)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to update password")
	}

	// Mark reset token as used
	err = s.verificationRepo.MarkTokenAsUsed(ctx, req.Token)
	if err != nil {
		s.logger.Error("failed to mark reset token as used", logging.Error(err))
	}

	// TODO: Store password history if enabled
	// s.storePasswordHistory(ctx, user.ID, user.PasswordHash)

	// Invalidate all user sessions for security
	_, err = s.sessionService.InvalidateAllUserSessions(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	// Audit log
	s.auditPasswordReset(ctx, user.ID)

	return &model.PasswordResetConfirmResponse{
		Success: true,
		Message: "Password reset successfully",
	}, nil
}

// ValidatePasswordResetToken validates a password reset token and ensures it is valid, not expired, and associated with a user.
func (s *passwordService) ValidatePasswordResetToken(ctx context.Context, token string) (*model.ValidateTokenResponse, error) {
	if token == "" {
		return nil, errors.New(errors.CodeBadRequest, "reset token is required")
	}

	// Get and validate reset token
	verification, err := s.verificationRepo.GetValidToken(ctx, token)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeUnauthorized, "invalid or expired reset token")
	}

	if verification.Type != "password_reset" {
		return nil, errors.New(errors.CodeBadRequest, "invalid token type")
	}

	if verification.UserID.IsNil() {
		return nil, errors.New(errors.CodeInternalServer, "invalid verification record")
	}

	// Get user
	_, err = s.userRepo.GetByID(ctx, verification.UserID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "user not found")
	}

	if verification.Used {
		return nil, errors.New(errors.CodeUnauthorized, "reset token has already been used")
	}

	if verification.ExpiresAt.Before(time.Now()) {
		return nil, errors.New(errors.CodeUnauthorized, "reset token has expired")
	}

	// Audit log
	// s.auditPasswordReset(ctx, user.ID)

	return &model.ValidateTokenResponse{
		Valid:   true,
		Message: "Token is valid",
	}, nil
}

// ChangePassword changes a user's password (requires current password)
func (s *passwordService) ChangePassword(ctx context.Context, userID xid.ID, req model.ChangePasswordRequest) error {
	if req.CurrentPassword == "" {
		return errors.New(errors.CodeBadRequest, "current password is required")
	}

	if req.NewPassword == "" {
		return errors.New(errors.CodeBadRequest, "new password is required")
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "user not found")
	}

	// Verify current password
	if !s.VerifyPassword(req.CurrentPassword, user.PasswordHash) {
		return errors.New(errors.CodeUnauthorized, "current password is incorrect")
	}

	// Prevent setting the same password
	if s.VerifyPassword(req.NewPassword, user.PasswordHash) {
		return errors.New(errors.CodeBadRequest, "new password must be different from current password")
	}

	// Validate new password strength
	if err := s.ValidatePasswordStrength(req.NewPassword); err != nil {
		return err
	}

	// Check password history if enabled
	if s.config.PreventReuse {
		if err := s.CheckPasswordHistory(ctx, userID, req.NewPassword); err != nil {
			return err
		}
	}

	// Hash new password
	newPasswordHash, err := s.HashPassword(req.NewPassword)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to hash new password")
	}

	// Update user password
	err = s.userRepo.UpdatePassword(ctx, user.ID, newPasswordHash)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to update password")
	}

	// TODO: Store password history if enabled
	// s.storePasswordHistory(ctx, userID, user.PasswordHash)

	// Audit log
	s.auditPasswordChange(ctx, userID)

	return nil
}

// SetPassword sets a user's password (admin operation, no current password required)
func (s *passwordService) SetPassword(ctx context.Context, userID xid.ID, req model.SetPasswordRequest) error {
	if req.Password == "" {
		return errors.New(errors.CodeBadRequest, "password is required")
	}

	// Validate password strength
	if err := s.ValidatePasswordStrength(req.Password); err != nil {
		return err
	}

	// Hash password
	passwordHash, err := s.HashPassword(req.Password)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to hash password")
	}

	// Mark as temporary if specified
	if req.Temporary {
		// TODO: Add temporary password flag to user schema
		// updateInput.TemporaryPassword = &req.Temporary
	}

	err = s.userRepo.UpdatePassword(ctx, userID, passwordHash)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to set password")
	}

	// Audit log
	s.auditPasswordSet(ctx, userID, req.Temporary)

	return nil
}

// CheckPasswordHistory checks if password was used recently
func (s *passwordService) CheckPasswordHistory(ctx context.Context, userID xid.ID, newPassword string) error {
	if !s.config.PreventReuse || s.config.MaxReusedPasswords <= 0 {
		return nil
	}

	// TODO: Implement password history checking
	// This would require a password_history table to store hashed previous passwords
	// For now, just check against current password

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil // Don't fail if we can't check history
	}

	if s.VerifyPassword(newPassword, user.PasswordHash) {
		return errors.New(errors.CodeBadRequest, "cannot reuse current password")
	}

	return nil
}

// IsPasswordExpired checks if user's password has expired
func (s *passwordService) IsPasswordExpired(ctx context.Context, userID xid.ID) (bool, error) {
	if s.config.ExpiryDays <= 0 {
		return false, nil // Password expiry disabled
	}

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return false, errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	}

	if user.LastPasswordChange == nil {
		// No password change recorded, consider it expired for safety
		return true, nil
	}

	expiryDate := user.LastPasswordChange.AddDate(0, 0, s.config.ExpiryDays)
	return time.Now().After(expiryDate), nil
}

// GetPasswordPolicy returns password policy for organization
func (s *passwordService) GetPasswordPolicy(ctx context.Context, organizationID *xid.ID) (*model.PasswordPolicy, error) {
	// TODO: Implement organization-specific password policies
	// For now, return default policy

	return &model.PasswordPolicy{
		MinLength:        s.config.MinLength,
		MaxLength:        s.config.MaxLength,
		RequireUppercase: s.config.RequireUppercase,
		RequireLowercase: s.config.RequireLowercase,
		RequireDigit:     s.config.RequireDigit,
		RequireSpecial:   s.config.RequireSpecial,
		PreventReuse:     s.config.PreventReuse,
		MaxAge:           s.config.ExpiryDays,
	}, nil
}

// GenerateTemporaryPassword generates a temporary password for user
func (s *passwordService) GenerateTemporaryPassword(ctx context.Context, userID xid.ID) (string, error) {
	// Generate a secure temporary password
	tempPassword, err := s.GenerateSecurePassword(12)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternalServer, "failed to generate temporary password")
	}

	// Set the temporary password
	err = s.SetPassword(ctx, userID, model.SetPasswordRequest{
		Password:  tempPassword,
		Temporary: true,
	})
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternalServer, "failed to set temporary password")
	}

	return tempPassword, nil
}

// IsTemporaryPassword checks if user has temporary password
func (s *passwordService) IsTemporaryPassword(ctx context.Context, userID xid.ID) (bool, error) {
	// TODO: Check temporary password flag from user schema
	// For now, return false
	return false, nil
}

// Helper methods

func (s *passwordService) findUserByEmail(ctx context.Context, email string) (*model.User, error) {
	// This is similar to auth service, might want to extract to common utility
	// Try external user first
	user, err := s.userService.GetUserByEmail(ctx, email, model.UserTypeExternal, nil)
	if err == nil && user != nil {
		return user, nil
	}

	// Try internal user
	user, err = s.userService.GetUserByEmail(ctx, email, model.UserTypeInternal, nil)
	if err == nil && user != nil {
		return user, nil
	}

	return nil, nil
}

func (s *passwordService) generateResetToken() (string, error) {
	// Generate cryptographically secure token
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("reset_%s", base64.URLEncoding.EncodeToString(bytes)), nil
}

func (s *passwordService) secureRandomInt(max int) (int, error) {
	bytes := make([]byte, 4)
	_, err := rand.Read(bytes)
	if err != nil {
		return 0, err
	}

	// Convert bytes to int and mod by max
	randomInt := int(bytes[0])<<24 | int(bytes[1])<<16 | int(bytes[2])<<8 | int(bytes[3])
	if randomInt < 0 {
		randomInt = -randomInt
	}

	return randomInt % max, nil
}

func (s *passwordService) checkCommonPatterns(password string) error {
	// Convert to lowercase for checking
	lower := strings.ToLower(password)

	// Check for common weak patterns
	commonPatterns := []string{
		"password", "123456", "qwerty", "abc123", "admin", "user",
		"login", "welcome", "master", "secret", "guest", "root"}

	for _, pattern := range commonPatterns {
		if strings.Contains(lower, pattern) {
			return errors.New(errors.CodePasswordTooWeak, "password contains common pattern")
		}
	}

	// Check for simple sequences
	if s.containsSequence(password, 3) {
		return errors.New(errors.CodePasswordTooWeak, "password contains simple sequence")
	}

	// Check for repeated characters
	if s.containsRepeatedChars(password, 3) {
		return errors.New(errors.CodePasswordTooWeak, "password contains too many repeated characters")
	}

	return nil
}

func (s *passwordService) containsSequence(password string, minLength int) bool {
	if len(password) < minLength {
		return false
	}

	for i := 0; i <= len(password)-minLength; i++ {
		isSequence := true
		for j := 1; j < minLength; j++ {
			if password[i+j] != password[i]+byte(j) {
				isSequence = false
				break
			}
		}
		if isSequence {
			return true
		}
	}

	return false
}

func (s *passwordService) containsRepeatedChars(password string, maxRepeats int) bool {
	if len(password) < maxRepeats {
		return false
	}

	count := 1
	for i := 1; i < len(password); i++ {
		if password[i] == password[i-1] {
			count++
			if count >= maxRepeats {
				return true
			}
		} else {
			count = 1
		}
	}

	return false
}

func isSpecialCharacter(r rune) bool {
	// Define special characters
	specialChars := "!@#$%^&*()_+-=[]{}|;:,.<>?"
	return strings.ContainsRune(specialChars, r)
}

func (s *passwordService) getIPFromContext(ctx context.Context) string {
	ip, _ := contexts.GetIPAddressFromContext(ctx)
	return ip
}

func (s *passwordService) getUserAgentFromContext(ctx context.Context) string {
	ag, _ := contexts.GetUserAgentFromContext(ctx)
	return ag
}

// Audit methods
func (s *passwordService) auditPasswordResetInitiated(ctx context.Context, userID xid.ID, email string) {
	// TODO: Implement audit logging
}

func (s *passwordService) auditPasswordReset(ctx context.Context, userID xid.ID) {
	// TODO: Implement audit logging
}

func (s *passwordService) auditPasswordChange(ctx context.Context, userID xid.ID) {
	// TODO: Implement audit logging
}

func (s *passwordService) auditPasswordSet(ctx context.Context, userID xid.ID, temporary bool) {
	// TODO: Implement audit logging
}
