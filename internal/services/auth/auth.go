package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/ent/userpermission"
	"github.com/juicycleff/frank/internal/model"
	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/internal/services/audit"
	"github.com/juicycleff/frank/internal/services/mfa"
	"github.com/juicycleff/frank/internal/services/notification"
	"github.com/juicycleff/frank/internal/services/oauth"
	userService "github.com/juicycleff/frank/internal/services/user"
	"github.com/juicycleff/frank/pkg/crypto"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
	"github.com/samber/lo"
)

// AuthService defines the interface for authentication operations
type AuthService interface {
	// Authentication
	Login(ctx context.Context, req model.LoginRequest) (*model.LoginResponse, error)
	Register(ctx context.Context, req model.RegisterRequest) (*model.RegisterResponse, error)
	Logout(ctx context.Context, req model.LogoutRequest) (*model.LogoutResponse, error)
	RefreshToken(ctx context.Context, req model.RefreshTokenRequest) (*model.RefreshTokenResponse, error)

	// Passwordless Authentication
	SendMagicLink(ctx context.Context, req model.MagicLinkRequest) (*model.MagicLinkResponse, error)
	VerifyMagicLink(ctx context.Context, token string) (*model.LoginResponse, error)

	// Email/Phone Verification
	SendVerification(ctx context.Context, userID xid.ID, verificationType string) error
	VerifyEmail(ctx context.Context, req model.VerificationRequest) (*model.VerificationResponse, error)
	VerifyPhone(ctx context.Context, req model.VerificationRequest) (*model.VerificationResponse, error)
	ResendVerification(ctx context.Context, req model.ResendVerificationRequest) (*model.ResendVerificationResponse, error)

	// Authentication Status
	GetAuthStatus(ctx context.Context, userID xid.ID, ctxType userpermission.ContextType, sessionId *xid.ID, contextId *xid.ID) (*model.AuthStatus, error)
	ValidateSession(ctx context.Context, sessionToken string) (*model.Session, error)

	// MFA Support
	InitiateMFA(ctx context.Context, userID xid.ID, method string) error
	ValidateMFA(ctx context.Context, userID xid.ID, token, method string) (bool, error)

	// OAuth Integration
	HandleOAuthCallback(ctx context.Context, provider, code, state string) (*model.LoginResponse, error)
	GetOAuthURL(ctx context.Context, provider, redirectURL string) (string, error)
}

// authService implements the AuthService interface
type authService struct {
	cfg                 *config.Config
	verificationRepo    repository.VerificationRepository
	membershipRepo      repository.MembershipRepository
	repo                repository.Repository
	tokenService        TokenService
	passwordService     PasswordService
	sessionService      SessionService
	userService         userService.Service
	mfaService          mfa.Service
	oauthService        oauth.Service
	auditService        audit.Service
	crypto              crypto.Util
	notificationService notification.Service
	logger              logging.Logger
}

// NewAuthService creates a new authentication service
func NewAuthService(
	cfg *config.Config,
	repo repository.Repository,
	tokenService TokenService,
	passwordService PasswordService,
	sessionService SessionService,
	userService userService.Service,
	notificationService notification.Service,
	mfaService mfa.Service,
	oauthService oauth.Service,
	auditService audit.Service,
	crypto crypto.Util,
	logger logging.Logger,
) AuthService {
	return &authService{
		cfg:                 cfg,
		repo:                repo,
		userService:         userService,
		verificationRepo:    repo.Verification(),
		membershipRepo:      repo.Membership(),
		tokenService:        tokenService,
		passwordService:     passwordService,
		sessionService:      sessionService,
		mfaService:          mfaService,
		auditService:        auditService,
		oauthService:        oauthService,
		notificationService: notificationService,
		crypto:              crypto,
		logger:              logger,
	}
}

// Login authenticates a user and returns tokens and session
func (s *authService) Login(ctx context.Context, req model.LoginRequest) (*model.LoginResponse, error) {
	// Audit log for login attempt
	defer s.auditLoginAttempt(ctx, req.Email, req.IPAddress, req.UserAgent)

	// Validate input
	if req.Email == "" && req.Username == "" && req.PhoneNumber == "" {
		return nil, errors.New(errors.CodeBadRequest, "email, username, or phone number is required")
	}

	// Find user by email, username, or phone
	var foundUser *model.User
	var err error

	if req.Email != "" {
		foundUser, err = s.findUserByEmail(ctx, req.Email)
	} else if req.Username != "" {
		foundUser, err = s.findUserByUsername(ctx, req.Username)
	} else if req.PhoneNumber != "" {
		foundUser, err = s.findUserByPhone(ctx, req.PhoneNumber)
	}

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "invalid credentials")
	}

	if foundUser == nil {
		return nil, errors.New(errors.CodeUnauthorized, "invalid credentials")
	}

	// Check if user is active and not blocked
	if !foundUser.Active {
		return nil, errors.New(errors.CodeUnauthorized, "account is deactivated")
	}

	if foundUser.Blocked {
		return nil, errors.New(errors.CodeUnauthorized, "account is blocked")
	}

	// Handle OAuth provider login
	if req.Provider != "" && req.Provider != "password" && req.Provider != "email" {
		return s.handleOAuthLogin(ctx, req, foundUser)
	}

	// Validate password for regular login
	if req.Password == "" {
		return nil, errors.New(errors.CodeBadRequest, "password is required")
	}

	if !s.passwordService.VerifyPassword(req.Password, foundUser.PasswordHash) {
		return nil, errors.New(errors.CodeUnauthorized, "invalid credentials")
	}

	if !foundUser.EmailVerified && s.cfg.Auth.RequireEmailVerification {
		return &model.LoginResponse{
			VerificationRequired: true,
			VerificationTarget:   "email",
		}, nil
	}

	// Check if MFA is required
	mfaRequired, mfaMethods, err := s.checkMFARequired(ctx, foundUser.ID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to check MFA requirements")
	}

	if mfaRequired && req.MFAToken == "" {
		return &model.LoginResponse{
			MFARequired: true,
			MFAMethods:  mfaMethods,
		}, nil
	}

	// Validate MFA if provided
	if req.MFAToken != "" {
		valid, err := s.ValidateMFA(ctx, foundUser.ID, req.MFAToken, req.MFAMethod)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternalServer, "MFA validation failed")
		}
		if !valid {
			return nil, errors.New(errors.CodeUnauthorized, "invalid MFA token")
		}
	}

	// Update last login
	err = s.userService.UpdateLastLogin(ctx, foundUser.ID, req.IPAddress)
	if err != nil {
		s.logger.Error("failed to update last login", logging.Error(err))
	}

	// Increment login count
	err = s.userService.IncrementLoginCount(ctx, foundUser.ID)
	if err != nil {
		s.logger.Error("failed to increment login count", logging.Error(err))
	}

	// Create session
	sessionInput := repository.CreateSessionInput{
		UserID:         foundUser.ID,
		IPAddress:      &req.IPAddress,
		UserAgent:      &req.UserAgent,
		DeviceID:       &req.DeviceID,
		Location:       &req.Location,
		OrganizationID: foundUser.OrganizationID,
		ExpiresAt:      time.Now().Add(24 * time.Hour), // Default 24 hours
		Metadata: map[string]interface{}{
			"login_method": "password",
			"provider":     req.Provider,
		},
	}

	if req.RememberMe {
		sessionInput.ExpiresAt = time.Now().Add(30 * 24 * time.Hour) // 30 days
	}

	session, err := s.sessionService.CreateSession(ctx, sessionInput)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to create session")
	}

	// Generate tokens
	accessToken, err := s.tokenService.CreateAccessToken(ctx, foundUser.ID, foundUser.OrganizationID, session.ID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to create access token")
	}

	refreshToken, err := s.tokenService.CreateRefreshToken(ctx, foundUser.ID, session.ID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to create refresh token")
	}

	response := &model.LoginResponse{
		AccessToken:  accessToken.Token,
		RefreshToken: refreshToken.Token,
		TokenType:    "Bearer",
		ExpiresIn:    int(time.Until(accessToken.ExpiresAt).Seconds()),
		ExpiresAt:    &accessToken.ExpiresAt,
		User:         foundUser,
		Session:      session,
		MFARequired:  false,
	}

	return response, nil
}

// Register creates a new user account
func (s *authService) Register(ctx context.Context, req model.RegisterRequest) (*model.RegisterResponse, error) {
	// Validate input
	if req.Email == "" {
		return nil, errors.New(errors.CodeBadRequest, "email is required")
	}

	// Check if user already exists
	exists, err := s.userService.ExistsByEmail(ctx, req.Email, user.UserType(req.UserType), req.OrganizationID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to check user existence")
	}

	if exists {
		return nil, errors.New(errors.CodeConflict, "user already exists")
	}

	// Hash password if provided
	var passwordHash string
	if req.Password != "" {
		if err := s.passwordService.ValidatePasswordStrength(req.Password); err != nil {
			return nil, errors.Wrap(err, errors.CodeBadRequest, "password validation failed")
		}

		passwordHash, err = s.passwordService.HashPassword(req.Password)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to hash password")
		}
	}

	// Create user
	userInput := model.CreateUserRequest{
		Email:              req.Email,
		Username:           req.Username,
		PhoneNumber:        req.PhoneNumber,
		FirstName:          req.FirstName,
		LastName:           req.LastName,
		PasswordHash:       passwordHash,
		UserType:           user.UserType(req.UserType),
		OrganizationID:     req.OrganizationID,
		Locale:             req.Locale,
		Timezone:           req.Timezone,
		CustomAttributes:   req.CustomAttributes,
		Active:             true, // Active by default, pending email verification
		EmailVerified:      false,
		PhoneVerified:      false,
		CreatedByIP:        req.IPAddress,
		CreatedByUserAgent: req.UserAgent,
	}

	createdUser, err := s.userService.CreateUser(ctx, userInput)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to create user")
	}

	// Send email verification if required
	var verificationToken string
	emailVerificationRequired := s.cfg.Auth.RequireEmailVerification
	if emailVerificationRequired {
		err = s.SendVerification(ctx, createdUser.ID, "email")
		if err != nil {
			s.logger.Error("failed to send email verification", logging.Error(err))
		}
		// Generate token for response (dev/testing purposes)
		verificationToken = s.generateVerificationToken()
	}

	response := &model.RegisterResponse{
		User:                      *createdUser,
		EmailVerificationRequired: emailVerificationRequired,
		PhoneVerificationRequired: false, // Based on config
		VerificationToken:         verificationToken,
	}

	// Auto-login if not requiring verification
	if !emailVerificationRequired {
		// Create session and tokens for auto-login
		sessionInput := repository.CreateSessionInput{
			UserID:         createdUser.ID,
			IPAddress:      &req.IPAddress,
			UserAgent:      &req.UserAgent,
			OrganizationID: req.OrganizationID,
			ExpiresAt:      time.Now().Add(24 * time.Hour),
			Metadata: map[string]interface{}{
				"login_method": "registration",
			},
		}

		session, err := s.sessionService.CreateSession(ctx, sessionInput)
		if err == nil {
			accessToken, _ := s.tokenService.CreateAccessToken(ctx, createdUser.ID, req.OrganizationID, session.ID)
			refreshToken, _ := s.tokenService.CreateRefreshToken(ctx, createdUser.ID, session.ID)

			if accessToken != nil && refreshToken != nil {
				response.AccessToken = accessToken.Token
				response.RefreshToken = refreshToken.Token
				response.TokenType = "Bearer"
				response.ExpiresIn = int(time.Until(accessToken.ExpiresAt).Seconds())
			}
		}
	}

	// Audit log
	s.auditUserRegistration(ctx, createdUser.ID, req.IPAddress, req.UserAgent)

	return response, nil
}

// Logout invalidates user session and tokens
func (s *authService) Logout(ctx context.Context, req model.LogoutRequest) (*model.LogoutResponse, error) {
	sessionsEnded := 0

	if req.LogoutAll {
		// Get user from session if session ID provided
		if req.SessionID != nil {
			session, err := s.sessionService.GetSession(ctx, *req.SessionID)
			if err == nil && session != nil {
				count, err := s.sessionService.InvalidateAllUserSessions(ctx, session.UserID)
				if err == nil {
					sessionsEnded = count
				}
			}
		}
	} else if req.SessionID != nil {
		// Logout specific session
		err := s.sessionService.InvalidateSession(ctx, *req.SessionID)
		if err == nil {
			sessionsEnded = 1
		}
	}

	// Revoke refresh token if provided
	if req.RefreshToken != "" {
		err := s.tokenService.RevokeRefreshToken(ctx, req.RefreshToken)
		if err != nil {
			s.logger.Error("failed to revoke refresh token", logging.Error(err))
		}
	}

	return &model.LogoutResponse{
		Success:       true,
		SessionsEnded: sessionsEnded,
	}, nil
}

// RefreshToken generates new access token using refresh token
func (s *authService) RefreshToken(ctx context.Context, req model.RefreshTokenRequest) (*model.RefreshTokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, errors.New(errors.CodeBadRequest, "refresh token is required")
	}

	// Validate refresh token
	claims, err := s.tokenService.ValidateRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "invalid refresh token")
	}

	// Get user
	foundUser, err := s.userService.GetUser(ctx, claims.UserID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "user not found")
	}

	// Check if user is still active
	if !foundUser.Active || foundUser.Blocked {
		return nil, errors.New(errors.CodeUnauthorized, "user account is inactive")
	}

	// Create new access token
	accessToken, err := s.tokenService.CreateAccessToken(ctx, foundUser.ID, foundUser.OrganizationID, claims.SessionID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to create access token")
	}

	// Optionally rotate refresh token
	var newRefreshToken string
	rotateRefreshToken := true // From config
	if rotateRefreshToken {
		refreshToken, err := s.tokenService.CreateRefreshToken(ctx, foundUser.ID, claims.SessionID)
		if err == nil {
			newRefreshToken = refreshToken.Token
		}
		// Revoke old refresh token
		_ = s.tokenService.RevokeRefreshToken(ctx, req.RefreshToken)
	}

	response := &model.RefreshTokenResponse{
		AccessToken:  accessToken.Token,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(time.Until(accessToken.ExpiresAt).Seconds()),
		ExpiresAt:    accessToken.ExpiresAt,
	}

	return response, nil
}

// SendMagicLink sends a magic link for passwordless authentication
func (s *authService) SendMagicLink(ctx context.Context, req model.MagicLinkRequest) (*model.MagicLinkResponse, error) {
	if req.Email == "" {
		return nil, errors.New(errors.CodeBadRequest, "email is required")
	}

	// Find user by email
	foundUser, err := s.findUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to find user")
	}

	if foundUser == nil {
		// For security, don't reveal if user exists
		return &model.MagicLinkResponse{
			Success: true,
			Message: "Magic link sent to your email",
		}, nil
	}

	// Generate magic link token
	token := s.generateMagicLinkToken()
	expiresAt := time.Now().Add(15 * time.Minute) // 15 minutes

	attemptCount := 0

	// Store verification token
	verificationInput := repository.CreateVerificationInput{
		UserID:       foundUser.ID,
		Email:        req.Email,
		Token:        token,
		Type:         "magic_link",
		ExpiresAt:    expiresAt,
		AttemptCount: &attemptCount,
		Used:         false,
		Metadata: map[string]interface{}{
			"redirect_url": req.RedirectURL,
		},
	}

	_, err = s.verificationRepo.Create(ctx, verificationInput)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to create verification")
	}

	// Send email with magic link
	err = s.notificationService.Email().SendMagicLinkEmail(ctx, foundUser, token, req.RedirectURL)
	if err != nil {
		return nil, err
	}

	return &model.MagicLinkResponse{
		Success: true,
		Message: "Magic link sent to your email",
		Token:   token, // For dev/testing
	}, nil
}

// VerifyMagicLink verifies magic link token and logs user in
func (s *authService) VerifyMagicLink(ctx context.Context, token string) (*model.LoginResponse, error) {
	if token == "" {
		return nil, errors.New(errors.CodeBadRequest, "token is required")
	}

	// Get verification
	verification, err := s.verificationRepo.GetValidToken(ctx, token)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "invalid or expired token")
	}

	if verification.Type != "magic_link" {
		return nil, errors.New(errors.CodeBadRequest, "invalid token type")
	}

	// Get user
	foundUser, err := s.userService.GetUser(ctx, verification.UserID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "user not found")
	}

	// Mark token as used
	err = s.verificationRepo.MarkTokenAsUsed(ctx, token)
	if err != nil {
		s.logger.Error("failed to mark verification as used", logging.Error(err))
	}

	// Create session
	sessionInput := repository.CreateSessionInput{
		UserID:         foundUser.ID,
		OrganizationID: foundUser.OrganizationID,
		ExpiresAt:      time.Now().Add(24 * time.Hour),
		Metadata: map[string]interface{}{
			"login_method": "magic_link",
		},
	}

	session, err := s.sessionService.CreateSession(ctx, sessionInput)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to create session")
	}

	// Generate tokens
	accessToken, err := s.tokenService.CreateAccessToken(ctx, foundUser.ID, foundUser.OrganizationID, session.ID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to create access token")
	}

	refreshToken, err := s.tokenService.CreateRefreshToken(ctx, foundUser.ID, session.ID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to create refresh token")
	}

	return &model.LoginResponse{
		AccessToken:  accessToken.Token,
		RefreshToken: refreshToken.Token,
		TokenType:    "Bearer",
		ExpiresIn:    int(time.Until(accessToken.ExpiresAt).Seconds()),
		ExpiresAt:    &accessToken.ExpiresAt,
		User:         foundUser,
		Session:      session,
	}, nil
}

func (s *authService) findUserByEmail(ctx context.Context, email string) (*model.User, error) {
	// Try external user first
	foundUser, err := s.userService.GetUserByEmail(ctx, email, user.UserTypeExternal, nil)
	if err == nil && foundUser != nil {
		return foundUser, nil
	}

	// Try internal user
	foundUser, err = s.userService.GetUserByEmail(ctx, email, user.UserTypeInternal, nil)
	if err == nil && foundUser != nil {
		return foundUser, nil
	}

	return nil, nil
}

func (s *authService) findUserByUsername(ctx context.Context, username string) (*model.User, error) {
	// Try external user first
	foundUser, err := s.userService.GetUserByUsername(ctx, username, user.UserTypeExternal, nil)
	if err == nil && foundUser != nil {
		return foundUser, nil
	}

	// Try internal user
	foundUser, err = s.userService.GetUserByUsername(ctx, username, user.UserTypeInternal, nil)
	if err == nil && foundUser != nil {
		return foundUser, nil
	}

	return nil, nil
}

func (s *authService) findUserByPhone(ctx context.Context, phone string) (*model.User, error) {
	// Try external user first
	foundUser, err := s.userService.GetUserByPhone(ctx, phone, user.UserTypeExternal, nil)
	if err == nil && foundUser != nil {
		return foundUser, nil
	}

	// Try internal user
	foundUser, err = s.userService.GetUserByPhone(ctx, phone, user.UserTypeInternal, nil)
	if err == nil && foundUser != nil {
		return foundUser, nil
	}

	return nil, nil
}

func (s *authService) handleOAuthLogin(ctx context.Context, req model.LoginRequest, user *model.User) (*model.LoginResponse, error) {
	// TODO: Implement OAuth login flow
	return nil, errors.New(errors.CodeNotImplemented, "OAuth login not implemented")
}

func (s *authService) checkMFARequired(ctx context.Context, userID xid.ID) (bool, []model.MFAInfo, error) {
	// Check if user has MFA methods configured
	mfaMethods, err := s.mfaService.ListUserMFAMethods(ctx, userID)
	if err != nil {
		return false, nil, err
	}

	if len(mfaMethods) == 0 {
		return false, nil, nil
	}

	// Convert to model
	var methods []model.MFAInfo
	for _, method := range mfaMethods {
		methods = append(methods, model.MFAInfo{
			Method:   method.Method,
			Enabled:  method.Active,
			Verified: method.Verified,
		})
	}

	return true, methods, nil
}

func (s *authService) convertUserToModel(user *ent.User) *model.User {
	return &model.User{
		Base: model.Base{
			ID:        user.ID,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
		},
		Email:         user.Email,
		Username:      user.Username,
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		EmailVerified: user.EmailVerified,
		PhoneVerified: user.PhoneVerified,
		Active:        user.Active,
		Blocked:       user.Blocked,
		LastLogin:     user.LastLogin,
		UserType:      string(user.UserType),
		Locale:        user.Locale,
		Timezone:      user.Timezone,
	}
}

func (s *authService) convertSessionToModel(session *ent.Session) *model.Session {
	return &model.Session{
		Base: model.Base{
			ID:        session.ID,
			CreatedAt: session.CreatedAt,
			UpdatedAt: session.UpdatedAt,
		},
		UserID:         session.UserID,
		Token:          session.Token,
		IPAddress:      session.IPAddress,
		UserAgent:      session.UserAgent,
		DeviceID:       session.DeviceID,
		Location:       session.Location,
		OrganizationID: &session.OrganizationID,
		Active:         session.Active,
		ExpiresAt:      session.ExpiresAt,
		LastActiveAt:   session.LastActiveAt,
	}
}

func (s *authService) generateVerificationToken() string {
	return fmt.Sprintf("verify_%s", xid.New().String())
}

func (s *authService) generateMagicLinkToken() string {
	return fmt.Sprintf("magic_%s", xid.New().String())
}

func (s *authService) auditLoginAttempt(ctx context.Context, email, ip, userAgent string) {
	// TODO: Implement audit logging
}

func (s *authService) auditUserRegistration(ctx context.Context, userID xid.ID, ip, userAgent string) {
	// TODO: Implement audit logging
}

// Additional interface methods (placeholders for now)

func (s *authService) SendVerification(ctx context.Context, userID xid.ID, verificationType string) error {
	if verificationType == "" {
		return errors.New(errors.CodeBadRequest, "verification type is required")
	}

	// Get user
	user, err := s.userService.GetUser(ctx, userID)
	if err != nil {
		return errors.Wrap(err, errors.CodeBadRequest, "user not found")
	}

	// Check if user is active
	if !user.Active {
		return errors.New(errors.CodeBadRequest, "user account is inactive")
	}

	// Generate verification token
	token := s.generateVerificationToken()
	expiresAt := time.Now().Add(24 * time.Hour) // 24 hours expiration
	attemptCount := 0

	var verificationInput repository.CreateVerificationInput

	switch verificationType {
	case "email":
		if user.Email == "" {
			return errors.New(errors.CodeBadRequest, "user has no email address")
		}

		if user.EmailVerified {
			return errors.New(errors.CodeBadRequest, "email is already verified")
		}

		code, err := s.crypto.Random().GenerateOTP(6)
		if err != nil {
			return errors.Wrap(err, errors.CodeInternalServer, "failed to generate OTP")
		}

		verificationInput = repository.CreateVerificationInput{
			UserID:       userID,
			Email:        user.Email,
			Token:        token,
			Type:         "email",
			ExpiresAt:    expiresAt,
			AttemptCount: &attemptCount,
			Used:         false,
			Metadata: map[string]interface{}{
				"user_id":    userID.String(),
				"code":       code,
				"email":      user.Email,
				"created_at": time.Now(),
				"methods":    []string{"token", "code"}, // Both methods available
			},
		}

		// Send verification email
		err = s.notificationService.Email().SendVerificationEmail(ctx, user, token, code, "")
		if err != nil {
			return errors.Wrap(err, errors.CodeInternalServer, "failed to send verification email")
		}

	case "phone", "sms":
		if user.PhoneNumber == "" {
			return errors.New(errors.CodeBadRequest, "user has no phone number")
		}

		if user.PhoneVerified {
			return errors.New(errors.CodeBadRequest, "phone is already verified")
		}

		// Generate numeric code for SMS
		code, err := s.crypto.Random().GenerateOTP(6)
		if err != nil {
			return errors.Wrap(err, errors.CodeInternalServer, "failed to generate OTP")
		}

		verificationInput = repository.CreateVerificationInput{
			UserID:       userID,
			PhoneNumber:  &user.PhoneNumber,
			Token:        code, // Use numeric code for SMS
			Type:         "phone",
			ExpiresAt:    time.Now().Add(10 * time.Minute), // 10 minutes for SMS
			AttemptCount: &attemptCount,
			Used:         false,
			Metadata: map[string]interface{}{
				"user_id":      userID.String(),
				"phone_number": user.PhoneNumber,
				"created_at":   time.Now(),
			},
		}

		// Convert model.User to ent.User for SMS service
		entUser := &ent.User{
			ID:          user.ID,
			Email:       user.Email,
			FirstName:   user.FirstName,
			LastName:    user.LastName,
			PhoneNumber: user.PhoneNumber,
			Username:    user.Username,
		}

		// Send verification SMS
		err = s.notificationService.SMS().SendVerificationSMS(ctx, entUser, code)
		if err != nil {
			return errors.Wrap(err, errors.CodeInternalServer, "failed to send verification SMS")
		}

	default:
		return errors.New(errors.CodeBadRequest, "invalid verification type")
	}

	// Store verification record
	_, err = s.verificationRepo.Create(ctx, verificationInput)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to create verification record")
	}

	// Audit log
	s.auditVerificationSent(ctx, userID, verificationType)

	return nil
}

func (s *authService) VerifyEmail(ctx context.Context, req model.VerificationRequest) (*model.VerificationResponse, error) {
	if req.Token == "" {
		return nil, errors.New(errors.CodeBadRequest, "verification token or code is required")
	}

	var verification *ent.Verification
	var err error
	var verificationMethod string

	// Determine if input is a code (6 digits) or token (longer string)
	if s.isNumericCode(req.Token, 6) {
		// Input is a verification code - find by code in metadata
		verification, err = s.verificationRepo.GetValidTokenByCode(ctx, req.Token, "email")
		verificationMethod = "code"
	} else {
		// Input is a verification token - find by token
		verification, err = s.verificationRepo.GetValidToken(ctx, req.Token)
		verificationMethod = "token"
	}

	if err != nil {
		return &model.VerificationResponse{
			Success:  false,
			Message:  "Invalid or expired verification token/code",
			Verified: false,
		}, nil
	}

	if verification.Type != "email" {
		return &model.VerificationResponse{
			Success:  false,
			Message:  "Invalid verification type",
			Verified: false,
		}, nil
	}

	if verification.Used {
		return &model.VerificationResponse{
			Success:  false,
			Message:  "Verification token/code has already been used",
			Verified: false,
		}, nil
	}

	// Get user
	user, err := s.userService.GetUser(ctx, verification.UserID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "user not found")
	}

	// Check if email is already verified
	if user.EmailVerified {
		// Mark token as used anyway
		_ = s.verificationRepo.MarkTokenAsUsed(ctx, req.Token)

		return &model.VerificationResponse{
			Success:  true,
			Message:  "Email is already verified",
			Verified: true,
			User:     user,
		}, nil
	}

	// Update user email verification status
	err = s.repo.User().MarkEmailVerified(ctx, verification.UserID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to update user verification status")
	}

	// Mark token as used
	err = s.verificationRepo.MarkTokenAsUsed(ctx, req.Token)
	if err != nil {
		s.logger.Error("failed to mark verification token as used", logging.Error(err))
	}

	// Get updated user
	updatedUser, err := s.userService.GetUser(ctx, verification.UserID)
	if err != nil {
		updatedUser = user // Use original user if we can't get updated one
	}

	// Audit log with verification method
	s.auditEmailVerified(ctx, verification.UserID, verificationMethod)

	// Send welcome email if this was the initial verification
	if s.cfg.Auth.SendWelcomeEmail {
		go func() {
			err := s.notificationService.Email().SendWelcomeEmail(context.Background(), updatedUser, "")
			if err != nil {
				s.logger.Error("failed to send welcome email", logging.Error(err))
			}
		}()
	}

	return &model.VerificationResponse{
		Success:  true,
		Message:  "Email verified successfully",
		Verified: true,
		User:     updatedUser,
	}, nil
}

func (s *authService) VerifyPhone(ctx context.Context, req model.VerificationRequest) (*model.VerificationResponse, error) {
	if req.Token == "" {
		return nil, errors.New(errors.CodeBadRequest, "verification code is required")
	}

	// Get verification record
	verification, err := s.verificationRepo.GetValidToken(ctx, req.Token)
	if err != nil {
		return &model.VerificationResponse{
			Success:  false,
			Message:  "Invalid or expired verification code",
			Verified: false,
		}, nil
	}

	if verification.Type != "phone" {
		return &model.VerificationResponse{
			Success:  false,
			Message:  "Invalid verification type",
			Verified: false,
		}, nil
	}

	if verification.Used {
		return &model.VerificationResponse{
			Success:  false,
			Message:  "Verification code has already been used",
			Verified: false,
		}, nil
	}

	// Get user
	user, err := s.userService.GetUser(ctx, verification.UserID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "user not found")
	}

	// Check if phone is already verified
	if user.PhoneVerified {
		// Mark token as used anyway
		_ = s.verificationRepo.MarkTokenAsUsed(ctx, req.Token)

		return &model.VerificationResponse{
			Success:  true,
			Message:  "Phone number is already verified",
			Verified: true,
			User:     user,
		}, nil
	}

	// Update user phone verification status
	err = s.repo.User().MarkPhoneVerified(ctx, verification.UserID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to update user verification status")
	}

	// Mark token as used
	err = s.verificationRepo.MarkTokenAsUsed(ctx, req.Token)
	if err != nil {
		s.logger.Error("failed to mark verification token as used", logging.Error(err))
	}

	// Get updated user
	updatedUser, err := s.userService.GetUser(ctx, verification.UserID)
	if err != nil {
		updatedUser = user // Use original user if we can't get updated one
	}

	// Audit log
	s.auditPhoneVerified(ctx, verification.UserID)

	return &model.VerificationResponse{
		Success:  true,
		Message:  "Phone number verified successfully",
		Verified: true,
		User:     updatedUser,
	}, nil
}

func (s *authService) ResendVerification(ctx context.Context, req model.ResendVerificationRequest) (*model.ResendVerificationResponse, error) {
	if req.Type == "" {
		return nil, errors.New(errors.CodeBadRequest, "verification type is required")
	}

	var user *model.User
	var err error

	// Find user by email or phone
	switch req.Type {
	case "email":
		if req.Email == "" {
			return nil, errors.New(errors.CodeBadRequest, "email is required for email verification")
		}

		user, err = s.findUserByEmail(ctx, req.Email)
		if err != nil || user == nil {
			// Don't reveal if user exists for security
			return &model.ResendVerificationResponse{
				Success: true,
				Message: "If the email exists in our system, a verification email has been sent",
			}, nil
		}

		if user.EmailVerified {
			return &model.ResendVerificationResponse{
				Success: false,
				Message: "Email is already verified",
			}, nil
		}

	case "phone", "sms":
		if req.PhoneNumber == "" {
			return nil, errors.New(errors.CodeBadRequest, "phone number is required for phone verification")
		}

		user, err = s.findUserByPhone(ctx, req.PhoneNumber)
		if err != nil || user == nil {
			// Don't reveal if user exists for security
			return &model.ResendVerificationResponse{
				Success: true,
				Message: "If the phone number exists in our system, a verification code has been sent",
			}, nil
		}

		if user.PhoneVerified {
			return &model.ResendVerificationResponse{
				Success: false,
				Message: "Phone number is already verified",
			}, nil
		}

	default:
		return nil, errors.New(errors.CodeBadRequest, "invalid verification type")
	}

	before := time.Now().Add(-1 * time.Hour)

	// Check rate limiting - prevent abuse
	existingVerifications, err := s.verificationRepo.ListByUserID(ctx, user.ID, repository.ListVerificationFilter{
		Type:   &req.Type,
		Before: &before,
	})
	if err != nil {
		s.logger.Error("failed to check recent verifications", logging.Error(err))
	} else if len(existingVerifications.Data) >= 3 {
		return &model.ResendVerificationResponse{
			Success: false,
			Message: "Too many verification attempts. Please wait before requesting another verification",
		}, nil
	}

	// Invalidate existing unused verifications of the same type
	_, err = s.verificationRepo.InvalidateUserVerifications(ctx, user.ID, req.Type)
	if err != nil {
		s.logger.Error("failed to invalidate existing verifications", logging.Error(err))
	}

	// Send new verification
	err = s.SendVerification(ctx, user.ID, req.Type)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to send verification")
	}

	var message string
	switch req.Type {
	case "email":
		message = "Verification email sent successfully"
	case "phone", "sms":
		message = "Verification code sent successfully"
	default:
		message = "Verification sent successfully"
	}

	return &model.ResendVerificationResponse{
		Success: true,
		Message: message,
	}, nil
}

func (s *authService) GetAuthStatus(
	ctx context.Context,
	userID xid.ID,
	ctxType userpermission.ContextType,
	sessionId *xid.ID,
	contextId *xid.ID,
) (*model.AuthStatus, error) {

	user, err := s.userService.GetUser(ctx, userID)
	if err != nil {
		return &model.AuthStatus{
			IsAuthenticated: false,
		}, nil
	}

	permissions, err := s.userService.GetUserPermissions(ctx, userID, string(ctxType), contextId)
	if err != nil {
		return &model.AuthStatus{
			IsAuthenticated: false,
		}, nil
	}

	roles, err := s.userService.GetUserRoles(ctx, userID, string(ctxType), contextId)
	if err != nil {
		return &model.AuthStatus{
			IsAuthenticated: false,
		}, nil
	}

	var session *model.Session
	if sessionId != nil {
		session, err = s.sessionService.GetSession(ctx, *sessionId)
		if err != nil {
			return &model.AuthStatus{
				IsAuthenticated: false,
			}, nil
		}
	}

	return &model.AuthStatus{
		IsAuthenticated: true,
		User:            user,
		Permissions: lo.Map(permissions, func(item model.UserPermissionAssignment, index int) string {
			return item.PermissionName
		}),
		Roles: lo.Map(roles, func(item model.UserRoleAssignment, index int) model.RoleInfo {
			return model.RoleInfo{
				ID:          item.RoleID,
				ContextID:   item.ContextID,
				DisplayName: item.DisplayName,
				Context:     item.ContextID.String(),
				Name:        item.RoleName,
			}
		}),
		Session: session,
	}, nil
}

func (s *authService) ValidateSession(ctx context.Context, sessionToken string) (*model.Session, error) {
	return s.sessionService.ValidateSession(ctx, sessionToken)
}

func (s *authService) InitiateMFA(ctx context.Context, userID xid.ID, method string) error {
	// TODO: Implement MFA initiation
	return errors.New(errors.CodeNotImplemented, "not implemented")
}

func (s *authService) ValidateMFA(ctx context.Context, userID xid.ID, token, method string) (bool, error) {
	val, err := s.mfaService.VerifyMFA(ctx, userID, token, method)
	if err != nil {
		return false, err
	}

	return val.Success, nil
}

func (s *authService) HandleOAuthCallback(ctx context.Context, provider, code, state string) (*model.LoginResponse, error) {
	// TODO: Implement OAuth callback logic
	// 1. Validate state parameter
	// 2. Exchange code for tokens
	// 3. Get user info from provider
	// 4. Create or link user account
	// 5. Return authentication tokens

	return nil, errors.New(errors.CodeNotImplemented, "not implemented")
}

func (s *authService) GetOAuthURL(ctx context.Context, provider, redirectURL string) (string, error) {
	// TODO: Implement OAuth authorize logic
	// 1. Validate OAuth provider
	// 2. Generate state parameter
	// 3. Redirect to OAuth provider

	return "", errors.New(errors.CodeNotImplemented, "not implemented")
}

func (s *authService) isNumericCode(input string, expectedLength int) bool {
	if len(input) != expectedLength {
		return false
	}

	for _, char := range input {
		if char < '0' || char > '9' {
			return false
		}
	}

	return true
}

// Audit methods for verification

func (s *authService) auditVerificationSent(ctx context.Context, userID xid.ID, verificationType string) {
	// TODO: Implement audit logging
	s.logger.Info("verification sent",
		logging.String("user_id", userID.String()),
		logging.String("type", verificationType),
	)
}

func (s *authService) auditEmailVerified(ctx context.Context, userID xid.ID, method ...string) {
	// TODO: Implement audit logging
	verificationMethod := "token"
	if len(method) > 0 {
		verificationMethod = method[0]
	}

	s.logger.Info("email verified",
		logging.String("user_id", userID.String()),
		logging.String("method", verificationMethod),
	)
}

func (s *authService) auditPhoneVerified(ctx context.Context, userID xid.ID) {
	// TODO: Implement audit logging
	s.logger.Info("phone verified",
		logging.String("user_id", userID.String()),
	)
}
