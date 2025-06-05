package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/session"
	"github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/ent/verification"
	"github.com/juicycleff/frank/pkg/crypto"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
)

// Service handles authentication operations
type Service struct {
	db     *ent.Client
	config *config.Config
	logger logging.Logger
}

// NewService creates a new authentication service
func NewService(db *ent.Client, config *config.Config, logger logging.Logger) *Service {
	return &Service{
		db:     db,
		config: config,
		logger: logger,
	}
}

// Authentication Models

// LoginInput represents login request data
type LoginInput struct {
	Email        string  `json:"email" validate:"required,email"`
	Password     string  `json:"password" validate:"required"`
	RememberMe   bool    `json:"remember_me"`
	UserAgent    *string `json:"user_agent,omitempty"`
	IPAddress    *string `json:"ip_address,omitempty"`
	DeviceID     *string `json:"device_id,omitempty"`
	Organization *string `json:"organization,omitempty"` // Optional org slug for context
}

// LoginResponse represents successful login response
type LoginResponse struct {
	AccessToken          string            `json:"access_token"`
	RefreshToken         string            `json:"refresh_token"`
	TokenType            string            `json:"token_type"`
	ExpiresIn            int               `json:"expires_in"`
	User                 *ent.User         `json:"user"`
	RequiresMFA          bool              `json:"requires_mfa"`
	RequiresVerification bool              `json:"requires_verification"`
	AvailableMFAMethods  []string          `json:"available_mfa_methods,omitempty"`
	Session              *ent.Session      `json:"session"`
	Organizations        []*ent.Membership `json:"organizations,omitempty"`
}

// MFALoginInput represents MFA login request
type MFALoginInput struct {
	SessionToken string `json:"session_token" validate:"required"`
	Code         string `json:"code" validate:"required"`
	Method       string `json:"method" validate:"required,oneof=totp sms email backup_code"`
	RememberMe   bool   `json:"remember_me"`
}

// RefreshTokenInput represents refresh token request
type RefreshTokenInput struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// LogoutInput represents logout request
type LogoutInput struct {
	RefreshToken *string `json:"refresh_token,omitempty"`
	AllSessions  bool    `json:"all_sessions"`
}

// VerifyEmailInput represents email verification request
type VerifyEmailInput struct {
	Token string `json:"token" validate:"required"`
}

// RegisterInput represents user registration request
type RegisterInput struct {
	Email           string                 `json:"email" validate:"required,email"`
	Password        string                 `json:"password" validate:"required,min=8"`
	FirstName       *string                `json:"first_name,omitempty"`
	LastName        *string                `json:"last_name,omitempty"`
	Username        *string                `json:"username,omitempty"`
	PhoneNumber     *string                `json:"phone_number,omitempty"`
	OrganizationID  *xid.ID                `json:"organization_id,omitempty"`
	InvitationToken *string                `json:"invitation_token,omitempty"`
	UserAgent       *string                `json:"user_agent,omitempty"`
	IPAddress       *string                `json:"ip_address,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// JWT Claims
type Claims struct {
	UserID         string   `json:"user_id"`
	Email          string   `json:"email"`
	UserType       string   `json:"user_type"`
	OrganizationID *string  `json:"organization_id,omitempty"`
	Organizations  []string `json:"organizations,omitempty"`
	SessionID      string   `json:"session_id"`
	TokenType      string   `json:"token_type"` // "access" or "refresh"
	jwt.RegisteredClaims
}

// Login authenticates a user and returns tokens
func (s *Service) Login(ctx context.Context, input LoginInput) (*LoginResponse, error) {
	// Find user by email
	var foundUser *ent.User
	var err error

	if input.Organization != nil {
		// Look for user in specific organization context
		foundUser, err = s.db.User.Query().
			Where(
				user.Email(input.Email),
				user.Active(true),
				user.Blocked(false),
			).
			WithOrganization().
			WithMemberships(func(q *ent.MembershipQuery) {
				q.WithOrganization()
			}).
			First(ctx)
	} else {
		// Find user globally
		foundUser, err = s.db.User.Query().
			Where(
				user.Email(input.Email),
				user.Active(true),
				user.Blocked(false),
			).
			WithOrganization().
			WithMemberships(func(q *ent.MembershipQuery) {
				q.WithOrganization()
			}).
			First(ctx)
	}

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeInvalidCredentials, "invalid email or password")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to find user")
	}

	// Verify password
	if foundUser.PasswordHash == "" || crypto.VerifyPassword(input.Password, foundUser.PasswordHash) != nil {
		return nil, errors.New(errors.CodeInvalidCredentials, "invalid email or password")
	}

	// Check if email verification is required
	if s.config.Auth.RequireEmailVerification && !foundUser.EmailVerified {
		return &LoginResponse{
			RequiresVerification: true,
			User:                 foundUser,
		}, nil
	}

	// Check if MFA is required
	hasMFA, mfaMethods, err := s.checkMFARequirement(ctx, foundUser.ID)
	if err != nil {
		return nil, err
	}

	if hasMFA {
		// Create temporary session for MFA
		tempSession, err := s.createTempSession(ctx, foundUser, input.UserAgent, input.IPAddress, input.DeviceID)
		if err != nil {
			return nil, err
		}

		return &LoginResponse{
			RequiresMFA:         true,
			AvailableMFAMethods: mfaMethods,
			Session:             tempSession,
			User:                foundUser,
		}, nil
	}

	// Create full session and tokens
	return s.createSuccessfulLoginResponse(ctx, foundUser, input.RememberMe, input.UserAgent, input.IPAddress, input.DeviceID)
}

// LoginWithMFA completes login with MFA verification
func (s *Service) LoginWithMFA(ctx context.Context, input MFALoginInput) (*LoginResponse, error) {
	// Find temporary session
	tempSession, err := s.db.Session.Query().
		Where(
			session.Token(input.SessionToken),
			session.Active(true),
			session.ExpiresAtGT(time.Now()),
		).
		WithUser(func(q *ent.UserQuery) {
			q.WithOrganization().WithMemberships(func(mq *ent.MembershipQuery) {
				mq.WithOrganization()
			})
		}).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeInvalidToken, "invalid or expired session token")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to find session")
	}

	// Verify MFA code
	if err := s.verifyMFACode(ctx, tempSession.Edges.User.ID, input.Method, input.Code); err != nil {
		return nil, err
	}

	// Delete temporary session
	if err := s.db.Session.DeleteOne(tempSession).Exec(ctx); err != nil {
		s.logger.Warn("Failed to delete temporary session", logging.Error(err))
	}

	// Create full session and tokens
	return s.createSuccessfulLoginResponse(ctx, tempSession.Edges.User, input.RememberMe, nil, nil, nil)
}

// RefreshToken refreshes access token using refresh token
func (s *Service) RefreshToken(ctx context.Context, input RefreshTokenInput) (*LoginResponse, error) {
	// Parse and validate refresh token
	claims, err := s.parseToken(input.RefreshToken)
	if err != nil {
		return nil, errors.New(errors.CodeInvalidToken, "invalid refresh token")
	}

	if claims.TokenType != "refresh" {
		return nil, errors.New(errors.CodeInvalidToken, "invalid token type")
	}

	// Find user and session
	userID, err := xid.FromString(claims.UserID)
	if err != nil {
		return nil, errors.New(errors.CodeInvalidToken, "invalid user ID in token")
	}

	sessionID, err := xid.FromString(claims.SessionID)
	if err != nil {
		return nil, errors.New(errors.CodeInvalidToken, "invalid session ID in token")
	}

	// Verify session is still active
	activeSession, err := s.db.Session.Query().
		Where(
			session.ID(sessionID),
			session.UserID(userID),
			session.Active(true),
			session.ExpiresAtGT(time.Now()),
		).
		WithUser(func(q *ent.UserQuery) {
			q.WithOrganization().WithMemberships(func(mq *ent.MembershipQuery) {
				mq.WithOrganization()
			})
		}).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeSessionExpired, "session expired or invalid")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to find session")
	}

	// Check if user is still active
	if !activeSession.Edges.User.Active || activeSession.Edges.User.Blocked {
		return nil, errors.New(errors.CodeUnauthorized, "user account is inactive")
	}

	// Generate new tokens
	accessToken, refreshToken, err := s.generateTokens(activeSession.Edges.User, activeSession.ID)
	if err != nil {
		return nil, err
	}

	// Update session last active time
	_, err = s.db.Session.UpdateOne(activeSession).
		SetLastActiveAt(time.Now()).
		Save(ctx)
	if err != nil {
		s.logger.Warn("Failed to update session last active time", logging.Error(err))
	}

	return &LoginResponse{
		AccessToken:   accessToken,
		RefreshToken:  refreshToken,
		TokenType:     "Bearer",
		ExpiresIn:     int(s.config.Auth.AccessTokenDuration.Seconds()),
		User:          activeSession.Edges.User,
		Session:       activeSession,
		Organizations: activeSession.Edges.User.Edges.Memberships,
	}, nil
}

// Logout invalidates user session(s)
func (s *Service) Logout(ctx context.Context, userID xid.ID, input LogoutInput) error {
	if input.AllSessions {
		// Invalidate all sessions for user
		_, err := s.db.Session.Update().
			Where(session.UserID(userID)).
			SetActive(false).
			Save(ctx)
		if err != nil {
			return errors.Wrap(errors.CodeDatabaseError, err, "failed to invalidate all sessions")
		}
	} else if input.RefreshToken != nil {
		// Invalidate specific session
		claims, err := s.parseToken(*input.RefreshToken)
		if err != nil {
			return errors.New(errors.CodeInvalidToken, "invalid refresh token")
		}

		sessionID, err := xid.FromString(claims.SessionID)
		if err != nil {
			return errors.New(errors.CodeInvalidToken, "invalid session ID")
		}

		_, err = s.db.Session.Update().
			Where(
				session.ID(sessionID),
				session.UserID(userID),
			).
			SetActive(false).
			Save(ctx)
		if err != nil {
			return errors.Wrap(errors.CodeDatabaseError, err, "failed to invalidate session")
		}
	}

	s.logger.Info("User logged out",
		logging.String("user_id", userID.String()),
		logging.Bool("all_sessions", input.AllSessions),
	)

	return nil
}

// Register creates a new user account
func (s *Service) Register(ctx context.Context, input RegisterInput) (*LoginResponse, error) {
	// Hash password
	passwordHash, err := crypto.HashPassword(input.Password)
	if err != nil {
		return nil, errors.Wrap(errors.CodeCryptoError, err, "failed to hash password")
	}

	// Determine user type and organization context
	userType := user.UserTypeExternal
	var orgID *xid.ID

	// If invitation token provided, validate it
	if input.InvitationToken != nil {
		membership, err := s.validateInvitationToken(ctx, *input.InvitationToken)
		if err != nil {
			return nil, err
		}
		orgID = &membership.OrganizationID
		userType = user.UserTypeExternal
	} else if input.OrganizationID != nil {
		orgID = input.OrganizationID
		userType = user.UserTypeEndUser
	}

	// Check email uniqueness
	exists, err := s.db.User.Query().
		Where(
			user.Email(input.Email),
			user.UserTypeEQ(userType),
		).
		Exist(ctx)
	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check email uniqueness")
	}
	if exists {
		return nil, errors.New(errors.CodeConflict, "email already registered")
	}

	// Start transaction
	tx, err := s.db.Tx(ctx)
	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to start transaction")
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	// Create user
	newUser, err := tx.User.Create().
		SetEmail(input.Email).
		SetPasswordHash(passwordHash).
		SetNillableFirstName(input.FirstName).
		SetNillableLastName(input.LastName).
		SetNillableUsername(input.Username).
		SetNillablePhoneNumber(input.PhoneNumber).
		SetUserType(userType).
		SetNillableOrganizationID(orgID).
		SetEmailVerified(!s.config.Auth.RequireEmailVerification).
		SetActive(true).
		SetMetadata(input.Metadata).
		Save(ctx)
	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to create user")
	}

	// If invitation token provided, accept the invitation
	if input.InvitationToken != nil {
		_, err = tx.Membership.Update().
			Where(
			// membership.InvitationToken(*input.InvitationToken),
			// membership.Status(membership.StatusPending),
			).
			// SetStatus(membership.StatusActive).
			// SetJoinedAt(time.Now()).
			// ClearInvitationToken().
			Save(ctx)
		if err != nil {
			return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to accept invitation")
		}
	}

	// Send verification email if required
	if s.config.Auth.RequireEmailVerification {
		if err := s.sendVerificationEmail(ctx, tx, newUser); err != nil {
			return nil, err
		}
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to commit transaction")
	}

	s.logger.Info("User registered",
		logging.String("user_id", newUser.ID.String()),
		logging.String("email", newUser.Email),
		logging.String("user_type", string(newUser.UserType)),
	)

	// If email verification is required, return early
	if s.config.Auth.RequireEmailVerification {
		return &LoginResponse{
			RequiresVerification: true,
			User:                 newUser,
		}, nil
	}

	// Auto-login after registration
	return s.createSuccessfulLoginResponse(ctx, newUser, false, input.UserAgent, input.IPAddress, nil)
}

// VerifyEmail verifies user's email address
func (s *Service) VerifyEmail(ctx context.Context, input VerifyEmailInput) error {
	// Find verification token
	verificationRecord, err := s.db.Verification.Query().
		Where(
			verification.Token(input.Token),
			verification.Type("email"),
			verification.Used(false),
			verification.ExpiresAtGT(time.Now()),
		).
		WithUser().
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeInvalidToken, "invalid or expired verification token")
		}
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to find verification token")
	}

	// Start transaction
	tx, err := s.db.Tx(ctx)
	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to start transaction")
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	// Mark user as verified
	err = tx.User.UpdateOne(verificationRecord.Edges.User).
		SetEmailVerified(true).
		Exec(ctx)
	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to verify user")
	}

	// Mark verification as used
	err = tx.Verification.UpdateOne(verificationRecord).
		SetUsed(true).
		SetUsedAt(time.Now()).
		Exec(ctx)
	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to mark verification as used")
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to commit transaction")
	}

	s.logger.Info("Email verified",
		logging.String("user_id", verificationRecord.Edges.User.ID.String()),
		logging.String("email", verificationRecord.Edges.User.Email),
	)

	return nil
}

// ValidateToken validates and parses a JWT token
func (s *Service) ValidateToken(ctx context.Context, tokenString string) (*Claims, error) {
	return s.parseToken(tokenString)
}

// GetUserFromToken extracts user information from a valid token
func (s *Service) GetUserFromToken(ctx context.Context, tokenString string) (*ent.User, error) {
	claims, err := s.parseToken(tokenString)
	if err != nil {
		return nil, err
	}

	userID, err := xid.FromString(claims.UserID)
	if err != nil {
		return nil, errors.New(errors.CodeInvalidToken, "invalid user ID in token")
	}

	user, err := s.db.User.Query().
		Where(
			user.ID(userID),
			user.Active(true),
			user.Blocked(false),
		).
		WithOrganization().
		WithMemberships(func(q *ent.MembershipQuery) {
			q.WithOrganization().WithRole()
		}).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeUnauthorized, "user not found or inactive")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get user")
	}

	return user, nil
}

// GetUserIDFromContext extracts user ID from request context
func (s *Service) GetUserIDFromContext(ctx context.Context) (xid.ID, error) {
	userID, ok := ctx.Value("user_id").(xid.ID)
	if !ok {
		return xid.ID{}, errors.New(errors.CodeUnauthorized, "user not authenticated")
	}
	return userID, nil
}

// Helper Functions

// createSuccessfulLoginResponse creates a complete login response with tokens and session
func (s *Service) createSuccessfulLoginResponse(ctx context.Context, user *ent.User, rememberMe bool, userAgent, ipAddress, deviceID *string) (*LoginResponse, error) {
	// Create session
	sessionToken, err := s.generateSecureToken(32)
	if err != nil {
		return nil, errors.Wrap(errors.CodeCryptoError, err, "failed to generate session token")
	}

	expiresAt := time.Now().Add(s.config.Auth.SessionDuration)
	if rememberMe {
		expiresAt = time.Now().Add(s.config.Auth.RememberMeDuration)
	}

	activeSessionMut := s.db.Session.Create().
		SetUserID(user.ID).
		SetToken(sessionToken).
		SetNillableIPAddress(ipAddress).
		SetNillableUserAgent(userAgent).
		SetNillableDeviceID(deviceID).
		SetActive(true).
		SetExpiresAt(expiresAt).
		SetLastActiveAt(time.Now())

	if !user.OrganizationID.IsNil() {
		activeSessionMut.SetOrganizationID(user.OrganizationID)
	}

	activeSession, err := activeSessionMut.Save(ctx)
	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to create session")
	}

	// Generate JWT tokens
	accessToken, refreshToken, err := s.generateTokens(user, activeSession.ID)
	if err != nil {
		return nil, err
	}

	// Update user last login
	_, err = s.db.User.UpdateOne(user).
		SetLastLogin(time.Now()).
		SetLoginCount(user.LoginCount + 1).
		SetNillableLastLoginIP(ipAddress).
		Save(ctx)
	if err != nil {
		s.logger.Warn("Failed to update user last login", logging.Error(err))
	}

	return &LoginResponse{
		AccessToken:   accessToken,
		RefreshToken:  refreshToken,
		TokenType:     "Bearer",
		ExpiresIn:     int(s.config.Auth.AccessTokenDuration.Seconds()),
		User:          user,
		Session:       activeSession,
		Organizations: user.Edges.Memberships,
	}, nil
}

// generateTokens generates access and refresh JWT tokens
func (s *Service) generateTokens(user *ent.User, sessionID xid.ID) (string, string, error) {
	now := time.Now()

	// Collect organization IDs
	var orgIDs []string
	if !user.OrganizationID.IsNil() {
		orgIDs = append(orgIDs, user.OrganizationID.String())
	}
	for _, membership := range user.Edges.Memberships {
		orgIDs = append(orgIDs, membership.OrganizationID.String())
	}

	// Access token claims
	accessClaims := Claims{
		UserID:   user.ID.String(),
		Email:    user.Email,
		UserType: string(user.UserType),
		OrganizationID: func() *string {
			if !user.OrganizationID.IsNil() {
				s := user.OrganizationID.String()
				return &s
			}
			return nil
		}(),
		Organizations: orgIDs,
		SessionID:     sessionID.String(),
		TokenType:     "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(s.config.Auth.AccessTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    s.config.Auth.TokenIssuer,
			Subject:   user.ID.String(),
		},
	}

	// Refresh token claims
	refreshClaims := Claims{
		UserID:    user.ID.String(),
		SessionID: sessionID.String(),
		TokenType: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(s.config.Auth.RefreshTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    s.config.Auth.TokenIssuer,
			Subject:   user.ID.String(),
		},
	}

	// Generate tokens
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)

	accessTokenString, err := accessToken.SignedString([]byte(s.config.Auth.TokenSecretKey))
	if err != nil {
		return "", "", errors.Wrap(errors.CodeCryptoError, err, "failed to sign access token")
	}

	refreshTokenString, err := refreshToken.SignedString([]byte(s.config.Auth.TokenSecretKey))
	if err != nil {
		return "", "", errors.Wrap(errors.CodeCryptoError, err, "failed to sign refresh token")
	}

	return accessTokenString, refreshTokenString, nil
}

// parseToken parses and validates a JWT token
func (s *Service) parseToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.Auth.TokenSecretKey), nil
	})

	if err != nil {
		return nil, errors.Wrap(errors.CodeInvalidToken, err, "failed to parse token")
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New(errors.CodeInvalidToken, "invalid token claims")
}

// checkMFARequirement checks if user has MFA enabled
func (s *Service) checkMFARequirement(ctx context.Context, userID xid.ID) (bool, []string, error) {
	// This would integrate with MFA service
	// For now, return false (no MFA required)
	return false, nil, nil
}

// verifyMFACode verifies MFA code
func (s *Service) verifyMFACode(ctx context.Context, userID xid.ID, method, code string) error {
	// This would integrate with MFA service
	// For now, accept any code
	return nil
}

// createTempSession creates a temporary session for MFA flow
func (s *Service) createTempSession(ctx context.Context, user *ent.User, userAgent, ipAddress, deviceID *string) (*ent.Session, error) {
	sessionToken, err := s.generateSecureToken(32)
	if err != nil {
		return nil, errors.Wrap(errors.CodeCryptoError, err, "failed to generate session token")
	}

	// Temporary session expires in 10 minutes
	expiresAt := time.Now().Add(10 * time.Minute)

	tempSessionMut := s.db.Session.Create().
		SetUserID(user.ID).
		SetToken(sessionToken).
		SetNillableIPAddress(ipAddress).
		SetNillableUserAgent(userAgent).
		SetNillableDeviceID(deviceID).
		SetActive(true).
		SetExpiresAt(expiresAt).
		SetLastActiveAt(time.Now()).
		SetMetadata(map[string]interface{}{
			"temp_session": true,
			"purpose":      "mfa",
		})

	if !user.OrganizationID.IsNil() {
		tempSessionMut.SetOrganizationID(user.OrganizationID)
	}

	tempSession, err := tempSessionMut.Save(ctx)
	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to create temporary session")
	}

	return tempSession, nil
}

// validateInvitationToken validates an invitation token
func (s *Service) validateInvitationToken(ctx context.Context, token string) (*ent.Membership, error) {
	// This would integrate with organization service
	// For now, return nil
	return nil, errors.New(errors.CodeNotImplemented, "invitation token validation not implemented")
}

// sendVerificationEmail sends email verification
func (s *Service) sendVerificationEmail(ctx context.Context, tx *ent.Tx, user *ent.User) error {
	// Generate verification token
	token, err := s.generateSecureToken(32)
	if err != nil {
		return errors.Wrap(errors.CodeCryptoError, err, "failed to generate verification token")
	}

	// Create verification record
	_, err = tx.Verification.Create().
		SetUserID(user.ID).
		SetType("email").
		SetToken(token).
		SetEmail(user.Email).
		SetExpiresAt(time.Now().Add(s.config.Auth.VerificationTokenDuration)).
		Save(ctx)
	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to create verification record")
	}

	// TODO: Send email via notification service
	s.logger.Info("Verification email sent",
		logging.String("user_id", user.ID.String()),
		logging.String("email", user.Email),
	)

	return nil
}

// generateSecureToken generates a cryptographically secure token
func (s *Service) generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// ExtractTokenFromRequest extracts JWT token from HTTP request
func (s *Service) ExtractTokenFromRequest(r *http.Request) (string, error) {
	// Check Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			return parts[1], nil
		}
	}

	// Check query parameter
	token := r.URL.Query().Get("token")
	if token != "" {
		return token, nil
	}

	// Check cookie
	cookie, err := r.Cookie("access_token")
	if err == nil && cookie.Value != "" {
		return cookie.Value, nil
	}

	return "", errors.New(errors.CodeUnauthorized, "no token provided")
}

// GetActiveSessions returns all active sessions for a user
func (s *Service) GetActiveSessions(ctx context.Context, userID xid.ID) ([]*ent.Session, error) {
	sessions, err := s.db.Session.Query().
		Where(
			session.UserID(userID),
			session.Active(true),
			session.ExpiresAtGT(time.Now()),
		).
		Order(ent.Desc(session.FieldLastActiveAt)).
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to get active sessions")
	}

	return sessions, nil
}

// RevokeSession revokes a specific session
func (s *Service) RevokeSession(ctx context.Context, userID, sessionID xid.ID) error {
	_, err := s.db.Session.Update().
		Where(
			session.ID(sessionID),
			session.UserID(userID),
		).
		SetActive(false).
		Save(ctx)
	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to revoke session")
	}

	return nil
}

// CleanupExpiredSessions removes expired sessions
func (s *Service) CleanupExpiredSessions(ctx context.Context) error {
	_, err := s.db.Session.Delete().
		Where(
			session.Or(
				session.ExpiresAtLT(time.Now()),
				session.Active(false),
			),
		).
		Exec(ctx)
	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to cleanup expired sessions")
	}

	return nil
}
