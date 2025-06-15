package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/hooks"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// Auth service implementation with MFA session store
func (s *authService) storePendingMFALogin(ctx context.Context, token string, login *model.PendingMFALogin) error {
	if s.mfaService.SessionStore() == nil {
		return errors.New(errors.CodeInternalServer, "MFA session store not configured")
	}

	expiry := time.Until(login.ExpiresAt)
	return s.mfaService.SessionStore().Store(ctx, token, login, expiry)
}

func (s *authService) getPendingMFALogin(ctx context.Context, token string) (*model.PendingMFALogin, error) {
	if s.mfaService.SessionStore() == nil {
		return nil, errors.New(errors.CodeInternalServer, "MFA session store not configured")
	}

	return s.mfaService.SessionStore().Get(ctx, token)
}

func (s *authService) invalidatePendingMFALogin(ctx context.Context, token string) error {
	if s.mfaService.SessionStore() == nil {
		return nil // Gracefully handle missing store
	}

	return s.mfaService.SessionStore().Delete(ctx, token)
}

func (s *authService) findUserByUsername(ctx context.Context, username string) (*model.User, error) {
	// Try external user first
	foundUser, err := s.userService.GetUserByUsername(ctx, username, model.UserTypeExternal, nil)
	if err == nil && foundUser != nil {
		return foundUser, nil
	}

	// Try internal user
	foundUser, err = s.userService.GetUserByUsername(ctx, username, model.UserTypeInternal, nil)
	if err == nil && foundUser != nil {
		return foundUser, nil
	}

	return nil, nil
}

func (s *authService) findUserByPhone(ctx context.Context, phone string) (*model.User, error) {
	// Try external user first
	foundUser, err := s.userService.GetUserByPhone(ctx, phone, model.UserTypeExternal, nil)
	if err == nil && foundUser != nil {
		return foundUser, nil
	}

	// Try internal user
	foundUser, err = s.userService.GetUserByPhone(ctx, phone, model.UserTypeInternal, nil)
	if err == nil && foundUser != nil {
		return foundUser, nil
	}

	return nil, nil
}

func (s *authService) handleOAuthLogin(ctx context.Context, req model.LoginRequest, user *model.User) (*model.LoginResponse, error) {
	// TODO: Implement OAuth login flow
	return nil, errors.New(errors.CodeNotImplemented, "OAuth login not implemented")
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
		UserType:      user.UserType,
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

// Helper method to build hook context
func (s *authService) buildHookContext(ctx context.Context, userID *xid.ID, orgID *xid.ID) *hooks.HookContext {
	hookCtx := &hooks.HookContext{
		UserID:         userID,
		OrganizationID: orgID,
		Timestamp:      time.Now(),
	}

	// Extract additional context from request context
	if ip, ok := ctx.Value("ip_address").(string); ok {
		hookCtx.IPAddress = ip
	}
	if ua, ok := ctx.Value("user_agent").(string); ok {
		hookCtx.UserAgent = ua
	}
	if reqID, ok := ctx.Value("request_id").(string); ok {
		hookCtx.RequestID = reqID
	}
	if sessionID, ok := ctx.Value("session_id").(xid.ID); ok {
		hookCtx.SessionID = &sessionID
	}

	return hookCtx
}

// Token generation utility
func generateMFAToken() string {
	return "mfa_" + xid.New().String()
}
