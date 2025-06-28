package auth

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/pkg/contexts"
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

func (s *authService) findUserByUsername(ctx context.Context, username string, userType model.UserType, orgId *xid.ID) (*model.User, error) {
	foundUser, err := s.userService.GetUserByUsername(ctx, username, userType, orgId)
	if err == nil && foundUser != nil {
		return foundUser, nil
	}

	return nil, nil
}

func (s *authService) findUserByPhone(ctx context.Context, phone string, userType model.UserType, orgId *xid.ID) (*model.User, error) {
	foundUser, err := s.userService.GetUserByPhone(ctx, phone, userType, orgId)
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

func (s *authService) auditOrganizationRegistration(ctx context.Context, orgID xid.ID, userID xid.ID, ip, userAgent string) {
	// TODO: Implement audit logging
	s.logger.Info("phone verified",
		logging.String("user_id", userID.String()),
	)
}
func (s *authService) auditInvitationRegistration(ctx context.Context, ivID, userID xid.ID, token, ip, userAgent string) {
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

// logSecurely logs sensitive operations without exposing credentials
func (s *authService) logSecurely(level string, message string, fields ...logging.Field) {
	switch level {
	case "info":
		s.logger.Info(message, fields...)
	case "warn":
		s.logger.Warn(message, fields...)
	case "error":
		s.logger.Error(message, fields...)
	default:
		s.logger.Debug(message, fields...)
	}
}

// getOrganizationNameFromRequest extracts organization name from register request
func (s *authService) getOrganizationNameFromRequest(req model.RegisterRequest) string {
	if metadata, ok := req.CustomAttributes["organization_name"].(string); ok {
		return metadata
	}
	return ""
}

// getOrganizationSlugFromRequest extracts organization slug from register request
func (s *authService) getOrganizationSlugFromRequest(req model.RegisterRequest) string {
	if metadata, ok := req.CustomAttributes["organization_slug"].(string); ok {
		return metadata
	}
	return ""
}

// getDomainFromRequest extracts domain from register request
func (s *authService) getDomainFromRequest(req model.RegisterRequest) *string {
	if metadata, ok := req.CustomAttributes["domain"].(string); ok {
		return &metadata
	}
	return nil
}

// getPlanFromRequest extracts plan from register request
func (s *authService) getPlanFromRequest(req model.RegisterRequest) string {
	if metadata, ok := req.CustomAttributes["plan"].(string); ok {
		return metadata
	}
	return "free"
}

// getPlanFromRequest extracts plan from register request
func (s *authService) getIpAddress(ctx context.Context, fallbackIP string) string {
	ip, ok := contexts.GetIPAddressFromContext(ctx)
	if !ok {
		return fallbackIP
	}
	return ip
}

// getPlanFromRequest extracts plan from register request
func (s *authService) getUserAgent(ctx context.Context, fallbackAgent string) string {
	ip, ok := contexts.GetUserAgentFromContext(ctx)
	if !ok {
		return fallbackAgent
	}
	return ip
}

func (s *authService) generateSlug(name string) string {
	// Convert to lowercase and replace spaces/special chars with hyphens
	slug := strings.ToLower(name)
	slug = regexp.MustCompile(`[^a-z0-9\-_]`).ReplaceAllString(slug, "-")
	slug = regexp.MustCompile(`-+`).ReplaceAllString(slug, "-")
	slug = strings.Trim(slug, "-")

	// Ensure minimum length
	if len(slug) < 2 {
		slug = "org-" + slug
	}

	// Truncate if too long
	if len(slug) > 50 {
		slug = slug[:50]
	}

	return slug
}
