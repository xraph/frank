package controllers

import (
	"context"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/gen/auth"
	"github.com/juicycleff/frank/gen/designtypes"
	authhttp "github.com/juicycleff/frank/gen/http/auth/server"
	"github.com/juicycleff/frank/internal/auth/session"
	middleware2 "github.com/juicycleff/frank/internal/middleware"
	"github.com/juicycleff/frank/internal/services"
	"github.com/juicycleff/frank/pkg/automapper"
	"github.com/juicycleff/frank/pkg/crypto"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/hooks"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"
	"github.com/juicycleff/frank/user"
	"goa.design/clue/debug"
	"goa.design/clue/log"
	goahttp "goa.design/goa/v3/http"
	"goa.design/goa/v3/security"
)

// AuthService implements the genconcerts.Service interface
type AuthService struct {
	userService    user.Service
	config         *config.Config
	logger         logging.Logger
	sessionManager *session.Manager
	sessionStore   sessions.Store
	cookieHandler  *session.CookieHandler
	auther         *AutherService
	mapper         *automapper.Mapper
	hooks          *hooks.Hooks
}

func (a *AuthService) SendEmailVerification(ctx context.Context, payload *auth.SendEmailVerificationPayload) (res *auth.SendEmailVerificationResult, err error) {
	info, ok := middleware2.GetRequestInfo(ctx)
	if !ok {
		return nil, errors.New(errors.CodeInternalServer, "failed to get request info")
	}

	authUser, err := a.userService.GetByEmail(ctx, payload.Email)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(a.config.Auth.EmailVerificationExpiry)
	verification, err := a.userService.CreateVerification(ctx, user.CreateVerificationInput{
		UserID:      authUser.ID,
		Type:        "email",
		Email:       authUser.Email,
		Method:      payload.Method,
		ExpiresAt:   expiresAt,
		IPAddress:   utils.GetRealIP(info.Req),
		UserAgent:   utils.GetUserAgent(info.Req),
		RedirectURL: a.config.RedirectURL,
	})

	if err != nil {
		a.logger.Error("Failed to create verification",
			logging.String("user_id", authUser.ID),
			logging.Error(err),
		)
		return nil, errors.New(errors.CodeEmailNotVerified, "email verification required")
	}

	return &auth.SendEmailVerificationResult{
		Message:   "Email verification sent",
		ExpiresAt: verification.ExpiresAt.Unix(),
	}, nil
}

func (a *AuthService) CheckEmailVerification(ctx context.Context, payload *auth.CheckEmailVerificationPayload) (res *auth.CheckEmailVerificationResult, err error) {
	// TODO implement me
	panic("implement me")
}

func (a *AuthService) Csrf(ctx context.Context, payload *auth.CsrfPayload) (res *auth.CSRFTokenResponse, err error) {
	info, ok := middleware2.GetRequestInfo(ctx)
	if !ok {
		return nil, errors.New(errors.CodeInternalServer, "failed to get request info")
	}

	csrfToken, _ := crypto.GenerateRandomString(32)
	a.cookieHandler.SetCSRFCookie(info.Res, csrfToken, a.config.Auth.SessionDuration)

	return &auth.CSRFTokenResponse{
		CsrfToken: csrfToken,
	}, nil
}

func (a *AuthService) Login(ctx context.Context, payload *auth.LoginPayload) (res *auth.LoginResponse, err error) {
	info, ok := middleware2.GetRequestInfo(ctx)
	if !ok {
		return nil, errors.New(errors.CodeInternalServer, "failed to get request info")
	}

	orgId := ""
	if payload.OrganizationID != nil {
		orgId = *payload.OrganizationID
	}

	// Authenticate user
	authenticatedUser, err := a.userService.Authenticate(ctx, payload.Email, payload.Password, orgId)
	if err != nil {
		return nil, err
	}

	userOut := &designtypes.User{}
	mapper := automapper.CreateMap[*ent.User, designtypes.User]()
	automapper.MapTo(authenticatedUser.User, userOut, mapper)

	// Check if email verification is required
	if a.config.Auth.RequireEmailVerification && !authenticatedUser.EmailVerified {
		method := "otp"

		// Create verification
		expiresAt := time.Now().Add(a.config.Auth.EmailVerificationExpiry)
		verification, err := a.userService.CreateVerification(ctx, user.CreateVerificationInput{
			UserID:    authenticatedUser.User.ID,
			Type:      "email",
			Email:     authenticatedUser.User.Email,
			Method:    user.VerificationMethod(method),
			ExpiresAt: expiresAt,
			IPAddress: utils.GetRealIP(info.Req),
			UserAgent: utils.GetUserAgent(info.Req),
		})
		if err != nil {
			a.logger.Error("Failed to create verification",
				logging.String("user_id", authenticatedUser.User.ID),
				logging.Error(err),
			)
			return nil, errors.New(errors.CodeEmailNotVerified, "email verification required")
		}

		reqVer := true
		return &auth.LoginResponse{
			User:                 userOut,
			VerificationID:       &verification.ID,
			EmailVerified:        &authenticatedUser.EmailVerified,
			VerificationMethod:   &method,
			ExpiresAt:            expiresAt.Unix(),
			RequiresVerification: &reqVer,
			Message:              "Email verification required",
		}, nil
	}

	_ = a.hooks.BeforeLogin(user.LoginResult{
		User:           authenticatedUser.User,
		EmailVerified:  authenticatedUser.User.EmailVerified,
		VerificationID: "",
	})

	// Check if MFA is required
	mfaRequired, mfaTypes, err := a.checkMFA(ctx, authenticatedUser.User.ID)
	if err != nil {
		return nil, err
	}

	// Create tokens
	token, refreshToken, expiresAt, err := a.createTokens(authenticatedUser.User, orgId)
	if err != nil {
		return nil, err
	}

	sessionData := &session.CookieSessionData{
		UserID:         authenticatedUser.User.ID,
		OrganizationID: orgId,
		ExpiresAt:      time.Now().Add(a.config.Auth.SessionDuration),
		IssuedAt:       time.Now(),
		Metadata: map[string]interface{}{
			"login_method": "password",
		},
	}

	// Create session if session manager is available
	if a.sessionManager != nil {
		sess, err := a.createSession(ctx, info.Req, info.Res, authenticatedUser.User, orgId, payload.RememberMe)
		if err != nil {
			a.logger.Error("Failed to create session",
				logging.String("user_id", authenticatedUser.User.ID),
				logging.Error(err),
			)
			// Continue without session
		}

		// If a session was created, don't include token in response
		if sess != nil {
			// token = ""
			// refreshToken = ""
			sessionData.Metadata["sessionId"] = sess.ID
			// payload.SessionID = &sess.ID
		}
	}

	csrfToken, _ := crypto.GenerateRandomString(32)
	a.cookieHandler.SetCSRFCookie(info.Res, csrfToken, a.config.Auth.SessionDuration)

	authRes := &auth.LoginResponse{
		User:          userOut,
		Token:         token,
		RefreshToken:  refreshToken,
		ExpiresAt:     expiresAt,
		MfaRequired:   mfaRequired,
		MfaTypes:      mfaTypes,
		CsrfToken:     csrfToken,
		EmailVerified: &userOut.EmailVerified,
	}

	_ = a.hooks.OnLogin(authRes)
	return authRes, nil
}

func (a *AuthService) Register(ctx context.Context, payload *auth.RegisterPayload) (res *auth.LoginResponse, err error) {
	res = &auth.LoginResponse{}

	info, ok := middleware2.GetRequestInfo(ctx)
	if !ok {
		return nil, errors.New(errors.CodeInternalServer, "failed to get request info")
	}

	// Create user
	createInput := user.CreateUserInput{
		Email:    payload.Email,
		Password: payload.Password,
		Metadata: payload.Metadata,
	}

	if payload.OrganizationID != nil {
		createInput.OrganizationID = *payload.OrganizationID
	}

	if payload.FirstName != nil {
		createInput.FirstName = *payload.FirstName
	}

	if payload.LastName != nil {
		createInput.LastName = *payload.LastName
	}

	_ = a.hooks.BeforeSignup(&createInput)

	newUser, err := a.userService.Create(ctx, createInput)
	if err != nil {
		return nil, err
	}

	// Create tokens if email verification is not required
	var token, refreshToken string
	var expiresAt int64

	if !a.config.Auth.RequireEmailVerification {
		token, refreshToken, expiresAt, err = a.createTokens(newUser, createInput.OrganizationID)
		if err != nil {
			return nil, err
		}

		// Create session if session manager is available
		if a.sessionManager != nil {
			session, err := a.createSession(ctx, info.Req, info.Res, newUser, createInput.OrganizationID, false)
			if err != nil {
				a.logger.Error("Failed to create session",
					logging.String("user_id", newUser.ID),
					logging.Error(err),
				)
				// Continue without session
			}

			// If session was created, don't include token in response
			if session != nil {
				// token = ""
				// refreshToken = ""
			}

		}
	}

	userOut := &designtypes.User{}
	mapper := automapper.CreateMap[*ent.User, designtypes.User]()
	automapper.MapTo(newUser, userOut, mapper)

	csrfToken, _ := crypto.GenerateRandomString(32)
	a.cookieHandler.SetCSRFCookie(info.Res, csrfToken, a.config.Auth.SessionDuration)

	res.User = userOut
	res.Token = token
	res.RefreshToken = refreshToken
	res.ExpiresAt = expiresAt
	res.CsrfToken = csrfToken

	_ = a.hooks.OnSignup(res)

	return res, nil

}

func (a *AuthService) Logout(ctx context.Context, payload *auth.LogoutPayload) (res *auth.LogoutResult, err error) {
	info, ok := middleware2.GetRequestInfo(ctx)
	if !ok {
		return nil, errors.New(errors.CodeInternalServer, "failed to get request info")
	}

	// Get user ID from request context
	userID, ok := middleware2.GetUserID(ctx)
	if !ok || userID == "" {
		return nil, errors.New(errors.CodeUnauthorized, "not authenticated")
	}

	// Get user from database
	userEntity, err := a.userService.Get(ctx, userID)
	if err != nil {
		return nil, err
	}

	_ = a.hooks.BeforeLogout(userEntity)

	// Clear session if using sessions
	if a.sessionManager != nil {
		session, err := session.GetSessionHelper(info.Req, a.config, a.cookieHandler, a.sessionStore, a.logger)
		if err == nil {
			// Get user ID from session
			userID, ok := session.Values["user_id"].(string)
			if ok && userID != "" {
				// Get token from session
				token, ok := session.Values["token"].(string)
				if ok && token != "" {
					// Try to revoke the token in the session
					err := a.sessionManager.RevokeSession(ctx, token)
					if err != nil {
						a.logger.Error("Failed to revoke session",
							logging.String("user_id", userID),
							logging.Error(err),
						)
						// Continue with logout anyway
					}
				}
			}

			// Clear all session values
			for key := range session.Values {
				delete(session.Values, key)
			}

			// Save the session to clear it
			err = session.Save(info.Req, info.Res)
			if err != nil {
				a.logger.Error("Failed to save cleared session",
					logging.Error(err),
				)
				// Continue with logout anyway
			}
		}
	}

	// Clear csrf tokens
	a.cookieHandler.ClearSessionCookie(info.Res)
	a.cookieHandler.ClearCSRFCookie(info.Res)

	_ = a.hooks.OnLogout(userEntity)

	// Respond with success
	return &auth.LogoutResult{
		Message: "Successfully logged out",
	}, nil
}

func (a *AuthService) RefreshToken(ctx context.Context, payload *auth.RefreshTokenPayload) (res *auth.RefreshTokenResponse, err error) {
	// Create JWT config
	jwtConfig := &crypto.JWTConfig{
		SigningMethod: a.config.Auth.TokenSigningMethod,
		SignatureKey:  []byte(a.config.Auth.TokenSecretKey),
		ValidationKey: []byte(a.config.Auth.TokenSecretKey),
		Issuer:        a.config.Auth.TokenIssuer,
		Audience:      a.config.Auth.TokenAudience,
	}

	// Extract claims from refresh token
	claims, err := jwtConfig.ValidateToken(payload.RefreshToken)
	if err != nil {
		return nil, errors.New(errors.CodeInvalidRefreshToken, "invalid refresh token")
	}

	// Check token type
	tokenType, ok := claims["token_type"].(string)
	if !ok || tokenType != "refresh" {
		return nil, errors.New(errors.CodeInvalidRefreshToken, "invalid token type")
	}

	// Extract user ID
	subject, err := jwtConfig.GetSubjectFromToken(payload.RefreshToken)
	if err != nil {
		return nil, errors.New(errors.CodeInvalidRefreshToken, "invalid token subject")
	}

	// Get user from database
	userEntity, err := a.userService.Get(ctx, subject)
	if err != nil {
		return nil, errors.New(errors.CodeInvalidRefreshToken, "user not found")
	}

	// Extract organization ID if present
	var organizationID string
	if orgID, ok := claims["organization_id"].(string); ok {
		organizationID = orgID
	}

	// Generate new tokens
	token, refreshToken, expiresAt, err := a.createTokens(userEntity, organizationID)
	if err != nil {
		return nil, err
	}

	// Return new tokens
	return &auth.RefreshTokenResponse{
		Token:        token,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}, nil
}

func (a *AuthService) ForgotPassword(ctx context.Context, payload *auth.ForgotPasswordPayload) (res *auth.ForgotPasswordResult, err error) {
	info, ok := middleware2.GetRequestInfo(ctx)
	if !ok {
		return nil, errors.New(errors.CodeInternalServer, "failed to get request info")
	}

	// Find user by email
	userEntity, err := a.userService.GetByEmail(ctx, payload.Email)
	if err != nil {
		// Return success even if user not found for security
		return &auth.ForgotPasswordResult{
			Message: "If your email is registered, you will receive a password reset link",
		}, nil
	}

	redirectURL := a.config.RedirectURL
	if payload.RedirectURL != nil {
		redirectURL = *payload.RedirectURL
	}

	// Generate verification
	expiresAt := time.Now().Add(time.Hour * 24) // 24 hour expiry
	_, err = a.userService.CreateVerification(ctx, user.CreateVerificationInput{
		UserID:      userEntity.ID,
		Type:        "password_reset",
		Email:       userEntity.Email,
		ExpiresAt:   expiresAt,
		RedirectURL: redirectURL,
		IPAddress:   utils.GetRealIP(info.Req),
		UserAgent:   info.Req.UserAgent(),
	})

	if err != nil {
		a.logger.Error("Failed to create password reset verification",
			logging.String("user_id", userEntity.ID),
			logging.Error(err),
		)
		// Return success anyway for security
	}

	return &auth.ForgotPasswordResult{
		Message: "If your email is registered, you will receive a password reset link",
	}, nil
}

func (a *AuthService) ResetPassword(ctx context.Context, payload *auth.ResetPasswordPayload) (res *auth.ResetPasswordResult, err error) {
	// Verify the token
	verification, err := a.userService.VerifyToken(ctx, payload.Token)
	if err != nil {
		return nil, err
	}

	// Check if this is a password reset token
	if verification.Type != "password_reset" {
		return nil, errors.New(errors.CodeInvalidToken, "invalid token type")
	}

	// Update user password
	err = a.userService.UpdatePassword(ctx, verification.UserID, "", payload.NewPassword)
	if err != nil {
		return nil, err
	}

	return &auth.ResetPasswordResult{
		Message: "Password has been reset successfully",
	}, nil
}

func (a *AuthService) VerifyEmail(ctx context.Context, payload *auth.VerifyEmailPayload) (res *auth.VerifyEmailResult, err error) {
	var verification *ent.Verification

	// Determine verification method based on provided inputs
	if payload.Method == user.VerificationMethodLink {
		// Token-based verification (link method)
		verification, err = a.userService.VerifyToken(ctx, *payload.Token)
	} else if payload.Email != "" && payload.Otp != nil {
		// OTP-based verification
		verification, err = a.userService.VerifyEmailOTP(ctx, payload.Email, *payload.Otp)
	} else {
		return nil, errors.New(errors.CodeInvalidInput, "either token or email and OTP are required")
	}
	if err != nil {
		return nil, err
	}

	// Check if this is an email verification token
	if verification.Type != "email" {
		return nil, errors.New(errors.CodeInvalidToken, "invalid token type")
	}

	// Update user's email verification status
	err = a.userService.VerifyEmail(ctx, verification.UserID)
	if err != nil {
		_ = a.hooks.OnAccountVerified(*payload, false)
		return nil, err
	}

	_ = a.hooks.OnAccountVerified(*payload, true)

	return &auth.VerifyEmailResult{
		Message: "Email verification successful",
	}, nil
}

func (a *AuthService) Me(ctx context.Context, payload *auth.MePayload) (res *designtypes.User, err error) {
	// Get user ID from request context
	userID, ok := middleware2.GetUserID(ctx)
	if !ok || userID == "" {
		return nil, errors.New(errors.CodeUnauthorized, "not authenticated")
	}

	// Get user from database
	userEntity, err := a.userService.Get(ctx, userID)
	if err != nil {
		return nil, err
	}
	userOut := &designtypes.User{}
	mapper := automapper.CreateMap[*ent.User, designtypes.User]()

	automapper.MapTo(userEntity, userOut, mapper)

	// Return user data
	return userOut, nil
}

// createTokens generates JWT tokens for a user
func (a *AuthService) createTokens(user *ent.User, organizationID string) (string, string, int64, error) {
	// Create JWT config
	jwtConfig := &crypto.JWTConfig{
		SigningMethod: a.config.Auth.TokenSigningMethod,
		SignatureKey:  []byte(a.config.Auth.TokenSecretKey),
		ValidationKey: []byte(a.config.Auth.TokenSecretKey),
		Issuer:        a.config.Auth.TokenIssuer,
		Audience:      a.config.Auth.TokenAudience,
		DefaultExpiry: a.config.Auth.AccessTokenDuration,
	}

	// Create claims for access token
	accessClaims := map[string]interface{}{
		"user_id":    user.ID,
		"email":      user.Email,
		"token_type": "access",
	}

	if organizationID != "" {
		accessClaims["organization_id"] = organizationID
	}

	// Generate access token
	accessToken, err := jwtConfig.GenerateToken(user.ID, accessClaims, a.config.Auth.AccessTokenDuration)
	if err != nil {
		return "", "", 0, errors.Wrap(errors.CodeCryptoError, err, "failed to generate access token")
	}

	// Create claims for refresh token
	refreshClaims := map[string]interface{}{
		"user_id":    user.ID,
		"email":      user.Email,
		"token_type": "refresh",
	}

	if organizationID != "" {
		refreshClaims["organization_id"] = organizationID
	}

	// Generate refresh token
	refreshToken, err := jwtConfig.GenerateToken(user.ID, refreshClaims, a.config.Auth.RefreshTokenDuration)
	if err != nil {
		return "", "", 0, errors.Wrap(errors.CodeCryptoError, err, "failed to generate refresh token")
	}

	// Calculate expiration time
	expiresAt := time.Now().Add(a.config.Auth.AccessTokenDuration).Unix()

	return accessToken, refreshToken, expiresAt, nil
}

// createSession creates a new session for the user
func (a *AuthService) createSession(ctx context.Context, r *http.Request, w http.ResponseWriter, user *ent.User, organizationID string, rememberMe bool) (*session.SessionInfo, error) {
	// Skip if session manager not initialized
	if a.sessionManager == nil {
		return nil, nil
	}

	// Create options for session
	options := []session.Option{
		session.WithIPAddress(utils.GetRealIP(r)),
		session.WithUserAgent(r.UserAgent()),
	}

	if organizationID != "" {
		options = append(options, session.WithOrganizationID(organizationID))
	}

	// Create session
	sessionInfo, err := a.sessionManager.CreateSession(ctx, user.ID, options...)
	if err != nil {
		return nil, err
	}

	// Store session info in cookie session
	sess, err := session.GetSessionHelper(r, a.config, a.cookieHandler, a.sessionStore, a.logger)
	if err != nil {
		return nil, err
	}

	// Set session values
	sess.Values["user_id"] = user.ID
	sess.Values["authenticated"] = true
	sess.Values["token"] = sessionInfo.Token
	sess.Values["session_id"] = sessionInfo.ID

	if organizationID != "" {
		sess.Values["organization_id"] = organizationID
	}

	// Set session expiration based on remember me option
	if rememberMe {
		sess.Options.MaxAge = int(a.config.Auth.RememberMeDuration.Seconds())
		sess.Values["expires_at"] = int(a.config.Auth.RememberMeDuration.Seconds())
	} else {
		sess.Options.MaxAge = int(a.config.Auth.SessionDuration.Seconds())
		sess.Values["expires_at"] = int(a.config.Auth.SessionDuration.Seconds())
	}

	// Save session
	if err = sess.Save(r, w); err != nil {
		return nil, err
	}

	return sessionInfo, nil
}

// checkMFA checks if MFA is required for the user
func (a *AuthService) checkMFA(ctx context.Context, userID string) (bool, []string, error) {
	// Implement MFA check logic here
	// For now returning false (no MFA required)
	return false, nil, nil
}

// OAuth2Auth implements the authorization logic for the OAuth2 security scheme.
func (a *AuthService) OAuth2Auth(ctx context.Context, token string, schema *security.OAuth2Scheme) (context.Context, error) {
	return a.auther.OAuth2Auth(ctx, token, schema)
}

// APIKeyAuth implements the authorization logic for the APIKey security scheme.
func (a *AuthService) APIKeyAuth(ctx context.Context, key string, schema *security.APIKeyScheme) (context.Context, error) {
	return a.auther.APIKeyAuth(ctx, key, schema)
}

// JWTAuth implements the authorization logic for the JWT security scheme.
func (a *AuthService) JWTAuth(ctx context.Context, token string, schema *security.JWTScheme) (context.Context, error) {
	return a.auther.JWTAuth(ctx, token, schema)
}

func NewAuthService(
	userService user.Service,
	sessionManager *session.Manager,
	cookieHandler *session.CookieHandler,
	sessionStore sessions.Store,
	config *config.Config,
	logger logging.Logger,
	auther *AutherService,
	hooks *hooks.Hooks,
) auth.Service {
	mapper := automapper.NewMapper()

	// Create and configure the mapper
	userMapper := automapper.CreateMap[*ent.User, designtypes.User]()
	automapper.RegisterWithTypes(mapper, userMapper)

	return &AuthService{
		userService:    userService,
		config:         config,
		logger:         logger,
		sessionManager: sessionManager,
		auther:         auther,
		mapper:         mapper,
		cookieHandler:  cookieHandler,
		sessionStore:   sessionStore,
		hooks:          hooks,
	}
}

func RegisterAuthHTTPService(
	mux goahttp.Muxer,
	svcs *services.Services,
	config *config.Config,
	logger logging.Logger,
	auther *AutherService,
	hooks *hooks.Hooks,
) {
	eh := errorHandler(logger)
	svc := NewAuthService(svcs.User, svcs.Session, svcs.CookieHandler, svcs.SessionStore, config, logger, auther, hooks)

	csrfInterceptor := NewCSRFInterceptor(config, logger)
	endpoints := auth.NewEndpoints(svc, csrfInterceptor)
	handler := authhttp.New(endpoints, mux, decoder, encoder, eh, errors.CustomErrorFormatter)

	endpoints.Use(debug.LogPayloads())
	endpoints.Use(log.Endpoint)

	// handler2 := otelhttp.NewHandler(handler, "auth-service")
	authhttp.Mount(mux, handler)
}
