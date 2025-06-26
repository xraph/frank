package model

import (
	"time"

	"github.com/rs/xid"
)

// LoginRequest represents a login request
type LoginRequest struct {
	Email         string `json:"email" example:"user@example.com" doc:"User email address"`
	Password      string `json:"password,omitempty" example:"password123" doc:"User password (optional for passwordless)"`
	Username      string `json:"username,omitempty" example:"johndoe" doc:"Username (alternative to email)"`
	PhoneNumber   string `json:"phoneNumber,omitempty" example:"+1234567890" doc:"Phone number for SMS authentication"`
	Provider      string `json:"provider,omitempty" example:"google" doc:"OAuth provider (google, github, etc.)"`
	ProviderToken string `json:"providerToken,omitempty" doc:"Token from OAuth provider"`
	RememberMe    bool   `json:"rememberMe" example:"true" doc:"Whether to remember the user for extended session"`
	IPAddress     string `json:"ipAddress,omitempty" example:"192.168.1.1" doc:"Client IP address"`
	UserAgent     string `json:"userAgent,omitempty" example:"Mozilla/5.0..." doc:"Client user agent"`
	DeviceID      string `json:"deviceId,omitempty" example:"device-123" doc:"Unique device identifier"`
	DeviceName    string `json:"deviceName,omitempty" example:"John's iPhone" doc:"Device name"`
	Location      string `json:"location,omitempty" example:"New York, NY" doc:"User location"`
	MFAToken      string `json:"mfaToken,omitempty" example:"123456" doc:"MFA token for two-factor authentication"`
	MFAMethod     string `json:"mfaMethod,omitempty" example:"totp" doc:"MFA method used (totp, sms, email)"`
	MFACode       string `json:"mfaCode,omitempty" example:"123456" doc:"MFA verification code"`

	// Organization context (auto-detected if not provided)
	OrganizationID   *xid.ID `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	OrganizationSlug string  `json:"organizationSlug,omitempty" example:"acme-corp" doc:"Organization slug"`
}

// LoginResponse represents a successful login response
type LoginResponse struct {
	AccessToken          string     `json:"accessToken,omitempty" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." doc:"JWT access token"`
	RefreshToken         string     `json:"refreshToken,omitempty" example:"refresh_token_123" doc:"Refresh token for token renewal"`
	TokenType            string     `json:"tokenType,omitempty" example:"Bearer" doc:"Token type (usually Bearer)"`
	ExpiresIn            int        `json:"expiresIn,omitempty" example:"3600" doc:"Token expiration time in seconds"`
	ExpiresAt            *time.Time `json:"expiresAt,omitempty" example:"2023-01-01T13:00:00Z" doc:"Token expiration timestamp"`
	User                 *User      `json:"user,omitempty" doc:"User information"`
	Session              *Session   `json:"session,omitempty" doc:"Session information"`
	VerificationRequired bool       `json:"verificationRequired,omitempty" example:"true" doc:"Whether verification is required for this user"`
	VerificationTarget   string     `json:"verificationTarget,omitempty" example:"email oor phone" doc:"Verification target"`
	MFARequired          bool       `json:"mfaRequired,omitempty" example:"false" doc:"Whether MFA is required for this user"`
	MFAMethods           []MFAInfo  `json:"mfaMethods,omitempty" doc:"Available MFA methods if MFA is required"`
	MFAToken             string     `json:"mfaToken,omitempty" doc:"MFA session token for completing authentication"`
}

// RegisterRequest represents a user registration request
type RegisterRequest struct {
	Email       string  `json:"email" example:"newuser@example.com" doc:"User email address"`
	Password    string  `json:"password,omitempty" example:"password123" doc:"User password (optional for passwordless)"`
	Username    *string `json:"username,omitempty" example:"johndoe" doc:"Desired username"`
	PhoneNumber *string `json:"phoneNumber,omitempty" example:"+1234567890" doc:"Phone number"`
	FirstName   *string `json:"firstName,omitempty" example:"John" doc:"First name"`
	LastName    *string `json:"lastName,omitempty" example:"Doe" doc:"Last name"`

	OrganizationID *xid.ID `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID (for end users)"`
	UserType       string  `json:"userType" example:"external" doc:"User type (internal, external, end_user)"`

	CustomAttributes map[string]interface{} `json:"customAttributes,omitempty" doc:"Custom user attributes"`
	IPAddress        string                 `json:"ipAddress,omitempty" example:"192.168.1.1" doc:"Client IP address"`
	UserAgent        string                 `json:"userAgent,omitempty" example:"Mozilla/5.0..." doc:"Client user agent"`
	Metadata         map[string]interface{} `json:"metadata,omitempty" doc:"Additional user metadata"`

	Timezone         string `json:"timezone,omitempty" example:"America/New_York" doc:"User timezone"`
	Locale           string `json:"locale,omitempty" example:"en" doc:"User locale"`
	AcceptTerms      bool   `json:"acceptTerms" example:"true" doc:"Whether user accepts terms and conditions"`
	AcceptPrivacy    bool   `json:"acceptPrivacy,omitempty" example:"true" doc:"Accept privacy policy"`
	AcceptMarketing  bool   `json:"acceptMarketing,omitempty" example:"false" doc:"Accept marketing communications"`
	MarketingConsent bool   `json:"marketingConsent,omitempty" example:"false" doc:"Whether user consents to marketing communications"`
}

// RegisterResponse represents a successful registration response
type RegisterResponse struct {
	User                      User          `json:"user" doc:"Created user information"`
	AccessToken               string        `json:"accessToken,omitempty" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." doc:"JWT access token (if auto-login enabled)"`
	RefreshToken              string        `json:"refreshToken,omitempty" example:"refresh_token_123" doc:"Refresh token"`
	TokenType                 string        `json:"tokenType,omitempty" example:"Bearer" doc:"Token type"`
	ExpiresAt                 *time.Time    `json:"expiresAt,omitempty" example:"2023-01-01T13:00:00Z" doc:"Token expiration timestamp"`
	ExpiresIn                 int           `json:"expiresIn,omitempty" example:"3600" doc:"Token expiration in seconds"`
	VerificationRequired      bool          `json:"verificationRequired,omitempty" example:"true" doc:"Whether verification is required for this user"`
	EmailVerificationRequired bool          `json:"emailVerificationRequired" example:"true" doc:"Whether email verification is required"`
	PhoneVerificationRequired bool          `json:"phoneVerificationRequired" example:"false" doc:"Whether phone verification is required"`
	VerificationToken         string        `json:"verificationToken,omitempty" example:"verify_123" doc:"Verification token"`
	Success                   bool          `json:"success" example:"true" doc:"Whether registration was successful"`
	Message                   string        `json:"message" example:"Registration successful" doc:"Response message"`
	Organization              *Organization `json:"organization,omitempty" doc:"Created organization information"`
	Membership                *Membership   `json:"membership,omitempty" doc:"Created membership information"`
}

// InvitationRegistrationRequest represents a request to register via invitation
type InvitationRegistrationRequest struct {
	InvitationToken string `json:"invitationToken" example:"inv_abc123xyz..." doc:"Invitation token" validate:"required"`

	// User details
	Email            string                 `json:"email" example:"developer@acme.com" doc:"User email (must match invitation)" validate:"required,email"`
	Password         string                 `json:"password" example:"SecurePassword123!" doc:"User password" validate:"required,min=8"`
	FirstName        string                 `json:"firstName" example:"Jane" doc:"User first name" validate:"required"`
	LastName         string                 `json:"lastName" example:"Smith" doc:"User last name" validate:"required"`
	CustomAttributes map[string]interface{} `json:"customAttributes,omitempty" doc:"Custom user attributes"`

	Phone string `json:"phone,omitempty" example:"+1-555-0124" doc:"User phone number"`

	// Optional profile info
	JobTitle   string `json:"jobTitle,omitempty" example:"Senior Developer" doc:"Job title"`
	Department string `json:"department,omitempty" example:"Engineering" doc:"Department"`
	Timezone   string `json:"timezone,omitempty" example:"America/Los_Angeles" doc:"User timezone"`

	// Acceptance
	AcceptTerms   bool `json:"acceptTerms" example:"true" doc:"Accept terms of service" validate:"required"`
	AcceptPrivacy bool `json:"acceptPrivacy" example:"true" doc:"Accept privacy policy" validate:"required"`

	IPAddress string `json:"ipAddress,omitempty" example:"192.168.1.1" doc:"Client IP address"`
	UserAgent string `json:"userAgent,omitempty" example:"Mozilla/5.0..." doc:"Client user agent"`
}

// OrganizationRegistrationRequest represents a request to register an organization with owner
type OrganizationRegistrationRequest struct {
	// Organization details
	OrganizationName string `json:"organizationName" example:"Acme Corporation" doc:"Organization name" validate:"required"`
	OrganizationSlug string `json:"organizationSlug,omitempty" example:"acme-corp" doc:"Organization slug (auto-generated if not provided)"`
	Domain           string `json:"domain,omitempty" example:"acme.com" doc:"Organization primary domain"`
	Plan             string `json:"plan,omitempty" example:"pro" doc:"Initial subscription plan"`

	// Owner user details
	UserEmail            string                 `json:"userEmail" example:"ceo@acme.com" doc:"Owner user email" validate:"required,email"`
	UserPassword         string                 `json:"userPassword" example:"SecurePassword123!" doc:"Owner user password" validate:"required,min=8"`
	UserFirstName        string                 `json:"userFirstName" example:"John" doc:"Owner user first name" validate:"required"`
	UserLastName         string                 `json:"userLastName" example:"Doe" doc:"Owner user last name" validate:"required"`
	UserPhone            string                 `json:"userPhone,omitempty" example:"+1-555-0123" doc:"Owner user phone number"`
	UserCustomAttributes map[string]interface{} `json:"customAttributes,omitempty" doc:"Custom user attributes"`

	// Optional settings
	IndustryType string                 `json:"industryType,omitempty" example:"technology" doc:"Organization industry"`
	CompanySize  string                 `json:"companySize,omitempty" example:"11-50" doc:"Company size range"`
	UseCase      string                 `json:"useCase,omitempty" example:"customer_auth" doc:"Primary use case"`
	Timezone     string                 `json:"timezone,omitempty" example:"America/New_York" doc:"Organization timezone"`
	Metadata     map[string]interface{} `json:"metadata,omitempty" doc:"Additional organization metadata"`

	// Marketing/Tracking
	ReferralSource string `json:"referralSource,omitempty" example:"google_search" doc:"How they found us"`
	UTMSource      string `json:"utmSource,omitempty" example:"google" doc:"UTM source"`
	UTMCampaign    string `json:"utmCampaign,omitempty" example:"auth_platform" doc:"UTM campaign"`

	IPAddress string `json:"ipAddress,omitempty" example:"192.168.1.1" doc:"Client IP address"`
	UserAgent string `json:"userAgent,omitempty" example:"Mozilla/5.0..." doc:"Client user agent"`
}

// RefreshTokenRequest represents a token refresh request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken" example:"refresh_token_123" doc:"Refresh token"`
}

// RefreshTokenResponse represents a token refresh response
type RefreshTokenResponse struct {
	AccessToken  string    `json:"accessToken" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." doc:"New JWT access token"`
	RefreshToken string    `json:"refreshToken,omitempty" example:"new_refresh_token_456" doc:"New refresh token (if rotation enabled)"`
	TokenType    string    `json:"tokenType" example:"Bearer" doc:"Token type"`
	ExpiresIn    int       `json:"expiresIn" example:"3600" doc:"Token expiration in seconds"`
	ExpiresAt    time.Time `json:"expiresAt" example:"2023-01-01T13:00:00Z" doc:"Token expiration timestamp"`
}

// LogoutRequest represents a logout request
type LogoutRequest struct {
	SessionID    *xid.ID `json:"sessionId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Specific session to logout"`
	RefreshToken string  `json:"refreshToken,omitempty" example:"refresh_token_123" doc:"Refresh token to revoke"`
	LogoutAll    bool    `json:"logoutAll" example:"false" doc:"Whether to logout from all devices"`
}

// LogoutResponse represents a logout response
type LogoutResponse struct {
	Success       bool `json:"success" example:"true" doc:"Whether logout was successful"`
	SessionsEnded int  `json:"sessionsEnded" example:"1" doc:"Number of sessions that were ended"`
}

// PasswordResetRequest represents a password reset request
type PasswordResetRequest struct {
	Email       string `json:"email" example:"user@example.com" doc:"User email address"`
	RedirectURL string `json:"redirectUrl,omitempty" example:"https://app.example.com/reset-password" doc:"URL to redirect to after reset"`
}

// PasswordResetResponse represents a password reset response
type PasswordResetResponse struct {
	Success bool   `json:"success" example:"true" doc:"Whether reset email was sent"`
	Message string `json:"message" example:"Password reset email sent" doc:"Response message"`
	Token   string `json:"token,omitempty" example:"reset_token_123" doc:"Reset token (for testing/dev)"`
}

// PasswordResetConfirmRequest represents a password reset confirmation
type PasswordResetConfirmRequest struct {
	Token       string `json:"token" example:"reset_token_123" doc:"Password reset token"`
	NewPassword string `json:"newPassword" example:"newpassword123" doc:"New password"`
}

// PasswordResetConfirmResponse represents a password reset confirmation response
type PasswordResetConfirmResponse struct {
	Success bool   `json:"success" example:"true" doc:"Whether password was reset successfully"`
	Message string `json:"message" example:"Password reset successfully" doc:"Response message"`
}

// ValidateTokenInputBody represents a password reset confirmation response
type ValidateTokenInputBody struct {
	Type  string `json:"type" example:"password" doc:"Token type"`
	Token string `json:"token" example:"reset_token_123" doc:"Token"`
}

// ValidateTokenResponse represents a password reset confirmation response
type ValidateTokenResponse struct {
	Valid   bool   `json:"valid" example:"true" doc:"Whether token is valid"`
	Message string `json:"message" example:"Password reset successfully" doc:"Response message"`
}

// VerificationRequest represents an email/phone verification request
type VerificationRequest struct {
	Token string `json:"token" example:"verify_token_123 or 123456" doc:"Verification token (from email link) or verification code (6-digit number)"`
	Code  string `json:"code,omitempty" example:"123456" doc:"Alternative field for verification code (for clarity)"`
}

// VerificationResponse represents a verification response
type VerificationResponse struct {
	Success            bool   `json:"success" example:"true" doc:"Whether verification was successful"`
	Message            string `json:"message" example:"Email verified successfully" doc:"Response message"`
	Verified           bool   `json:"verified" example:"true" doc:"Whether the item is now verified"`
	User               *User  `json:"user,omitempty" doc:"Updated user information"`
	VerificationMethod string `json:"verificationMethod,omitempty" example:"code" doc:"Method used for verification (token or code)"`
}

// ResendVerificationRequest represents a request to resend verification
type ResendVerificationRequest struct {
	Email       string `json:"email,omitempty" example:"user@example.com" doc:"Email to resend verification to"`
	PhoneNumber string `json:"phoneNumber,omitempty" example:"+1234567890" doc:"Phone number to resend verification to"`
	Type        string `json:"type" example:"email" doc:"Verification type (email, phone)"`
	Method      string `json:"method,omitempty" example:"both" doc:"Preferred method (token, code, or both)"`
}

// ResendVerificationResponse represents a resend verification response
type ResendVerificationResponse struct {
	Success            bool       `json:"success" example:"true" doc:"Whether verification was resent"`
	Message            string     `json:"message" example:"Verification email sent" doc:"Response message"`
	AvailableMethods   []string   `json:"availableMethods,omitempty" example:"[\"token\", \"code\"]" doc:"Available verification methods"`
	RateLimitRemaining int        `json:"rateLimitRemaining,omitempty" example:"2" doc:"Remaining verification attempts"`
	NextAttemptAt      *time.Time `json:"nextAttemptAt,omitempty" example:"2023-01-01T13:15:00Z" doc:"When next attempt is allowed"`
}

// VerificationStatus represents current verification status
type VerificationStatus struct {
	UserID               xid.ID                `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	EmailVerified        bool                  `json:"emailVerified" example:"true" doc:"Whether email is verified"`
	PhoneVerified        bool                  `json:"phoneVerified" example:"false" doc:"Whether phone is verified"`
	PendingVerifications []PendingVerification `json:"pendingVerifications,omitempty" doc:"Active verification attempts"`
}

// PendingVerification represents an active verification attempt
type PendingVerification struct {
	Type             string    `json:"type" example:"email" doc:"Verification type"`
	Target           string    `json:"target" example:"user@example.com" doc:"Email or phone being verified"`
	ExpiresAt        time.Time `json:"expiresAt" example:"2023-01-01T13:15:00Z" doc:"When verification expires"`
	AttemptCount     int       `json:"attemptCount" example:"1" doc:"Number of attempts made"`
	AvailableMethods []string  `json:"availableMethods" example:"[\"token\", \"code\"]" doc:"Available verification methods"`
	LastSentAt       time.Time `json:"lastSentAt" example:"2023-01-01T12:00:00Z" doc:"When last verification was sent"`
}

// SendVerificationRequest represents a request to send verification
type SendVerificationRequest struct {
	Type   string `json:"type" example:"email" doc:"Verification type (email, phone, sms)"`
	Method string `json:"method,omitempty" example:"both" doc:"Delivery method (token, code, or both)"`
}

// SendVerificationResponse represents a send verification response
type SendVerificationResponse struct {
	Success           bool     `json:"success" example:"true" doc:"Whether verification was sent"`
	Message           string   `json:"message" example:"Verification sent" doc:"Response message"`
	VerificationToken string   `json:"verificationToken,omitempty" example:"verify_123" doc:"Verification token (for testing/dev)"`
	VerificationCode  string   `json:"verificationCode,omitempty" example:"123456" doc:"Verification code (for testing/dev)"`
	ExpiresAt         string   `json:"expiresAt,omitempty" example:"2023-01-01T13:15:00Z" doc:"When verification expires"`
	AvailableMethods  []string `json:"availableMethods,omitempty" example:"[\"token\", \"code\"]" doc:"Available verification methods"`
}

// SessionInfo represents session information
type SessionInfo struct {
	ID           xid.ID    `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Session ID"`
	UserID       xid.ID    `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	IPAddress    string    `json:"ipAddress,omitempty" example:"192.168.1.1" doc:"IP address"`
	UserAgent    string    `json:"userAgent,omitempty" example:"Mozilla/5.0..." doc:"User agent"`
	DeviceID     string    `json:"deviceId,omitempty" example:"device-123" doc:"Device ID"`
	Location     string    `json:"location,omitempty" example:"New York, NY" doc:"Location"`
	Active       bool      `json:"active" example:"true" doc:"Whether session is active"`
	ExpiresAt    time.Time `json:"expiresAt" example:"2023-01-01T13:00:00Z" doc:"Session expiration time"`
	LastActiveAt time.Time `json:"lastActiveAt" example:"2023-01-01T12:30:00Z" doc:"Last activity time"`
	CreatedAt    time.Time `json:"createdAt" example:"2023-01-01T12:00:00Z" doc:"Session creation time"`
}

// Session represents a complete session with metadata
type Session struct {
	Base
	UserID         xid.ID                 `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	Token          string                 `json:"token,omitempty" example:"session_token_123" doc:"Session token"`
	IPAddress      string                 `json:"ipAddress,omitempty" example:"192.168.1.1" doc:"IP address"`
	UserAgent      string                 `json:"userAgent,omitempty" example:"Mozilla/5.0..." doc:"User agent"`
	DeviceID       string                 `json:"deviceId,omitempty" example:"device-123" doc:"Device ID"`
	Location       string                 `json:"location,omitempty" example:"New York, NY" doc:"Location"`
	OrganizationID *xid.ID                `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	Active         bool                   `json:"active" example:"true" doc:"Whether session is active"`
	ExpiresAt      time.Time              `json:"expiresAt" example:"2023-01-01T13:00:00Z" doc:"Session expiration time"`
	LastActiveAt   time.Time              `json:"lastActiveAt" example:"2023-01-01T12:30:00Z" doc:"Last activity time"`
	Metadata       map[string]interface{} `json:"metadata,omitempty" doc:"Additional session metadata"`
}

// MagicLinkRequest represents a magic link authentication request
type MagicLinkRequest struct {
	Email       string `json:"email" example:"user@example.com" doc:"User email address"`
	RedirectURL string `json:"redirectUrl,omitempty" example:"https://app.example.com/dashboard" doc:"URL to redirect to after authentication"`
}

// MagicLinkResponse represents a magic link response
type MagicLinkResponse struct {
	Success bool   `json:"success" example:"true" doc:"Whether magic link was sent"`
	Message string `json:"message" example:"Magic link sent to your email" doc:"Response message"`
	Token   string `json:"token,omitempty" example:"magic_token_123" doc:"Magic link token (for testing/dev)"`
}

// AuthStatus represents the current authentication status
type AuthStatus struct {
	IsAuthenticated bool `json:"isAuthenticated" example:"true" doc:"Whether user is authenticated"`
	HasAPIAccess    bool `json:"hasAPIAccess" example:"true" doc:"Whether user has API access"`

	// User information (only present when authenticated)
	User           *User       `json:"user,omitempty" doc:"Current user information"`
	Session        *Session    `json:"session,omitempty" doc:"Current session information"`
	OrganizationID *xid.ID     `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Current organization ID"`
	Membership     *Membership `json:"membership,omitempty" doc:"Organization membership info"`

	// API Key information (present when using API key)
	APIKeyType string  `json:"apiKeyType,omitempty" example:"client" doc:"Type of API key being used"`
	APIKeyID   *xid.ID `json:"apiKeyId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"API key ID"`

	// Permissions and access
	Permissions []string   `json:"permissions,omitempty" example:"[\"read:users\"]" doc:"User or API key permissions"`
	Scopes      []string   `json:"scopes,omitempty" example:"[\"api:read\"]" doc:"API scopes"`
	Roles       []RoleInfo `json:"roles,omitempty" doc:"User roles"`

	// Context information
	AuthMethod string `json:"authMethod,omitempty" example:"jwt" doc:"Authentication method used"`
	IPAddress  string `json:"ipAddress,omitempty" example:"192.168.1.1" doc:"Client IP address"`
	UserAgent  string `json:"userAgent,omitempty" example:"Mozilla/5.0..." doc:"User agent"`

	// MFA status
	MFAEnabled  bool `json:"mfaEnabled" example:"true" doc:"Whether MFA is enabled"`
	MFAVerified bool `json:"mfaVerified" example:"true" doc:"Whether MFA is verified for current session"`

	// Session metadata
	LastActiveAt *time.Time `json:"lastActiveAt,omitempty" example:"2023-01-01T12:00:00Z" doc:"Last activity timestamp"`
	ExpiresAt    *time.Time `json:"expiresAt,omitempty" example:"2023-01-01T13:00:00Z" doc:"Authentication expiration time"`

	// Feature flags and capabilities
	Features     map[string]bool `json:"features,omitempty" example:"{\"webhooks\": true}" doc:"Available features"`
	Capabilities []string        `json:"capabilities,omitempty" example:"[\"create:users\"]" doc:"User capabilities"`
}

// RoleInfo represents role information for auth status
type RoleInfo struct {
	ID          xid.ID  `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Role ID"`
	Name        string  `json:"name" example:"admin" doc:"Role name"`
	DisplayName string  `json:"displayName" example:"Administrator" doc:"Role display name"`
	Context     string  `json:"context" example:"organization" doc:"Role context"`
	ContextID   *xid.ID `json:"contextId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Context ID"`
}

// AuthProvider represents authentication provider information
type AuthProvider struct {
	Name        string `json:"name" example:"google" doc:"Provider name"`
	DisplayName string `json:"displayName" example:"Google" doc:"Provider display name"`
	Type        string `json:"type" example:"oauth" doc:"Provider type"`
	Enabled     bool   `json:"enabled" example:"true" doc:"Whether provider is enabled"`
	IconURL     string `json:"iconUrl,omitempty" example:"https://example.com/google-icon.png" doc:"Provider icon URL"`
	AuthURL     string `json:"authUrl,omitempty" example:"https://api.example.com/auth/google" doc:"Authentication URL"`
}

// SetupMFARequest represents a request to setup any MFA method
type SetupMFARequest struct {
	Method      string `json:"method" example:"totp" doc:"MFA method type (totp, sms, email)"`
	Name        string `json:"name,omitempty" example:"My Authenticator" doc:"User-friendly name for the method"`
	PhoneNumber string `json:"phoneNumber,omitempty" example:"+1234567890" doc:"Phone number for SMS MFA"`
	Email       string `json:"email,omitempty" example:"user@example.com" doc:"Email for email MFA (optional, uses user's primary email if not provided)"`
}

// MFASetupResponse represents a unified response for MFA setup
type MFASetupResponse struct {
	Method                   string `json:"method" example:"totp" doc:"MFA method type"`
	MethodID                 xid.ID `json:"methodId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"MFA method ID"`
	Secret                   string `json:"secret,omitempty" example:"JBSWY3DPEHPK3PXP" doc:"TOTP secret (for TOTP only)"`
	QRCode                   string `json:"qrCode,omitempty" example:"data:image/png;base64,..." doc:"QR code data URL (for TOTP only)"`
	BackupURL                string `json:"backupUrl,omitempty" example:"otpauth://totp/..." doc:"Manual entry URL (for TOTP only)"`
	PhoneNumber              string `json:"phoneNumber,omitempty" example:"+1234567890" doc:"Phone number (for SMS only)"`
	Email                    string `json:"email,omitempty" example:"user@example.com" doc:"Email address (for email MFA only)"`
	RequiresVerification     bool   `json:"requiresVerification" example:"true" doc:"Whether verification is required to complete setup"`
	VerificationInstructions string `json:"verificationInstructions" example:"Scan the QR code..." doc:"Instructions for verification"`
	Message                  string `json:"message,omitempty" example:"Setup initiated successfully" doc:"Additional message"`
}

// VerifyMFASetupRequest represents a request to verify MFA setup
type VerifyMFASetupRequest struct {
	MethodID            *xid.ID `json:"methodId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"MFA method ID (optional if method is provided)"`
	Method              string  `json:"method,omitempty" example:"totp" doc:"MFA method type (optional if methodId is provided)"`
	Code                string  `json:"code" example:"123456" doc:"Verification code"`
	GenerateBackupCodes bool    `json:"generateBackupCodes" example:"true" doc:"Whether to generate backup codes (for TOTP)"`
}

// MFASetupVerifyResponse represents the response to MFA setup verification
type MFASetupVerifyResponse struct {
	Success     bool     `json:"success" example:"true" doc:"Whether verification was successful"`
	Method      string   `json:"method" example:"totp" doc:"MFA method type"`
	MethodID    xid.ID   `json:"methodId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"MFA method ID"`
	Message     string   `json:"message" example:"MFA setup completed successfully" doc:"Response message"`
	IsVerified  bool     `json:"isVerified" example:"true" doc:"Whether the method is now verified and active"`
	BackupCodes []string `json:"backupCodes,omitempty" example:"[\"123456789\", \"987654321\"]" doc:"Generated backup codes (if requested)"`
}
