package model

import (
	"time"

	"github.com/rs/xid"
)

// MFAMethod represents a multi-factor authentication method
type MFAMethod struct {
	Base
	UserID      xid.ID                 `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	Method      string                 `json:"method" example:"totp" doc:"MFA method type (totp, sms, email, backup_codes)"`
	Secret      string                 `json:"secret,omitempty" example:"SECRET123" doc:"MFA secret (write-only)"`
	Verified    bool                   `json:"verified" example:"true" doc:"Whether method is verified"`
	Active      bool                   `json:"active" example:"true" doc:"Whether method is active"`
	BackupCodes []string               `json:"backupCodes,omitempty" example:"[\"123456\", \"789012\"]" doc:"Backup recovery codes (write-only)"`
	PhoneNumber string                 `json:"phoneNumber,omitempty" example:"+1234567890" doc:"Phone number for SMS"`
	Email       string                 `json:"email,omitempty" example:"user@example.com" doc:"Email for email-based MFA"`
	LastUsed    *time.Time             `json:"lastUsed,omitempty" example:"2023-01-01T12:00:00Z" doc:"Last usage timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" doc:"Additional MFA metadata"`
	Name        string                 `json:"name,omitempty" example:"My Authenticator" doc:"User-friendly name"`

	// Relationships
	User *UserSummary `json:"user,omitempty" doc:"User information"`
}

// MFAInfo represents MFA method information
type MFAInfo struct {
	Method   string `json:"method" example:"totp" doc:"MFA method (totp, sms, email)"`
	Enabled  bool   `json:"enabled" example:"true" doc:"Whether method is enabled"`
	Verified bool   `json:"verified" example:"true" doc:"Whether method is verified"`
	Masked   string `json:"masked,omitempty" example:"***-***-1234" doc:"Masked phone/email for display"`
	Name     string `json:"name,omitempty" example:"My Authenticator" doc:"User-friendly name"`
}

// MFA represents MFA method information
type MFA = MFAMethod

// MFAMethodSummary represents a simplified MFA method for listings
type MFAMethodSummary struct {
	ID         xid.ID     `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"MFA method ID"`
	Method     string     `json:"method" example:"totp" doc:"MFA method type"`
	Name       string     `json:"name,omitempty" example:"My Authenticator" doc:"User-friendly name"`
	Verified   bool       `json:"verified" example:"true" doc:"Whether method is verified"`
	Active     bool       `json:"active" example:"true" doc:"Whether method is active"`
	LastUsed   *time.Time `json:"lastUsed,omitempty" example:"2023-01-01T12:00:00Z" doc:"Last usage"`
	CreatedAt  time.Time  `json:"createdAt" example:"2023-01-01T10:00:00Z" doc:"Creation timestamp"`
	MaskedInfo string     `json:"maskedInfo,omitempty" example:"***-***-1234" doc:"Masked phone/email for display"`
}
type MFASummary = MFAMethodSummary

// SetupTOTPRequest represents a request to setup TOTP
type SetupTOTPRequest struct {
	Name string `json:"name,omitempty" example:"My Authenticator App" doc:"User-friendly name"`
}

type TOTPSecret struct {
	Secret      string `json:"secret,omitempty" example:"SECRET123" doc:"TOTP secret"`
	URL         string `json:"url,omitempty" example:"otp" doc:"TOTP URL"`
	Issuer      string `json:"issuer,omitempty" example:"otp" doc:"TOTP issuer"`
	AccountName string `json:"accountName,omitempty" example:"otp" doc:"TOTP account name"`
	Algorithm   string `json:"algorithm,omitempty" example:"SHA1" doc:"TOTP algorithm"`
	Digits      int    `json:"digits,omitempty" example:"6" doc:"TOTP digits"`
	Period      int    `json:"period,omitempty" example:"30" doc:"TOTP period"`
}

// TOTPSetupResponse represents the response to TOTP setup
type TOTPSetupResponse struct {
	Secret      string   `json:"secret" example:"JBSWY3DPEHPK3PXP" doc:"TOTP secret"`
	QRCode      string   `json:"qrCode" example:"data:image/png;base64,..." doc:"QR code data URL"`
	BackupURL   string   `json:"backupUrl" example:"otpauth://totp/..." doc:"Manual entry URL"`
	MethodID    xid.ID   `json:"methodId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"MFA method ID"`
	BackupCodes []string `json:"backupCodes" example:"data:image/png;base64,..." doc:"Backup code URLs"`
}

// VerifyTOTPRequest represents a request to verify TOTP
type VerifyTOTPRequest struct {
	MethodID xid.ID `json:"methodId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"MFA method ID"`
	Code     string `json:"code" example:"123456" doc:"TOTP code"`
}

// SetupSMSRequest represents a request to setup SMS MFA
type SetupSMSRequest struct {
	PhoneNumber string `json:"phoneNumber" example:"+1234567890" doc:"Phone number"`
	Name        string `json:"name,omitempty" example:"My Phone" doc:"User-friendly name"`
}

// SetupSMSResponse represents the response to SMS setup
type SetupSMSResponse struct {
	MethodID    xid.ID    `json:"methodId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"MFA method ID"`
	PhoneNumber string    `json:"phoneNumber" example:"+1234567890" doc:"Phone number"`
	CodeSent    bool      `json:"codeSent" example:"true" doc:"Whether verification code was sent"`
	ExpiresAt   time.Time `json:"expiresAt" example:"2023-01-01T12:05:00Z" doc:"Code expiration"`
	Message     string    `json:"message" example:"SMS verification code"`
}

// VerifySMSRequest represents a request to verify SMS code
type VerifySMSRequest struct {
	MethodID xid.ID `json:"methodId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"MFA method ID"`
	Code     string `json:"code" example:"123456" doc:"SMS verification code"`
}

// SetupEmailRequest represents a request to setup email MFA
type SetupEmailRequest struct {
	Email string `json:"email" example:"user@example.com" doc:"Email address"`
	Name  string `json:"name,omitempty" example:"My Email" doc:"User-friendly name"`
}

// EmailMFASetupResponse represents the response to email MFA setup
type EmailMFASetupResponse struct {
	MethodID  xid.ID    `json:"methodId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"MFA method ID"`
	Email     string    `json:"email" example:"user@example.com" doc:"Email address"`
	CodeSent  bool      `json:"codeSent" example:"true" doc:"Whether verification code was sent"`
	ExpiresAt time.Time `json:"expiresAt" example:"2023-01-01T12:05:00Z" doc:"Code expiration"`
	Message   string    `json:"message" example:"SMS verification code"`
}

// VerifyEmailRequestBody represents a request to verify email code
type VerifyEmailRequestBody struct {
	MethodID xid.ID `json:"methodId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"MFA method ID"`
	Code     string `json:"code" example:"123456" doc:"Email verification code"`
}

// GenerateBackupCodesRequest represents a request to generate backup codes
type GenerateBackupCodesRequest struct {
	Count int `json:"count,omitempty" example:"10" doc:"Number of backup codes to generate (default 10)"`
}

// MFABackCodes represents the response to backup code generation
type MFABackCodes struct {
	MethodID xid.ID   `json:"methodId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"MFA method ID"`
	Codes    []string `json:"codes" example:"[\"123456789\", \"987654321\"]" doc:"Generated backup codes"`
	Message  string   `json:"message" example:"Backup codes generated successfully" doc:"Success message"`
}

// UseBackupCodeRequest represents a request to use a backup code
type UseBackupCodeRequest struct {
	Code string `json:"code" example:"123456789" doc:"Backup code"`
}

// UseBackupCodeResponse represents the response to backup code usage
type UseBackupCodeResponse struct {
	Success        bool   `json:"success" example:"true" doc:"Whether code was valid"`
	CodesRemaining int    `json:"codesRemaining" example:"8" doc:"Number of unused backup codes remaining"`
	Message        string `json:"message" example:"Backup code used successfully" doc:"Response message"`
}

// MFAVerifyRequest represents a general MFA verification request
type MFAVerifyRequest struct {
	Method   string  `json:"method" example:"totp" doc:"MFA method type"`
	Code     string  `json:"code" example:"123456" doc:"MFA code"`
	MethodID *xid.ID `json:"methodId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Specific method ID"`
	MFAToken string  `json:"mfaToken,omitempty" doc:"MFA session token for login completion"`
	Context  string  `json:"context,omitempty" example:"setup" doc:"Verification context (setup, login, management)"`
}

// ValidateMFAChallengeRequest represents a request to validate an MFA challenge
type ValidateMFAChallengeRequest struct {
	ChallengeID string `json:"challengeId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Challenge ID from CreateMFAChallenge" validate:"required"`
	Method      string `json:"method" example:"totp" doc:"MFA method type (totp, sms, email, backup_code)" validate:"required,oneof=totp sms email backup_code"`
	Code        string `json:"code" example:"123456" doc:"MFA verification code" validate:"required,min=4,max=12"`
}

// MFAVerifyResponse represents a general MFA verification response
type MFAVerifyResponse struct {
	Success    bool           `json:"success" example:"true" doc:"Whether verification was successful"`
	Method     string         `json:"method" example:"totp" doc:"MFA method used"`
	Message    string         `json:"message" example:"MFA verification successful" doc:"Response message"`
	BackupUsed bool           `json:"backupUsed" example:"false" doc:"Whether a backup code was used"`
	LoginData  *LoginResponse `json:"loginData,omitempty" doc:"Full login response if completing authentication"`
}

// PendingMFALogin represents a pending login waiting for MFA completion
type PendingMFALogin struct {
	UserID      xid.ID                 `json:"userId"`
	SessionID   string                 `json:"sessionId"`
	LoginMethod string                 `json:"loginMethod"`
	IPAddress   string                 `json:"ipAddress,omitempty"`
	UserAgent   string                 `json:"userAgent,omitempty"`
	ExpiresAt   time.Time              `json:"expiresAt"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type MFARecoveryOptions struct {
	Available      bool     `json:"available" example:"true" doc:"Whether a backup code was available"`
	Methods        []string `json:"methods" example:"totp" doc:"MFA methods used"`
	HasBackupCodes bool     `json:"hasBackupCodes" example:"true" doc:"Whether a backup code was available"`
	ContactSupport bool     `json:"contactSupport" example:"true" doc:"Whether a contact support"`
}

// UpdateMFAMethodRequest represents a request to update an MFA method
type UpdateMFAMethodRequest struct {
	Name   string `json:"name,omitempty" example:"Updated Authenticator" doc:"Updated name"`
	Active bool   `json:"active,omitempty" example:"true" doc:"Updated active status"`
}

// MFAListRequest represents a request to list MFA methods
type MFAListRequest struct {
	PaginationParams
	UserID   OptionalParam[xid.ID] `json:"userId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by user" query:"userId"`
	Method   string                `json:"method,omitempty" example:"totp" doc:"Filter by method type" query:"method"`
	Verified OptionalParam[bool]   `json:"verified,omitempty" example:"true" doc:"Filter by verified status" query:"verified"`
	Active   OptionalParam[bool]   `json:"active,omitempty" example:"true" doc:"Filter by active status" query:"active"`
	Search   string                `json:"search,omitempty" example:"authenticator" doc:"Search in method name" query:"search"`
}

// MFAListResponse represents a list of MFA methods
type MFAListResponse = PaginatedOutput[MFAMethodSummary]

// MFAStats represents MFA statistics
type MFAStats struct {
	TotalMethods          int            `json:"totalMethods" example:"500" doc:"Total MFA methods"`
	VerifiedMethods       int            `json:"verifiedMethods" example:"450" doc:"Verified MFA methods"`
	ActiveMethods         int            `json:"activeMethods" example:"425" doc:"Active MFA methods"`
	MethodsByType         map[string]int `json:"methodsByType" example:"{\"totp\": 300, \"sms\": 150, \"email\": 50}" doc:"Methods by type"`
	UsersWithMFA          int            `json:"usersWithMFA" example:"380" doc:"Users with MFA enabled"`
	UsersWithMultipleMFA  int            `json:"usersWithMultipleMFA" example:"120" doc:"Users with multiple MFA methods"`
	MFAUsageToday         int            `json:"mfaUsageToday" example:"250" doc:"MFA verifications today"`
	MFAUsageWeek          int            `json:"mfaUsageWeek" example:"1750" doc:"MFA verifications this week"`
	BackupCodesUsed       int            `json:"backupCodesUsed" example:"15" doc:"Backup codes used this month"`
	AverageMethodsPerUser float64        `json:"averageMethodsPerUser" example:"1.3" doc:"Average MFA methods per user"`
}

// MFAActivity represents MFA activity information
type MFAActivity struct {
	ID         xid.ID                 `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Activity ID"`
	UserID     xid.ID                 `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	MethodID   *xid.ID                `json:"methodId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"MFA method ID"`
	Method     string                 `json:"method" example:"totp" doc:"MFA method type"`
	Action     string                 `json:"action" example:"verify" doc:"Action type (setup, verify, disable)"`
	Success    bool                   `json:"success" example:"true" doc:"Whether action was successful"`
	IPAddress  string                 `json:"ipAddress,omitempty" example:"192.168.1.1" doc:"IP address"`
	UserAgent  string                 `json:"userAgent,omitempty" example:"Mozilla/5.0..." doc:"User agent"`
	Location   string                 `json:"location,omitempty" example:"New York, NY" doc:"Location"`
	Error      string                 `json:"error,omitempty" example:"Invalid code" doc:"Error message if failed"`
	BackupUsed bool                   `json:"backupUsed" example:"false" doc:"Whether backup code was used"`
	Timestamp  time.Time              `json:"timestamp" example:"2023-01-01T12:00:00Z" doc:"Activity timestamp"`
	Details    map[string]interface{} `json:"details,omitempty" doc:"Additional activity details"`
}

// MFAActivityRequest represents a request for MFA activity
type MFAActivityRequest struct {
	PaginationParams
	UserID    OptionalParam[xid.ID]    `json:"userId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by user" query:"userId"`
	MethodID  OptionalParam[xid.ID]    `json:"methodId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by method" query:"methodId"`
	Method    string                   `json:"method,omitempty" example:"totp" doc:"Filter by method type" query:"method"`
	Action    string                   `json:"action,omitempty" example:"verify" doc:"Filter by action type" query:"action"`
	Success   OptionalParam[bool]      `json:"success,omitempty" example:"true" doc:"Filter by success status" query:"success"`
	StartDate OptionalParam[time.Time] `json:"startDate,omitempty" example:"2023-01-01T00:00:00Z" doc:"Start date" query:"startDate"`
	EndDate   OptionalParam[time.Time] `json:"endDate,omitempty" example:"2023-01-31T23:59:59Z" doc:"End date" query:"endDate"`
}

// MFAActivityResponse represents MFA activity response
type MFAActivityResponse = PaginatedOutput[MFAActivity]

// ResendMFACodeRequest represents a request to resend MFA code
type ResendMFACodeRequest struct {
	MethodID xid.ID `json:"methodId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"MFA method ID"`
}

// ResendMFACodeResponse represents the response to MFA code resend
type ResendMFACodeResponse struct {
	Success   bool      `json:"success" example:"true" doc:"Whether code was sent"`
	Message   string    `json:"message" example:"Code sent successfully" doc:"Response message"`
	ExpiresAt time.Time `json:"expiresAt" example:"2023-01-01T12:05:00Z" doc:"Code expiration"`
}

// MFARequirementCheck represents MFA requirement check
type MFARequirementCheck struct {
	UserID       xid.ID     `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	Required     bool       `json:"required" example:"true" doc:"Whether MFA is required"`
	Configured   bool       `json:"configured" example:"true" doc:"Whether user has MFA configured"`
	Methods      []string   `json:"methods" example:"[\"totp\", \"sms\"]" doc:"Available MFA methods"`
	GracePeriod  bool       `json:"gracePeriod" example:"false" doc:"Whether user is in grace period"`
	GraceExpires *time.Time `json:"graceExpires,omitempty" example:"2023-01-02T00:00:00Z" doc:"Grace period expiration"`
}

// MFAChallengeResponse represents MFA challenge response
type MFAChallengeResponse struct {
	ChallengeID  string     `json:"challengeId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Challenge ID"`
	Required     bool       `json:"required" example:"true" doc:"Whether MFA is required"`
	Configured   bool       `json:"configured" example:"true" doc:"Whether user has MFA configured"`
	Methods      []string   `json:"methods" example:"[\"totp\", \"sms\"]" doc:"Available MFA methods"`
	ExpiresAt    time.Time  `json:"expiresAt,omitempty" example:"2023-01-01T12:05:00Z" doc:"Challenge expiration"`
	GracePeriod  bool       `json:"gracePeriod" example:"false" doc:"Whether user is in grace period"`
	GraceExpires *time.Time `json:"graceExpires,omitempty" example:"2023-01-02T00:00:00Z" doc:"Grace period expiration"`
}

// MFAEnforcementRequest represents MFA enforcement settings
type MFAEnforcementRequest struct {
	Required         bool     `json:"required" example:"true" doc:"Whether MFA is required"`
	AllowedMethods   []string `json:"allowedMethods" example:"[\"totp\", \"sms\"]" doc:"Allowed MFA methods"`
	GracePeriodHours int      `json:"gracePeriodHours" example:"24" doc:"Grace period in hours"`
	ExemptUserTypes  []string `json:"exemptUserTypes,omitempty" example:"[\"service_account\"]" doc:"Exempt user types"`
}

// BulkMFAOperation represents a bulk MFA operation
type BulkMFAOperation struct {
	UserIDs   []xid.ID `json:"userIds" example:"[\"01FZS6TV7KP869DR7RXNEHXQKX\"]" doc:"User IDs"`
	Operation string   `json:"operation" example:"require_mfa" doc:"Operation (require_mfa, disable_mfa, reset_mfa)"`
	Reason    string   `json:"reason,omitempty" example:"Security policy update" doc:"Reason for operation"`
}

// BulkMFAOperationResponse represents bulk MFA operation response
type BulkMFAOperationResponse struct {
	Success      []xid.ID `json:"success" example:"[\"01FZS6TV7KP869DR7RXNEHXQKX\"]" doc:"Successful user IDs"`
	Failed       []xid.ID `json:"failed,omitempty" example:"[]" doc:"Failed user IDs"`
	SuccessCount int      `json:"successCount" example:"5" doc:"Success count"`
	FailureCount int      `json:"failureCount" example:"0" doc:"Failure count"`
	Errors       []string `json:"errors,omitempty" example:"[]" doc:"Error messages"`
}

// MFARecoveryRequest represents an MFA recovery request
type MFARecoveryRequest struct {
	UserID   xid.ID `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	Reason   string `json:"reason" example:"Lost device" doc:"Reason for recovery"`
	NewPhone string `json:"newPhone,omitempty" example:"+1234567890" doc:"New phone number for SMS recovery"`
	NewEmail string `json:"newEmail,omitempty" example:"new@example.com" doc:"New email for email recovery"`
}

// MFARecoveryResponse represents MFA recovery response
type MFARecoveryResponse struct {
	Success       bool     `json:"success" example:"true" doc:"Whether recovery was successful"`
	RecoveryToken string   `json:"recoveryToken,omitempty" example:"recovery_token_123" doc:"Recovery token"`
	BackupCodes   []string `json:"backupCodes,omitempty" example:"[\"123456789\"]" doc:"New backup codes"`
	Message       string   `json:"message" example:"MFA recovery successful" doc:"Response message"`
	MethodsReset  int      `json:"methodsReset" example:"2" doc:"Number of methods reset"`
}

// MFAExportRequest represents a request to export MFA data
type MFAExportRequest struct {
	UserID          *xid.ID    `json:"userId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by user"`
	Method          string     `json:"method,omitempty" example:"totp" doc:"Filter by method type"`
	StartDate       *time.Time `json:"startDate,omitempty" example:"2023-01-01T00:00:00Z" doc:"Start date"`
	EndDate         *time.Time `json:"endDate,omitempty" example:"2023-01-31T23:59:59Z" doc:"End date"`
	Format          string     `json:"format" example:"json" doc:"Export format (json, csv)"`
	IncludeActivity bool       `json:"includeActivity" example:"true" doc:"Include activity data"`
}

// MFAExportResponse represents MFA export response
type MFAExportResponse struct {
	DownloadURL string    `json:"downloadUrl" example:"https://api.example.com/downloads/mfa-export-123.json" doc:"Download URL"`
	ExpiresAt   time.Time `json:"expiresAt" example:"2023-01-01T13:00:00Z" doc:"Download URL expiration"`
	Format      string    `json:"format" example:"json" doc:"Export format"`
	RecordCount int       `json:"recordCount" example:"500" doc:"Number of records exported"`
}

// MFAConfiguration represents MFA configuration settings
type MFAConfiguration struct {
	Enabled            bool               `json:"enabled" example:"true" doc:"Whether MFA is enabled"`
	Required           bool               `json:"required" example:"false" doc:"Whether MFA is required"`
	AllowedMethods     []string           `json:"allowedMethods" example:"[\"totp\", \"sms\", \"email\"]" doc:"Allowed MFA methods"`
	TOTPSettings       TOTPSettings       `json:"totpSettings" doc:"TOTP configuration"`
	SMSSettings        SMSSettings        `json:"smsSettings" doc:"SMS configuration"`
	EmailSettings      EmailSettings      `json:"emailSettings" doc:"Email configuration"`
	BackupCodeSettings BackupCodeSettings `json:"backupCodeSettings" doc:"Backup code configuration"`
	GracePeriodHours   int                `json:"gracePeriodHours" example:"24" doc:"Grace period for MFA setup"`
	MaxFailedAttempts  int                `json:"maxFailedAttempts" example:"5" doc:"Max failed attempts before lockout"`
	LockoutDuration    int                `json:"lockoutDuration" example:"300" doc:"Lockout duration in seconds"`
}

// TOTPSettings represents TOTP configuration
type TOTPSettings struct {
	Issuer     string `json:"issuer" example:"MyApp" doc:"TOTP issuer name"`
	Algorithm  string `json:"algorithm" example:"SHA1" doc:"TOTP algorithm"`
	Digits     int    `json:"digits" example:"6" doc:"Number of digits"`
	Period     int    `json:"period" example:"30" doc:"Time period in seconds"`
	WindowSize int    `json:"windowSize" example:"1" doc:"Validation window size"`
}

// SMSSettings represents SMS MFA configuration
type SMSSettings struct {
	Enabled       bool   `json:"enabled" example:"true" doc:"Whether SMS MFA is enabled"`
	Provider      string `json:"provider" example:"twilio" doc:"SMS provider"`
	CodeLength    int    `json:"codeLength" example:"6" doc:"SMS code length"`
	ExpiryMinutes int    `json:"expiryMinutes" example:"5" doc:"Code expiry in minutes"`
	RateLimit     int    `json:"rateLimit" example:"3" doc:"Max SMS per hour"`
}

// EmailSettings represents email MFA configuration
type EmailSettings struct {
	Enabled       bool `json:"enabled" example:"true" doc:"Whether email MFA is enabled"`
	CodeLength    int  `json:"codeLength" example:"6" doc:"Email code length"`
	ExpiryMinutes int  `json:"expiryMinutes" example:"10" doc:"Code expiry in minutes"`
	RateLimit     int  `json:"rateLimit" example:"5" doc:"Max emails per hour"`
}

// BackupCodeSettings represents backup code configuration
type BackupCodeSettings struct {
	Enabled    bool `json:"enabled" example:"true" doc:"Whether backup codes are enabled"`
	Count      int  `json:"count" example:"10" doc:"Number of backup codes to generate"`
	Length     int  `json:"length" example:"8" doc:"Backup code length"`
	OneTimeUse bool `json:"oneTimeUse" example:"true" doc:"Whether codes are single-use"`
}
