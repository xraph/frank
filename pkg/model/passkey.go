package model

import (
	"time"

	"github.com/rs/xid"
)

// Passkey represents a WebAuthn passkey credential
type Passkey struct {
	Base
	UserID         xid.ID                 `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	Name           string                 `json:"name" example:"Touch ID" doc:"User-friendly name for the passkey"`
	CredentialID   string                 `json:"credentialId" example:"credential_abc123" doc:"WebAuthn credential ID"`
	PublicKey      []byte                 `json:"publicKey,omitempty" doc:"Public key bytes (write-only)"`
	SignCount      int                    `json:"signCount" example:"5" doc:"WebAuthn signature counter"`
	Active         bool                   `json:"active" example:"true" doc:"Whether passkey is active"`
	DeviceType     string                 `json:"deviceType,omitempty" example:"platform" doc:"Device type (platform, roaming)"`
	AAGUID         string                 `json:"aaguid,omitempty" example:"00000000-0000-0000-0000-000000000000" doc:"Authenticator AAGUID"`
	LastUsed       *time.Time             `json:"lastUsed,omitempty" example:"2023-01-01T12:00:00Z" doc:"Last usage timestamp"`
	Transports     []string               `json:"transports,omitempty" example:"[\"internal\", \"usb\"]" doc:"Supported transports"`
	Attestation    map[string]interface{} `json:"attestation,omitempty" doc:"Attestation data"`
	UserAgent      string                 `json:"userAgent,omitempty" example:"Mozilla/5.0..." doc:"User agent when created"`
	IPAddress      string                 `json:"ipAddress,omitempty" example:"192.168.1.1" doc:"IP address when created"`
	BackupEligible bool                   `json:"backupEligible" example:"true" doc:"Whether credential is backup eligible"`
	BackupState    bool                   `json:"backupState" example:"false" doc:"Whether credential is backed up"`

	// Relationships
	User *UserSummary `json:"user,omitempty" doc:"User information"`
}

// PasskeySummary represents a simplified passkey for listings
type PasskeySummary struct {
	ID          xid.ID     `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Passkey ID"`
	Name        string     `json:"name" example:"Touch ID" doc:"Passkey name"`
	DeviceType  string     `json:"deviceType,omitempty" example:"platform" doc:"Device type"`
	Active      bool       `json:"active" example:"true" doc:"Whether passkey is active"`
	LastUsed    *time.Time `json:"lastUsed,omitempty" example:"2023-01-01T12:00:00Z" doc:"Last usage"`
	CreatedAt   time.Time  `json:"createdAt" example:"2023-01-01T10:00:00Z" doc:"Creation timestamp"`
	BackupState bool       `json:"backupState" example:"false" doc:"Backup status"`
	SignCount   int        `json:"signCount" example:"5" doc:"Usage count"`
}

// CreatePasskeyRequest represents a request to create a passkey
type CreatePasskeyRequest struct {
	Name           string                 `json:"name" example:"My Security Key" doc:"User-friendly name"`
	CredentialID   string                 `json:"credentialId" example:"credential_abc123" doc:"WebAuthn credential ID"`
	PublicKey      []byte                 `json:"publicKey" doc:"Public key bytes"`
	DeviceType     *string                `json:"deviceType,omitempty" example:"platform" doc:"Device type"`
	AAGUID         *string                `json:"aaguid,omitempty" example:"00000000-0000-0000-0000-000000000000" doc:"Authenticator AAGUID"`
	Transports     []string               `json:"transports,omitempty" example:"[\"internal\", \"usb\"]" doc:"Supported transports"`
	Attestation    map[string]interface{} `json:"attestation,omitempty" doc:"Attestation data"`
	UserAgent      string                 `json:"userAgent,omitempty" example:"Mozilla/5.0..." doc:"User agent"`
	IPAddress      string                 `json:"ipAddress,omitempty" example:"192.168.1.1" doc:"IP address"`
	BackupEligible bool                   `json:"backupEligible" example:"true" doc:"Backup eligible"`
	BackupState    bool                   `json:"backupState" example:"false" doc:"Backup state"`
}

// UpdatePasskeyRequest represents a request to update a passkey
type UpdatePasskeyRequest struct {
	Name   string `json:"name,omitempty" example:"Updated Security Key" doc:"Updated name"`
	Active bool   `json:"active,omitempty" example:"true" doc:"Updated active status"`
}

// PasskeyRegistrationBeginRequest represents a request to begin passkey registration
type PasskeyRegistrationBeginRequest struct {
	Username           string `json:"username,omitempty" example:"user@example.com" doc:"Username for registration"`
	DisplayName        string `json:"displayName,omitempty" example:"John Doe" doc:"Display name"`
	RequireResidentKey bool   `json:"requireResidentKey" example:"false" doc:"Require resident key"`
	UserVerification   string `json:"userVerification,omitempty" example:"preferred" doc:"User verification requirement"`
	AttestationType    string `json:"attestationType,omitempty" example:"none" doc:"Attestation type"`
	AuthenticatorType  string `json:"authenticatorType,omitempty" example:"platform" doc:"Authenticator type preference"`
}

// PasskeyRegistrationBeginResponse represents the response to begin passkey registration
type PasskeyRegistrationBeginResponse struct {
	Options   map[string]interface{} `json:"options" doc:"WebAuthn credential creation options"`
	Challenge string                 `json:"challenge" example:"challenge_abc123" doc:"Registration challenge"`
	SessionID string                 `json:"sessionId" example:"session_xyz789" doc:"Registration session ID"`
	ExpiresAt time.Time              `json:"expiresAt" example:"2023-01-01T12:05:00Z" doc:"Challenge expiration"`
}

// PasskeyRegistrationFinishRequest represents a request to finish passkey registration
type PasskeyRegistrationFinishRequest struct {
	SessionID string                 `json:"sessionId" example:"session_xyz789" doc:"Registration session ID"`
	Response  map[string]interface{} `json:"response" doc:"WebAuthn credential creation response"`
	Name      string                 `json:"name" example:"My Security Key" doc:"User-friendly name for the passkey"`
}

// PasskeyRegistrationFinishResponse represents the response to finish passkey registration
type PasskeyRegistrationFinishResponse struct {
	Success bool    `json:"success" example:"true" doc:"Whether registration was successful"`
	Passkey Passkey `json:"passkey" doc:"Created passkey"`
	Message string  `json:"message" example:"Passkey registered successfully" doc:"Success message"`
}

// PasskeyAuthenticationBeginRequest represents a request to begin passkey authentication
type PasskeyAuthenticationBeginRequest struct {
	Username         string `json:"username,omitempty" example:"user@example.com" doc:"Username for authentication"`
	UserVerification string `json:"userVerification,omitempty" example:"preferred" doc:"User verification requirement"`
}

// PasskeyAuthenticationBeginResponse represents the response to begin passkey authentication
type PasskeyAuthenticationBeginResponse struct {
	Options   map[string]interface{} `json:"options" doc:"WebAuthn credential request options"`
	Challenge string                 `json:"challenge" example:"challenge_abc123" doc:"Authentication challenge"`
	SessionID string                 `json:"sessionId" example:"session_xyz789" doc:"Authentication session ID"`
	ExpiresAt time.Time              `json:"expiresAt" example:"2023-01-01T12:05:00Z" doc:"Challenge expiration"`
}

// PasskeyAuthenticationFinishRequest represents a request to finish passkey authentication
type PasskeyAuthenticationFinishRequest struct {
	SessionID string                 `json:"sessionId" example:"session_xyz789" doc:"Authentication session ID"`
	Response  map[string]interface{} `json:"response" doc:"WebAuthn credential assertion response"`
}

// PasskeyAuthenticationFinishResponse represents the response to finish passkey authentication
type PasskeyAuthenticationFinishResponse struct {
	Success      bool   `json:"success" example:"true" doc:"Whether authentication was successful"`
	User         User   `json:"user" doc:"Authenticated user"`
	AccessToken  string `json:"accessToken,omitempty" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." doc:"Access token"`
	RefreshToken string `json:"refreshToken,omitempty" example:"refresh_token_123" doc:"Refresh token"`
	ExpiresIn    int    `json:"expiresIn,omitempty" example:"3600" doc:"Token expiration in seconds"`
	Message      string `json:"message" example:"Authentication successful" doc:"Success message"`
}

// PasskeyListRequest represents a request to list passkeys
type PasskeyListRequest struct {
	PaginationParams
	UserID     OptionalParam[xid.ID] `json:"userId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by user" query:"userId"`
	Active     OptionalParam[bool]   `json:"active,omitempty" example:"true" doc:"Filter by active status" query:"active"`
	DeviceType string                `json:"deviceType,omitempty" example:"platform" doc:"Filter by device type" query:"deviceType"`
	Search     string                `json:"search,omitempty" example:"touch" doc:"Search in passkey name" query:"search"`
}

// PasskeyListResponse represents a list of passkeys
type PasskeyListResponse = PaginatedOutput[PasskeySummary]

// PasskeyStats represents passkey statistics
type PasskeyStats struct {
	TotalPasskeys     int     `json:"totalPasskeys" example:"150" doc:"Total passkeys"`
	ActivePasskeys    int     `json:"activePasskeys" example:"140" doc:"Active passkeys"`
	PlatformPasskeys  int     `json:"platformPasskeys" example:"120" doc:"Platform passkeys"`
	RoamingPasskeys   int     `json:"roamingPasskeys" example:"30" doc:"Roaming passkeys"`
	BackedUpPasskeys  int     `json:"backedUpPasskeys" example:"80" doc:"Backed up passkeys"`
	PasskeysUsedToday int     `json:"passkeysUsedToday" example:"25" doc:"Passkeys used today"`
	PasskeysUsedWeek  int     `json:"passkeysUsedWeek" example:"95" doc:"Passkeys used this week"`
	PasskeysThisMonth int     `json:"passkeysThisMonth" example:"15" doc:"Passkeys created this month"`
	UniqueUsers       int     `json:"uniqueUsers" example:"85" doc:"Users with passkeys"`
	AveragePerUser    float64 `json:"averagePerUser" example:"1.8" doc:"Average passkeys per user"`
}

// PasskeyActivity represents passkey activity information
type PasskeyActivity struct {
	ID        xid.ID                 `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Activity ID"`
	PasskeyID xid.ID                 `json:"passkeyId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Passkey ID"`
	UserID    xid.ID                 `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	Action    string                 `json:"action" example:"authentication" doc:"Action type"`
	Success   bool                   `json:"success" example:"true" doc:"Whether action was successful"`
	IPAddress string                 `json:"ipAddress,omitempty" example:"192.168.1.1" doc:"IP address"`
	UserAgent string                 `json:"userAgent,omitempty" example:"Mozilla/5.0..." doc:"User agent"`
	Location  string                 `json:"location,omitempty" example:"New York, NY" doc:"Location"`
	Error     string                 `json:"error,omitempty" example:"Invalid signature" doc:"Error message if failed"`
	Timestamp time.Time              `json:"timestamp" example:"2023-01-01T12:00:00Z" doc:"Activity timestamp"`
	Details   map[string]interface{} `json:"details,omitempty" doc:"Additional activity details"`
}

// PasskeyActivityRequest represents a request for passkey activity
type PasskeyActivityRequest struct {
	PaginationParams
	PasskeyID OptionalParam[xid.ID]    `json:"passkeyId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by passkey" query:"passkeyId"`
	UserID    OptionalParam[xid.ID]    `json:"userId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by user" query:"userId"`
	Action    string                   `json:"action,omitempty" example:"authentication" doc:"Filter by action type" query:"action"`
	Success   OptionalParam[bool]      `json:"success,omitempty" example:"true" doc:"Filter by success status" query:"success"`
	StartDate OptionalParam[time.Time] `json:"startDate,omitempty" example:"2023-01-01T00:00:00Z" doc:"Start date" query:"startDate"`
	EndDate   OptionalParam[time.Time] `json:"endDate,omitempty" example:"2023-01-31T23:59:59Z" doc:"End date" query:"endDate"`
}

// PasskeyActivityResponse represents passkey activity response
type PasskeyActivityResponse = PaginatedOutput[PasskeyActivity]

// BulkDeletePasskeysRequest represents a bulk passkey deletion request
type BulkDeletePasskeysRequest struct {
	PasskeyIDs []xid.ID `json:"passkeyIds" example:"[\"01FZS6TV7KP869DR7RXNEHXQKX\"]" doc:"Passkey IDs to delete"`
	Reason     string   `json:"reason,omitempty" example:"Security incident" doc:"Reason for deletion"`
}

// BulkDeletePasskeysResponse represents bulk passkey deletion response
type BulkDeletePasskeysResponse struct {
	DeletedCount int      `json:"deletedCount" example:"5" doc:"Number of passkeys deleted"`
	Failed       []xid.ID `json:"failed,omitempty" example:"[]" doc:"Failed passkey IDs"`
	Errors       []string `json:"errors,omitempty" example:"[]" doc:"Error messages"`
}

// PasskeyVerificationRequest represents a passkey verification request
type PasskeyVerificationRequest struct {
	CredentialID string `json:"credentialId" example:"credential_abc123" doc:"Credential ID to verify"`
	Challenge    string `json:"challenge" example:"challenge_xyz789" doc:"Verification challenge"`
	Origin       string `json:"origin" example:"https://example.com" doc:"Origin of the request"`
}

// PasskeyVerificationResponse represents a passkey verification response
type PasskeyVerificationResponse struct {
	Valid     bool   `json:"valid" example:"true" doc:"Whether passkey is valid"`
	PasskeyID xid.ID `json:"passkeyId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Passkey ID if valid"`
	UserID    xid.ID `json:"userId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID if valid"`
	SignCount int    `json:"signCount,omitempty" example:"6" doc:"Updated sign count"`
	Error     string `json:"error,omitempty" example:"Invalid signature" doc:"Error message if invalid"`
}

// PasskeyBackupRequest represents a passkey backup eligibility request
type PasskeyBackupRequest struct {
	PasskeyIDs  []xid.ID `json:"passkeyIds" example:"[\"01FZS6TV7KP869DR7RXNEHXQKX\"]" doc:"Passkey IDs"`
	BackupState bool     `json:"backupState" example:"true" doc:"New backup state"`
}

// PasskeyBackupResponse represents a passkey backup response
type PasskeyBackupResponse struct {
	UpdatedCount int      `json:"updatedCount" example:"3" doc:"Number of passkeys updated"`
	Failed       []xid.ID `json:"failed,omitempty" example:"[]" doc:"Failed passkey IDs"`
	Errors       []string `json:"errors,omitempty" example:"[]" doc:"Error messages"`
}

// PasskeyDiscoveryRequest represents a request for passkey discovery
type PasskeyDiscoveryRequest struct {
	Username string `json:"username,omitempty" example:"user@example.com" doc:"Username to discover passkeys for"`
	Origin   string `json:"origin" example:"https://example.com" doc:"Origin of the request"`
}

// PasskeyDiscoveryResponse represents passkey discovery response
type PasskeyDiscoveryResponse struct {
	Available        bool     `json:"available" example:"true" doc:"Whether passkeys are available"`
	Count            int      `json:"count" example:"2" doc:"Number of available passkeys"`
	PlatformSupport  bool     `json:"platformSupport" example:"true" doc:"Whether platform authenticator is supported"`
	RoamingSupport   bool     `json:"roamingSupport" example:"true" doc:"Whether roaming authenticator is supported"`
	ConditionalUI    bool     `json:"conditionalUI" example:"true" doc:"Whether conditional UI is supported"`
	SupportedMethods []string `json:"supportedMethods" example:"[\"platform\", \"roaming\"]" doc:"Supported authenticator methods"`
}

// PasskeyExportRequest represents a request to export passkey data
type PasskeyExportRequest struct {
	UserID          *xid.ID    `json:"userId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by user"`
	StartDate       *time.Time `json:"startDate,omitempty" example:"2023-01-01T00:00:00Z" doc:"Start date"`
	EndDate         *time.Time `json:"endDate,omitempty" example:"2023-01-31T23:59:59Z" doc:"End date"`
	Format          string     `json:"format" example:"json" doc:"Export format (json, csv)"`
	IncludeActivity bool       `json:"includeActivity" example:"true" doc:"Include activity data"`
}

// PasskeyExportResponse represents passkey export response
type PasskeyExportResponse struct {
	DownloadURL string    `json:"downloadUrl" example:"https://api.example.com/downloads/passkeys-export-123.json" doc:"Download URL"`
	ExpiresAt   time.Time `json:"expiresAt" example:"2023-01-01T13:00:00Z" doc:"Download URL expiration"`
	Format      string    `json:"format" example:"json" doc:"Export format"`
	RecordCount int       `json:"recordCount" example:"150" doc:"Number of records exported"`
}
