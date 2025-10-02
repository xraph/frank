package models

import (
	"context"
	"time"

	"github.com/uptrace/bun"
	"github.com/xraph/frank/pkg/model"
)

// User model - handles all user types
type User struct {
	CommonModel
	Timestamps
	bun.BaseModel `bun:"table:users,alias:u"`

	Email                     string                 `bun:"email,notnull" json:"email"`
	PhoneNumber               *string                `bun:"phone_number" json:"phone_number,omitempty"`
	FirstName                 *string                `bun:"first_name" json:"first_name,omitempty"`
	LastName                  *string                `bun:"last_name" json:"last_name,omitempty"`
	Username                  *string                `bun:"username" json:"username,omitempty"`
	PasswordHash              *string                `bun:"password_hash" json:"-"`
	EmailVerified             bool                   `bun:"email_verified,notnull,default:false" json:"email_verified"`
	PhoneVerified             bool                   `bun:"phone_verified,notnull,default:false" json:"phone_verified"`
	Active                    bool                   `bun:"active,notnull,default:true" json:"active"`
	Blocked                   bool                   `bun:"blocked,notnull,default:false" json:"blocked"`
	LastLogin                 *time.Time             `bun:"last_login" json:"last_login,omitempty"`
	LastPasswordChange        *time.Time             `bun:"last_password_change" json:"last_password_change,omitempty"`
	Metadata                  map[string]interface{} `bun:"metadata,type:jsonb" json:"metadata,omitempty"`
	ProfileImageURL           *string                `bun:"profile_image_url" json:"profile_image_url,omitempty"`
	Locale                    string                 `bun:"locale,notnull,default:'en'" json:"locale"`
	Timezone                  *string                `bun:"timezone" json:"timezone,omitempty"`
	UserType                  model.UserType         `bun:"user_type,notnull,default:'external'" json:"user_type"`
	OrganizationID            *string                `bun:"organization_id,type:varchar(20)" json:"organization_id,omitempty"`
	PrimaryOrganizationID     *string                `bun:"primary_organization_id,type:varchar(20)" json:"primary_organization_id,omitempty"`
	IsPlatformAdmin           bool                   `bun:"is_platform_admin,notnull,default:false" json:"is_platform_admin"`
	AuthProvider              string                 `bun:"auth_provider,notnull,default:'internal'" json:"auth_provider"`
	ExternalID                *string                `bun:"external_id" json:"external_id,omitempty"`
	CustomerID                *string                `bun:"customer_id" json:"customer_id,omitempty"`
	CustomAttributes          map[string]interface{} `bun:"custom_attributes,type:jsonb" json:"custom_attributes,omitempty"`
	CreatedBy                 *string                `bun:"created_by,type:varchar(20)" json:"created_by,omitempty"`
	PasswordResetTokenExpires *time.Time             `bun:"password_reset_token_expires" json:"-"`
	PasswordResetToken        *string                `bun:"password_reset_token" json:"-"`
	LoginCount                int                    `bun:"login_count,notnull,default:0" json:"login_count"`
	LastLoginIP               *string                `bun:"last_login_ip" json:"last_login_ip,omitempty"`

	// Relations
	Organization        *Organization         `bun:"rel:belongs-to,join:organization_id=id" json:"organization,omitempty"`
	Memberships         []*Membership         `bun:"rel:has-many,join:id=user_id" json:"memberships,omitempty"`
	SentInvitations     []*Membership         `bun:"rel:has-many,join:id=invited_by" json:"sent_invitations,omitempty"`
	Sessions            []*Session            `bun:"rel:has-many,join:id=user_id" json:"sessions,omitempty"`
	APIKeys             []*APIKey             `bun:"rel:has-many,join:id=user_id" json:"api_keys,omitempty"`
	MFAMethods          []*MFA                `bun:"rel:has-many,join:id=user_id" json:"mfa_methods,omitempty"`
	Passkeys            []*Passkey            `bun:"rel:has-many,join:id=user_id" json:"passkeys,omitempty"`
	OAuthTokens         []*OAuthToken         `bun:"rel:has-many,join:id=user_id" json:"oauth_tokens,omitempty"`
	OAuthAuthorizations []*OAuthAuthorization `bun:"rel:has-many,join:id=user_id" json:"oauth_authorizations,omitempty"`
	Verifications       []*Verification       `bun:"rel:has-many,join:id=user_id" json:"verifications,omitempty"`
	UserRoles           []*UserRole           `bun:"rel:has-many,join:id=user_id" json:"user_roles,omitempty"`
	UserPermissions     []*UserPermission     `bun:"rel:has-many,join:id=user_id" json:"user_permissions,omitempty"`
	AuditLogs           []*Audit              `bun:"rel:has-many,join:id=user_id" json:"audit_logs,omitempty"`
	Activities          []*Activity           `bun:"rel:has-many,join:id=user_id" json:"activities,omitempty"`
}

// Session model
type Session struct {
	CommonModel
	Timestamps
	bun.BaseModel `bun:"table:sessions,alias:s"`

	UserID         string                 `bun:"user_id,notnull,type:varchar(20)" json:"user_id"`
	Token          string                 `bun:"token,unique,notnull" json:"-"`
	IPAddress      *string                `bun:"ip_address" json:"ip_address,omitempty"`
	UserAgent      *string                `bun:"user_agent" json:"user_agent,omitempty"`
	DeviceID       *string                `bun:"device_id" json:"device_id,omitempty"`
	Location       *string                `bun:"location" json:"location,omitempty"`
	OrganizationID *string                `bun:"organization_id,type:varchar(20)" json:"organization_id,omitempty"`
	Active         bool                   `bun:"active,notnull,default:true" json:"active"`
	ExpiresAt      time.Time              `bun:"expires_at,notnull" json:"expires_at"`
	LastActiveAt   time.Time              `bun:"last_active_at,notnull" json:"last_active_at"`
	Metadata       map[string]interface{} `bun:"metadata,type:jsonb" json:"metadata,omitempty"`

	// Relations
	User       *User       `bun:"rel:belongs-to,join:user_id=id" json:"user,omitempty"`
	AuditLogs  []*Audit    `bun:"rel:has-many,join:id=session_id" json:"audit_logs,omitempty"`
	Activities []*Activity `bun:"rel:has-many,join:id=session_id" json:"activities,omitempty"`
}

// BeforeAppendModel hook for Session
func (s *Session) BeforeAppendModel(ctx context.Context, query bun.Query) error {
	switch query.(type) {
	case *bun.InsertQuery:
		now := time.Now()
		if s.LastActiveAt.IsZero() {
			s.LastActiveAt = now
		}
	case *bun.UpdateQuery:
		s.LastActiveAt = time.Now()
	}
	return nil
}

// MFA model
type MFA struct {
	CommonModel
	Timestamps
	SoftDelete
	bun.BaseModel `bun:"table:mfa,alias:mfa"`

	UserID      string                 `bun:"user_id,notnull,type:varchar(20)" json:"user_id"`
	Method      string                 `bun:"method,notnull" json:"method"`
	Secret      string                 `bun:"secret,notnull" json:"-"`
	Verified    bool                   `bun:"verified,notnull,default:false" json:"verified"`
	Active      bool                   `bun:"active,notnull,default:true" json:"active"`
	BackupCodes []string               `bun:"backup_codes,type:jsonb" json:"-"`
	PhoneNumber *string                `bun:"phone_number" json:"phone_number,omitempty"`
	Email       *string                `bun:"email" json:"email,omitempty"`
	LastUsed    *time.Time             `bun:"last_used" json:"last_used,omitempty"`
	Metadata    map[string]interface{} `bun:"metadata,type:jsonb" json:"metadata,omitempty"`

	// Relations
	User *User `bun:"rel:belongs-to,join:user_id=id" json:"user,omitempty"`
}

// Passkey model
type Passkey struct {
	CommonModel
	Timestamps
	SoftDelete
	bun.BaseModel `bun:"table:passkeys,alias:pk"`

	UserID         string                 `bun:"user_id,notnull,type:varchar(20)" json:"user_id"`
	Name           string                 `bun:"name,notnull" json:"name"`
	CredentialID   string                 `bun:"credential_id,unique,notnull" json:"credential_id"`
	PublicKey      []byte                 `bun:"public_key,notnull" json:"-"`
	SignCount      int                    `bun:"sign_count,notnull,default:0" json:"sign_count"`
	Active         bool                   `bun:"active,notnull,default:true" json:"active"`
	DeviceType     *string                `bun:"device_type" json:"device_type,omitempty"`
	AAGUID         *string                `bun:"aaguid" json:"aaguid,omitempty"`
	LastUsed       *time.Time             `bun:"last_used" json:"last_used,omitempty"`
	Transports     []string               `bun:"transports,type:jsonb" json:"transports,omitempty"`
	Attestation    map[string]interface{} `bun:"attestation,type:jsonb" json:"attestation,omitempty"`
	BackupState    *bool                  `bun:"backup_state" json:"backup_state,omitempty"`
	BackupEligible *bool                  `bun:"backup_eligible" json:"backup_eligible,omitempty"`
	UserAgent      *string                `bun:"user_agent" json:"user_agent,omitempty"`
	IPAddress      *string                `bun:"ip_address" json:"ip_address,omitempty"`

	// Relations
	User *User `bun:"rel:belongs-to,join:user_id=id" json:"user,omitempty"`
}

// Verification model
type Verification struct {
	CommonModel
	Timestamps
	SoftDelete
	bun.BaseModel `bun:"table:verifications,alias:v"`

	UserID      string                 `bun:"user_id,notnull,type:varchar(20)" json:"user_id"`
	Type        string                 `bun:"type,notnull" json:"type"`
	Token       string                 `bun:"token,unique,notnull" json:"-"`
	Email       *string                `bun:"email" json:"email,omitempty"`
	PhoneNumber *string                `bun:"phone_number" json:"phone_number,omitempty"`
	RedirectURL *string                `bun:"redirect_url" json:"redirect_url,omitempty"`
	Used        bool                   `bun:"used,notnull,default:false" json:"used"`
	UsedAt      *time.Time             `bun:"used_at" json:"used_at,omitempty"`
	Attempts    int                    `bun:"attempts,notnull,default:0" json:"attempts"`
	ExpiresAt   time.Time              `bun:"expires_at,notnull" json:"expires_at"`
	IPAddress   *string                `bun:"ip_address" json:"ip_address,omitempty"`
	UserAgent   *string                `bun:"user_agent" json:"user_agent,omitempty"`
	Attestation map[string]interface{} `bun:"attestation,type:jsonb" json:"attestation,omitempty"`
	Metadata    map[string]interface{} `bun:"metadata,type:jsonb" json:"metadata,omitempty"`

	// Relations
	User *User `bun:"rel:belongs-to,join:user_id=id" json:"user,omitempty"`
}
