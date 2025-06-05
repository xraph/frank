package user

import (
	"time"

	"github.com/juicycleff/frank/internal/model"
	"github.com/rs/xid"
)

// VerificationMethod represents the method used for verification
type VerificationMethod string

const (
	// VerificationMethodLink uses a magic link for verification
	VerificationMethodLink VerificationMethod = "link"

	// VerificationMethodOTP uses a one-time password for verification
	VerificationMethodOTP VerificationMethod = "otp"
)

// CreateUserInput represents input for creating a user
type CreateUserInput struct {
	Email           string                 `json:"email" validate:"required,email"`
	Password        string                 `json:"password,omitempty"`
	PhoneNumber     string                 `json:"phone_number,omitempty"`
	FirstName       string                 `json:"first_name,omitempty"`
	LastName        string                 `json:"last_name,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
	ProfileImageURL string                 `json:"profile_image_url,omitempty"`
	Locale          string                 `json:"locale,omitempty"`
	OrgID           xid.ID                 `json:"orgId,omitempty"`
}

// UpdateUserInput represents input for updating a user
type UpdateUserInput struct {
	PhoneNumber     *string                `json:"phone_number,omitempty"`
	FirstName       *string                `json:"first_name,omitempty"`
	LastName        *string                `json:"last_name,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
	ProfileImageURL *string                `json:"profile_image_url,omitempty"`
	Locale          *string                `json:"locale,omitempty"`
	Active          *bool                  `json:"active,omitempty"`
	PrimaryOrgID    *xid.ID                `json:"primaryOrgId,omitempty"`
}

// CreateVerificationInput represents input for creating a verification
type CreateVerificationInput struct {
	UserID      xid.ID             `json:"user_id" validate:"required"`
	Type        string             `json:"type" validate:"required"` // email, phone, password_reset, magic_link
	Email       string             `json:"email,omitempty"`
	PhoneNumber string             `json:"phone_number,omitempty"`
	RedirectURL string             `json:"redirect_url,omitempty"`
	ExpiresAt   time.Time          `json:"expires_at"`
	IPAddress   string             `json:"ip_address,omitempty"`
	UserAgent   string             `json:"user_agent,omitempty"`
	Method      VerificationMethod `json:"method,omitempty"`
}

// LoginResult represents the result of an authentication attempt
type LoginResult struct {
	User           *model.User // The authenticated user (now DTO)
	EmailVerified  bool        `json:"email_verified"`
	VerificationID xid.ID      `json:"verification_id"`
}

// ListUsersParams defines the parameters for listing users
type ListUsersParams struct {
	model.PaginationParams
	model.OrganisationParams
	Search string `query:"search"`
	// OrganizationID string `query:"organizationId"`
	Active model.OptionalParam[bool] `query:"active"`
}

// Verification is the DTO entity for the Verification schema.
type Verification struct {
	model.Base
	// UserID holds the value of the "user_id" field.
	UserID xid.ID `json:"user_id,omitempty"`
	// Verification type: email, phone, password_reset, magic_link
	Type string `json:"type,omitempty"`
	// Token holds the value of the "token" field.
	Token string `json:"-"`
	// Email holds the value of the "email" field.
	Email string `json:"email,omitempty"`
	// PhoneNumber holds the value of the "phone_number" field.
	PhoneNumber string `json:"phone_number,omitempty"`
	// RedirectURL holds the value of the "redirect_url" field.
	RedirectURL string `json:"redirect_url,omitempty"`
	// Used holds the value of the "used" field.
	Used bool `json:"used,omitempty"`
	// UsedAt holds the value of the "used_at" field.
	UsedAt *time.Time `json:"used_at,omitempty"`
	// Attempts holds the value of the "attempts" field.
	Attempts int `json:"attempts,omitempty"`
	// ExpiresAt holds the value of the "expires_at" field.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	// IPAddress holds the value of the "ip_address" field.
	IPAddress string `json:"ip_address,omitempty"`
	// UserAgent holds the value of the "user_agent" field.
	UserAgent string `json:"user_agent,omitempty"`
	// Attestation holds the value of the "attestation" field.
	Attestation map[string]interface{} `json:"attestation,omitempty"`
}
