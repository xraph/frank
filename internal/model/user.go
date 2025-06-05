package model

import (
	"time"

	"github.com/rs/xid"
)

// User represents the user data sent in responses
type User struct {
	Base
	// Email holds the value of the "email" field.
	Email string `json:"email,omitempty"`
	// PhoneNumber holds the value of the "phone_number" field.
	PhoneNumber string `json:"phone_number,omitempty"`
	// FirstName holds the value of the "first_name" field.
	FirstName string `json:"first_name,omitempty"`
	// LastName holds the value of the "last_name" field.
	LastName string `json:"last_name,omitempty"`
	// ProfileImageURL holds the value of the "profile_image_url" field.
	ProfileImageURL string `json:"profile_image_url,omitempty"`
	// Locale holds the value of the "locale" field.
	Locale string `json:"locale,omitempty"`
	// Active holds the value of the "active" field.
	Active bool `json:"active,omitempty"`
	// EmailVerified holds the value of the "email_verified" field.
	EmailVerified bool `json:"email_verified,omitempty"`
	// PhoneVerified holds the value of the "phone_verified" field.
	PhoneVerified bool `json:"phone_verified,omitempty"`
	// LastLogin holds the value of the "last_login" field.
	LastLogin *time.Time `json:"last_login,omitempty"`
	// LastPasswordChange holds the value of the "last_password_change" field.
	LastPasswordChange *time.Time `json:"last_password_change,omitempty"`
	// PrimaryOrganizationID holds the value of the "primary_organization_id" field.
	PrimaryOrganizationID *xid.ID `json:"primary_organization_id,omitempty"`
	// Metadata holds the value of the "metadata" field.
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Auditor represents the user data sent in responses
type Auditor struct {
	ID          xid.ID `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX"`
	Email       string `json:"email"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	AvatarURL   string `json:"avatarUrl,omitempty"`
}
