package model

import (
	"time"

	"github.com/juicycleff/frank/ent"
)

// Organization is the DTO entity for the Organization schema.
type Organization struct {
	Base
	// Name holds the value of the "name" field.
	Name string `json:"name,omitempty"`
	// Slug holds the value of the "slug" field.
	Slug string `json:"slug,omitempty"`
	// Domain holds the value of the "domain" field.
	Domain string `json:"domain,omitempty"`
	// LogoURL holds the value of the "logo_url" field.
	LogoURL string `json:"logo_url,omitempty"`
	// Plan holds the value of the "plan" field.
	Plan string `json:"plan,omitempty"`
	// Active holds the value of the "active" field.
	Active bool `json:"active,omitempty"`
	// Metadata holds the value of the "metadata" field.
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	// TrialEndsAt holds the value of the "trial_ends_at" field.
	TrialEndsAt *time.Time `json:"trial_ends_at,omitempty"`
	// TrialUsed holds the value of the "trial_used" field.
	TrialUsed bool `json:"trial_used,omitempty"`
}

// ConvertOrganizationToDTO converts an ent.Organization to Organization DTO
func ConvertOrganizationToDTO(entOrg *ent.Organization) *Organization {
	return &Organization{
		Base: Base{
			ID:        entOrg.ID,
			CreatedAt: entOrg.CreatedAt,
			UpdatedAt: entOrg.UpdatedAt,
		},
		Name:        entOrg.Name,
		Slug:        entOrg.Slug,
		Active:      entOrg.Active,
		Metadata:    entOrg.Metadata,
		LogoURL:     entOrg.LogoURL,
		Domain:      entOrg.Domain,
		TrialEndsAt: entOrg.TrialEndsAt,
		TrialUsed:   entOrg.TrialUsed,
	}
}

// ConvertOrganizationsToDTO converts a slice of ent.Organization to Organization DTOs
func ConvertOrganizationsToDTO(entOrgs []*ent.Organization) []*Organization {
	orgs := make([]*Organization, len(entOrgs))
	for i, entOrg := range entOrgs {
		orgs[i] = ConvertOrganizationToDTO(entOrg)
	}
	return orgs
}

// ConvertUserToDTO converts an ent.User to User DTO
func ConvertUserToDTO(entUser *ent.User) *User {
	return &User{
		Base: Base{
			ID:        entUser.ID,
			CreatedAt: entUser.CreatedAt,
			UpdatedAt: entUser.UpdatedAt,
		},
		Email:                 entUser.Email,
		PhoneNumber:           entUser.PhoneNumber,
		FirstName:             entUser.FirstName,
		LastName:              entUser.LastName,
		ProfileImageURL:       entUser.ProfileImageURL,
		Locale:                entUser.Locale,
		Active:                entUser.Active,
		EmailVerified:         entUser.EmailVerified,
		PhoneVerified:         entUser.PhoneVerified,
		LastLogin:             entUser.LastLogin,
		LastPasswordChange:    entUser.LastPasswordChange,
		PrimaryOrganizationID: &entUser.PrimaryOrganizationID,
		Metadata:              entUser.Metadata,
	}
}

// ConvertUsersToDTO converts a slice of ent.User to User DTOs
func ConvertUsersToDTO(entUsers []*ent.User) []*User {
	users := make([]*User, len(entUsers))
	for i, entUser := range entUsers {
		users[i] = ConvertUserToDTO(entUser)
	}
	return users
}
