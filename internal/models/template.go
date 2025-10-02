package models

import (
	"time"

	"github.com/uptrace/bun"
)

// EmailTemplate model
type EmailTemplate struct {
	CommonModel
	Timestamps
	SoftDelete
	bun.BaseModel `bun:"table:email_templates,alias:et"`

	Name           string                 `bun:"name,notnull" json:"name"`
	Subject        string                 `bun:"subject,notnull" json:"subject"`
	Type           string                 `bun:"type,notnull" json:"type"`
	HTMLContent    string                 `bun:"html_content,notnull" json:"html_content"`
	TextContent    *string                `bun:"text_content" json:"text_content,omitempty"`
	OrganizationID *string                `bun:"organization_id,type:varchar(20)" json:"organization_id,omitempty"`
	Active         bool                   `bun:"active,notnull,default:true" json:"active"`
	System         bool                   `bun:"system,notnull,default:false" json:"system"`
	Locale         string                 `bun:"locale,notnull,default:'en'" json:"locale"`
	Metadata       map[string]interface{} `bun:"metadata,type:jsonb" json:"metadata,omitempty"`

	// Relations
	Organization *Organization `bun:"rel:belongs-to,join:organization_id=id" json:"organization,omitempty"`
}

// SMSTemplate model
type SMSTemplate struct {
	CommonModel
	Timestamps
	SoftDelete
	bun.BaseModel `bun:"table:sms_templates,alias:st"`

	Name              string                 `bun:"name,notnull" json:"name"`
	Content           string                 `bun:"content,notnull" json:"content"`
	Type              string                 `bun:"type,notnull" json:"type"`
	OrganizationID    *string                `bun:"organization_id,type:varchar(20)" json:"organization_id,omitempty"`
	Active            bool                   `bun:"active,notnull,default:true" json:"active"`
	System            bool                   `bun:"system,notnull,default:false" json:"system"`
	Locale            string                 `bun:"locale,notnull,default:'en'" json:"locale"`
	MaxLength         int                    `bun:"max_length,notnull,default:160" json:"max_length"`
	MessageType       string                 `bun:"message_type,notnull,default:'transactional'" json:"message_type"`
	EstimatedSegments *int                   `bun:"estimated_segments,default:1" json:"estimated_segments,omitempty"`
	EstimatedCost     *float64               `bun:"estimated_cost,default:0.0" json:"estimated_cost,omitempty"`
	Currency          *string                `bun:"currency,default:'USD'" json:"currency,omitempty"`
	Variables         []string               `bun:"variables,type:jsonb" json:"variables,omitempty"`
	Metadata          map[string]interface{} `bun:"metadata,type:jsonb" json:"metadata,omitempty"`
	LastUsedAt        *time.Time             `bun:"last_used_at" json:"last_used_at,omitempty"`
	UsageCount        int                    `bun:"usage_count,notnull,default:0" json:"usage_count"`

	// Relations
	Organization *Organization `bun:"rel:belongs-to,join:organization_id=id" json:"organization,omitempty"`
}

// FeatureComponent enum
type FeatureComponent string

const (
	FeatureComponentOAuth2       FeatureComponent = "oauth2"
	FeatureComponentPasswordless FeatureComponent = "passwordless"
	FeatureComponentMFA          FeatureComponent = "mfa"
	FeatureComponentPasskeys     FeatureComponent = "passkeys"
	FeatureComponentSSO          FeatureComponent = "sso"
	FeatureComponentEnterprise   FeatureComponent = "enterprise"
	FeatureComponentWebhooks     FeatureComponent = "webhooks"
	FeatureComponentAPIKeys      FeatureComponent = "api_keys"
)

// FeatureFlag model
type FeatureFlag struct {
	CommonModel
	Timestamps
	SoftDelete
	bun.BaseModel `bun:"table:feature_flags,alias:ff"`

	Name        string           `bun:"name,unique,notnull" json:"name"`
	Key         string           `bun:"key,unique,notnull" json:"key"`
	Description *string          `bun:"description" json:"description,omitempty"`
	Enabled     bool             `bun:"enabled,notnull,default:false" json:"enabled"`
	IsPremium   bool             `bun:"is_premium,notnull,default:false" json:"is_premium"`
	Component   FeatureComponent `bun:"component,notnull" json:"component"`

	// Relations
	OrganizationFeatures []*OrganizationFeature `bun:"rel:has-many,join:id=feature_id" json:"organization_features,omitempty"`
}

// OrganizationFeature model
type OrganizationFeature struct {
	CommonModel
	Timestamps
	SoftDelete
	bun.BaseModel `bun:"table:organization_features,alias:of"`

	OrganizationID string                 `bun:"organization_id,notnull,type:varchar(20)" json:"organization_id"`
	FeatureID      string                 `bun:"feature_id,notnull,type:varchar(20)" json:"feature_id"`
	Enabled        bool                   `bun:"enabled,notnull,default:true" json:"enabled"`
	Settings       map[string]interface{} `bun:"settings,type:jsonb" json:"settings,omitempty"`

	// Relations
	Organization *Organization `bun:"rel:belongs-to,join:organization_id=id" json:"organization,omitempty"`
	Feature      *FeatureFlag  `bun:"rel:belongs-to,join:feature_id=id" json:"feature,omitempty"`
}

// SSOState model - for temporary SSO state storage
type SSOState struct {
	CommonModel
	Timestamps
	SoftDelete
	bun.BaseModel `bun:"table:sso_states,alias:ss"`

	State       string    `bun:"state,unique,notnull" json:"state"`
	Data        string    `bun:"data,notnull" json:"data"` // JSON-encoded data
	ExpiresAt   time.Time `bun:"expires_at,notnull" json:"expires_at"`
	RedirectURL *string   `bun:"redirect_url" json:"redirect_url,omitempty"`
}
