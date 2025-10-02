package models

import (
	"time"

	"github.com/uptrace/bun"
	"github.com/xraph/frank/pkg/model"
)

// SubscriptionStatus enum
type SubscriptionStatus string

const (
	SubscriptionStatusActive   SubscriptionStatus = "active"
	SubscriptionStatusTrialing SubscriptionStatus = "trialing"
	SubscriptionStatusPastDue  SubscriptionStatus = "past_due"
	SubscriptionStatusCanceled SubscriptionStatus = "canceled"
	SubscriptionStatusUnpaid   SubscriptionStatus = "unpaid"
)

// Organization model
type Organization struct {
	CommonModel
	Timestamps
	SoftDelete
	bun.BaseModel `bun:"table:organizations,alias:o"`

	Name                   string                 `bun:"name,notnull" json:"name"`
	Slug                   string                 `bun:"slug,unique,notnull" json:"slug"`
	Domains                []string               `bun:"domains,type:text[],array" json:"domains,omitempty"`
	VerifiedDomains        []string               `bun:"verified_domains,type:text[],array" json:"verified_domains,omitempty"`
	Domain                 *string                `bun:"domain" json:"domain,omitempty"`
	LogoURL                *string                `bun:"logo_url" json:"logo_url,omitempty"`
	Plan                   string                 `bun:"plan,notnull,default:'free'" json:"plan"`
	Active                 bool                   `bun:"active,notnull,default:true" json:"active"`
	Metadata               map[string]interface{} `bun:"metadata,type:jsonb" json:"metadata,omitempty"`
	TrialEndsAt            *time.Time             `bun:"trial_ends_at" json:"trial_ends_at,omitempty"`
	TrialUsed              bool                   `bun:"trial_used,notnull,default:false" json:"trial_used"`
	OwnerID                *string                `bun:"owner_id,type:varchar(20)" json:"owner_id,omitempty"`
	OrgType                model.OrgType          `bun:"org_type,notnull,default:'customer'" json:"org_type"`
	IsPlatformOrganization bool                   `bun:"is_platform_organization,notnull,default:false" json:"is_platform_organization"`
	ExternalUserLimit      int                    `bun:"external_user_limit,notnull,default:5" json:"external_user_limit"`
	EndUserLimit           int                    `bun:"end_user_limit,notnull,default:100" json:"end_user_limit"`
	SSOEnabled             bool                   `bun:"sso_enabled,notnull,default:false" json:"sso_enabled"`
	SSODomain              *string                `bun:"sso_domain" json:"sso_domain,omitempty"`
	SubscriptionID         *string                `bun:"subscription_id" json:"subscription_id,omitempty"`
	CustomerID             *string                `bun:"customer_id" json:"customer_id,omitempty"`
	SubscriptionStatus     SubscriptionStatus     `bun:"subscription_status,notnull,default:'trialing'" json:"subscription_status"`
	AuthServiceEnabled     bool                   `bun:"auth_service_enabled,notnull,default:false" json:"auth_service_enabled"`
	AuthConfig             map[string]interface{} `bun:"auth_config,type:jsonb" json:"auth_config,omitempty"`
	AuthDomain             *string                `bun:"auth_domain" json:"auth_domain,omitempty"`
	APIRequestLimit        int                    `bun:"api_request_limit,notnull,default:10000" json:"api_request_limit"`
	APIRequestsUsed        int                    `bun:"api_requests_used,notnull,default:0" json:"api_requests_used"`
	CurrentExternalUsers   int                    `bun:"current_external_users,notnull,default:0" json:"current_external_users"`
	CurrentEndUsers        int                    `bun:"current_end_users,notnull,default:0" json:"current_end_users"`

	// Relations
	Users                  []*User                 `bun:"rel:has-many,join:id=organization_id" json:"users,omitempty"`
	Memberships            []*Membership           `bun:"rel:has-many,join:id=organization_id" json:"memberships,omitempty"`
	SMSTemplates           []*SMSTemplate          `bun:"rel:has-many,join:id=organization_id" json:"sms_templates,omitempty"`
	EmailTemplates         []*EmailTemplate        `bun:"rel:has-many,join:id=organization_id" json:"email_templates,omitempty"`
	APIKeys                []*APIKey               `bun:"rel:has-many,join:id=organization_id" json:"api_keys,omitempty"`
	Webhooks               []*Webhook              `bun:"rel:has-many,join:id=organization_id" json:"webhooks,omitempty"`
	FeatureFlags           []*OrganizationFeature  `bun:"rel:has-many,join:id=organization_id" json:"feature_flags,omitempty"`
	IdentityProviders      []*IdentityProvider     `bun:"rel:has-many,join:id=organization_id" json:"identity_providers,omitempty"`
	OAuthClients           []*OAuthClient          `bun:"rel:has-many,join:id=organization_id" json:"oauth_clients,omitempty"`
	Roles                  []*Role                 `bun:"rel:has-many,join:id=organization_id" json:"roles,omitempty"`
	UserRoleContexts       []*UserRole             `bun:"rel:has-many,join:id=context_id" json:"user_role_contexts,omitempty"`
	UserPermissionContexts []*UserPermission       `bun:"rel:has-many,join:id=context_id" json:"user_permission_contexts,omitempty"`
	AuditLogs              []*Audit                `bun:"rel:has-many,join:id=organization_id" json:"audit_logs,omitempty"`
	OrganizationProviders  []*OrganizationProvider `bun:"rel:has-many,join:id=organization_id" json:"organization_providers,omitempty"`
	Activities             []*Activity             `bun:"rel:has-many,join:id=organization_id" json:"activities,omitempty"`
}

// MembershipStatus enum
type MembershipStatus string

const (
	MembershipStatusPending  MembershipStatus = "pending"
	MembershipStatusActive   MembershipStatus = "active"
	MembershipStatusInactive MembershipStatus = "inactive"
)

// Membership model
type Membership struct {
	CommonModel
	Timestamps
	SoftDelete
	bun.BaseModel `bun:"table:memberships,alias:m"`

	UserID           string                 `bun:"user_id,notnull,type:varchar(20)" json:"user_id"`
	OrganizationID   string                 `bun:"organization_id,notnull,type:varchar(20)" json:"organization_id"`
	RoleID           string                 `bun:"role_id,notnull,type:varchar(20)" json:"role_id"`
	Email            string                 `bun:"email,notnull" json:"email"`
	Status           MembershipStatus       `bun:"status,notnull,default:'pending'" json:"status"`
	InvitedBy        *string                `bun:"invited_by,type:varchar(20)" json:"invited_by,omitempty"`
	InvitedAt        time.Time              `bun:"invited_at,notnull" json:"invited_at"`
	JoinedAt         *time.Time             `bun:"joined_at" json:"joined_at,omitempty"`
	ExpiresAt        *time.Time             `bun:"expires_at" json:"expires_at,omitempty"`
	InvitationToken  *string                `bun:"invitation_token" json:"-"`
	IsBillingContact bool                   `bun:"is_billing_contact,notnull,default:false" json:"is_billing_contact"`
	IsPrimaryContact bool                   `bun:"is_primary_contact,notnull,default:false" json:"is_primary_contact"`
	LeftAt           *time.Time             `bun:"left_at" json:"left_at,omitempty"`
	Metadata         map[string]interface{} `bun:"metadata,type:jsonb" json:"metadata,omitempty"`
	CustomFields     map[string]interface{} `bun:"custom_fields,type:jsonb" json:"custom_fields,omitempty"`

	// Relations
	User         *User         `bun:"rel:belongs-to,join:user_id=id" json:"user,omitempty"`
	Organization *Organization `bun:"rel:belongs-to,join:organization_id=id" json:"organization,omitempty"`
	Role         *Role         `bun:"rel:belongs-to,join:role_id=id" json:"role,omitempty"`
	Inviter      *User         `bun:"rel:belongs-to,join:invited_by=id" json:"inviter,omitempty"`
}

// IdentityProvider model
type IdentityProvider struct {
	CommonModel
	Timestamps
	SoftDelete
	bun.BaseModel `bun:"table:identity_providers,alias:idp"`

	Name                  string                 `bun:"name,notnull" json:"name"`
	OrganizationID        string                 `bun:"organization_id,notnull,type:varchar(20)" json:"organization_id"`
	ProviderType          string                 `bun:"provider_type,notnull" json:"provider_type"`
	ClientID              *string                `bun:"client_id" json:"client_id,omitempty"`
	ClientSecret          *string                `bun:"client_secret" json:"-"`
	Issuer                *string                `bun:"issuer" json:"issuer,omitempty"`
	AuthorizationEndpoint *string                `bun:"authorization_endpoint" json:"authorization_endpoint,omitempty"`
	TokenEndpoint         *string                `bun:"token_endpoint" json:"token_endpoint,omitempty"`
	UserinfoEndpoint      *string                `bun:"userinfo_endpoint" json:"userinfo_endpoint,omitempty"`
	JWKSURI               *string                `bun:"jwks_uri" json:"jwks_uri,omitempty"`
	MetadataURL           *string                `bun:"metadata_url" json:"metadata_url,omitempty"`
	RedirectURI           *string                `bun:"redirect_uri" json:"redirect_uri,omitempty"`
	Certificate           *string                `bun:"certificate" json:"-"`
	PrivateKey            *string                `bun:"private_key" json:"-"`
	Active                bool                   `bun:"active,notnull,default:true" json:"active"`
	Enabled               bool                   `bun:"enabled,notnull,default:true" json:"enabled"`
	Primary               bool                   `bun:"primary,notnull,default:false" json:"primary"`
	AutoProvision         bool                   `bun:"auto_provision,notnull,default:false" json:"auto_provision"`
	DefaultRole           *string                `bun:"default_role" json:"default_role,omitempty"`
	Domain                *string                `bun:"domain" json:"domain,omitempty"`
	IconURL               *string                `bun:"icon_url" json:"icon_url,omitempty"`
	ButtonText            *string                `bun:"button_text" json:"button_text,omitempty"`
	Protocol              *string                `bun:"protocol" json:"protocol,omitempty"`
	Domains               []string               `bun:"domains,type:text[],array" json:"domains,omitempty"`
	AttributesMapping     map[string]string      `bun:"attributes_mapping,type:jsonb" json:"attributes_mapping,omitempty"`
	Metadata              map[string]interface{} `bun:"metadata,type:jsonb" json:"metadata,omitempty"`

	// Relations
	Organization          *Organization           `bun:"rel:belongs-to,join:organization_id=id" json:"organization,omitempty"`
	OrganizationProviders []*OrganizationProvider `bun:"rel:has-many,join:id=provider_id" json:"organization_providers,omitempty"`
}

// OrganizationProvider model
type OrganizationProvider struct {
	CommonModel
	Timestamps
	SoftDelete
	bun.BaseModel `bun:"table:organization_providers,alias:op"`

	OrganizationID      string                 `bun:"organization_id,notnull,type:varchar(20)" json:"organization_id"`
	ProviderID          string                 `bun:"provider_id,notnull,type:varchar(20)" json:"provider_id"`
	TemplateID          string                 `bun:"template_id,notnull,type:varchar(20)" json:"template_id"`
	TemplateKey         string                 `bun:"template_key,notnull" json:"template_key"`
	CustomConfig        map[string]interface{} `bun:"custom_config,type:jsonb" json:"custom_config,omitempty"`
	EnabledAt           time.Time              `bun:"enabled_at,notnull" json:"enabled_at"`
	LastUsed            *time.Time             `bun:"last_used" json:"last_used,omitempty"`
	UsageCount          int                    `bun:"usage_count,notnull,default:0" json:"usage_count"`
	Enabled             bool                   `bun:"enabled,notnull,default:true" json:"enabled"`
	SuccessRate         float64                `bun:"success_rate,notnull,default:0.0" json:"success_rate"`
	TotalLogins         int                    `bun:"total_logins,notnull,default:0" json:"total_logins"`
	SuccessfulLogins    int                    `bun:"successful_logins,notnull,default:0" json:"successful_logins"`
	FailedLogins        int                    `bun:"failed_logins,notnull,default:0" json:"failed_logins"`
	LastSuccess         *time.Time             `bun:"last_success" json:"last_success,omitempty"`
	LastFailure         *time.Time             `bun:"last_failure" json:"last_failure,omitempty"`
	ConfigErrors        int                    `bun:"config_errors,notnull,default:0" json:"config_errors"`
	AverageResponseTime float64                `bun:"average_response_time,notnull,default:0.0" json:"average_response_time"`
	AnalyticsData       map[string]interface{} `bun:"analytics_data,type:jsonb" json:"analytics_data,omitempty"`
	Metadata            map[string]interface{} `bun:"metadata,type:jsonb" json:"metadata,omitempty"`

	// Relations
	Organization *Organization     `bun:"rel:belongs-to,join:organization_id=id" json:"organization,omitempty"`
	Provider     *IdentityProvider `bun:"rel:belongs-to,join:provider_id=id" json:"provider,omitempty"`
	Template     *ProviderTemplate `bun:"rel:belongs-to,join:template_id=id" json:"template,omitempty"`
}

// ProviderTemplate model
type ProviderTemplate struct {
	CommonModel
	Timestamps
	SoftDelete
	bun.BaseModel `bun:"table:provider_templates,alias:pt"`

	Key               string                 `bun:"key,unique,notnull" json:"key"`
	Name              string                 `bun:"name,notnull" json:"name"`
	DisplayName       string                 `bun:"display_name,notnull" json:"display_name"`
	Type              string                 `bun:"type,notnull" json:"type"`
	Protocol          string                 `bun:"protocol,notnull" json:"protocol"`
	IconURL           *string                `bun:"icon_url" json:"icon_url,omitempty"`
	Category          string                 `bun:"category,notnull,default:'general'" json:"category"`
	Popular           bool                   `bun:"popular,notnull,default:false" json:"popular"`
	Active            bool                   `bun:"active,notnull,default:true" json:"active"`
	Description       *string                `bun:"description,type:text" json:"description,omitempty"`
	ConfigTemplate    map[string]interface{} `bun:"config_template,type:jsonb,notnull" json:"config_template"`
	RequiredFields    []string               `bun:"required_fields,type:jsonb" json:"required_fields,omitempty"`
	SupportedFeatures []string               `bun:"supported_features,type:jsonb" json:"supported_features,omitempty"`
	DocumentationURL  *string                `bun:"documentation_url" json:"documentation_url,omitempty"`
	SetupGuideURL     *string                `bun:"setup_guide_url" json:"setup_guide_url,omitempty"`
	UsageCount        int                    `bun:"usage_count,notnull,default:0" json:"usage_count"`
	AverageSetupTime  *float64               `bun:"average_setup_time" json:"average_setup_time,omitempty"`
	SuccessRate       float64                `bun:"success_rate,notnull,default:0.0" json:"success_rate"`
	PopularityRank    int                    `bun:"popularity_rank,notnull,default:0" json:"popularity_rank"`
	Metadata          map[string]interface{} `bun:"metadata,type:jsonb" json:"metadata,omitempty"`

	// Relations
	OrganizationProviders []*OrganizationProvider `bun:"rel:has-many,join:id=template_id" json:"organization_providers,omitempty"`
}
