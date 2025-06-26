package model

import (
	"time"

	"github.com/rs/xid"
)

// Organization represents an organization in the system
type Organization struct {
	Base
	Name                   string                 `json:"name" example:"Acme Corp" doc:"Organization name"`
	Slug                   string                 `json:"slug" example:"acme-corp" doc:"Unique organization slug"`
	Domains                []string               `json:"domains,omitempty" example:"[\"acme.com\", \"acmecorp.com\"]" doc:"Organization domains"`
	VerifiedDomains        []string               `json:"verifiedDomains,omitempty" example:"[\"acme.com\"]" doc:"Verified domains"`
	Domain                 string                 `json:"domain,omitempty" example:"acme.com" doc:"Primary domain"`
	LogoURL                string                 `json:"logoUrl,omitempty" example:"https://example.com/logo.png" doc:"Organization logo URL"`
	Plan                   string                 `json:"plan" example:"pro" doc:"Subscription plan"`
	Active                 bool                   `json:"active" example:"true" doc:"Whether organization is active"`
	Metadata               map[string]interface{} `json:"metadata,omitempty" doc:"Additional organization metadata"`
	TrialEndsAt            *time.Time             `json:"trialEndsAt,omitempty" example:"2023-02-01T00:00:00Z" doc:"Trial end date"`
	TrialUsed              bool                   `json:"trialUsed" example:"false" doc:"Whether trial has been used"`
	OwnerID                *xid.ID                `json:"ownerId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization owner ID"`
	OrgType                OrgType                `json:"orgType" example:"customer" doc:"Organization type (platform, customer)"`
	IsPlatformOrganization bool                   `json:"isPlatformOrganization" example:"false" doc:"Whether this is the platform organization"`
	ExternalUserLimit      int                    `json:"externalUserLimit" example:"100" doc:"Maximum external users allowed"`
	EndUserLimit           int                    `json:"endUserLimit" example:"1000" doc:"Maximum end users allowed"`
	SSOEnabled             bool                   `json:"ssoEnabled" example:"false" doc:"Whether SSO is enabled"`
	SSODomain              string                 `json:"ssoDomain,omitempty" example:"sso.acme.com" doc:"SSO domain"`
	SubscriptionID         string                 `json:"subscriptionId,omitempty" example:"sub_123456" doc:"Billing subscription ID"`
	CustomerID             string                 `json:"customerId,omitempty" example:"cus_123456" doc:"Billing customer ID"`
	SubscriptionStatus     string                 `json:"subscriptionStatus" example:"active" doc:"Subscription status"`
	AuthServiceEnabled     bool                   `json:"authServiceEnabled" example:"true" doc:"Whether auth service is enabled"`
	AuthConfig             map[string]interface{} `json:"authConfig,omitempty" doc:"Auth service configuration"`
	AuthDomain             string                 `json:"authDomain,omitempty" example:"auth.acme.com" doc:"Custom auth domain"`
	APIRequestLimit        int                    `json:"apiRequestLimit" example:"100000" doc:"Monthly API request limit"`
	APIRequestsUsed        int                    `json:"apiRequestsUsed" example:"5000" doc:"API requests used this month"`
	CurrentExternalUsers   int                    `json:"currentExternalUsers" example:"25" doc:"Current external user count"`
	CurrentEndUsers        int                    `json:"currentEndUsers" example:"500" doc:"Current end user count"`

	// Relationships
	Owner    *UserSummary     `json:"owner,omitempty" doc:"Organization owner"`
	Members  []MemberSummary  `json:"members,omitempty" doc:"Organization members"`
	Features []FeatureSummary `json:"features,omitempty" doc:"Enabled features"`
	Stats    *OrgStats        `json:"stats,omitempty" doc:"Organization statistics"`
}

// OrganizationSummary represents a simplified organization for listings
type OrganizationSummary struct {
	ID          xid.ID  `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	Name        string  `json:"name" example:"Acme Corp" doc:"Organization name"`
	Slug        string  `json:"slug" example:"acme-corp" doc:"Organization slug"`
	LogoURL     string  `json:"logoUrl,omitempty" example:"https://example.com/logo.png" doc:"Logo URL"`
	Plan        string  `json:"plan" example:"pro" doc:"Subscription plan"`
	Active      bool    `json:"active" example:"true" doc:"Whether organization is active"`
	OrgType     OrgType `json:"orgType" example:"customer" doc:"Organization type"`
	MemberCount int     `json:"memberCount" example:"25" doc:"Number of members"`
	Role        string  `json:"role" example:"admin" doc:"Organization role"`
}

// CreateOrganizationRequest represents a request to create an organization
type CreateOrganizationRequest struct {
	Name    string  `json:"name" example:"Acme Corp" doc:"Organization name" required:"true"`
	Slug    string  `json:"slug,omitempty" example:"acme-corp" doc:"Unique slug (auto-generated if not provided)"`
	Domain  *string `json:"domain,omitempty" example:"acme.com" doc:"Primary domain"`
	LogoURL *string `json:"logoUrl,omitempty" example:"https://example.com/logo.png" doc:"Logo URL"`
	Plan    string  `json:"plan" example:"free" doc:"Initial subscription plan"`
}

// CreateOrganizationPlatformRequest represents a request to create an organization
type CreateOrganizationPlatformRequest struct {
	Name              string                 `json:"name" example:"Acme Corp" doc:"Organization name" required:"true"`
	Slug              string                 `json:"slug,omitempty" example:"acme-corp" doc:"Unique slug (auto-generated if not provided)"`
	Domain            *string                `json:"domain,omitempty" example:"acme.com" doc:"Primary domain"`
	LogoURL           *string                `json:"logoUrl,omitempty" example:"https://example.com/logo.png" doc:"Logo URL"`
	Plan              string                 `json:"plan" example:"free" doc:"Initial subscription plan"`
	OrgType           OrgType                `json:"orgType" example:"customer" doc:"Organization type"`
	OwnerEmail        string                 `json:"ownerEmail,omitempty" example:"owner@acme.com" doc:"Owner email (will create user if not exists)"`
	ExternalUserLimit int                    `json:"externalUserLimit" example:"50" doc:"External user limit"`
	EndUserLimit      int                    `json:"endUserLimit" example:"1000" doc:"End user limit"`
	EnableAuthService bool                   `json:"enableAuthService" example:"true" doc:"Enable auth service"`
	AuthConfig        map[string]interface{} `json:"authConfig,omitempty" doc:"Auth service configuration"`
	Metadata          map[string]interface{} `json:"metadata,omitempty" doc:"Additional metadata"`
	CreateTrialPeriod bool                   `json:"createTrialPeriod" example:"true" doc:"Whether to create trial period"`
}

// UpdateOrganizationRequest represents a request to update an organization
type UpdateOrganizationRequest struct {
	Name               *string                `json:"name,omitempty" example:"Updated Corp" doc:"Updated name"`
	Slug               *string                `json:"slug,omitempty" example:"updated-corp" doc:"Updated slug"`
	Domain             *string                `json:"domain,omitempty" example:"updated.com" doc:"Updated domain"`
	LogoURL            *string                `json:"logoUrl,omitempty" example:"https://example.com/logo.png" doc:"Updated logo URL"`
	Plan               *string                `json:"plan,omitempty" example:"pro" doc:"Updated plan"`
	ExternalUserLimit  *int                   `json:"externalUserLimit,omitempty" example:"100" doc:"Updated external user limit"`
	EndUserLimit       *int                   `json:"endUserLimit,omitempty" example:"2000" doc:"Updated end user limit"`
	SSOEnabled         *bool                  `json:"ssoEnabled,omitempty" example:"true" doc:"Enable/disable SSO"`
	SSODomain          *string                `json:"ssoDomain,omitempty" example:"sso.updated.com" doc:"Updated SSO domain"`
	AuthServiceEnabled *bool                  `json:"authServiceEnabled,omitempty" example:"true" doc:"Enable/disable auth service"`
	AuthConfig         map[string]interface{} `json:"authConfig,omitempty" doc:"Updated auth config"`
	AuthDomain         *string                `json:"authDomain,omitempty" example:"auth.updated.com" doc:"Updated auth domain"`
	APIRequestLimit    *int                   `json:"apiRequestLimit,omitempty" example:"200000" doc:"Updated API request limit"`
	Active             *bool                  `json:"active,omitempty" example:"true" doc:"Updated active status"`
	Metadata           map[string]interface{} `json:"metadata,omitempty" doc:"Updated metadata"`
}

// MemberSummary represents a member summary for organization listings
type MemberSummary struct {
	UserID     xid.ID           `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	Email      string           `json:"email" example:"member@acme.com" doc:"Member email"`
	FirstName  string           `json:"firstName,omitempty" example:"John" doc:"First name"`
	LastName   string           `json:"lastName,omitempty" example:"Doe" doc:"Last name"`
	RoleName   string           `json:"roleName" example:"admin" doc:"Role name"`
	Status     MembershipStatus `json:"status" example:"active" doc:"Membership status"`
	JoinedAt   *time.Time       `json:"joinedAt,omitempty" example:"2023-01-01T12:00:00Z" doc:"When member joined"`
	LastActive *time.Time       `json:"lastActive,omitempty" example:"2023-01-01T12:00:00Z" doc:"Last activity"`
	IsOwner    bool             `json:"isOwner" example:"false" doc:"Whether member is the owner"`
	IsBilling  bool             `json:"isBilling" example:"false" doc:"Whether member handles billing"`
	IsPrimary  bool             `json:"isPrimary" example:"false" doc:"Whether member is primary contact"`

	FullName    string     `json:"fullName" example:"John Doe" doc:"User full name"`
	Avatar      string     `json:"avatar,omitempty" example:"https://example.com/avatar.jpg" doc:"User avatar URL"`
	RoleID      xid.ID     `json:"roleId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Role ID"`
	RoleDisplay string     `json:"roleDisplay" example:"Administrator" doc:"Role display name"`
	LastSeenAt  *time.Time `json:"lastSeenAt,omitempty" example:"2023-01-15T08:30:00Z" doc:"Last activity timestamp"`
	InvitedBy   *xid.ID    `json:"invitedBy,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Who invited this member"`
	InviterName string     `json:"inviterName,omitempty" example:"Admin User" doc:"Inviter full name"`
	Department  string     `json:"department,omitempty" example:"Engineering" doc:"Member department"`
	JobTitle    string     `json:"jobTitle,omitempty" example:"Senior Developer" doc:"Member job title"`
	Location    string     `json:"location,omitempty" example:"San Francisco, CA" doc:"Member location"`
	Timezone    string     `json:"timezone,omitempty" example:"America/Los_Angeles" doc:"Member timezone"`
	Tags        []string   `json:"tags,omitempty" example:"[\"developer\", \"senior\"]" doc:"Member tags"`
}

// FeatureSummary represents an enabled feature summary
type FeatureSummary struct {
	Name        string                 `json:"name" example:"sso" doc:"Feature name"`
	DisplayName string                 `json:"displayName" example:"Single Sign-On" doc:"Feature display name"`
	Enabled     bool                   `json:"enabled" example:"true" doc:"Whether feature is enabled"`
	Config      map[string]interface{} `json:"config,omitempty" doc:"Feature configuration"`
	UpdatedAt   time.Time              `json:"updatedAt" example:"2023-01-01T12:00:00Z" doc:"Last update time"`
}

// OrgStats represents organization statistics
type OrgStats struct {
	TotalMembers       int        `json:"totalMembers" example:"25" doc:"Total number of members"`
	ActiveMembers      int        `json:"activeMembers" example:"23" doc:"Number of active members"`
	PendingInvitations int        `json:"pendingInvitations" example:"2" doc:"Number of pending invitations"`
	TotalEndUsers      int        `json:"totalEndUsers" example:"500" doc:"Total number of end users"`
	ActiveEndUsers     int        `json:"activeEndUsers" example:"450" doc:"Number of active end users"`
	APICallsThisMonth  int        `json:"apiCallsThisMonth" example:"5000" doc:"API calls this month"`
	LoginThisMonth     int        `json:"loginsThisMonth" example:"1200" doc:"Logins this month"`
	StorageUsed        int        `json:"storageUsed" example:"1024000" doc:"Storage used in bytes"`
	LastActivity       *time.Time `json:"lastActivity,omitempty" example:"2023-01-01T12:00:00Z" doc:"Last organization activity"`
}

// OrganizationListRequest represents a request to list organizations
type OrganizationListRequest struct {
	PaginationParams
	OrgType    OrgType               `json:"orgType,omitempty" query:"orgType" example:"customer" doc:"Filter by organization type"`
	Plan       string                `json:"plan,omitempty" query:"plan" example:"pro" doc:"Filter by plan"`
	Active     OptionalParam[bool]   `json:"active,omitempty" query:"active" example:"true" doc:"Filter by active status"`
	Search     string                `json:"search,omitempty" query:"search" example:"acme" doc:"Search in name, slug, domain"`
	OwnerID    OptionalParam[xid.ID] `json:"ownerId,omitempty"  query:"ownerId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by owner"`
	HasTrial   OptionalParam[bool]   `json:"hasTrial,omitempty"  query:"hasTrial" example:"true" doc:"Filter by trial status"`
	SSOEnabled OptionalParam[bool]   `json:"ssoEnabled,omitempty"  query:"ssoEnabled" example:"true" doc:"Filter by SSO status"`
}

// OrganizationListResponse represents a list of organizations
type OrganizationListResponse = PaginatedOutput[OrganizationSummary]

// DomainVerificationRequest represents a domain verification request
type DomainVerificationRequest struct {
	Domain string `json:"domain" example:"acme.com" doc:"Domain to verify"`
}

// DomainVerificationResponse represents domain verification response
type DomainVerificationResponse struct {
	Domain           string `json:"domain" example:"acme.com" doc:"Domain being verified"`
	Verified         bool   `json:"verified" example:"false" doc:"Whether domain is verified"`
	DNSRecord        string `json:"dnsRecord,omitempty" example:"frank-verify=abc123..." doc:"DNS record to add"`
	VerificationCode string `json:"verificationCode,omitempty" example:"abc123..." doc:"Verification code"`
	Instructions     string `json:"instructions,omitempty" doc:"Verification instructions"`
}

// OrganizationBilling represents billing information
type OrganizationBilling struct {
	CustomerID         string     `json:"customerId" example:"cus_123456" doc:"Billing customer ID"`
	SubscriptionID     string     `json:"subscriptionId" example:"sub_123456" doc:"Subscription ID"`
	Plan               string     `json:"plan" example:"pro" doc:"Current plan"`
	Status             string     `json:"status" example:"active" doc:"Billing status"`
	CurrentPeriodStart time.Time  `json:"currentPeriodStart" example:"2023-01-01T00:00:00Z" doc:"Current billing period start"`
	CurrentPeriodEnd   time.Time  `json:"currentPeriodEnd" example:"2023-02-01T00:00:00Z" doc:"Current billing period end"`
	TrialStart         *time.Time `json:"trialStart,omitempty" example:"2023-01-01T00:00:00Z" doc:"Trial start date"`
	TrialEnd           *time.Time `json:"trialEnd,omitempty" example:"2023-01-15T00:00:00Z" doc:"Trial end date"`
	Amount             int        `json:"amount" example:"2900" doc:"Amount in cents"`
	Currency           string     `json:"currency" example:"usd" doc:"Currency"`
	NextInvoiceDate    *time.Time `json:"nextInvoiceDate,omitempty" example:"2023-02-01T00:00:00Z" doc:"Next invoice date"`
	PaymentMethod      string     `json:"paymentMethod,omitempty" example:"card" doc:"Payment method type"`
}

// UpdateBillingRequest represents a billing update request
type UpdateBillingRequest struct {
	Plan            string   `json:"plan,omitempty" example:"pro" doc:"New plan"`
	PaymentMethodID string   `json:"paymentMethodId,omitempty" example:"pm_123456" doc:"New payment method ID"`
	BillingEmail    string   `json:"billingEmail,omitempty" example:"billing@acme.com" doc:"Billing email"`
	TaxID           string   `json:"taxId,omitempty" example:"12-3456789" doc:"Tax ID"`
	BillingAddress  *Address `json:"billingAddress,omitempty" doc:"Billing address"`
}

// Address represents a billing address
type Address struct {
	Line1      string `json:"line1" example:"123 Main St" doc:"Address line 1"`
	Line2      string `json:"line2,omitempty" example:"Apt 4B" doc:"Address line 2"`
	City       string `json:"city" example:"New York" doc:"City"`
	State      string `json:"state" example:"NY" doc:"State"`
	PostalCode string `json:"postalCode" example:"10001" doc:"Postal code"`
	Country    string `json:"country" example:"US" doc:"Country code"`
}

// OrganizationUsage represents usage information
type OrganizationUsage struct {
	Period            string    `json:"period" example:"2023-01" doc:"Usage period"`
	ExternalUsers     int       `json:"externalUsers" example:"25" doc:"External user count"`
	EndUsers          int       `json:"endUsers" example:"500" doc:"End user count"`
	APIRequests       int       `json:"apiRequests" example:"5000" doc:"API request count"`
	Storage           int       `json:"storage" example:"1024000" doc:"Storage used in bytes"`
	Bandwidth         int       `json:"bandwidth" example:"2048000" doc:"Bandwidth used in bytes"`
	LoginEvents       int       `json:"loginEvents" example:"1200" doc:"Login event count"`
	EmailsSent        int       `json:"emailsSent" example:"150" doc:"Emails sent count"`
	SMSSent           int       `json:"smsSent" example:"50" doc:"SMS sent count"`
	WebhookDeliveries int       `json:"webhookDeliveries" example:"800" doc:"Webhook delivery count"`
	LastUpdated       time.Time `json:"lastUpdated" example:"2023-01-31T23:59:59Z" doc:"Last update time"`
}

// TransferUserOwnershipRequest represents an ownership transfer request
type TransferUserOwnershipRequest struct {
	NewOwnerID xid.ID `json:"newOwnerId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"New owner user ID"`
	Reason     string `json:"reason,omitempty" example:"Original owner leaving company" doc:"Reason for transfer"`
}

// DeleteOrganizationRequest represents an organization deletion request
type DeleteOrganizationRequest struct {
	Confirm       bool   `json:"confirm" example:"true" doc:"Confirmation of deletion"`
	Reason        string `json:"reason,omitempty" example:"Company closure" doc:"Reason for deletion"`
	DataRetention int    `json:"dataRetention" example:"30" doc:"Data retention period in days"`
	NotifyMembers bool   `json:"notifyMembers" example:"true" doc:"Whether to notify members"`
}

// OrganizationSettings represents organization settings
type OrganizationSettings struct {
	AllowedDomains           []string         `json:"allowedDomains,omitempty" example:"[\"acme.com\"]" doc:"Allowed email domains for members"`
	RequireEmailVerification bool             `json:"requireEmailVerification" example:"true" doc:"Require email verification"`
	RequirePhoneVerification bool             `json:"requirePhoneVerification" example:"false" doc:"Require phone verification"`
	PasswordPolicy           PasswordPolicy   `json:"passwordPolicy" doc:"Password policy settings"`
	SessionSettings          SessionSettings  `json:"sessionSettings" doc:"Session management settings"`
	MFASettings              MFASettings      `json:"mfaSettings" doc:"MFA settings"`
	WebhookSettings          WebhookSettings  `json:"webhookSettings" doc:"Webhook settings"`
	AuditSettings            AuditSettings    `json:"auditSettings" doc:"Audit settings"`
	CustomFields             []CustomField    `json:"customFields,omitempty" doc:"Custom user fields"`
	Branding                 BrandingSettings `json:"branding" doc:"Branding settings"`
}

// PasswordPolicy represents password policy settings
type PasswordPolicy struct {
	MinLength        int  `json:"minLength" example:"8" doc:"Minimum password length"`
	MaxLength        int  `json:"maxLength" example:"8" doc:"Maximum password length"`
	RequireUppercase bool `json:"requireUppercase" example:"true" doc:"Require uppercase letters"`
	RequireLowercase bool `json:"requireLowercase" example:"true" doc:"Require lowercase letters"`
	RequireDigit     bool `json:"requireDigit" example:"true" doc:"RequireDigit"`
	RequireSpecial   bool `json:"requireSpecial" example:"false" doc:"RequireSpecial"`
	MaxAge           int  `json:"maxAge" example:"90" doc:"Password max age in days (0 = no expiry)"`
	PreventReuse     bool `json:"preventReuse" example:"false" doc:"Prevent reusing last N passwords"`
	ExpiryDays       int  `json:"expiryDays" example:"30" doc:"Expiry days"`
}

// SessionSettings represents session management settings
type SessionSettings struct {
	MaxConcurrentSessions int      `json:"maxConcurrentSessions" example:"5" doc:"Maximum concurrent sessions per user"`
	SessionTimeout        int      `json:"sessionTimeout" example:"3600" doc:"Session timeout in seconds"`
	RememberMeDuration    int      `json:"rememberMeDuration" example:"2592000" doc:"Remember me duration in seconds"`
	RequireReauth         []string `json:"requireReauth,omitempty" example:"[\"sensitive_action\"]" doc:"Actions requiring re-authentication"`
}

// MFASettings represents MFA settings
type MFASettings struct {
	Required       bool     `json:"required" example:"false" doc:"Whether MFA is required for all users"`
	AllowedMethods []string `json:"allowedMethods" example:"[\"totp\", \"sms\"]" doc:"Allowed MFA methods"`
	GracePeriod    int      `json:"gracePeriod" example:"24" doc:"Grace period in hours for MFA setup"`
}

// WebhookSettings represents webhook settings
type WebhookSettings struct {
	Enabled        bool     `json:"enabled" example:"true" doc:"Whether webhooks are enabled"`
	AllowedEvents  []string `json:"allowedEvents" example:"[\"user.created\", \"user.updated\"]" doc:"Allowed webhook events"`
	RetryAttempts  int      `json:"retryAttempts" example:"3" doc:"Number of retry attempts"`
	TimeoutSeconds int      `json:"timeoutSeconds" example:"30" doc:"Webhook timeout in seconds"`
}

// AuditSettings represents audit settings
type AuditSettings struct {
	Enabled       bool     `json:"enabled" example:"true" doc:"Whether audit logging is enabled"`
	RetentionDays int      `json:"retentionDays" example:"365" doc:"Audit log retention in days"`
	EventTypes    []string `json:"eventTypes" example:"[\"login\", \"logout\", \"user.created\"]" doc:"Audit event types to log"`
	ExportEnabled bool     `json:"exportEnabled" example:"true" doc:"Whether audit export is enabled"`
}

// CustomField represents a custom user field definition
type CustomField struct {
	Name         string      `json:"name" example:"department" doc:"Field name"`
	DisplayName  string      `json:"displayName" example:"Department" doc:"Display name"`
	Type         string      `json:"type" example:"string" doc:"Field type (string, number, boolean, select)"`
	Required     bool        `json:"required" example:"false" doc:"Whether field is required"`
	Options      []string    `json:"options,omitempty" example:"[\"Engineering\", \"Sales\"]" doc:"Options for select type"`
	DefaultValue interface{} `json:"defaultValue,omitempty" doc:"Default value"`
}

// BrandingSettings represents branding settings
type BrandingSettings struct {
	LogoURL        string `json:"logoUrl,omitempty" example:"https://acme.com/logo.png" doc:"Logo URL"`
	FaviconURL     string `json:"faviconUrl,omitempty" example:"https://acme.com/favicon.ico" doc:"Favicon URL"`
	PrimaryColor   string `json:"primaryColor,omitempty" example:"#007bff" doc:"Primary brand color"`
	SecondaryColor string `json:"secondaryColor,omitempty" example:"#6c757d" doc:"Secondary brand color"`
	FontFamily     string `json:"fontFamily,omitempty" example:"Inter" doc:"Font family"`
	CustomCSS      string `json:"customCss,omitempty" doc:"Custom CSS"`
}

// UpdateOrganizationSettingsRequest represents a settings update request
type UpdateOrganizationSettingsRequest struct {
	AllowedDomains           []string          `json:"allowedDomains,omitempty" doc:"Updated allowed domains"`
	RequireEmailVerification *bool             `json:"requireEmailVerification,omitempty" doc:"Updated email verification requirement"`
	RequirePhoneVerification *bool             `json:"requirePhoneVerification,omitempty" doc:"Updated phone verification requirement"`
	PasswordPolicy           *PasswordPolicy   `json:"passwordPolicy,omitempty" doc:"Updated password policy"`
	SessionSettings          *SessionSettings  `json:"sessionSettings,omitempty" doc:"Updated session settings"`
	MFASettings              *MFASettings      `json:"mfaSettings,omitempty" doc:"Updated MFA settings"`
	WebhookSettings          *WebhookSettings  `json:"webhookSettings,omitempty" doc:"Updated webhook settings"`
	AuditSettings            *AuditSettings    `json:"auditSettings,omitempty" doc:"Updated audit settings"`
	CustomFields             []CustomField     `json:"customFields,omitempty" doc:"Updated custom fields"`
	Branding                 *BrandingSettings `json:"branding,omitempty" doc:"Updated branding settings"`
}
