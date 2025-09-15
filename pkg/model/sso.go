package model

import (
	"time"

	"github.com/rs/xid"
)

type IdentityProviderConfig = SSOProviderConfig

// IdentityProvider represents a single sign-on identity provider
type IdentityProvider struct {
	Base
	AuditBase
	Name             string                 `json:"name" example:"Google SSO" doc:"Identity provider name"`
	Type             string                 `json:"type" example:"oidc" doc:"Provider type (oidc, saml, oauth2)"`
	Protocol         string                 `json:"protocol" example:"openid_connect" doc:"Authentication protocol"`
	OrganizationID   xid.ID                 `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	Domain           string                 `json:"domain,omitempty" example:"acme.com" doc:"Email domain for auto-provisioning"`
	Enabled          bool                   `json:"enabled" example:"true" doc:"Whether provider is enabled"`
	AutoProvision    bool                   `json:"autoProvision" example:"true" doc:"Whether to auto-create users"`
	DefaultRole      string                 `json:"defaultRole,omitempty" example:"member" doc:"Default role for new users"`
	AttributeMapping map[string]string      `json:"attributeMapping,omitempty" doc:"Attribute mapping configuration"`
	Config           IdentityProviderConfig `json:"config,omitempty" doc:"Provider-specific configuration"`
	IconURL          string                 `json:"iconUrl,omitempty" example:"https://example.com/google-icon.png" doc:"Provider icon URL"`
	ButtonText       string                 `json:"buttonText,omitempty" example:"Sign in with Google" doc:"Login button text"`
	Active           bool                   `json:"active" example:"true" doc:"Whether provider is active"`

	// Relationships
	Organization *OrganizationSummary `json:"organization,omitempty" doc:"Organization information"`
	Stats        *SSOProviderStats    `json:"stats,omitempty" doc:"Usage statistics"`
}

// IdentityProviderSummary represents a simplified identity provider for listings
type IdentityProviderSummary struct {
	ID        xid.ID     `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Provider ID"`
	Name      string     `json:"name" example:"Google SSO" doc:"Provider name"`
	Type      string     `json:"type" example:"oidc" doc:"Provider type"`
	Domain    string     `json:"domain,omitempty" example:"acme.com" doc:"Email domain"`
	Enabled   bool       `json:"enabled" example:"true" doc:"Whether provider is enabled"`
	UserCount int        `json:"userCount" example:"150" doc:"Number of users using this provider"`
	LastUsed  *time.Time `json:"lastUsed,omitempty" example:"2023-01-01T12:00:00Z" doc:"Last usage timestamp"`
	CreatedAt time.Time  `json:"createdAt" example:"2023-01-01T10:00:00Z" doc:"Creation timestamp"`
}

// CreateIdentityProviderRequest represents a request to create an identity provider
type CreateIdentityProviderRequest struct {
	Name             string            `json:"name" example:"Google SSO" doc:"Provider name"`
	Type             string            `json:"type" example:"oidc" doc:"Provider type (oidc, saml, oauth2)"`
	Protocol         string            `json:"protocol" example:"openid_connect" doc:"Authentication protocol"`
	Domain           string            `json:"domain,omitempty" example:"acme.com" doc:"Email domain"`
	AutoProvision    bool              `json:"autoProvision" example:"true" doc:"Auto-provision users"`
	DefaultRole      string            `json:"defaultRole,omitempty" example:"member" doc:"Default role"`
	AttributeMapping map[string]string `json:"attributeMapping,omitempty" doc:"Attribute mappings"`
	Config           map[string]any    `json:"config" doc:"Provider configuration"`
	IconURL          string            `json:"iconUrl,omitempty" example:"https://example.com/icon.png" doc:"Icon URL"`
	ButtonText       string            `json:"buttonText,omitempty" example:"Sign in with Provider" doc:"Button text"`
}

// UpdateIdentityProviderRequest represents a request to update an identity provider
type UpdateIdentityProviderRequest struct {
	Name             string            `json:"name,omitempty" example:"Updated Google SSO" doc:"Updated name"`
	Domain           string            `json:"domain,omitempty" example:"updated.com" doc:"Updated domain"`
	Enabled          bool              `json:"enabled,omitempty" example:"true" doc:"Updated enabled status"`
	AutoProvision    bool              `json:"autoProvision,omitempty" example:"false" doc:"Updated auto-provision"`
	DefaultRole      string            `json:"defaultRole,omitempty" example:"viewer" doc:"Updated default role"`
	AttributeMapping map[string]string `json:"attributeMapping,omitempty" doc:"Updated attribute mappings"`
	Config           map[string]any    `json:"config,omitempty" doc:"Updated configuration"`
	IconURL          string            `json:"iconUrl,omitempty" example:"https://example.com/new-icon.png" doc:"Updated icon URL"`
	ButtonText       string            `json:"buttonText,omitempty" example:"Updated button text" doc:"Updated button text"`
	Active           bool              `json:"active,omitempty" example:"true" doc:"Updated active status"`
}

// SSOLoginRequest represents an SSO login request
type SSOLoginRequest struct {
	ProviderID  xid.ID `json:"providerId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Identity provider ID"`
	RedirectURL string `json:"redirectUrl,omitempty" example:"https://app.example.com/dashboard" doc:"Post-login redirect URL"`
	State       string `json:"state,omitempty" example:"state_abc123" doc:"OAuth state parameter"`
	Domain      string `json:"domain,omitempty" example:"acme.com" doc:"Organization domain hint"`
}

// SSOLoginResponse represents an SSO login response
type SSOLoginResponse struct {
	AuthURL   string    `json:"authUrl" example:"https://accounts.google.com/oauth/authorize?..." doc:"Authentication URL"`
	State     string    `json:"state" example:"state_abc123" doc:"OAuth state parameter"`
	ExpiresAt time.Time `json:"expiresAt" example:"2023-01-01T12:10:00Z" doc:"Auth URL expiration"`
}

// SSOCallbackRequest represents an SSO callback request
type SSOCallbackRequest struct {
	ProviderID   xid.ID `json:"providerId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Identity provider ID"`
	Code         string `json:"code,omitempty" example:"auth_code_123" doc:"Authorization code"`
	State        string `json:"state,omitempty" example:"state_abc123" doc:"OAuth state parameter"`
	SAMLResponse string `json:"samlResponse,omitempty" doc:"SAML response (for SAML providers)"`
	RelayState   string `json:"relayState,omitempty" example:"relay_state_123" doc:"SAML relay state"`
	RedirectURL  string `json:"redirectUrl,omitempty" example:"https://app.example.com/dashboard" doc:"Redirect URL"`
}

// SSOCallbackResponse represents an SSO callback response
type SSOCallbackResponse struct {
	Success      bool   `json:"success" example:"true" doc:"Whether authentication was successful"`
	User         User   `json:"user" doc:"Authenticated user"`
	AccessToken  string `json:"accessToken,omitempty" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." doc:"Access token"`
	RefreshToken string `json:"refreshToken,omitempty" example:"refresh_token_123" doc:"Refresh token"`
	ExpiresIn    int    `json:"expiresIn,omitempty" example:"3600" doc:"Token expiration in seconds"`
	UserCreated  bool   `json:"userCreated" example:"false" doc:"Whether a new user was created"`
	RedirectURL  string `json:"redirectUrl,omitempty" example:"https://app.example.com/dashboard" doc:"Redirect URL"`
}

// SSOProviderConfig represents SSO provider configuration
type SSOProviderConfig struct {
	// OIDC/OAuth2 Configuration
	ClientID     string   `json:"clientId,omitempty" example:"client_123" doc:"OAuth client ID"`
	ClientSecret string   `json:"clientSecret,omitempty" example:"secret_456" doc:"OAuth client secret (write-only)"`
	AuthURL      string   `json:"authUrl,omitempty" example:"https://accounts.google.com/oauth/authorize" doc:"Authorization URL"`
	TokenURL     string   `json:"tokenUrl,omitempty" example:"https://oauth2.googleapis.com/token" doc:"Token URL"`
	UserInfoURL  string   `json:"userInfoUrl,omitempty" example:"https://www.googleapis.com/oauth2/v2/userinfo" doc:"User info URL"`
	JWKSUrl      string   `json:"jwksUrl,omitempty" example:"https://www.googleapis.com/oauth2/v3/certs" doc:"JWKS URL"`
	Scopes       []string `json:"scopes,omitempty" example:"[\"openid\", \"email\", \"profile\"]" doc:"OAuth scopes"`

	// SAML Configuration
	EntityID            string `json:"entityId,omitempty" example:"https://app.example.com/saml/metadata" doc:"SAML entity ID"`
	SSOUrl              string `json:"ssoUrl,omitempty" example:"https://idp.example.com/sso" doc:"SAML SSO URL"`
	SLOUrl              string `json:"sloUrl,omitempty" example:"https://idp.example.com/slo" doc:"SAML SLO URL"`
	Certificate         string `json:"certificate,omitempty" doc:"SAML certificate"`
	SignatureAlgorithm  string `json:"signatureAlgorithm,omitempty" example:"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" doc:"SAML signature algorithm"`
	NameIDFormat        string `json:"nameIdFormat,omitempty" example:"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" doc:"SAML NameID format"`
	SignRequests        bool   `json:"signRequests" example:"false" doc:"Whether a request was signed by an IdentityProvider"`
	WantAssertionSigned bool   `json:"wantAssertionSigned" example:"false" doc:"Whether the assertion was signed by an IdentityProvider"`

	// Common Configuration
	Issuer    string `json:"issuer,omitempty" example:"https://accounts.google.com" doc:"Token issuer"`
	Audience  string `json:"audience,omitempty" example:"client_123" doc:"Token audience"`
	Algorithm string `json:"algorithm,omitempty" example:"RS256" doc:"Signature algorithm"`
}

// TestSSOConnectionRequest represents a request to test SSO connection
type TestSSOConnectionRequest struct {
	ProviderID xid.ID `json:"providerId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Provider ID to test"`
	TestEmail  string `json:"testEmail,omitempty" example:"test@acme.com" doc:"Test email for simulation"`
}

// TestSSOConnectionResponse represents SSO connection test response
type TestSSOConnectionResponse struct {
	Success bool                   `json:"success" example:"true" doc:"Whether connection test was successful"`
	Message string                 `json:"message" example:"Connection test successful" doc:"Test result message"`
	Details map[string]interface{} `json:"details,omitempty" doc:"Additional test details"`
	Error   string                 `json:"error,omitempty" example:"Invalid certificate" doc:"Error message if failed"`
	Latency int                    `json:"latency,omitempty" example:"250" doc:"Connection latency in milliseconds"`
}

// SSOProviderListRequest represents a request to list SSO providers
type SSOProviderListRequest struct {
	PaginationParams
	OrganizationID OptionalParam[xid.ID] `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by organization" query:"organizationId"`
	Type           string                `json:"type,omitempty" example:"oidc" doc:"Filter by provider type" query:"type"`
	Protocol       string                `json:"protocol,omitempty" example:"openid_connect" doc:"Filter by protocol" query:"protocol"`
	Enabled        OptionalParam[bool]   `json:"enabled,omitempty" example:"true" doc:"Filter by enabled status" query:"enabled"`
	Active         OptionalParam[bool]   `json:"active,omitempty" example:"true" doc:"Filter by active status" query:"active"`
	Domain         string                `json:"domain,omitempty" example:"acme.com" doc:"Filter by domain" query:"domain"`
	Search         string                `json:"search,omitempty" example:"google" doc:"Search in provider name" query:"search"`
}

// SSOProviderListResponse represents a list of SSO providers
type SSOProviderListResponse = PaginatedOutput[IdentityProviderSummary]

// SSOStats represents SSO statistics
type SSOStats struct {
	TotalProviders       int            `json:"totalProviders" example:"5" doc:"Total SSO providers"`
	ActiveProviders      int            `json:"activeProviders" example:"4" doc:"Active SSO providers"`
	EnabledProviders     int            `json:"enabledProviders" example:"4" doc:"Enabled SSO providers"`
	ProvidersByType      map[string]int `json:"providersByType" example:"{\"oidc\": 3, \"saml\": 2}" doc:"Providers by type"`
	SSOLoginsToday       int            `json:"ssoLoginsToday" example:"150" doc:"SSO logins today"`
	SSOLoginsWeek        int            `json:"ssoLoginsWeek" example:"1050" doc:"SSO logins this week"`
	SSOLoginsMonth       int            `json:"ssoLoginsMonth" example:"4500" doc:"SSO logins this month"`
	UniqueUsersToday     int            `json:"uniqueUsersToday" example:"85" doc:"Unique users today"`
	UniqueUsersWeek      int            `json:"uniqueUsersWeek" example:"425" doc:"Unique users this week"`
	AutoProvisionedUsers int            `json:"autoProvisionedUsers" example:"320" doc:"Auto-provisioned users"`
	FailedLoginsToday    int            `json:"failedLoginsToday" example:"12" doc:"Failed SSO logins today"`
	AverageLoginTime     float64        `json:"averageLoginTime" example:"2.5" doc:"Average login time in seconds"`
}

// SSOProviderStats represents statistics for a specific SSO provider
type SSSProviderStats struct {
	ProviderID           xid.ID     `json:"providerId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Provider ID"`
	TotalLogins          int        `json:"totalLogins" example:"1500" doc:"Total logins"`
	SuccessfulLogins     int        `json:"successfulLogins" example:"1485" doc:"Successful logins"`
	FailedLogins         int        `json:"failedLogins" example:"15" doc:"Failed logins"`
	UniqueUsers          int        `json:"uniqueUsers" example:"350" doc:"Unique users"`
	AutoProvisionedUsers int        `json:"autoProvisionedUsers" example:"85" doc:"Auto-provisioned users"`
	LoginsToday          int        `json:"loginsToday" example:"45" doc:"Logins today"`
	LoginsWeek           int        `json:"loginsWeek" example:"315" doc:"Logins this week"`
	LoginsMonth          int        `json:"loginsMonth" example:"1350" doc:"Logins this month"`
	AverageLoginTime     float64    `json:"averageLoginTime" example:"2.1" doc:"Average login time in seconds"`
	LastUsed             *time.Time `json:"lastUsed,omitempty" example:"2023-01-01T12:00:00Z" doc:"Last usage timestamp"`
	SuccessRate          float64    `json:"successRate" example:"99.0" doc:"Login success rate percentage"`
}

// SSOActivity represents SSO activity information
type SSOActivity struct {
	ID          xid.ID                 `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Activity ID"`
	ProviderID  xid.ID                 `json:"providerId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Provider ID"`
	UserID      *xid.ID                `json:"userId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	Email       string                 `json:"email,omitempty" example:"user@example.com" doc:"User email"`
	Action      string                 `json:"action" example:"login" doc:"Action type (login, logout, provisioning)"`
	Success     bool                   `json:"success" example:"true" doc:"Whether action was successful"`
	IPAddress   string                 `json:"ipAddress,omitempty" example:"192.168.1.1" doc:"IP address"`
	UserAgent   string                 `json:"userAgent,omitempty" example:"Mozilla/5.0..." doc:"User agent"`
	Location    string                 `json:"location,omitempty" example:"New York, NY" doc:"Location"`
	Duration    int                    `json:"duration,omitempty" example:"2500" doc:"Action duration in milliseconds"`
	Error       string                 `json:"error,omitempty" example:"Invalid SAML response" doc:"Error message if failed"`
	UserCreated bool                   `json:"userCreated" example:"false" doc:"Whether user was auto-provisioned"`
	Attributes  map[string]interface{} `json:"attributes,omitempty" doc:"User attributes from provider"`
	Timestamp   time.Time              `json:"timestamp" example:"2023-01-01T12:00:00Z" doc:"Activity timestamp"`
}

// SSOActivityRequest represents a request for SSO activity
type SSOActivityRequest struct {
	PaginationParams
	ProviderID OptionalParam[xid.ID]    `json:"providerId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by provider" query:"providerId"`
	UserID     OptionalParam[xid.ID]    `json:"userId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by user" query:"userId"`
	Action     string                   `json:"action,omitempty" example:"login" doc:"Filter by action type" query:"action"`
	Success    OptionalParam[bool]      `json:"success,omitempty" example:"true" doc:"Filter by success status" query:"success"`
	StartDate  OptionalParam[time.Time] `json:"startDate,omitempty" example:"2023-01-01T00:00:00Z" doc:"OnStart date" query:"startDate"`
	EndDate    OptionalParam[time.Time] `json:"endDate,omitempty" example:"2023-01-31T23:59:59Z" doc:"End date" query:"endDate"`
	Email      string                   `json:"email,omitempty" example:"user@example.com" doc:"Filter by email" query:"email"`
}

// SSOActivityResponse represents SSO activity response
type SSOActivityResponse = PaginatedOutput[SSOActivity]

// SSOAttributeMapping represents attribute mapping between SSO provider and local user
type SSOAttributeMapping struct {
	LocalAttribute    string `json:"localAttribute" example:"email" doc:"Local user attribute"`
	ProviderAttribute string `json:"providerAttribute" example:"email" doc:"Provider attribute name"`
	Required          bool   `json:"required" example:"true" doc:"Whether attribute is required"`
	DefaultValue      string `json:"defaultValue,omitempty" example:"user@domain.com" doc:"Default value if missing"`
	Transform         string `json:"transform,omitempty" example:"lowercase" doc:"Transformation to apply"`
}

// SSODomainVerificationRequest represents a domain verification request for SSO
type SSODomainVerificationRequest struct {
	Domain string `json:"domain" example:"acme.com" doc:"Domain to verify for SSO"`
}

// SSODomainVerificationResponse represents domain verification response
type SSODomainVerificationResponse struct {
	Domain       string    `json:"domain" example:"acme.com" doc:"Domain being verified"`
	Verified     bool      `json:"verified" example:"false" doc:"Whether domain is verified"`
	TXTRecord    string    `json:"txtRecord,omitempty" example:"frank-sso-verify=abc123..." doc:"TXT record to add"`
	Instructions string    `json:"instructions,omitempty" doc:"Verification instructions"`
	ExpiresAt    time.Time `json:"expiresAt,omitempty" example:"2023-01-02T00:00:00Z" doc:"Verification expiration"`
}

// SSOMetadataRequest represents a request for SSO metadata
type SSOMetadataRequest struct {
	ProviderID xid.ID `json:"providerId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Provider ID"`
	Format     string `json:"format,omitempty" example:"xml" doc:"Metadata format (xml, json)"`
}

// SSOMetadataResponse represents SSO metadata response
type SSOMetadataResponse struct {
	Metadata    string `json:"metadata" doc:"SSO metadata content"`
	Format      string `json:"format" example:"xml" doc:"Metadata format"`
	ContentType string `json:"contentType" example:"application/samlmetadata+xml" doc:"Content type"`
	DownloadURL string `json:"downloadUrl,omitempty" example:"https://api.example.com/sso/metadata/123.xml" doc:"Download URL"`
}

// SSOBulkProvisionRequest represents a bulk user provisioning request
type SSOBulkProvisionRequest struct {
	ProviderID xid.ID                `json:"providerId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Provider ID"`
	Users      []SSOProvisioningUser `json:"users" doc:"Users to provision"`
	DryRun     bool                  `json:"dryRun" example:"false" doc:"Whether to perform a dry run"`
}

// SSOProvisioningUser represents a user for SSO provisioning
type SSOProvisioningUser struct {
	Email      string            `json:"email" example:"user@acme.com" doc:"User email"`
	FirstName  string            `json:"firstName,omitempty" example:"John" doc:"First name"`
	LastName   string            `json:"lastName,omitempty" example:"Doe" doc:"Last name"`
	Attributes map[string]string `json:"attributes,omitempty" doc:"Additional user attributes"`
	Role       string            `json:"role,omitempty" example:"member" doc:"Initial role"`
}

// SSOBulkProvisionResponse represents bulk provisioning response
type SSOBulkProvisionResponse struct {
	Success      []SSOProvisionedUser `json:"success" doc:"Successfully provisioned users"`
	Failed       []SSOProvisionError  `json:"failed,omitempty" doc:"Failed provisionings"`
	SuccessCount int                  `json:"successCount" example:"8" doc:"Success count"`
	FailureCount int                  `json:"failureCount" example:"2" doc:"Failure count"`
	DryRun       bool                 `json:"dryRun" example:"false" doc:"Whether this was a dry run"`
}

// SSOProvisionedUser represents a successfully provisioned user
type SSOProvisionedUser struct {
	Email   string `json:"email" example:"user@acme.com" doc:"User email"`
	UserID  xid.ID `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Created user ID"`
	Created bool   `json:"created" example:"true" doc:"Whether user was newly created"`
}

// SSOProvisionError represents a provisioning error
type SSOProvisionError struct {
	Email string `json:"email" example:"invalid@email" doc:"Email that failed"`
	Error string `json:"error" example:"Invalid email format" doc:"Error message"`
	Index int    `json:"index" example:"5" doc:"Index in original request"`
}

// SSOExportRequest represents a request to export SSO data
type SSOExportRequest struct {
	ProviderID      *xid.ID    `json:"providerId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by provider"`
	StartDate       *time.Time `json:"startDate,omitempty" example:"2023-01-01T00:00:00Z" doc:"OnStart date"`
	EndDate         *time.Time `json:"endDate,omitempty" example:"2023-01-31T23:59:59Z" doc:"End date"`
	Format          string     `json:"format" example:"json" doc:"Export format (json, csv)"`
	IncludeActivity bool       `json:"includeActivity" example:"true" doc:"Include activity data"`
	IncludeConfig   bool       `json:"includeConfig" example:"false" doc:"Include configuration data"`
}

// SSOExportResponse represents SSO export response
type SSOExportResponse struct {
	DownloadURL string    `json:"downloadUrl" example:"https://api.example.com/downloads/sso-export-123.json" doc:"Download URL"`
	ExpiresAt   time.Time `json:"expiresAt" example:"2023-01-01T13:00:00Z" doc:"Download URL expiration"`
	Format      string    `json:"format" example:"json" doc:"Export format"`
	RecordCount int       `json:"recordCount" example:"1500" doc:"Number of records exported"`
}

// SSOHealthCheck represents SSO provider health check
type SSOHealthCheck struct {
	ProviderID   xid.ID    `json:"providerId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Provider ID"`
	Healthy      bool      `json:"healthy" example:"true" doc:"Whether provider is healthy"`
	LastCheck    time.Time `json:"lastCheck" example:"2023-01-01T12:00:00Z" doc:"Last health check timestamp"`
	ResponseTime int       `json:"responseTime" example:"250" doc:"Response time in milliseconds"`
	Status       string    `json:"status" example:"operational" doc:"Health status"`
	Issues       []string  `json:"issues,omitempty" example:"[]" doc:"Health issues if any"`
	NextCheck    time.Time `json:"nextCheck" example:"2023-01-01T12:15:00Z" doc:"Next scheduled check"`
}

// SSOProviderMetrics represents detailed metrics for an SSO provider
type SSOProviderMetrics struct {
	ProviderID    xid.ID         `json:"providerId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Provider ID"`
	Period        string         `json:"period" example:"24h" doc:"Metrics period"`
	LoginsByHour  map[string]int `json:"loginsByHour" example:"{\"00\": 5, \"01\": 3}" doc:"Logins by hour"`
	LoginsByDay   map[string]int `json:"loginsByDay" example:"{\"monday\": 150, \"tuesday\": 160}" doc:"Logins by day"`
	ErrorsByType  map[string]int `json:"errorsByType" example:"{\"timeout\": 3, \"invalid_cert\": 1}" doc:"Errors by type"`
	ResponseTimes []int          `json:"responseTimes" example:"[200, 250, 180]" doc:"Response times in milliseconds"`
	UsersByDomain map[string]int `json:"usersByDomain" example:"{\"acme.com\": 120, \"corp.com\": 30}" doc:"Users by email domain"`
	DeviceTypes   map[string]int `json:"deviceTypes" example:"{\"desktop\": 100, \"mobile\": 50}" doc:"Logins by device type"`
	Locations     map[string]int `json:"locations" example:"{\"US\": 120, \"CA\": 30}" doc:"Logins by location"`
	GeneratedAt   time.Time      `json:"generatedAt" example:"2023-01-01T12:00:00Z" doc:"Metrics generation timestamp"`
}

// Alias for SSOProviderStats to fix typo
type SSOProviderStats = SSSProviderStats

// // ProviderTemplate represents a reusable SSO provider template
// type ProviderTemplate struct {
// 	Base
// 	Key               string                 `json:"key" example:"google" doc:"Unique template key"`
// 	Name              string                 `json:"name" example:"Google" doc:"Provider name"`
// 	DisplayName       string                 `json:"displayName" example:"Sign in with Google" doc:"Display name for UI"`
// 	Type              string                 `json:"type" example:"oidc" doc:"Provider type (oidc, saml, oauth2)"`
// 	Protocol          string                 `json:"protocol" example:"openid_connect" doc:"Authentication protocol"`
// 	IconURL           string                 `json:"iconUrl" example:"https://developers.google.com/identity/images/g-logo.png" doc:"Provider icon URL"`
// 	Category          string                 `json:"category" example:"social" doc:"Provider category (social, enterprise, developer)"`
// 	Popular           bool                   `json:"popular" example:"true" doc:"Whether provider is popular"`
// 	Description       string                 `json:"description" example:"Sign in with your Google account" doc:"Provider description"`
// 	ConfigTemplate    IdentityProviderConfig `json:"configTemplate" doc:"Default configuration template"`
// 	RequiredFields    []string               `json:"requiredFields" example:"[\"client_id\", \"client_secret\"]" doc:"Required configuration fields"`
// 	SupportedFeatures []string               `json:"supportedFeatures" example:"[\"auto_discovery\", \"pkce\"]" doc:"Supported features"`
// 	Documentation     string                 `json:"documentation,omitempty" doc:"Setup documentation"`
// 	SetupGuideURL     string                 `json:"setupGuideUrl,omitempty" example:"https://docs.example.com/sso/google" doc:"Setup guide URL"`
// 	Active            bool                   `json:"active" example:"true" doc:"Whether template is active"`
// 	Metadata          map[string]any         `json:"metadata,omitempty" doc:"Provider metadata"`
//
// 	// Usage statistics
// 	UsageCount int       `json:"usageCount" example:"150" doc:"Number of organizations using this template"`
// 	LastUsed   time.Time `json:"lastUsed" example:"2023-01-01T12:00:00Z" doc:"Last usage timestamp"`
// }

// // EnableProviderBody represents a request to enable a provider for an organization
// type EnableProviderBody struct {
// 	OrganizationID   xid.ID                 `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
// 	TemplateKey      string                 `json:"templateKey" example:"google" doc:"Provider template key"`
// 	CustomName       string                 `json:"customName,omitempty" example:"Company Google SSO" doc:"Custom provider name"`
// 	CustomButtonText string                 `json:"customButtonText,omitempty" example:"Sign in with Company Google" doc:"Custom button text"`
// 	Config           IdentityProviderConfig `json:"config" doc:"Provider configuration"`
// 	Domain           string                 `json:"domain,omitempty" example:"company.com" doc:"Allowed email domain"`
// 	AutoProvision    bool                   `json:"autoProvision" example:"true" doc:"Enable auto-provisioning"`
// 	DefaultRole      string                 `json:"defaultRole,omitempty" example:"member" doc:"Default role for new users"`
// 	AttributeMapping map[string]string      `json:"attributeMapping,omitempty" doc:"Custom attribute mappings"`
// }
//
// // OrganizationProvider represents the relationship between an organization and enabled provider
// type OrganizationProvider struct {
// 	Base
// 	OrganizationID xid.ID                 `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
// 	ProviderID     xid.ID                 `json:"providerId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Identity provider ID"`
// 	TemplateKey    string                 `json:"templateKey" example:"google" doc:"Template key used"`
// 	CustomConfig   IdentityProviderConfig `json:"customConfig" doc:"Organization-specific configuration"`
// 	EnabledAt      time.Time              `json:"enabledAt" example:"2023-01-01T12:00:00Z" doc:"When provider was enabled"`
// 	LastUsed       *time.Time             `json:"lastUsed,omitempty" example:"2023-01-01T12:00:00Z" doc:"Last usage timestamp"`
// 	UsageCount     int                    `json:"usageCount" example:"42" doc:"Number of times used"`
//
// 	// Relationships
// 	Provider     *IdentityProvider    `json:"provider,omitempty" doc:"Identity provider details"`
// 	Template     *ProviderTemplate    `json:"template,omitempty" doc:"Provider template details"`
// 	Organization *OrganizationSummary `json:"organization,omitempty" doc:"Organization details"`
// }
//
// // ProviderConfiguration represents provider configuration update request
// type ProviderConfiguration struct {
// 	Config           IdentityProviderConfig `json:"config" doc:"Updated configuration"`
// 	Domain           string                 `json:"domain,omitempty" example:"company.com" doc:"Updated allowed domain"`
// 	AutoProvision    bool                   `json:"autoProvision" example:"true" doc:"Updated auto-provision setting"`
// 	DefaultRole      string                 `json:"defaultRole,omitempty" example:"member" doc:"Updated default role"`
// 	AttributeMapping map[string]string      `json:"attributeMapping,omitempty" doc:"Updated attribute mappings"`
// 	Enabled          bool                   `json:"enabled" example:"true" doc:"Whether provider is enabled"`
// }
//
// // ProviderMarketplace represents the SSO provider marketplace
// type ProviderMarketplace struct {
// 	FeaturedProviders []ProviderTemplate `json:"featuredProviders" doc:"Featured provider templates"`
// 	PopularProviders  []ProviderTemplate `json:"popularProviders" doc:"Popular provider templates"`
// 	Categories        []ProviderCategory `json:"categories" doc:"Provider categories"`
// 	RecentlyAdded     []ProviderTemplate `json:"recentlyAdded" doc:"Recently added templates"`
// 	RecommendedForOrg []ProviderTemplate `json:"recommendedForOrg" doc:"Recommended for organization"`
// }
//
// // ProviderCategory represents a category of SSO providers
// type ProviderCategory struct {
// 	Key         string             `json:"key" example:"social" doc:"Category key"`
// 	Name        string             `json:"name" example:"Social" doc:"Category name"`
// 	Description string             `json:"description" example:"Social identity providers" doc:"Category description"`
// 	IconURL     string             `json:"iconUrl,omitempty" example:"https://example.com/social-icon.png" doc:"Category icon URL"`
// 	Providers   []ProviderTemplate `json:"providers" doc:"Providers in this category"`
// 	Count       int                `json:"count" example:"5" doc:"Number of providers in category"`
// }
//
// // ProviderSetupWizard represents a guided setup wizard for providers
// type ProviderSetupWizard struct {
// 	TemplateKey string                 `json:"templateKey" example:"google" doc:"Template key"`
// 	Steps       []SetupWizardStep      `json:"steps" doc:"Setup wizard steps"`
// 	Validation  SetupValidation        `json:"validation" doc:"Configuration validation"`
// 	TestResults *ConnectionTestResults `json:"testResults,omitempty" doc:"Connection test results"`
// }
//
// // SetupWizardStep represents a step in the provider setup wizard
// type SetupWizardStep struct {
// 	StepNumber  int                `json:"stepNumber" example:"1" doc:"Step number"`
// 	Title       string             `json:"title" example:"Configure OAuth Credentials" doc:"Step title"`
// 	Description string             `json:"description" example:"Enter your Google OAuth credentials" doc:"Step description"`
// 	Fields      []SetupWizardField `json:"fields" doc:"Fields to configure in this step"`
// 	Optional    bool               `json:"optional" example:"false" doc:"Whether step is optional"`
// 	HelpText    string             `json:"helpText,omitempty" doc:"Additional help text"`
// 	DocsURL     string             `json:"docsUrl,omitempty" example:"https://docs.google.com/oauth" doc:"Documentation URL"`
// }
//
// // SetupWizardField represents a configuration field in the setup wizard
// type SetupWizardField struct {
// 	Key          string      `json:"key" example:"client_id" doc:"Field key"`
// 	Label        string      `json:"label" example:"Client ID" doc:"Field label"`
// 	Type         string      `json:"type" example:"text" doc:"Field type (text, password, url, select, textarea, file)"`
// 	Required     bool        `json:"required" example:"true" doc:"Whether field is required"`
// 	Placeholder  string      `json:"placeholder,omitempty" example:"Enter your Google Client ID" doc:"Field placeholder"`
// 	HelpText     string      `json:"helpText,omitempty" doc:"Field help text"`
// 	Validation   string      `json:"validation,omitempty" doc:"Validation regex pattern"`
// 	Options      []string    `json:"options,omitempty" doc:"Options for select fields"`
// 	DefaultValue interface{} `json:"defaultValue,omitempty" doc:"Default field value"`
// 	Sensitive    bool        `json:"sensitive" example:"false" doc:"Whether field contains sensitive data"`
// }
//
// // SetupValidation represents configuration validation results
// type SetupValidation struct {
// 	ConfigValid     bool     `json:"configValid" example:"true" doc:"Whether configuration is valid"`
// 	MissingFields   []string `json:"missingFields,omitempty" example:"[\"client_secret\"]" doc:"Missing required fields"`
// 	InvalidFields   []string `json:"invalidFields,omitempty" example:"[\"redirect_uri\"]" doc:"Invalid field values"`
// 	Warnings        []string `json:"warnings,omitempty" doc:"Configuration warnings"`
// 	Recommendations []string `json:"recommendations,omitempty" doc:"Configuration recommendations"`
// }
//
// // ConnectionTestResults represents provider connection test results
// type ConnectionTestResults struct {
// 	Success         bool              `json:"success" example:"true" doc:"Whether connection test was successful"`
// 	TestsPerformed  []ConnectionTest  `json:"testsPerformed" doc:"Individual tests performed"`
// 	OverallLatency  int               `json:"overallLatency" example:"250" doc:"Overall latency in milliseconds"`
// 	Recommendations []string          `json:"recommendations,omitempty" doc:"Connection recommendations"`
// 	Issues          []ConnectionIssue `json:"issues,omitempty" doc:"Connection issues found"`
// }
//
// // ConnectionTest represents an individual connection test
// type ConnectionTest struct {
// 	TestName     string                 `json:"testName" example:"Authorization Endpoint" doc:"Test name"`
// 	Success      bool                   `json:"success" example:"true" doc:"Whether test was successful"`
// 	Latency      int                    `json:"latency" example:"120" doc:"Test latency in milliseconds"`
// 	ErrorMessage string                 `json:"errorMessage,omitempty" doc:"Error message if test failed"`
// 	Details      map[string]interface{} `json:"details,omitempty" doc:"Additional test details"`
// }
//
// // ConnectionIssue represents a connection issue
// type ConnectionIssue struct {
// 	Severity   string `json:"severity" example:"error" doc:"Issue severity (error, warning, info)"`
// 	Message    string `json:"message" example:"Invalid client credentials" doc:"Issue message"`
// 	Resolution string `json:"resolution,omitempty" doc:"Suggested resolution"`
// 	DocsURL    string `json:"docsUrl,omitempty" example:"https://docs.example.com/troubleshooting" doc:"Documentation URL"`
// }
//
// // ProviderFilters represents filters for provider search
// type ProviderFilters struct {
// 	Category        []string `json:"category,omitempty" example:"[\"social\", \"enterprise\"]" doc:"Filter by categories"`
// 	Type            []string `json:"type,omitempty" example:"[\"oidc\", \"saml\"]" doc:"Filter by provider types"`
// 	Popular         bool     `json:"popular,omitempty" example:"true" doc:"Filter popular providers only"`
// 	Enterprise      bool     `json:"enterprise,omitempty" example:"false" doc:"Filter enterprise providers only"`
// 	Features        []string `json:"features,omitempty" example:"[\"auto_discovery\", \"pkce\"]" doc:"Filter by supported features"`
// 	ComplexityLevel string   `json:"complexityLevel,omitempty" example:"simple" doc:"Filter by complexity (simple, intermediate, advanced)"`
// }

// // TemplateUsageStats represents usage statistics for a provider template
// type TemplateUsageStats struct {
// 	TemplateKey       string    `json:"templateKey" example:"google" doc:"Template key"`
// 	TemplateName      string    `json:"templateName" example:"Google" doc:"Template name"`
// 	OrganizationCount int       `json:"organizationCount" example:"150" doc:"Number of organizations using this template"`
// 	TotalLogins       int       `json:"totalLogins" example:"5000" doc:"Total logins across all organizations"`
// 	LastUsed          time.Time `json:"lastUsed" example:"2023-01-01T12:00:00Z" doc:"Last usage timestamp"`
// 	AverageSetupTime  float64   `json:"averageSetupTime" example:"12.5" doc:"Average setup time in minutes"`
// 	SuccessRate       float64   `json:"successRate" example:"98.5" doc:"Setup success rate percentage"`
// 	PopularityRank    int       `json:"popularityRank" example:"1" doc:"Popularity ranking"`
// }

// // OrganizationProviderStats represents provider statistics for an organization
// type OrganizationProviderStats struct {
// 	OrganizationID    xid.ID                    `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
// 	TotalProviders    int                       `json:"totalProviders" example:"5" doc:"Total configured providers"`
// 	EnabledProviders  int                       `json:"enabledProviders" example:"3" doc:"Currently enabled providers"`
// 	ProvidersByType   map[string]int            `json:"providersByType" example:"{\"oidc\": 2, \"saml\": 1}" doc:"Providers by type"`
// 	MostUsedProvider  string                    `json:"mostUsedProvider" example:"google" doc:"Most frequently used provider"`
// 	LastProviderAdded time.Time                 `json:"lastProviderAdded" example:"2023-01-01T12:00:00Z" doc:"When last provider was added"`
// 	ProviderStats     []IndividualProviderStats `json:"providerStats" doc:"Individual provider statistics"`
// }
//
// // IndividualProviderStats represents statistics for a single provider
// type IndividualProviderStats struct {
// 	ProviderID   xid.ID    `json:"providerId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Provider ID"`
// 	ProviderName string    `json:"providerName" example:"Google SSO" doc:"Provider name"`
// 	TemplateKey  string    `json:"templateKey" example:"google" doc:"Template key"`
// 	LoginCount   int       `json:"loginCount" example:"500" doc:"Number of successful logins"`
// 	LastUsed     time.Time `json:"lastUsed" example:"2023-01-01T12:00:00Z" doc:"Last usage timestamp"`
// 	SuccessRate  float64   `json:"successRate" example:"98.2" doc:"Login success rate percentage"`
// 	UniqueUsers  int       `json:"uniqueUsers" example:"45" doc:"Number of unique users"`
// 	SetupDate    time.Time `json:"setupDate" example:"2023-01-01T10:00:00Z" doc:"When provider was set up"`
// 	ConfigErrors int       `json:"configErrors" example:"2" doc:"Number of configuration errors"`
// }

// ProviderCatalogListRequest represents a request to list provider templates
type ProviderCatalogListRequest struct {
	PaginationParams
	Category        string              `json:"category,omitempty" example:"social" doc:"Filter by category" query:"category"`
	Type            string              `json:"type,omitempty" example:"oidc" doc:"Filter by type" query:"type"`
	Popular         OptionalParam[bool] `json:"popular,omitempty" example:"true" doc:"Filter by popularity" query:"popular"`
	Search          string              `json:"search,omitempty" example:"google" doc:"Search in name/description" query:"search"`
	IncludeInactive OptionalParam[bool] `json:"includeInactive,omitempty" example:"false" doc:"Include inactive templates" query:"includeInactive"`
}

// ProviderCatalogListResponse represents a list of provider templates
type ProviderCatalogListResponse = PaginatedOutput[ProviderTemplate]

// OrganizationProviderListRequest represents a request to list organization providers
type OrganizationProviderListRequest struct {
	PaginationParams
	OrganizationID xid.ID              `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID" path:"organizationId"`
	Enabled        OptionalParam[bool] `json:"enabled,omitempty" example:"true" doc:"Filter by enabled status" query:"enabled"`
	TemplateKey    string              `json:"templateKey,omitempty" example:"google" doc:"Filter by template" query:"templateKey"`
	Type           string              `json:"type,omitempty" example:"oidc" doc:"Filter by type" query:"type"`
}

// OrganizationProviderListResponse represents a list of organization providers
type OrganizationProviderListResponse = PaginatedOutput[OrganizationProvider]

// ProviderMarketplaceRequest represents a request to get the provider marketplace
type ProviderMarketplaceRequest struct {
	OrganizationID xid.ID `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID for personalized recommendations"`
}

// Provider quick setup templates for common scenarios
var QuickSetupTemplates = map[string]EnableProviderBody{
	"google_workspace": {
		TemplateKey:   "google",
		CustomName:    "Google Workspace SSO",
		AutoProvision: true,
		DefaultRole:   "member",
		AttributeMapping: map[string]string{
			"email":      "email",
			"first_name": "given_name",
			"last_name":  "family_name",
		},
	},
	"microsoft_365": {
		TemplateKey:   "microsoft",
		CustomName:    "Microsoft 365 SSO",
		AutoProvision: true,
		DefaultRole:   "member",
		AttributeMapping: map[string]string{
			"email":      "email",
			"first_name": "given_name",
			"last_name":  "family_name",
		},
	},
	"github_org": {
		TemplateKey:   "github",
		CustomName:    "GitHub Organization SSO",
		AutoProvision: false, // Usually want manual approval for dev access
		DefaultRole:   "developer",
		AttributeMapping: map[string]string{
			"email":      "email",
			"first_name": "name",
		},
	},
}

// Provider health check results
type ProviderHealthCheck struct {
	ProviderID   xid.ID    `json:"providerId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Provider ID"`
	Healthy      bool      `json:"healthy" example:"true" doc:"Whether provider is healthy"`
	LastCheck    time.Time `json:"lastCheck" example:"2023-01-01T12:00:00Z" doc:"Last health check timestamp"`
	ResponseTime int       `json:"responseTime" example:"250" doc:"Response time in milliseconds"`
	Status       string    `json:"status" example:"operational" doc:"Health status"`
	Issues       []string  `json:"issues,omitempty" example:"[]" doc:"Health issues if any"`
	NextCheck    time.Time `json:"nextCheck" example:"2023-01-01T12:15:00Z" doc:"Next scheduled check"`
}

// Provider metrics for monitoring
type ProviderMetrics struct {
	ProviderID    xid.ID         `json:"providerId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Provider ID"`
	Period        string         `json:"period" example:"24h" doc:"Metrics period"`
	LoginsByHour  map[string]int `json:"loginsByHour" example:"{\"00\": 5, \"01\": 3}" doc:"Logins by hour"`
	LoginsByDay   map[string]int `json:"loginsByDay" example:"{\"monday\": 150, \"tuesday\": 160}" doc:"Logins by day"`
	ErrorsByType  map[string]int `json:"errorsByType" example:"{\"timeout\": 3, \"invalid_cert\": 1}" doc:"Errors by type"`
	ResponseTimes []int          `json:"responseTimes" example:"[200, 250, 180]" doc:"Response times in milliseconds"`
	UsersByDomain map[string]int `json:"usersByDomain" example:"{\"company.com\": 120, \"corp.com\": 30}" doc:"Users by email domain"`
	DeviceTypes   map[string]int `json:"deviceTypes" example:"{\"desktop\": 100, \"mobile\": 50}" doc:"Logins by device type"`
	Locations     map[string]int `json:"locations" example:"{\"US\": 120, \"CA\": 30}" doc:"Logins by location"`
	GeneratedAt   time.Time      `json:"generatedAt" example:"2023-01-01T12:00:00Z" doc:"Metrics generation timestamp"`
}
