package model

import (
	"time"

	"github.com/juicycleff/frank/pkg/common"
	"github.com/rs/xid"
)

// APIKey represents an API key for authentication
type APIKey struct {
	Base
	Name string `json:"name" example:"Production API Key" doc:"API key name"`

	// Public/Secret key pair
	PublicKey       string `json:"publicKey,omitempty" example:"pk_test_123abc..." doc:"Public API key (safe to display)"`
	SecretKey       string `json:"secretKey,omitempty" example:"sk_test_456def..." doc:"Secret API key value (write-only)"`
	HashedSecretKey string `json:"hashedSecretKey,omitempty" doc:"Hashed secret key (internal use)"`

	// Legacy support (deprecated)
	Key       string `json:"key,omitempty" example:"frank_sk_123abc..." doc:"Legacy API key value (deprecated)"`
	HashedKey string `json:"hashedKey,omitempty" doc:"Legacy hashed API key (deprecated)"`

	UserID         xid.ID                 `json:"userId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID (for user-scoped keys)"`
	OrganizationID xid.ID                 `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	Type           APIKeyType             `json:"type" example:"server" doc:"API key type (server, client, admin)"`
	Environment    Environment            `json:"environment" example:"test" doc:"Environment (test, live)"`
	Active         bool                   `json:"active" example:"true" doc:"Whether API key is active"`
	Permissions    []string               `json:"permissions,omitempty" example:"[\"read:users\", \"write:organizations\"]" doc:"Granted permissions"`
	Scopes         []string               `json:"scopes,omitempty" example:"[\"api:read\", \"api:write\"]" doc:"API scopes"`
	Metadata       map[string]interface{} `json:"metadata,omitempty" doc:"Additional API key metadata"`
	LastUsed       *time.Time             `json:"lastUsed,omitempty" example:"2023-01-01T12:00:00Z" doc:"Last usage timestamp"`
	ExpiresAt      *time.Time             `json:"expiresAt,omitempty" example:"2023-12-31T23:59:59Z" doc:"Expiration timestamp"`
	IPWhitelist    []string               `json:"ipWhitelist,omitempty" example:"[\"192.168.1.0/24\", \"10.0.0.1\"]" doc:"Allowed IP addresses/ranges"`
	RateLimits     *APIKeyRateLimits      `json:"rateLimits,omitempty" doc:"Rate limiting configuration"`

	// Relationships
	User         *UserSummary         `json:"user,omitempty" doc:"User information (for user-scoped keys)"`
	Organization *OrganizationSummary `json:"organization,omitempty" doc:"Organization information"`
	Usage        *APIKeyUsage         `json:"usage,omitempty" doc:"Usage statistics"`
}

// APIKeySummary represents a simplified API key for listings
type APIKeySummary struct {
	ID              xid.ID      `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"API key ID"`
	Name            string      `json:"name" example:"Production API Key" doc:"API key name"`
	PublicKey       string      `json:"publicKey" example:"pk_test_123abc..." doc:"Public key (safe to display)"`
	Type            APIKeyType  `json:"type" example:"server" doc:"API key type"`
	Environment     Environment `json:"environment" example:"test" doc:"Environment"`
	Active          bool        `json:"active" example:"true" doc:"Whether key is active"`
	LastUsed        *time.Time  `json:"lastUsed,omitempty" example:"2023-01-01T12:00:00Z" doc:"Last usage"`
	ExpiresAt       *time.Time  `json:"expiresAt,omitempty" example:"2023-12-31T23:59:59Z" doc:"Expiration"`
	CreatedAt       time.Time   `json:"createdAt" example:"2023-01-01T10:00:00Z" doc:"Creation timestamp"`
	UsageCount      int         `json:"usageCount" example:"1500" doc:"Total usage count"`
	SecretKeyPrefix string      `json:"secretKeyPrefix" example:"sk_test_123..." doc:"Secret key prefix for identification"`
	PermissionCount int         `json:"permissionCount" example:"5" doc:"Number of permissions"`
}

// APIKeyRateLimits represents rate limiting configuration for API keys
type APIKeyRateLimits = common.APIKeyRateLimits

// APIKeyUsage represents API key usage statistics
type APIKeyUsage struct {
	TotalRequests      int             `json:"totalRequests" example:"15000" doc:"Total API requests"`
	RequestsToday      int             `json:"requestsToday" example:"250" doc:"Requests today"`
	RequestsWeek       int             `json:"requestsWeek" example:"1750" doc:"Requests this week"`
	RequestsMonth      int             `json:"requestsMonth" example:"7500" doc:"Requests this month"`
	SuccessfulRequests int             `json:"successfulRequests" example:"14750" doc:"Successful requests"`
	ErrorRequests      int             `json:"errorRequests" example:"250" doc:"Error requests"`
	SuccessRate        float64         `json:"successRate" example:"98.3" doc:"Success rate percentage"`
	LastUsed           *time.Time      `json:"lastUsed,omitempty" example:"2023-01-01T12:00:00Z" doc:"Last usage timestamp"`
	PopularEndpoints   []EndpointUsage `json:"popularEndpoints,omitempty" doc:"Most used endpoints"`
	ErrorsByCode       map[string]int  `json:"errorsByCode,omitempty" example:"{\"401\": 50, \"429\": 25}" doc:"Errors by HTTP status code"`
}

// EndpointUsage represents usage statistics for a specific endpoint
type EndpointUsage struct {
	Endpoint        string  `json:"endpoint" example:"/api/v1/users" doc:"API endpoint"`
	Method          string  `json:"method" example:"GET" doc:"HTTP method"`
	RequestCount    int     `json:"requestCount" example:"500" doc:"Request count"`
	SuccessRate     float64 `json:"successRate" example:"99.2" doc:"Success rate percentage"`
	AvgResponseTime int     `json:"avgResponseTime" example:"150" doc:"Average response time in milliseconds"`
}

// CreateAPIKeyRequest represents a request to create an API key
type CreateAPIKeyRequest struct {
	Name        string                 `json:"name" example:"My API Key" doc:"API key name"`
	Type        APIKeyType             `json:"type,omitempty" example:"server" doc:"API key type"`
	Environment Environment            `json:"environment,omitempty" example:"test" doc:"Environment (test, live)"`
	Permissions []string               `json:"permissions,omitempty" example:"[\"read:users\"]" doc:"Granted permissions"`
	Scopes      []string               `json:"scopes,omitempty" example:"[\"api:read\"]" doc:"API scopes"`
	ExpiresAt   *time.Time             `json:"expiresAt,omitempty" example:"2023-12-31T23:59:59Z" doc:"Expiration timestamp"`
	IPWhitelist []string               `json:"ipWhitelist,omitempty" example:"[\"192.168.1.0/24\"]" doc:"IP whitelist"`
	RateLimits  *APIKeyRateLimits      `json:"rateLimits,omitempty" doc:"Rate limits"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" doc:"Additional metadata"`
}

// CreateAPIKeyResponse represents the response to API key creation
type CreateAPIKeyResponse struct {
	APIKey    APIKey `json:"apiKey" doc:"Created API key information"`
	PublicKey string `json:"publicKey" example:"pk_test_123abc456def..." doc:"Generated public key (safe to display)"`
	SecretKey string `json:"secretKey" example:"sk_test_789ghi012jkl..." doc:"Generated secret key (store securely)"`
	Warning   string `json:"warning,omitempty" example:"Store the secret key securely. It will not be shown again." doc:"Security warning"`
}

// UpdateAPIKeyRequest represents a request to update an API key
type UpdateAPIKeyRequest struct {
	Name        string                 `json:"name,omitempty" example:"Updated API Key" doc:"Updated name"`
	Active      bool                   `json:"active,omitempty" example:"true" doc:"Updated active status"`
	Permissions []string               `json:"permissions,omitempty" example:"[\"read:users\", \"write:users\"]" doc:"Updated permissions"`
	Scopes      []string               `json:"scopes,omitempty" example:"[\"api:read\", \"api:write\"]" doc:"Updated scopes"`
	ExpiresAt   *time.Time             `json:"expiresAt,omitempty" example:"2024-12-31T23:59:59Z" doc:"Updated expiration"`
	IPWhitelist []string               `json:"ipWhitelist,omitempty" example:"[\"192.168.1.0/24\", \"10.0.0.1\"]" doc:"Updated IP whitelist"`
	RateLimits  *APIKeyRateLimits      `json:"rateLimits,omitempty" doc:"Updated rate limits"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" doc:"Updated metadata"`
}

// APIKeyListRequest represents a request to list API keys
type APIKeyListRequest struct {
	PaginationParams
	OrganizationID OptionalParam[xid.ID] `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by organization" query:"organizationId"`
	UserID         OptionalParam[xid.ID] `json:"userId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by user" query:"userId"`
	Type           APIKeyType            `json:"type,omitempty" example:"server" doc:"Filter by type" query:"type"`
	Environment    Environment           `json:"environment,omitempty" example:"test" doc:"Filter by environment" query:"environment"`
	Active         OptionalParam[bool]   `json:"active,omitempty" example:"true" doc:"Filter by active status" query:"active"`
	Expired        OptionalParam[bool]   `json:"expired,omitempty" example:"false" doc:"Filter by expiration status" query:"expired"`
	Used           OptionalParam[bool]   `json:"used,omitempty" example:"true" doc:"Filter by usage status" query:"used"`
	Search         string                `json:"search,omitempty" example:"production" doc:"Search in key name" query:"search"`
	Permission     string                `json:"permission,omitempty" example:"read:users" doc:"Filter by permission" query:"permission"`
	Scopes         []string              `json:"scopes,omitempty" example:"api:read" doc:"Filter by scope" query:"scope"`
}

// APIKeyListResponse represents a list of API keys
type APIKeyListResponse = PaginatedOutput[APIKeySummary]

// APIKeyStats represents API key statistics
type APIKeyStats struct {
	TotalKeys          int                 `json:"totalKeys" example:"25" doc:"Total API keys"`
	ActiveKeys         int                 `json:"activeKeys" example:"20" doc:"Active API keys"`
	ExpiredKeys        int                 `json:"expiredKeys" example:"3" doc:"Expired API keys"`
	KeysByType         map[APIKeyType]int  `json:"keysByType" example:"{\"server\": 15, \"client\": 8, \"admin\": 2}" doc:"Keys by type"`
	KeysByEnvironment  map[Environment]int `json:"keysByEnvironment" example:"{\"test\": 18, \"live\": 7}" doc:"Keys by environment"`
	TotalRequests      int                 `json:"totalRequests" example:"500000" doc:"Total API requests"`
	RequestsToday      int                 `json:"requestsToday" example:"5000" doc:"Requests today"`
	RequestsWeek       int                 `json:"requestsWeek" example:"35000" doc:"Requests this week"`
	RequestsMonth      int                 `json:"requestsMonth" example:"150000" doc:"Requests this month"`
	AverageSuccessRate float64             `json:"averageSuccessRate" example:"98.5" doc:"Average success rate"`
	TopEndpoints       []EndpointUsage     `json:"topEndpoints" doc:"Most used endpoints"`
	ErrorRate          float64             `json:"errorRate" example:"1.5" doc:"Error rate percentage"`
	UniqueUsers        int                 `json:"uniqueUsers" example:"150" doc:"Unique users with API keys"`
	KeysCreatedWeek    int                 `json:"keysCreatedWeek" example:"5" doc:"Keys created this week"`
	KeysCreatedMonth   int                 `json:"keysCreatedMonth" example:"18" doc:"Keys created this month"`
}

// RotateAPIKeyRequest represents a request to rotate an API key
type RotateAPIKeyRequest struct {
	KeyID     xid.ID     `json:"keyId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"API key ID to rotate"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty" example:"2024-12-31T23:59:59Z" doc:"New expiration date"`
	Reason    string     `json:"reason,omitempty" example:"Scheduled rotation" doc:"Reason for rotation"`
}

// RotateAPIKeyResponse represents API key rotation response
type RotateAPIKeyResponse struct {
	NewPublicKey string     `json:"newPublicKey" example:"pk_test_new123abc..." doc:"New public key"`
	NewSecretKey string     `json:"newSecretKey" example:"sk_test_new456def..." doc:"New secret key value"`
	OldKeyID     xid.ID     `json:"oldKeyId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Old key ID"`
	NewKeyID     xid.ID     `json:"newKeyId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"New key ID"`
	ExpiresAt    *time.Time `json:"expiresAt,omitempty" example:"2024-12-31T23:59:59Z" doc:"New key expiration"`
	Warning      string     `json:"warning" example:"Update your applications with the new secret key. Old key will be deactivated." doc:"Rotation warning"`
}

// ValidateAPIKeyRequest represents a request to validate an API key
type ValidateAPIKeyRequest struct {
	SecretKey string `json:"secretKey" example:"sk_test_123abc..." doc:"Secret API key to validate"`
	IPAddress string `json:"ipAddress,omitempty" example:"192.168.1.1" doc:"Request IP address"`
	UserAgent string `json:"userAgent,omitempty" example:"MyApp/1.0" doc:"User agent"`
	Endpoint  string `json:"endpoint,omitempty" example:"/api/v1/users" doc:"Requested endpoint"`
	Method    string `json:"method,omitempty" example:"GET" doc:"HTTP method"`
}

// ValidateAPIKeyResponse represents API key validation response
type ValidateAPIKeyResponse struct {
	Valid          bool           `json:"valid" example:"true" doc:"Whether key is valid"`
	KeyID          xid.ID         `json:"keyId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"API key ID"`
	PublicKey      string         `json:"publicKey,omitempty" example:"pk_test_123abc..." doc:"Public key"`
	UserID         xid.ID         `json:"userId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	OrganizationID xid.ID         `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	Type           APIKeyType     `json:"type,omitempty" example:"server" doc:"API key type"`
	Environment    Environment    `json:"environment,omitempty" example:"test" doc:"Environment"`
	Permissions    []string       `json:"permissions,omitempty" example:"[\"read:users\"]" doc:"Granted permissions"`
	Scopes         []string       `json:"scopes,omitempty" example:"[\"api:read\"]" doc:"API scopes"`
	RateLimitInfo  *RateLimitInfo `json:"rateLimitInfo,omitempty" doc:"Rate limit information"`
	Error          string         `json:"error,omitempty" example:"API key expired" doc:"Validation error"`
	ExpiresAt      *time.Time     `json:"expiresAt,omitempty" example:"2023-12-31T23:59:59Z" doc:"Key expiration"`
}

// RateLimitInfo represents rate limit information
type RateLimitInfo struct {
	Limit     int `json:"limit" example:"100" doc:"Rate limit"`
	Remaining int `json:"remaining" example:"85" doc:"Remaining requests"`
	Reset     int `json:"reset" example:"1640995200" doc:"Reset timestamp"`
	Window    int `json:"window" example:"60" doc:"Time window in seconds"`
}

// BulkAPIKeyOperationRequest represents a bulk operation on API keys
type BulkAPIKeyOperationRequest struct {
	KeyIDs    []xid.ID   `json:"keyIds" example:"[\"01FZS6TV7KP869DR7RXNEHXQKX\"]" doc:"API key IDs"`
	Operation string     `json:"operation" example:"deactivate" doc:"Operation (activate, deactivate, delete, extend)"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty" example:"2024-12-31T23:59:59Z" doc:"New expiration (for extend operation)"`
	Reason    string     `json:"reason,omitempty" example:"Security audit" doc:"Reason for operation"`
}

// BulkAPIKeyOperationResponse represents bulk operation response
type BulkAPIKeyOperationResponse struct {
	Success      []xid.ID `json:"success" example:"[\"01FZS6TV7KP869DR7RXNEHXQKX\"]" doc:"Successful key IDs"`
	Failed       []xid.ID `json:"failed,omitempty" example:"[]" doc:"Failed key IDs"`
	SuccessCount int      `json:"successCount" example:"5" doc:"Success count"`
	FailureCount int      `json:"failureCount" example:"0" doc:"Failure count"`
	Errors       []string `json:"errors,omitempty" example:"[]" doc:"Error messages"`
}

// APIKeyActivity represents API key activity
type APIKeyActivity struct {
	ID           xid.ID                 `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Activity ID"`
	KeyID        xid.ID                 `json:"keyId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"API key ID"`
	PublicKey    string                 `json:"publicKey,omitempty" example:"pk_test_123abc..." doc:"Public key used"`
	Action       string                 `json:"action" example:"api_request" doc:"Action type"`
	Endpoint     string                 `json:"endpoint,omitempty" example:"/api/v1/users" doc:"API endpoint"`
	Method       string                 `json:"method,omitempty" example:"GET" doc:"HTTP method"`
	StatusCode   int                    `json:"statusCode,omitempty" example:"200" doc:"HTTP status code"`
	ResponseTime int                    `json:"responseTime,omitempty" example:"150" doc:"Response time in milliseconds"`
	IPAddress    string                 `json:"ipAddress,omitempty" example:"192.168.1.1" doc:"IP address"`
	UserAgent    string                 `json:"userAgent,omitempty" example:"MyApp/1.0" doc:"User agent"`
	Success      bool                   `json:"success" example:"true" doc:"Whether request was successful"`
	Error        string                 `json:"error,omitempty" example:"Rate limit exceeded" doc:"Error message"`
	Timestamp    time.Time              `json:"timestamp" example:"2023-01-01T12:00:00Z" doc:"Activity timestamp"`
	Metadata     map[string]interface{} `json:"metadata,omitempty" doc:"Additional activity metadata"`
}

// APIKeyActivityRequest represents a request for API key activity
type APIKeyActivityRequest struct {
	PaginationParams
	KeyID      OptionalParam[xid.ID]    `json:"keyId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by API key" query:"keyId"`
	PublicKey  string                   `json:"publicKey,omitempty" example:"pk_test_123abc..." doc:"Filter by public key" query:"publicKey"`
	Action     string                   `json:"action,omitempty" example:"api_request" doc:"Filter by action" query:"action"`
	Endpoint   string                   `json:"endpoint,omitempty" example:"/api/v1/users" doc:"Filter by endpoint" query:"endpoint"`
	Method     string                   `json:"method,omitempty" example:"GET" doc:"Filter by HTTP method" query:"method"`
	Success    OptionalParam[bool]      `json:"success,omitempty" example:"true" doc:"Filter by success status" query:"success"`
	StartDate  OptionalParam[time.Time] `json:"startDate,omitempty" example:"2023-01-01T00:00:00Z" doc:"Start date" query:"startDate"`
	EndDate    OptionalParam[time.Time] `json:"endDate,omitempty" example:"2023-01-31T23:59:59Z" doc:"End date" query:"endDate"`
	IPAddress  string                   `json:"ipAddress,omitempty" example:"192.168.1.1" doc:"Filter by IP address" query:"ipAddress"`
	StatusCode int                      `json:"statusCode,omitempty" example:"200" doc:"Filter by status code" query:"statusCode"`
}

// APIKeyActivityResponse represents API key activity response
type APIKeyActivityResponse = PaginatedOutput[APIKeyActivity]

// APIKeyExportRequest represents a request to export API key data
type APIKeyExportRequest struct {
	KeyIDs          []xid.ID   `json:"keyIds,omitempty" example:"[\"01FZS6TV7KP869DR7RXNEHXQKX\"]" doc:"Specific key IDs to export"`
	OrganizationID  *xid.ID    `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Export keys for organization"`
	StartDate       *time.Time `json:"startDate,omitempty" example:"2023-01-01T00:00:00Z" doc:"Start date for activity"`
	EndDate         *time.Time `json:"endDate,omitempty" example:"2023-01-31T23:59:59Z" doc:"End date for activity"`
	Format          string     `json:"format" example:"json" doc:"Export format (json, csv)"`
	IncludeActivity bool       `json:"includeActivity" example:"true" doc:"Include activity data"`
	IncludeUsage    bool       `json:"includeUsage" example:"true" doc:"Include usage statistics"`
}

// APIKeyExportResponse represents API key export response
type APIKeyExportResponse struct {
	ExportID    xid.ID    `json:"exportId" example:"123" doc:"Export ID"`
	Status      string    `json:"status" example:"pending" doc:"Export status"`
	DownloadURL string    `json:"downloadUrl" example:"https://api.example.com/downloads/apikeys-export-123.json" doc:"Download URL"`
	ExpiresAt   time.Time `json:"expiresAt" example:"2023-01-01T13:00:00Z" doc:"Download URL expiration"`
	Format      string    `json:"format" example:"json" doc:"Export format"`
	KeyCount    int       `json:"keyCount" example:"25" doc:"Number of keys exported"`
	FileSize    int       `json:"fileSize" example:"1048576" doc:"File size in bytes"`
}
