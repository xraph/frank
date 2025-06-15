package model

import (
	"time"

	"github.com/rs/xid"
)

// Webhook represents a webhook endpoint
type Webhook struct {
	Base
	AuditBase
	Name           string                 `json:"name" example:"User Events Webhook" doc:"Webhook name"`
	URL            string                 `json:"url" example:"https://api.example.com/webhooks/events" doc:"Webhook endpoint URL"`
	OrganizationID xid.ID                 `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	Secret         string                 `json:"secret,omitempty" example:"whsec_abc123..." doc:"Webhook secret for signature verification (write-only)"`
	Active         bool                   `json:"active" example:"true" doc:"Whether webhook is active"`
	EventTypes     []string               `json:"eventTypes" example:"[\"user.created\", \"user.updated\", \"user.deleted\"]" doc:"Subscribed event types"`
	Version        string                 `json:"version" example:"v1" doc:"Webhook API version"`
	RetryCount     int                    `json:"retryCount" example:"3" doc:"Number of retry attempts"`
	TimeoutMs      int                    `json:"timeoutMs" example:"5000" doc:"Request timeout in milliseconds"`
	Format         WebhookFormat          `json:"format" example:"json" doc:"Payload format (json, form)" enum:"json,form"`
	Headers        map[string]string      `json:"headers,omitempty" doc:"Custom headers to include"`
	Metadata       map[string]interface{} `json:"metadata,omitempty" doc:"Additional webhook metadata"`

	// Relationships
	Organization *OrganizationSummary `json:"organization,omitempty" doc:"Organization information"`
	Events       []WebhookEvent       `json:"events,omitempty" doc:"Recent webhook events"`
	Stats        *WebhookStats        `json:"stats,omitempty" doc:"Webhook statistics"`
}

// WebhookSummary represents a simplified webhook for listings
type WebhookSummary struct {
	ID           xid.ID     `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Webhook ID"`
	Name         string     `json:"name" example:"User Events Webhook" doc:"Webhook name"`
	URL          string     `json:"url" example:"https://api.example.com/webhooks/events" doc:"Webhook URL"`
	Active       bool       `json:"active" example:"true" doc:"Whether webhook is active"`
	EventTypes   []string   `json:"eventTypes" example:"[\"user.created\", \"user.updated\"]" doc:"Event types"`
	LastDelivery *time.Time `json:"lastDelivery,omitempty" example:"2023-01-01T12:00:00Z" doc:"Last successful delivery"`
	SuccessRate  float64    `json:"successRate" example:"98.5" doc:"Success rate percentage"`
	TotalEvents  int        `json:"totalEvents" example:"1500" doc:"Total events sent"`
	FailedEvents int        `json:"failedEvents" example:"23" doc:"Failed events count"`
	CreatedAt    time.Time  `json:"createdAt" example:"2023-01-01T10:00:00Z" doc:"Creation timestamp"`
}

// WebhookEvent represents a webhook event delivery
type WebhookEvent struct {
	Base
	WebhookID    xid.ID                 `json:"webhookId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Webhook ID"`
	EventType    string                 `json:"eventType" example:"user.created" doc:"Event type"`
	Headers      map[string]string      `json:"headers,omitempty" doc:"Request headers sent"`
	Payload      map[string]interface{} `json:"payload,omitempty" doc:"Event payload"`
	Delivered    bool                   `json:"delivered" example:"true" doc:"Whether event was delivered successfully"`
	DeliveredAt  *time.Time             `json:"deliveredAt,omitempty" example:"2023-01-01T12:00:00Z" doc:"Delivery timestamp"`
	Attempts     int                    `json:"attempts" example:"1" doc:"Number of delivery attempts"`
	NextRetry    *time.Time             `json:"nextRetry,omitempty" example:"2023-01-01T12:05:00Z" doc:"Next retry timestamp"`
	StatusCode   *int                   `json:"statusCode,omitempty" example:"200" doc:"HTTP response status code"`
	ResponseBody string                 `json:"responseBody,omitempty" example:"{\"status\": \"received\"}" doc:"Response body from webhook endpoint"`
	Error        string                 `json:"error,omitempty" example:"Connection timeout" doc:"Error message if delivery failed"`
	Duration     int                    `json:"duration,omitempty" example:"250" doc:"Request duration in milliseconds"`

	// Relationships
	Webhook *WebhookSummary `json:"webhook,omitempty" doc:"Webhook information"`
}

// WebhookEventSummary represents a simplified webhook event for listings
type WebhookEventSummary struct {
	ID          xid.ID     `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Event ID"`
	EventType   string     `json:"eventType" example:"user.created" doc:"Event type"`
	Delivered   bool       `json:"delivered" example:"true" doc:"Delivery status"`
	Attempts    int        `json:"attempts" example:"1" doc:"Delivery attempts"`
	StatusCode  *int       `json:"statusCode,omitempty" example:"200" doc:"Response status code"`
	Duration    int        `json:"duration,omitempty" example:"250" doc:"Duration in milliseconds"`
	Error       string     `json:"error,omitempty" example:"Connection timeout" doc:"Error message"`
	CreatedAt   time.Time  `json:"createdAt" example:"2023-01-01T12:00:00Z" doc:"Event timestamp"`
	DeliveredAt *time.Time `json:"deliveredAt,omitempty" example:"2023-01-01T12:00:01Z" doc:"Delivery timestamp"`
}

// CreateWebhookRequest represents a request to create a webhook
type CreateWebhookRequest struct {
	Name       string                 `json:"name" example:"My Webhook" doc:"Webhook name"`
	URL        string                 `json:"url" example:"https://api.example.com/webhooks" doc:"Webhook endpoint URL"`
	EventTypes []string               `json:"eventTypes" example:"[\"user.created\", \"user.updated\"]" doc:"Event types to subscribe to"`
	Secret     string                 `json:"secret,omitempty" example:"my_webhook_secret" doc:"Webhook secret for signature verification"`
	Version    string                 `json:"version,omitempty" example:"v1" doc:"Webhook API version"`
	RetryCount int                    `json:"retryCount,omitempty" example:"3" doc:"Retry attempts"`
	TimeoutMs  int                    `json:"timeoutMs,omitempty" example:"5000" doc:"Timeout in milliseconds"`
	Format     WebhookFormat          `json:"format,omitempty" example:"json" doc:"Payload format"`
	Headers    map[string]string      `json:"headers,omitempty" doc:"Custom headers"`
	Metadata   map[string]interface{} `json:"metadata,omitempty" doc:"Additional metadata"`
}

// UpdateWebhookRequest represents a request to update a webhook
type UpdateWebhookRequest struct {
	Name       string                 `json:"name,omitempty" example:"Updated Webhook" doc:"Updated name"`
	URL        string                 `json:"url,omitempty" example:"https://api.example.com/new-webhook" doc:"Updated URL"`
	Active     bool                   `json:"active,omitempty" example:"true" doc:"Updated active status"`
	EventTypes []string               `json:"eventTypes,omitempty" example:"[\"user.created\", \"user.deleted\"]" doc:"Updated event types"`
	Secret     string                 `json:"secret,omitempty" example:"new_secret" doc:"Updated secret"`
	RetryCount int                    `json:"retryCount,omitempty" example:"5" doc:"Updated retry count"`
	TimeoutMs  int                    `json:"timeoutMs,omitempty" example:"10000" doc:"Updated timeout"`
	Headers    map[string]string      `json:"headers,omitempty" doc:"Updated headers"`
	Metadata   map[string]interface{} `json:"metadata,omitempty" doc:"Updated metadata"`
}

// WebhookListRequest represents a request to list webhooks
type WebhookListRequest struct {
	PaginationParams
	OrganizationID OptionalParam[xid.ID] `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by organization" query:"organizationId"`
	Active         OptionalParam[bool]   `json:"active,omitempty" example:"true" doc:"Filter by active status" query:"active"`
	EventType      string                `json:"eventType,omitempty" example:"user.created" doc:"Filter by event type" query:"eventType"`
	Search         string                `json:"search,omitempty" example:"user" doc:"Search in name/URL" query:"search"`
}

// WebhookListResponse represents a list of webhooks
type WebhookListResponse = PaginatedOutput[WebhookSummary]

// WebhookEventListRequest represents a request to list webhook events
type WebhookEventListRequest struct {
	PaginationParams
	WebhookID  OptionalParam[xid.ID]    `json:"webhookId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by webhook" query:"webhookId"`
	EventType  string                   `json:"eventType,omitempty" example:"user.created" doc:"Filter by event type" query:"eventType"`
	Delivered  OptionalParam[bool]      `json:"delivered,omitempty" example:"true" doc:"Filter by delivery status" query:"delivered"`
	StatusCode OptionalParam[int]       `json:"statusCode,omitempty" example:"200" doc:"Filter by status code" query:"statusCode"`
	StartDate  OptionalParam[time.Time] `json:"startDate,omitempty" example:"2023-01-01T00:00:00Z" doc:"Start date" query:"startDate"`
	EndDate    OptionalParam[time.Time] `json:"endDate,omitempty" example:"2023-01-31T23:59:59Z" doc:"End date" query:"endDate"`
	HasError   OptionalParam[bool]      `json:"hasError,omitempty" example:"false" doc:"Filter events with errors" query:"hasError"`
}

// WebhookEventListResponse represents a list of webhook events
type WebhookEventListResponse = PaginatedOutput[WebhookEventSummary]

// TestWebhookRequest represents a request to test a webhook
type TestWebhookRequest struct {
	WebhookID xid.ID                 `json:"webhookId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Webhook ID to test"`
	EventType string                 `json:"eventType,omitempty" example:"user.created" doc:"Event type for test"`
	Payload   map[string]interface{} `json:"payload,omitempty" doc:"Test payload"`
}

// TestWebhookResponse represents webhook test response
type TestWebhookResponse struct {
	Success      bool              `json:"success" example:"true" doc:"Whether test was successful"`
	StatusCode   int               `json:"statusCode" example:"200" doc:"HTTP status code"`
	ResponseBody string            `json:"responseBody" example:"{\"status\": \"received\"}" doc:"Response body"`
	Duration     int               `json:"duration" example:"250" doc:"Request duration in milliseconds"`
	Error        string            `json:"error,omitempty" example:"Connection failed" doc:"Error message if failed"`
	Headers      map[string]string `json:"headers,omitempty" doc:"Response headers"`
}

// RetryWebhookEventRequest represents a request to retry a webhook event
type RetryWebhookEventRequest struct {
	EventID xid.ID `json:"eventId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Event ID to retry"`
	Force   bool   `json:"force" example:"false" doc:"Force retry even if max attempts reached"`
}

// RetryWebhookEventResponse represents webhook event retry response
type RetryWebhookEventResponse struct {
	Success    bool       `json:"success" example:"true" doc:"Whether retry was initiated"`
	StatusCode int        `json:"statusCode,omitempty" example:"200" doc:"HTTP status code"`
	Duration   int        `json:"duration,omitempty" example:"300" doc:"Request duration in milliseconds"`
	Error      string     `json:"error,omitempty" example:"Max retries exceeded" doc:"Error message if failed"`
	NextRetry  *time.Time `json:"nextRetry,omitempty" example:"2023-01-01T12:10:00Z" doc:"Next retry time"`
}

// WebhookStats represents webhook statistics
type WebhookStats struct {
	WebhookID           xid.ID         `json:"webhookId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Webhook ID"`
	TotalEvents         int            `json:"totalEvents" example:"5000" doc:"Total events sent"`
	SuccessfulEvents    int            `json:"successfulEvents" example:"4875" doc:"Successful deliveries"`
	FailedEvents        int            `json:"failedEvents" example:"125" doc:"Failed deliveries"`
	SuccessRate         float64        `json:"successRate" example:"97.5" doc:"Success rate percentage"`
	EventsToday         int            `json:"eventsToday" example:"50" doc:"Events sent today"`
	EventsWeek          int            `json:"eventsWeek" example:"350" doc:"Events sent this week"`
	EventsMonth         int            `json:"eventsMonth" example:"1500" doc:"Events sent this month"`
	AverageResponseTime int            `json:"averageResponseTime" example:"250" doc:"Average response time in milliseconds"`
	LastDelivery        *time.Time     `json:"lastDelivery,omitempty" example:"2023-01-01T12:00:00Z" doc:"Last successful delivery"`
	LastFailure         *time.Time     `json:"lastFailure,omitempty" example:"2023-01-01T11:30:00Z" doc:"Last failed delivery"`
	EventsByType        map[string]int `json:"eventsByType" example:"{\"user.created\": 2000, \"user.updated\": 1500}" doc:"Events by type"`
	ErrorsByCode        map[string]int `json:"errorsByCode" example:"{\"404\": 50, \"500\": 75}" doc:"Errors by status code"`
	ResponseTimes       []int          `json:"responseTimes,omitempty" example:"[200, 250, 180, 300]" doc:"Recent response times"`
}

// WebhookGlobalStats represents global webhook statistics
type WebhookGlobalStats struct {
	TotalWebhooks       int                   `json:"totalWebhooks" example:"25" doc:"Total webhooks"`
	ActiveWebhooks      int                   `json:"activeWebhooks" example:"20" doc:"Active webhooks"`
	TotalEvents         int                   `json:"totalEvents" example:"100000" doc:"Total events sent"`
	SuccessfulEvents    int                   `json:"successfulEvents" example:"98000" doc:"Successful events"`
	FailedEvents        int                   `json:"failedEvents" example:"2000" doc:"Failed events"`
	OverallSuccessRate  float64               `json:"overallSuccessRate" example:"98.0" doc:"Overall success rate"`
	EventsToday         int                   `json:"eventsToday" example:"1000" doc:"Events sent today"`
	EventsWeek          int                   `json:"eventsWeek" example:"7000" doc:"Events sent this week"`
	EventsMonth         int                   `json:"eventsMonth" example:"30000" doc:"Events sent this month"`
	EventsByType        map[string]int        `json:"eventsByType" example:"{\"user.created\": 30000, \"user.updated\": 25000}" doc:"Events by type"`
	TopWebhooks         []WebhookSummary      `json:"topWebhooks" doc:"Most active webhooks"`
	RecentFailures      []WebhookEventSummary `json:"recentFailures" doc:"Recent failed events"`
	AverageResponseTime float64               `json:"averageResponseTime" example:"275.5" doc:"Average response time"`
}

// BulkWebhookOperationRequest represents a bulk webhook operation
type BulkWebhookOperationRequest struct {
	WebhookIDs []xid.ID `json:"webhookIds" example:"[\"01FZS6TV7KP869DR7RXNEHXQKX\"]" doc:"Webhook IDs"`
	Operation  string   `json:"operation" example:"activate" doc:"Operation (activate, deactivate, delete)"`
	Reason     string   `json:"reason,omitempty" example:"Maintenance" doc:"Reason for operation"`
}

// BulkWebhookOperationResponse represents bulk webhook operation response
type BulkWebhookOperationResponse struct {
	Success      []xid.ID `json:"success" example:"[\"01FZS6TV7KP869DR7RXNEHXQKX\"]" doc:"Successful webhook IDs"`
	Failed       []xid.ID `json:"failed,omitempty" example:"[]" doc:"Failed webhook IDs"`
	SuccessCount int      `json:"successCount" example:"5" doc:"Success count"`
	FailureCount int      `json:"failureCount" example:"0" doc:"Failure count"`
	Errors       []string `json:"errors,omitempty" example:"[]" doc:"Error messages"`
}

// WebhookDeliveryRetryRequest represents a bulk retry request
type WebhookDeliveryRetryRequest struct {
	WebhookID  *xid.ID    `json:"webhookId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Specific webhook ID"`
	EventType  string     `json:"eventType,omitempty" example:"user.created" doc:"Filter by event type"`
	StartDate  *time.Time `json:"startDate,omitempty" example:"2023-01-01T00:00:00Z" doc:"Start date for failed events"`
	EndDate    *time.Time `json:"endDate,omitempty" example:"2023-01-01T23:59:59Z" doc:"End date for failed events"`
	MaxRetries int        `json:"maxRetries,omitempty" example:"3" doc:"Maximum retries per event"`
}

// WebhookDeliveryRetryResponse represents bulk retry response
type WebhookDeliveryRetryResponse struct {
	QueuedCount   int      `json:"queuedCount" example:"50" doc:"Number of events queued for retry"`
	EventIDs      []xid.ID `json:"eventIds" example:"[\"01FZS6TV7KP869DR7RXNEHXQKX\"]" doc:"Event IDs queued"`
	EstimatedTime int      `json:"estimatedTime" example:"300" doc:"Estimated completion time in seconds"`
}

// WebhookSecuritySettings represents webhook security configuration
type WebhookSecuritySettings struct {
	WebhookID          xid.ID            `json:"webhookId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Webhook ID"`
	SignatureEnabled   bool              `json:"signatureEnabled" example:"true" doc:"Whether signature verification is enabled"`
	SignatureAlgorithm string            `json:"signatureAlgorithm" example:"sha256" doc:"Signature algorithm"`
	IPWhitelist        []string          `json:"ipWhitelist,omitempty" example:"[\"192.168.1.0/24\"]" doc:"Allowed source IP ranges"`
	RequireHTTPS       bool              `json:"requireHttps" example:"true" doc:"Whether HTTPS is required"`
	VerifySSL          bool              `json:"verifySsl" example:"true" doc:"Whether to verify SSL certificates"`
	CustomHeaders      map[string]string `json:"customHeaders,omitempty" doc:"Custom security headers"`
}

// UpdateWebhookSecurityRequest represents a request to update webhook security
type UpdateWebhookSecurityRequest struct {
	SignatureEnabled   bool              `json:"signatureEnabled,omitempty" example:"true" doc:"Enable signature verification"`
	SignatureAlgorithm string            `json:"signatureAlgorithm,omitempty" example:"sha256" doc:"Signature algorithm"`
	IPWhitelist        []string          `json:"ipWhitelist,omitempty" example:"[\"192.168.1.0/24\"]" doc:"IP whitelist"`
	RequireHTTPS       bool              `json:"requireHttps,omitempty" example:"true" doc:"Require HTTPS"`
	VerifySSL          bool              `json:"verifySsl,omitempty" example:"true" doc:"Verify SSL certificates"`
	CustomHeaders      map[string]string `json:"customHeaders,omitempty" doc:"Custom headers"`
	RegenerateSecret   bool              `json:"regenerateSecret,omitempty" example:"false" doc:"Regenerate webhook secret"`
}

// WebhookExportRequest represents a request to export webhook data
type WebhookExportRequest struct {
	WebhookIDs       []xid.ID   `json:"webhookIds,omitempty" example:"[\"01FZS6TV7KP869DR7RXNEHXQKX\"]" doc:"Specific webhook IDs"`
	OrganizationID   *xid.ID    `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	StartDate        *time.Time `json:"startDate,omitempty" example:"2023-01-01T00:00:00Z" doc:"Start date"`
	EndDate          *time.Time `json:"endDate,omitempty" example:"2023-01-31T23:59:59Z" doc:"End date"`
	Format           string     `json:"format" example:"json" doc:"Export format (json, csv)"`
	IncludeEvents    bool       `json:"includeEvents" example:"true" doc:"Include event data"`
	IncludePayloads  bool       `json:"includePayloads" example:"false" doc:"Include event payloads"`
	IncludeResponses bool       `json:"includeResponses" example:"false" doc:"Include response data"`
}

// WebhookExportResponse represents webhook export response
type WebhookExportResponse struct {
	DownloadURL  string    `json:"downloadUrl" example:"https://api.example.com/downloads/webhooks-export-123.json" doc:"Download URL"`
	ExpiresAt    time.Time `json:"expiresAt" example:"2023-01-01T13:00:00Z" doc:"Download URL expiration"`
	Format       string    `json:"format" example:"json" doc:"Export format"`
	WebhookCount int       `json:"webhookCount" example:"10" doc:"Number of webhooks exported"`
	EventCount   int       `json:"eventCount" example:"5000" doc:"Number of events exported"`
	FileSize     int       `json:"fileSize" example:"2097152" doc:"File size in bytes"`
}

// WebhookHealthCheck represents webhook health status
type WebhookHealthCheck struct {
	WebhookID        xid.ID    `json:"webhookId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Webhook ID"`
	Healthy          bool      `json:"healthy" example:"true" doc:"Whether webhook is healthy"`
	LastCheck        time.Time `json:"lastCheck" example:"2023-01-01T12:00:00Z" doc:"Last health check"`
	ResponseTime     int       `json:"responseTime" example:"250" doc:"Response time in milliseconds"`
	Status           string    `json:"status" example:"operational" doc:"Health status"`
	Issues           []string  `json:"issues,omitempty" example:"[]" doc:"Health issues"`
	NextCheck        time.Time `json:"nextCheck" example:"2023-01-01T12:15:00Z" doc:"Next check time"`
	ConsecutiveFails int       `json:"consecutiveFails" example:"0" doc:"Consecutive failed checks"`
}
