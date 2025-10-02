package models

import (
	"time"

	"github.com/uptrace/bun"
	"github.com/xraph/frank/pkg/model"
)

// Webhook model
type Webhook struct {
	CommonModel
	Timestamps
	SoftDelete
	bun.BaseModel `bun:"table:webhooks,alias:wh"`

	Name           string                 `bun:"name,notnull" json:"name"`
	URL            string                 `bun:"url,notnull" json:"url"`
	OrganizationID string                 `bun:"organization_id,notnull,type:varchar(20)" json:"organization_id"`
	Secret         string                 `bun:"secret,notnull" json:"-"`
	Active         bool                   `bun:"active,notnull,default:true" json:"active"`
	EventTypes     []string               `bun:"event_types,type:text[],array" json:"event_types"`
	Version        string                 `bun:"version,notnull,default:'v1'" json:"version"`
	RetryCount     int                    `bun:"retry_count,notnull,default:3" json:"retry_count"`
	TimeoutMS      int                    `bun:"timeout_ms,notnull,default:5000" json:"timeout_ms"`
	Format         model.WebhookFormat    `bun:"format,notnull,default:'json'" json:"format"`
	Metadata       map[string]interface{} `bun:"metadata,type:jsonb" json:"metadata,omitempty"`
	Headers        map[string]string      `bun:"headers,type:jsonb" json:"headers,omitempty"`

	// Relations
	Organization *Organization   `bun:"rel:belongs-to,join:organization_id=id" json:"organization,omitempty"`
	Events       []*WebhookEvent `bun:"rel:has-many,join:id=webhook_id" json:"events,omitempty"`
}

// WebhookEvent model
type WebhookEvent struct {
	CommonModel
	Timestamps
	SoftDelete
	bun.BaseModel `bun:"table:webhook_events,alias:we"`

	WebhookID    string                 `bun:"webhook_id,notnull,type:varchar(20)" json:"webhook_id"`
	EventType    string                 `bun:"event_type,notnull" json:"event_type"`
	Headers      map[string]string      `bun:"headers,type:jsonb" json:"headers,omitempty"`
	Payload      map[string]interface{} `bun:"payload,type:jsonb" json:"payload"`
	Delivered    bool                   `bun:"delivered,notnull,default:false" json:"delivered"`
	DeliveredAt  *time.Time             `bun:"delivered_at" json:"delivered_at,omitempty"`
	Attempts     int                    `bun:"attempts,notnull,default:0" json:"attempts"`
	NextRetry    *time.Time             `bun:"next_retry" json:"next_retry,omitempty"`
	StatusCode   *int                   `bun:"status_code" json:"status_code,omitempty"`
	ResponseBody *string                `bun:"response_body" json:"response_body,omitempty"`
	Error        *string                `bun:"error" json:"error,omitempty"`

	// Relations
	Webhook *Webhook `bun:"rel:belongs-to,join:webhook_id=id" json:"webhook,omitempty"`
}

// Activity model - generic activity tracking
type Activity struct {
	CommonModel
	bun.BaseModel `bun:"table:activities,alias:act"`

	ResourceType   model.ResourceType     `bun:"resource_type,notnull,default:'common'" json:"resource_type"`
	ResourceID     string                 `bun:"resource_id,notnull,type:varchar(20)" json:"resource_id"`
	UserID         *string                `bun:"user_id,type:varchar(20)" json:"user_id,omitempty"`
	OrganizationID *string                `bun:"organization_id,type:varchar(20)" json:"organization_id,omitempty"`
	SessionID      *string                `bun:"session_id,type:varchar(20)" json:"session_id,omitempty"`
	Action         string                 `bun:"action,notnull" json:"action"`
	Category       string                 `bun:"category,notnull,default:'general'" json:"category"`
	Source         *string                `bun:"source" json:"source,omitempty"`
	Endpoint       *string                `bun:"endpoint" json:"endpoint,omitempty"`
	Method         *string                `bun:"method" json:"method,omitempty"`
	StatusCode     *int                   `bun:"status_code" json:"status_code,omitempty"`
	ResponseTime   *int                   `bun:"response_time" json:"response_time,omitempty"`
	IPAddress      *string                `bun:"ip_address" json:"ip_address,omitempty"`
	UserAgent      *string                `bun:"user_agent" json:"user_agent,omitempty"`
	Location       *string                `bun:"location" json:"location,omitempty"`
	Success        bool                   `bun:"success,notnull,default:true" json:"success"`
	Error          *string                `bun:"error" json:"error,omitempty"`
	ErrorCode      *string                `bun:"error_code" json:"error_code,omitempty"`
	Size           *int                   `bun:"size" json:"size,omitempty"`
	Count          *int                   `bun:"count" json:"count,omitempty"`
	Value          *float64               `bun:"value" json:"value,omitempty"`
	Timestamp      time.Time              `bun:"timestamp,notnull" json:"timestamp"`
	ExpiresAt      *time.Time             `bun:"expires_at" json:"expires_at,omitempty"`
	Metadata       map[string]interface{} `bun:"metadata,type:jsonb" json:"metadata,omitempty"`
	Tags           []string               `bun:"tags,type:jsonb" json:"tags,omitempty"`

	// Relations
	User         *User         `bun:"rel:belongs-to,join:user_id=id" json:"user,omitempty"`
	Organization *Organization `bun:"rel:belongs-to,join:organization_id=id" json:"organization,omitempty"`
	Session      *Session      `bun:"rel:belongs-to,join:session_id=id" json:"session,omitempty"`
}

// Audit model
type Audit struct {
	CommonModel
	Timestamps
	SoftDelete
	bun.BaseModel `bun:"table:audit_logs,alias:audit"`

	UserID         *string                `bun:"user_id,type:varchar(20)" json:"user_id,omitempty"`
	OrganizationID *string                `bun:"organization_id,type:varchar(20)" json:"organization_id,omitempty"`
	SessionID      *string                `bun:"session_id,type:varchar(20)" json:"session_id,omitempty"`
	Action         string                 `bun:"action,notnull" json:"action"`
	ResourceType   string                 `bun:"resource_type,notnull" json:"resource_type"`
	ResourceID     *string                `bun:"resource_id,type:varchar(20)" json:"resource_id,omitempty"`
	Status         string                 `bun:"status,notnull" json:"status"`
	IPAddress      *string                `bun:"ip_address" json:"ip_address,omitempty"`
	UserAgent      *string                `bun:"user_agent" json:"user_agent,omitempty"`
	Location       *string                `bun:"location" json:"location,omitempty"`
	DeviceID       *string                `bun:"device_id" json:"device_id,omitempty"`
	RequestID      *string                `bun:"request_id" json:"request_id,omitempty"`
	ErrorCode      *string                `bun:"error_code" json:"error_code,omitempty"`
	ErrorMessage   *string                `bun:"error_message" json:"error_message,omitempty"`
	Description    *string                `bun:"description" json:"description,omitempty"`
	Metadata       map[string]interface{} `bun:"metadata,type:jsonb" json:"metadata,omitempty"`
	OldValues      map[string]interface{} `bun:"old_values,type:jsonb" json:"old_values,omitempty"`
	CurrentValues  map[string]interface{} `bun:"current_values,type:jsonb" json:"current_values,omitempty"`
	Timestamp      time.Time              `bun:"timestamp,notnull,nullzero" json:"timestamp"`

	// Relations
	User         *User         `bun:"rel:belongs-to,join:user_id=id" json:"user,omitempty"`
	Organization *Organization `bun:"rel:belongs-to,join:organization_id=id" json:"organization,omitempty"`
	Session      *Session      `bun:"rel:belongs-to,join:session_id=id" json:"session,omitempty"`
}
