package model

import (
	"time"

	"github.com/rs/xid"
)

// ActivityRecord represents an activity record in the repository layer
// This is separate from the service layer ActivityRecord to maintain layer separation
type ActivityRecord struct {
	ID             xid.ID                 `json:"id"`
	ResourceType   ResourceType           `json:"resourceType"`
	ResourceID     xid.ID                 `json:"resourceId"`
	UserID         *xid.ID                `json:"userId,omitempty"`
	OrganizationID *xid.ID                `json:"organizationId,omitempty"`
	SessionID      *xid.ID                `json:"sessionId,omitempty"`
	Action         string                 `json:"action"`
	Category       string                 `json:"category"`
	Source         string                 `json:"source"`
	Endpoint       string                 `json:"endpoint,omitempty"`
	Method         string                 `json:"method,omitempty"`
	StatusCode     int                    `json:"statusCode,omitempty"`
	ResponseTime   int                    `json:"responseTime,omitempty"`
	IPAddress      string                 `json:"ipAddress,omitempty"`
	UserAgent      string                 `json:"userAgent,omitempty"`
	Location       string                 `json:"location,omitempty"`
	Success        bool                   `json:"success"`
	Error          string                 `json:"error,omitempty"`
	ErrorCode      string                 `json:"errorCode,omitempty"`
	Size           int                    `json:"size,omitempty"`
	Count          int                    `json:"count,omitempty"`
	Value          float64                `json:"value,omitempty"`
	Timestamp      time.Time              `json:"timestamp"`
	ExpiresAt      *time.Time             `json:"expiresAt,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	Tags           []string               `json:"tags,omitempty"`
}
