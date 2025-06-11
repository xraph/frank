package model

import (
	"time"

	"github.com/rs/xid"
)

// ListSessionsParams represents parameters for listing sessions
type ListSessionsParams struct {
	PaginationParams
	UserID         OptionalParam[xid.ID]    `json:"user_id" query:"user_id"`
	Active         OptionalParam[bool]      `json:"active,omitempty"`
	OrganizationID OptionalParam[xid.ID]    `json:"organization_id,omitempty"`
	DeviceID       OptionalParam[string]    `json:"device_id,omitempty"`
	IPAddress      OptionalParam[string]    `json:"ip_address,omitempty"`
	Location       OptionalParam[string]    `json:"location,omitempty"`
	ExpiresAfter   OptionalParam[time.Time] `json:"expires_after,omitempty"`
	ExpiresBefore  OptionalParam[time.Time] `json:"expires_before,omitempty"`
	CreatedAfter   OptionalParam[time.Time] `json:"created_after,omitempty"`
	CreatedBefore  OptionalParam[time.Time] `json:"created_before,omitempty"`
}
