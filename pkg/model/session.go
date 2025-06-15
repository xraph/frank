package model

import (
	"time"

	"github.com/rs/xid"
)

// ListSessionsParams represents parameters for listing sessions
type ListSessionsParams struct {
	PaginationParams
	UserID         OptionalParam[xid.ID]    `json:"userId" query:"userId"`
	Active         OptionalParam[bool]      `json:"active,omitempty"`
	OrganizationID OptionalParam[xid.ID]    `json:"organizationId,omitempty"`
	DeviceID       OptionalParam[string]    `json:"deviceId,omitempty"`
	IPAddress      OptionalParam[string]    `json:"ipAddress,omitempty"`
	Location       OptionalParam[string]    `json:"location,omitempty"`
	ExpiresAfter   OptionalParam[time.Time] `json:"expiresAfter,omitempty"`
	ExpiresBefore  OptionalParam[time.Time] `json:"expiresBefore,omitempty"`
	CreatedAfter   OptionalParam[time.Time] `json:"createdAfter,omitempty"`
	CreatedBefore  OptionalParam[time.Time] `json:"createdBefore,omitempty"`
}
