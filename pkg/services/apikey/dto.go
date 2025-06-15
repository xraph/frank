package apikey

import (
	"github.com/rs/xid"
)

// Configuration options for various operations
type CreateOptions struct {
	UserID         *xid.ID
	OrganizationID *xid.ID
	SkipAudit      bool
}

type GetOptions struct {
	UserID         *xid.ID
	OrganizationID *xid.ID
	IncludeUsage   bool
	IncludeUser    bool
	IncludeOrg     bool
}

type UpdateOptions struct {
	UserID         *xid.ID
	OrganizationID *xid.ID
	SkipAudit      bool
}

type DeleteOptions struct {
	UserID         *xid.ID
	OrganizationID *xid.ID
	SkipAudit      bool

	Reason string
}

type RotateOptions struct {
	UserID         *xid.ID
	OrganizationID *xid.ID
	SkipAudit      bool
}

type DeactivateOptions struct {
	UserID         *xid.ID
	OrganizationID *xid.ID
	SkipAudit      bool
}

type ActivateOptions struct {
	UserID         *xid.ID
	OrganizationID *xid.ID
	SkipAudit      bool
}

type BulkOptions struct {
	UserID         *xid.ID
	OrganizationID *xid.ID
	SkipAudit      bool
}

type StatsOptions struct {
	OrganizationID *xid.ID
	UserID         *xid.ID
	TimeRange      string
}

type ActivityOptions struct {
	OrganizationID *xid.ID
	UserID         *xid.ID
}

type ExportOptions struct {
	OrganizationID *xid.ID
	UserID         *xid.ID
}

// Constants for API key generation
const (
	APIKeyPrefix = "frank_sk_"
	KeyLength    = 32
	MinKeyLength = 16
	MaxKeyLength = 64

	// Default API key types
	TypeServer = "server"
	TypeClient = "client"
	TypeAdmin  = "admin"

	// Rate limit defaults
	DefaultRequestsPerMinute = 1000
	DefaultRequestsPerHour   = 60000
	DefaultRequestsPerDay    = 1440000
	DefaultBurstLimit        = 100
)
