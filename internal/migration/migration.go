// Package migration provides database migration functionality for the Frank Auth SaaS platform.
// It handles entgo schema migrations, data seeding, and multi-tenant database operations
// with support for rollbacks, validation, and schema integrity checks.
package migration

import (
	"github.com/rs/xid"
)

// SeedOptions represents options for seeding operations
type SeedOptions struct {
	SeedFile string  `json:"seedFile,omitempty"`
	TenantID *xid.ID `json:"tenantId,omitempty"`
	Force    bool    `json:"force"`
}

// ValidationResult represents schema validation results
type ValidationResult struct {
	Valid  bool              `json:"valid"`
	Issues []ValidationIssue `json:"issues"`
}

// ValidationIssue represents a schema validation issue
type ValidationIssue struct {
	Type    string `json:"type"`
	Table   string `json:"table,omitempty"`
	Column  string `json:"column,omitempty"`
	Message string `json:"message"`
}
