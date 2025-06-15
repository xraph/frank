package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/audit"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// AuditRepository defines the interface for audit log data operations
type AuditRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input CreateAuditInput) (*ent.Audit, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.Audit, error)
	Delete(ctx context.Context, id xid.ID) error

	// Query operations
	ListByUserID(ctx context.Context, userID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error)
	ListByOrganizationID(ctx context.Context, orgID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error)
	ListByAction(ctx context.Context, action string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error)
	ListByResourceType(ctx context.Context, resourceType string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error)
	ListByResourceID(ctx context.Context, resourceType string, resourceID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error)
	ListByIPAddress(ctx context.Context, ipAddress string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error)

	// Advanced queries
	ListByUserAndOrganization(ctx context.Context, userID, orgID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error)
	ListByTimeRange(ctx context.Context, from, to time.Time, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error)
	ListByStatus(ctx context.Context, status string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error)
	ListFailedActions(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error)

	// Security queries
	ListSuspiciousActivity(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error)
	ListBySessionID(ctx context.Context, sessionID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error)
	CountByUserAndAction(ctx context.Context, userID xid.ID, action string, since time.Time) (int, error)
	CountByIPAndAction(ctx context.Context, ipAddress, action string, since time.Time) (int, error)

	// Compliance and reporting
	GetComplianceReport(ctx context.Context, orgID xid.ID, from, to time.Time) (*ComplianceReport, error)
	ExportAuditLogs(ctx context.Context, filters AuditExportFilters) ([]*ent.Audit, error)

	// Utility operations
	DeleteOldLogs(ctx context.Context, before time.Time) (int, error)
	CountByOrganizationID(ctx context.Context, orgID xid.ID) (int, error)
	GetMostRecentByUser(ctx context.Context, userID xid.ID, limit int) ([]*ent.Audit, error)

	// Analytics
	GetActionStats(ctx context.Context, orgID xid.ID, since time.Time) (map[string]int, error)
	GetUserActivityStats(ctx context.Context, orgID xid.ID, since time.Time) (*UserActivityStats, error)
}

// auditRepository implements AuditRepository interface
type auditRepository struct {
	client *ent.Client
}

// NewAuditRepository creates a new audit repository
func NewAuditRepository(client *ent.Client) AuditRepository {
	return &auditRepository{
		client: client,
	}
}

// CreateAuditInput defines the input for creating an audit log entry
type CreateAuditInput struct {
	UserID         *xid.ID        `json:"user_id,omitempty"`
	OrganizationID *xid.ID        `json:"organization_id,omitempty"`
	SessionID      *xid.ID        `json:"session_id,omitempty"`
	Action         string         `json:"action"`
	ResourceType   string         `json:"resource_type"`
	ResourceID     *xid.ID        `json:"resource_id,omitempty"`
	Status         string         `json:"status"`
	IPAddress      *string        `json:"ip_address,omitempty"`
	UserAgent      *string        `json:"user_agent,omitempty"`
	Location       *string        `json:"location,omitempty"`
	DeviceID       *string        `json:"device_id,omitempty"`
	RequestID      *string        `json:"request_id,omitempty"`
	ErrorCode      *string        `json:"error_code,omitempty"`
	ErrorMessage   *string        `json:"error_message,omitempty"`
	Description    *string        `json:"description,omitempty"`
	Details        map[string]any `json:"details,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	OldValues      map[string]any `json:"old_values,omitempty"`
	NewValues      map[string]any `json:"new_values,omitempty"`
	Timestamp      time.Time      `json:"timestamp"`

	Changes   map[string]interface{} `json:"changes,omitempty" doc:"Changed fields"`
	Error     string                 `json:"error,omitempty" example:"Invalid credentials" doc:"Error message"`
	Duration  int                    `json:"duration,omitempty" example:"250" doc:"Duration in milliseconds"`
	RiskLevel string                 `json:"riskLevel,omitempty" example:"low" doc:"Risk level"`
	Tags      []string               `json:"tags,omitempty" example:"[\"auth\"]" doc:"Audit tags"`
	Source    string                 `json:"source,omitempty" example:"web" doc:"Action source"`
}

// AuditExportFilters defines filters for exporting audit logs
type AuditExportFilters struct {
	UserID         *xid.ID    `json:"user_id,omitempty"`
	OrganizationID *xid.ID    `json:"organization_id,omitempty"`
	Action         *string    `json:"action,omitempty"`
	ResourceType   *string    `json:"resource_type,omitempty"`
	Status         *string    `json:"status,omitempty"`
	IPAddress      *string    `json:"ip_address,omitempty"`
	From           *time.Time `json:"from,omitempty"`
	To             *time.Time `json:"to,omitempty"`
	Limit          int        `json:"limit,omitempty"`
}

// ComplianceReport represents a compliance report for audit logs
type ComplianceReport struct {
	OrganizationID    xid.ID              `json:"organization_id"`
	ReportPeriod      string              `json:"report_period"`
	From              time.Time           `json:"from"`
	To                time.Time           `json:"to"`
	TotalEvents       int                 `json:"total_events"`
	SuccessfulEvents  int                 `json:"successful_events"`
	FailedEvents      int                 `json:"failed_events"`
	UniqueUsers       int                 `json:"unique_users"`
	ActionBreakdown   map[string]int      `json:"action_breakdown"`
	StatusBreakdown   map[string]int      `json:"status_breakdown"`
	ResourceBreakdown map[string]int      `json:"resource_breakdown"`
	TopIPAddresses    []IPAddressActivity `json:"top_ip_addresses"`
	SecurityEvents    int                 `json:"security_events"`
	ComplianceNotes   []string            `json:"compliance_notes"`
}

// UserActivityStats represents user activity statistics
type UserActivityStats struct {
	TotalUsers     int            `json:"total_users"`
	ActiveUsers    int            `json:"active_users"`
	UserActivities []UserActivity `json:"user_activities"`
	TopActions     []ActionCount  `json:"top_actions"`
}

// IPAddressActivity represents IP address activity
type IPAddressActivity struct {
	IPAddress string `json:"ip_address"`
	Location  string `json:"location"`
	Count     int    `json:"count"`
}

// UserActivity represents individual user activity
type UserActivity struct {
	UserID      xid.ID    `json:"user_id"`
	UserEmail   string    `json:"user_email"`
	ActionCount int       `json:"action_count"`
	LastSeen    time.Time `json:"last_seen"`
}

// ActionCount represents action frequency
type ActionCount struct {
	Action string `json:"action"`
	Count  int    `json:"count"`
}

// Create creates a new audit log entry
func (r *auditRepository) Create(ctx context.Context, input CreateAuditInput) (*ent.Audit, error) {
	builder := r.client.Audit.Create().
		SetAction(input.Action).
		SetResourceType(input.ResourceType).
		SetStatus(input.Status).
		SetTimestamp(input.Timestamp)

	if input.UserID != nil {
		builder.SetUserID(*input.UserID)
	}

	if input.OrganizationID != nil {
		builder.SetOrganizationID(*input.OrganizationID)
	}

	if input.SessionID != nil {
		builder.SetSessionID(*input.SessionID)
	}

	if input.ResourceID != nil {
		builder.SetResourceID(*input.ResourceID)
	}

	if input.IPAddress != nil {
		builder.SetIPAddress(*input.IPAddress)
	}

	if input.UserAgent != nil {
		builder.SetUserAgent(*input.UserAgent)
	}

	if input.Location != nil {
		builder.SetLocation(*input.Location)
	}

	if input.DeviceID != nil {
		builder.SetDeviceID(*input.DeviceID)
	}

	if input.RequestID != nil {
		builder.SetRequestID(*input.RequestID)
	}

	if input.ErrorCode != nil {
		builder.SetErrorCode(*input.ErrorCode)
	}

	if input.ErrorMessage != nil {
		builder.SetErrorMessage(*input.ErrorMessage)
	}

	if input.Description != nil {
		builder.SetDescription(*input.Description)
	}

	if input.Metadata != nil {
		builder.SetMetadata(input.Metadata)
	}

	if input.OldValues != nil {
		builder.SetOldValues(input.OldValues)
	}

	if input.NewValues != nil {
		builder.SetCurrentValues(input.NewValues)
	}

	auditLog, err := builder.Save(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to create audit log")
	}

	return auditLog, nil
}

// GetByID retrieves an audit log by its ID
func (r *auditRepository) GetByID(ctx context.Context, id xid.ID) (*ent.Audit, error) {
	auditLog, err := r.client.Audit.
		Query().
		Where(audit.ID(id)).
		WithUser().
		WithOrganization().
		WithSession().
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Audit log not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get audit log")
	}

	return auditLog, nil
}

// Delete deletes an audit log (rarely used, for compliance reasons)
func (r *auditRepository) Delete(ctx context.Context, id xid.ID) error {
	err := r.client.Audit.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Audit log not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to delete audit log")
	}

	return nil
}

// ListByUserID retrieves paginated audit logs for a user
func (r *auditRepository) ListByUserID(ctx context.Context, userID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error) {
	query := r.client.Audit.
		Query().
		Where(audit.UserID(userID)).
		WithUser().
		WithOrganization().
		WithSession()

	// Apply ordering
	query.Order(ent.Desc(audit.FieldTimestamp))

	result, err := model.WithPaginationAndOptions[*ent.Audit, *ent.AuditQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list audit logs by user ID")
	}

	return result, nil
}

// ListByOrganizationID retrieves paginated audit logs for an organization
func (r *auditRepository) ListByOrganizationID(ctx context.Context, orgID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error) {
	query := r.client.Audit.
		Query().
		Where(audit.OrganizationID(orgID)).
		WithUser().
		WithOrganization().
		WithSession()

	// Apply ordering
	query.Order(ent.Desc(audit.FieldTimestamp))

	result, err := model.WithPaginationAndOptions[*ent.Audit, *ent.AuditQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list audit logs by organization ID")
	}

	return result, nil
}

// ListByAction retrieves paginated audit logs by action type
func (r *auditRepository) ListByAction(ctx context.Context, action string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error) {
	query := r.client.Audit.
		Query().
		Where(audit.Action(action)).
		WithUser().
		WithOrganization().
		WithSession()

	// Apply ordering
	query.Order(ent.Desc(audit.FieldTimestamp))

	result, err := model.WithPaginationAndOptions[*ent.Audit, *ent.AuditQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, fmt.Sprintf("Failed to list audit logs by action %s", action))
	}

	return result, nil
}

// ListByResourceType retrieves paginated audit logs by resource type
func (r *auditRepository) ListByResourceType(ctx context.Context, resourceType string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error) {
	query := r.client.Audit.
		Query().
		Where(audit.ResourceType(resourceType)).
		WithUser().
		WithOrganization().
		WithSession()

	// Apply ordering
	query.Order(ent.Desc(audit.FieldTimestamp))

	result, err := model.WithPaginationAndOptions[*ent.Audit, *ent.AuditQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, fmt.Sprintf("Failed to list audit logs by resource type %s", resourceType))
	}

	return result, nil
}

// ListByResourceID retrieves paginated audit logs for a specific resource
func (r *auditRepository) ListByResourceID(ctx context.Context, resourceType string, resourceID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error) {
	query := r.client.Audit.
		Query().
		Where(
			audit.ResourceType(resourceType),
			audit.ResourceID(resourceID),
		).
		WithUser().
		WithOrganization().
		WithSession()

	// Apply ordering
	query.Order(ent.Desc(audit.FieldTimestamp))

	result, err := model.WithPaginationAndOptions[*ent.Audit, *ent.AuditQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, fmt.Sprintf("Failed to list audit logs by resource %s:%s", resourceType, resourceID))
	}

	return result, nil
}

// ListByIPAddress retrieves paginated audit logs by IP address
func (r *auditRepository) ListByIPAddress(ctx context.Context, ipAddress string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error) {
	query := r.client.Audit.
		Query().
		Where(audit.IPAddress(ipAddress)).
		WithUser().
		WithOrganization().
		WithSession()

	// Apply ordering
	query.Order(ent.Desc(audit.FieldTimestamp))

	result, err := model.WithPaginationAndOptions[*ent.Audit, *ent.AuditQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, fmt.Sprintf("Failed to list audit logs by IP address %s", ipAddress))
	}

	return result, nil
}

// ListByUserAndOrganization retrieves paginated audit logs by user and organization
func (r *auditRepository) ListByUserAndOrganization(ctx context.Context, userID, orgID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error) {
	query := r.client.Audit.
		Query().
		Where(
			audit.UserID(userID),
			audit.OrganizationID(orgID),
		).
		WithUser().
		WithOrganization().
		WithSession()

	// Apply ordering
	query.Order(ent.Desc(audit.FieldTimestamp))

	result, err := model.WithPaginationAndOptions[*ent.Audit, *ent.AuditQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list audit logs by user and organization")
	}

	return result, nil
}

// ListByTimeRange retrieves paginated audit logs within a time range
func (r *auditRepository) ListByTimeRange(ctx context.Context, from, to time.Time, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error) {
	query := r.client.Audit.
		Query().
		Where(
			audit.TimestampGTE(from),
			audit.TimestampLTE(to),
		).
		WithUser().
		WithOrganization().
		WithSession()

	// Apply ordering
	query.Order(ent.Desc(audit.FieldTimestamp))

	result, err := model.WithPaginationAndOptions[*ent.Audit, *ent.AuditQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list audit logs by time range")
	}

	return result, nil
}

// ListByStatus retrieves paginated audit logs by status
func (r *auditRepository) ListByStatus(ctx context.Context, status string, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error) {
	query := r.client.Audit.
		Query().
		Where(audit.Status(status)).
		WithUser().
		WithOrganization().
		WithSession()

	// Apply ordering
	query.Order(ent.Desc(audit.FieldTimestamp))

	result, err := model.WithPaginationAndOptions[*ent.Audit, *ent.AuditQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, fmt.Sprintf("Failed to list audit logs by status %s", status))
	}

	return result, nil
}

// ListFailedActions retrieves paginated failed audit logs
func (r *auditRepository) ListFailedActions(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error) {
	query := r.client.Audit.
		Query().
		Where(audit.Status("failure")).
		WithUser().
		WithOrganization().
		WithSession()

	// Apply ordering
	query.Order(ent.Desc(audit.FieldTimestamp))

	result, err := model.WithPaginationAndOptions[*ent.Audit, *ent.AuditQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list failed audit logs")
	}

	return result, nil
}

// ListSuspiciousActivity retrieves potentially suspicious audit logs
func (r *auditRepository) ListSuspiciousActivity(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error) {
	// Define suspicious actions
	suspiciousActions := []string{
		"failed_login",
		"multiple_failed_login",
		"admin_access_attempt",
		"permission_escalation",
		"unusual_access_pattern",
	}

	query := r.client.Audit.
		Query().
		Where(
			audit.Or(
				audit.ActionIn(suspiciousActions...),
				audit.Status("failure"),
			),
		).
		WithUser().
		WithOrganization().
		WithSession()

	// Apply ordering
	query.Order(ent.Desc(audit.FieldTimestamp))

	result, err := model.WithPaginationAndOptions[*ent.Audit, *ent.AuditQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list suspicious audit logs")
	}

	return result, nil
}

// ListBySessionID retrieves paginated audit logs for a session
func (r *auditRepository) ListBySessionID(ctx context.Context, sessionID xid.ID, opts model.PaginationParams) (*model.PaginatedOutput[*ent.Audit], error) {
	query := r.client.Audit.
		Query().
		Where(audit.SessionID(sessionID)).
		WithUser().
		WithOrganization().
		WithSession()

	// Apply ordering
	query.Order(ent.Desc(audit.FieldTimestamp))

	result, err := model.WithPaginationAndOptions[*ent.Audit, *ent.AuditQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list audit logs by session ID")
	}

	return result, nil
}

// CountByUserAndAction counts audit logs by user and action within a time frame
func (r *auditRepository) CountByUserAndAction(ctx context.Context, userID xid.ID, action string, since time.Time) (int, error) {
	count, err := r.client.Audit.
		Query().
		Where(
			audit.UserID(userID),
			audit.Action(action),
			audit.TimestampGTE(since),
		).
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count audit logs by user and action")
	}

	return count, nil
}

// CountByIPAndAction counts audit logs by IP address and action within a time frame
func (r *auditRepository) CountByIPAndAction(ctx context.Context, ipAddress, action string, since time.Time) (int, error) {
	count, err := r.client.Audit.
		Query().
		Where(
			audit.IPAddress(ipAddress),
			audit.Action(action),
			audit.TimestampGTE(since),
		).
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count audit logs by IP and action")
	}

	return count, nil
}

// GetComplianceReport generates a compliance report for an organization
func (r *auditRepository) GetComplianceReport(ctx context.Context, orgID xid.ID, from, to time.Time) (*ComplianceReport, error) {
	report := &ComplianceReport{
		OrganizationID: orgID,
		From:           from,
		To:             to,
		ReportPeriod:   fmt.Sprintf("%s to %s", from.Format("2006-01-02"), to.Format("2006-01-02")),
	}

	// Count total events
	totalEvents, err := r.client.Audit.
		Query().
		Where(
			audit.OrganizationID(orgID),
			audit.TimestampGTE(from),
			audit.TimestampLTE(to),
		).
		Count(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count total events for compliance report")
	}

	report.TotalEvents = totalEvents

	// Count successful events
	successfulEvents, err := r.client.Audit.
		Query().
		Where(
			audit.OrganizationID(orgID),
			audit.TimestampGTE(from),
			audit.TimestampLTE(to),
			audit.Status("success"),
		).
		Count(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count successful events for compliance report")
	}

	report.SuccessfulEvents = successfulEvents
	report.FailedEvents = totalEvents - successfulEvents

	// Get unique users count
	var uniqueUsers []xid.ID
	err = r.client.Audit.
		Query().
		Where(
			audit.OrganizationID(orgID),
			audit.TimestampGTE(from),
			audit.TimestampLTE(to),
			audit.UserIDNotNil(),
		).
		Select(audit.FieldUserID).
		GroupBy(audit.FieldUserID).
		Scan(ctx, &uniqueUsers)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count unique users for compliance report")
	}

	report.UniqueUsers = len(uniqueUsers)

	// TODO: Implement additional report sections
	// - ActionBreakdown
	// - StatusBreakdown
	// - ResourceBreakdown
	// - TopIPAddresses
	// - SecurityEvents
	// - ComplianceNotes

	return report, nil
}

// ExportAuditLogs exports audit logs based on filters
func (r *auditRepository) ExportAuditLogs(ctx context.Context, filters AuditExportFilters) ([]*ent.Audit, error) {
	query := r.client.Audit.Query().
		WithUser().
		WithOrganization().
		WithSession()

	// Apply filters
	if filters.UserID != nil {
		query = query.Where(audit.UserID(*filters.UserID))
	}

	if filters.OrganizationID != nil {
		query = query.Where(audit.OrganizationID(*filters.OrganizationID))
	}

	if filters.Action != nil {
		query = query.Where(audit.Action(*filters.Action))
	}

	if filters.ResourceType != nil {
		query = query.Where(audit.ResourceType(*filters.ResourceType))
	}

	if filters.Status != nil {
		query = query.Where(audit.Status(*filters.Status))
	}

	if filters.IPAddress != nil {
		query = query.Where(audit.IPAddress(*filters.IPAddress))
	}

	if filters.From != nil {
		query = query.Where(audit.TimestampGTE(*filters.From))
	}

	if filters.To != nil {
		query = query.Where(audit.TimestampLTE(*filters.To))
	}

	// Apply ordering
	query = query.Order(ent.Desc(audit.FieldTimestamp))

	// Apply limit if specified
	if filters.Limit > 0 {
		query = query.Limit(filters.Limit)
	}

	auditLogs, err := query.All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to export audit logs")
	}

	return auditLogs, nil
}

// DeleteOldLogs deletes audit logs older than the specified time
func (r *auditRepository) DeleteOldLogs(ctx context.Context, before time.Time) (int, error) {
	count, err := r.client.Audit.
		Delete().
		Where(audit.TimestampLT(before)).
		Exec(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to delete old audit logs")
	}

	return count, nil
}

// CountByOrganizationID counts audit logs for an organization
func (r *auditRepository) CountByOrganizationID(ctx context.Context, orgID xid.ID) (int, error) {
	count, err := r.client.Audit.
		Query().
		Where(audit.OrganizationID(orgID)).
		Count(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count audit logs by organization ID")
	}

	return count, nil
}

// GetMostRecentByUser retrieves the most recent audit logs for a user
func (r *auditRepository) GetMostRecentByUser(ctx context.Context, userID xid.ID, limit int) ([]*ent.Audit, error) {
	auditLogs, err := r.client.Audit.
		Query().
		Where(audit.UserID(userID)).
		WithUser().
		WithOrganization().
		WithSession().
		Order(ent.Desc(audit.FieldTimestamp)).
		Limit(limit).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get most recent audit logs by user")
	}

	return auditLogs, nil
}

// GetActionStats retrieves action statistics for an organization
func (r *auditRepository) GetActionStats(ctx context.Context, orgID xid.ID, since time.Time) (map[string]int, error) {
	var results []struct {
		Action string `json:"action"`
		Count  int    `json:"count"`
	}

	err := r.client.Audit.
		Query().
		Where(
			audit.OrganizationID(orgID),
			audit.TimestampGTE(since),
		).
		GroupBy(audit.FieldAction).
		Aggregate(ent.Count()).
		Scan(ctx, &results)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get action statistics")
	}

	stats := make(map[string]int)
	for _, result := range results {
		stats[result.Action] = result.Count
	}

	return stats, nil
}

// GetUserActivityStats retrieves user activity statistics for an organization
func (r *auditRepository) GetUserActivityStats(ctx context.Context, orgID xid.ID, since time.Time) (*UserActivityStats, error) {
	stats := &UserActivityStats{}

	// Get total unique users
	var uniqueUsers []xid.ID
	err := r.client.Audit.
		Query().
		Where(
			audit.OrganizationID(orgID),
			audit.TimestampGTE(since),
			audit.UserIDNotNil(),
		).
		Select(audit.FieldUserID).
		GroupBy(audit.FieldUserID).
		Scan(ctx, &uniqueUsers)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get user activity statistics")
	}

	stats.TotalUsers = len(uniqueUsers)
	stats.ActiveUsers = len(uniqueUsers) // All users in the time range are considered active

	// TODO: Implement additional statistics
	// - UserActivities
	// - TopActions

	return stats, nil
}
