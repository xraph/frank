package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/session"
	"github.com/juicycleff/frank/internal/model"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
)

// SessionRepository defines the interface for session data access
type SessionRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input CreateSessionInput) (*ent.Session, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.Session, error)
	GetByToken(ctx context.Context, token string) (*ent.Session, error)
	Update(ctx context.Context, id xid.ID, input UpdateSessionInput) (*ent.Session, error)
	Delete(ctx context.Context, id xid.ID) error
	DeleteByToken(ctx context.Context, token string) error

	// List and search operations
	List(ctx context.Context, params ListSessionsParams) (*model.PaginatedOutput[*ent.Session], error)
	ListByUser(ctx context.Context, userID xid.ID, params ListSessionsParams) (*model.PaginatedOutput[*ent.Session], error)
	ListByOrganization(ctx context.Context, organizationID xid.ID, params ListSessionsParams) (*model.PaginatedOutput[*ent.Session], error)

	// Session management
	GetActiveSessions(ctx context.Context, userID xid.ID) ([]*ent.Session, error)
	GetActiveSessionsCount(ctx context.Context, userID xid.ID) (int, error)
	RefreshSession(ctx context.Context, token string, newExpiresAt time.Time) (*ent.Session, error)
	ExtendSession(ctx context.Context, token string, duration time.Duration) (*ent.Session, error)
	UpdateLastActive(ctx context.Context, token string) error

	// Session validation
	IsValidSession(ctx context.Context, token string) (bool, error)
	IsActiveSession(ctx context.Context, token string) (bool, error)
	ValidateAndRefresh(ctx context.Context, token string) (*ent.Session, error)

	// Bulk operations
	InvalidateAllUserSessions(ctx context.Context, userID xid.ID) error
	InvalidateAllOrganizationSessions(ctx context.Context, organizationID xid.ID) error
	InvalidateExpiredSessions(ctx context.Context) (int, error)
	CleanupOldSessions(ctx context.Context, olderThan time.Time) (int, error)

	// Session analysis
	GetSessionStats(ctx context.Context, userID *xid.ID, organizationID *xid.ID) (*SessionStats, error)
	GetActiveSessionsByDevice(ctx context.Context, userID xid.ID) (map[string][]*ent.Session, error)
	// GetSessionsByLocation(ctx context.Context, userID xid.ID) (map[string][]*ent.Session, error)
	GetSuspiciousSessions(ctx context.Context, userID xid.ID) ([]*ent.Session, error)

	// Device management
	GetSessionsByDevice(ctx context.Context, userID xid.ID, deviceID string) ([]*ent.Session, error)
	InvalidateDeviceSessions(ctx context.Context, userID xid.ID, deviceID string) error
	GetUniqueDevices(ctx context.Context, userID xid.ID) ([]string, error)

	// IP and location tracking
	GetSessionsByIP(ctx context.Context, userID xid.ID, ipAddress string) ([]*ent.Session, error)
	GetRecentIPs(ctx context.Context, userID xid.ID, since time.Time) ([]string, error)
	GetSessionsByLocation(ctx context.Context, userID xid.ID, location string) ([]*ent.Session, error)
}

// CreateSessionInput represents input for creating a session
type CreateSessionInput struct {
	UserID         xid.ID                 `json:"user_id"`
	Token          string                 `json:"token"`
	IPAddress      *string                `json:"ip_address,omitempty"`
	UserAgent      *string                `json:"user_agent,omitempty"`
	DeviceID       *string                `json:"device_id,omitempty"`
	Location       *string                `json:"location,omitempty"`
	OrganizationID *xid.ID                `json:"organization_id,omitempty"`
	ExpiresAt      time.Time              `json:"expires_at"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	Active         bool                   `json:"active"`
	LastActiveAt   time.Time              `json:"last_active_at"`
}

// UpdateSessionInput represents input for updating a session
type UpdateSessionInput struct {
	IPAddress      *string                `json:"ip_address,omitempty"`
	UserAgent      *string                `json:"user_agent,omitempty"`
	DeviceID       *string                `json:"device_id,omitempty"`
	Location       *string                `json:"location,omitempty"`
	OrganizationID *xid.ID                `json:"organization_id,omitempty"`
	Active         *bool                  `json:"active,omitempty"`
	ExpiresAt      *time.Time             `json:"expires_at,omitempty"`
	LastActiveAt   *time.Time             `json:"last_active_at,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// ListSessionsParams represents parameters for listing sessions
type ListSessionsParams struct {
	model.PaginationParams
	UserID         *xid.ID    `json:"user_id" query:"user_id"`
	Active         *bool      `json:"active,omitempty"`
	OrganizationID *xid.ID    `json:"organization_id,omitempty"`
	DeviceID       *string    `json:"device_id,omitempty"`
	IPAddress      *string    `json:"ip_address,omitempty"`
	Location       *string    `json:"location,omitempty"`
	ExpiresAfter   *time.Time `json:"expires_after,omitempty"`
	ExpiresBefore  *time.Time `json:"expires_before,omitempty"`
	CreatedAfter   *time.Time `json:"created_after,omitempty"`
	CreatedBefore  *time.Time `json:"created_before,omitempty"`
}

// SessionStats represents session statistics
type SessionStats struct {
	TotalSessions          int               `json:"total_sessions"`
	ActiveSessions         int               `json:"active_sessions"`
	ExpiredSessions        int               `json:"expired_sessions"`
	UniqueDevices          int               `json:"unique_devices"`
	UniqueIPs              int               `json:"unique_ips"`
	UniqueLocations        int               `json:"unique_locations"`
	AverageSessionDuration time.Duration     `json:"average_session_duration"`
	DeviceBreakdown        map[string]int    `json:"device_breakdown"`
	LocationBreakdown      map[string]int    `json:"location_breakdown"`
	RecentActivity         []SessionActivity `json:"recent_activity"`
}

// SessionActivity represents recent session activity
type SessionActivity struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	IPAddress string    `json:"ip_address"`
	Location  string    `json:"location"`
	DeviceID  string    `json:"device_id"`
	UserAgent string    `json:"user_agent"`
}

// sessionRepository implements SessionRepository
type sessionRepository struct {
	client *ent.Client
	logger logging.Logger
}

// NewSessionRepository creates a new session repository
func NewSessionRepository(client *ent.Client, logger logging.Logger) SessionRepository {
	return &sessionRepository{
		client: client,
		logger: logger,
	}
}

// Create creates a new session
func (r *sessionRepository) Create(ctx context.Context, input CreateSessionInput) (*ent.Session, error) {
	create := r.client.Session.Create().
		SetUserID(input.UserID).
		SetToken(input.Token).
		SetExpiresAt(input.ExpiresAt)

	// Set optional fields
	if input.IPAddress != nil {
		create.SetIPAddress(*input.IPAddress)
	}
	if input.UserAgent != nil {
		create.SetUserAgent(*input.UserAgent)
	}
	if input.DeviceID != nil {
		create.SetDeviceID(*input.DeviceID)
	}
	if input.Location != nil {
		create.SetLocation(*input.Location)
	}
	if input.OrganizationID != nil {
		create.SetOrganizationID(*input.OrganizationID)
	}
	if input.Metadata != nil {
		create.SetMetadata(input.Metadata)
	}

	session, err := create.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, "Session with this token already exists")
		}
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return session, nil
}

// GetByID retrieves a session by ID
func (r *sessionRepository) GetByID(ctx context.Context, id xid.ID) (*ent.Session, error) {
	session, err := r.client.Session.Query().
		Where(session.ID(id)).
		WithUser().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Session not found")
		}
		return nil, fmt.Errorf("failed to get session by ID: %w", err)
	}
	return session, nil
}

// GetByToken retrieves a session by token
func (r *sessionRepository) GetByToken(ctx context.Context, token string) (*ent.Session, error) {
	session, err := r.client.Session.Query().
		Where(session.Token(token)).
		WithUser().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Session not found")
		}
		return nil, fmt.Errorf("failed to get session by token: %w", err)
	}
	return session, nil
}

// Update updates a session
func (r *sessionRepository) Update(ctx context.Context, id xid.ID, input UpdateSessionInput) (*ent.Session, error) {
	update := r.client.Session.UpdateOneID(id)

	if input.IPAddress != nil {
		update.SetIPAddress(*input.IPAddress)
	}
	if input.UserAgent != nil {
		update.SetUserAgent(*input.UserAgent)
	}
	if input.DeviceID != nil {
		update.SetDeviceID(*input.DeviceID)
	}
	if input.Location != nil {
		update.SetLocation(*input.Location)
	}
	if input.OrganizationID != nil {
		update.SetOrganizationID(*input.OrganizationID)
	}
	if input.Active != nil {
		update.SetActive(*input.Active)
	}
	if input.ExpiresAt != nil {
		update.SetExpiresAt(*input.ExpiresAt)
	}
	if input.LastActiveAt != nil {
		update.SetLastActiveAt(*input.LastActiveAt)
	}
	if input.Metadata != nil {
		update.SetMetadata(input.Metadata)
	}

	session, err := update.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Session not found")
		}
		return nil, fmt.Errorf("failed to update session: %w", err)
	}
	return session, nil
}

// Delete deletes a session
func (r *sessionRepository) Delete(ctx context.Context, id xid.ID) error {
	err := r.client.Session.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Session not found")
		}
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

// DeleteByToken deletes a session by token
func (r *sessionRepository) DeleteByToken(ctx context.Context, token string) error {
	_, err := r.client.Session.Delete().
		Where(session.Token(token)).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete session by token: %w", err)
	}
	return nil
}

// List retrieves sessions with pagination and filtering
func (r *sessionRepository) List(ctx context.Context, params ListSessionsParams) (*model.PaginatedOutput[*ent.Session], error) {
	query := r.client.Session.Query().
		WithUser()

	// Apply filters
	if params.Active != nil {
		query = query.Where(session.Active(*params.Active))
	}
	if params.OrganizationID != nil {
		query = query.Where(session.OrganizationID(*params.OrganizationID))
	}
	if params.DeviceID != nil {
		query = query.Where(session.DeviceID(*params.DeviceID))
	}
	if params.IPAddress != nil {
		query = query.Where(session.IPAddress(*params.IPAddress))
	}
	if params.Location != nil {
		query = query.Where(session.Location(*params.Location))
	}
	if params.ExpiresAfter != nil {
		query = query.Where(session.ExpiresAtGTE(*params.ExpiresAfter))
	}
	if params.ExpiresBefore != nil {
		query = query.Where(session.ExpiresAtLTE(*params.ExpiresBefore))
	}
	if params.CreatedAfter != nil {
		query = query.Where(session.CreatedAtGTE(*params.CreatedAfter))
	}
	if params.CreatedBefore != nil {
		query = query.Where(session.CreatedAtLTE(*params.CreatedBefore))
	}

	// Apply pagination
	return model.WithPaginationAndOptions[*ent.Session, *ent.SessionQuery](ctx, query, params.PaginationParams)
}

// ListByUser retrieves sessions for a specific user
func (r *sessionRepository) ListByUser(ctx context.Context, userID xid.ID, params ListSessionsParams) (*model.PaginatedOutput[*ent.Session], error) {
	query := r.client.Session.Query().
		Where(session.UserID(userID)).
		WithUser()

	// Apply same filters as List
	if params.Active != nil {
		query = query.Where(session.Active(*params.Active))
	}
	if params.OrganizationID != nil {
		query = query.Where(session.OrganizationID(*params.OrganizationID))
	}
	if params.DeviceID != nil {
		query = query.Where(session.DeviceID(*params.DeviceID))
	}
	if params.IPAddress != nil {
		query = query.Where(session.IPAddress(*params.IPAddress))
	}
	if params.Location != nil {
		query = query.Where(session.Location(*params.Location))
	}

	return model.WithPaginationAndOptions[*ent.Session, *ent.SessionQuery](ctx, query, params.PaginationParams)
}

// ListByOrganization retrieves sessions for a specific organization
func (r *sessionRepository) ListByOrganization(ctx context.Context, organizationID xid.ID, params ListSessionsParams) (*model.PaginatedOutput[*ent.Session], error) {
	query := r.client.Session.Query().
		Where(session.OrganizationID(organizationID)).
		WithUser()

	// Apply same filters as List (excluding organization filter)
	if params.Active != nil {
		query = query.Where(session.Active(*params.Active))
	}
	if params.DeviceID != nil {
		query = query.Where(session.DeviceID(*params.DeviceID))
	}
	if params.IPAddress != nil {
		query = query.Where(session.IPAddress(*params.IPAddress))
	}
	if params.Location != nil {
		query = query.Where(session.Location(*params.Location))
	}

	return model.WithPaginationAndOptions[*ent.Session, *ent.SessionQuery](ctx, query, params.PaginationParams)
}

// Session management methods

func (r *sessionRepository) GetActiveSessions(ctx context.Context, userID xid.ID) ([]*ent.Session, error) {
	sessions, err := r.client.Session.Query().
		Where(
			session.UserID(userID),
			session.Active(true),
			session.ExpiresAtGT(time.Now()),
		).
		WithUser().
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get active sessions: %w", err)
	}
	return sessions, nil
}

func (r *sessionRepository) GetActiveSessionsCount(ctx context.Context, userID xid.ID) (int, error) {
	count, err := r.client.Session.Query().
		Where(
			session.UserID(userID),
			session.Active(true),
			session.ExpiresAtGT(time.Now()),
		).
		Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get active sessions count: %w", err)
	}
	return count, nil
}

func (r *sessionRepository) RefreshSession(ctx context.Context, token string, newExpiresAt time.Time) (*ent.Session, error) {
	_, err := r.client.Session.Update().
		Where(session.Token(token)).
		SetExpiresAt(newExpiresAt).
		SetLastActiveAt(time.Now()).
		Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Session not found")
		}
		return nil, fmt.Errorf("failed to refresh session: %w", err)
	}
	return r.client.Session.Query().Where(session.Token(token)).First(ctx)
}

func (r *sessionRepository) ExtendSession(ctx context.Context, token string, duration time.Duration) (*ent.Session, error) {
	session, err := r.GetByToken(ctx, token)
	if err != nil {
		return nil, err
	}

	newExpiresAt := session.ExpiresAt.Add(duration)
	return r.RefreshSession(ctx, token, newExpiresAt)
}

func (r *sessionRepository) UpdateLastActive(ctx context.Context, token string) error {
	err := r.client.Session.Update().
		Where(session.Token(token)).
		SetLastActiveAt(time.Now()).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to update last active: %w", err)
	}
	return nil
}

// Session validation methods

func (r *sessionRepository) IsValidSession(ctx context.Context, token string) (bool, error) {
	exists, err := r.client.Session.Query().
		Where(
			session.Token(token),
			session.Active(true),
			session.ExpiresAtGT(time.Now()),
		).
		Exist(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to check session validity: %w", err)
	}
	return exists, nil
}

func (r *sessionRepository) IsActiveSession(ctx context.Context, token string) (bool, error) {
	exists, err := r.client.Session.Query().
		Where(
			session.Token(token),
			session.Active(true),
		).
		Exist(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to check session activity: %w", err)
	}
	return exists, nil
}

func (r *sessionRepository) ValidateAndRefresh(ctx context.Context, token string) (*ent.Session, error) {
	session, err := r.GetByToken(ctx, token)
	if err != nil {
		return nil, err
	}

	// Check if session is active
	if !session.Active {
		return nil, errors.New(errors.CodeUnauthorized, "Session is inactive")
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		return nil, errors.New(errors.CodeUnauthorized, "Session has expired")
	}

	// Update last active time
	err = r.UpdateLastActive(ctx, token)
	if err != nil {
		r.logger.Warnf("Failed to update last active time for session %s: %v", token, err)
	}

	return session, nil
}

// Bulk operations

func (r *sessionRepository) InvalidateAllUserSessions(ctx context.Context, userID xid.ID) error {
	err := r.client.Session.Update().
		Where(session.UserID(userID)).
		SetActive(false).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to invalidate user sessions: %w", err)
	}
	return nil
}

func (r *sessionRepository) InvalidateAllOrganizationSessions(ctx context.Context, organizationID xid.ID) error {
	err := r.client.Session.Update().
		Where(session.OrganizationID(organizationID)).
		SetActive(false).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to invalidate organization sessions: %w", err)
	}
	return nil
}

func (r *sessionRepository) InvalidateExpiredSessions(ctx context.Context) (int, error) {
	updated, err := r.client.Session.Update().
		Where(
			session.ExpiresAtLT(time.Now()),
			session.Active(true),
		).
		SetActive(false).
		Save(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to invalidate expired sessions: %w", err)
	}
	return updated, nil
}

func (r *sessionRepository) CleanupOldSessions(ctx context.Context, olderThan time.Time) (int, error) {
	deleted, err := r.client.Session.Delete().
		Where(
			session.CreatedAtLT(olderThan),
			session.Active(false),
		).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup old sessions: %w", err)
	}
	return deleted, nil
}

// Session analysis methods

func (r *sessionRepository) GetSessionStats(ctx context.Context, userID *xid.ID, organizationID *xid.ID) (*SessionStats, error) {
	query := r.client.Session.Query()

	if userID != nil {
		query = query.Where(session.UserID(*userID))
	}
	if organizationID != nil {
		query = query.Where(session.OrganizationID(*organizationID))
	}

	// Get total sessions
	total, err := query.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get total sessions: %w", err)
	}

	// Get active sessions
	activeQuery := query.Clone().Where(
		session.Active(true),
		session.ExpiresAtGT(time.Now()),
	)
	active, err := activeQuery.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get active sessions: %w", err)
	}

	// Get expired sessions
	expired := total - active

	// Get unique devices
	deviceIDs, err := query.Clone().
		Where(session.DeviceIDNotNil()).
		GroupBy(session.FieldDeviceID).
		Strings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get unique devices: %w", err)
	}

	// Get unique IPs
	ipAddresses, err := query.Clone().
		Where(session.IPAddressNotNil()).
		GroupBy(session.FieldIPAddress).
		Strings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get unique IPs: %w", err)
	}

	// Get unique locations
	locations, err := query.Clone().
		Where(session.LocationNotNil()).
		GroupBy(session.FieldLocation).
		Strings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get unique locations: %w", err)
	}

	return &SessionStats{
		TotalSessions:   total,
		ActiveSessions:  active,
		ExpiredSessions: expired,
		UniqueDevices:   len(deviceIDs),
		UniqueIPs:       len(ipAddresses),
		UniqueLocations: len(locations),
		// Note: More complex stats like average duration would require additional queries
	}, nil
}

func (r *sessionRepository) GetActiveSessionsByDevice(ctx context.Context, userID xid.ID) (map[string][]*ent.Session, error) {
	sessions, err := r.GetActiveSessions(ctx, userID)
	if err != nil {
		return nil, err
	}

	deviceSessions := make(map[string][]*ent.Session)
	for _, sess := range sessions {
		if sess.DeviceID != "" {
			deviceSessions[sess.DeviceID] = append(deviceSessions[sess.DeviceID], sess)
		}
	}

	return deviceSessions, nil
}

func (r *sessionRepository) GetSuspiciousSessions(ctx context.Context, userID xid.ID) ([]*ent.Session, error) {
	// Get sessions from the last 24 hours
	since := time.Now().AddDate(0, 0, -1)

	sessions, err := r.client.Session.Query().
		Where(
			session.UserID(userID),
			session.CreatedAtGTE(since),
		).
		WithUser().
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent sessions: %w", err)
	}

	// Simple heuristic: sessions from different locations within a short time frame
	var suspicious []*ent.Session
	locationMap := make(map[string]time.Time)

	for _, sess := range sessions {
		if sess.Location != "" {
			location := sess.Location
			if lastSeen, exists := locationMap[location]; exists {
				// If same location within 1 hour, might be suspicious
				if sess.CreatedAt.Sub(lastSeen) < time.Hour {
					suspicious = append(suspicious, sess)
				}
			}
			locationMap[location] = sess.CreatedAt
		}
	}

	return suspicious, nil
}

// Device management methods

func (r *sessionRepository) GetSessionsByDevice(ctx context.Context, userID xid.ID, deviceID string) ([]*ent.Session, error) {
	sessions, err := r.client.Session.Query().
		Where(
			session.UserID(userID),
			session.DeviceID(deviceID),
		).
		WithUser().
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get sessions by device: %w", err)
	}
	return sessions, nil
}

func (r *sessionRepository) InvalidateDeviceSessions(ctx context.Context, userID xid.ID, deviceID string) error {
	err := r.client.Session.Update().
		Where(
			session.UserID(userID),
			session.DeviceID(deviceID),
		).
		SetActive(false).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to invalidate device sessions: %w", err)
	}
	return nil
}

func (r *sessionRepository) GetUniqueDevices(ctx context.Context, userID xid.ID) ([]string, error) {
	devices, err := r.client.Session.Query().
		Where(
			session.UserID(userID),
			session.DeviceIDNotNil(),
		).
		GroupBy(session.FieldDeviceID).
		Strings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get unique devices: %w", err)
	}
	return devices, nil
}

// IP and location tracking methods

func (r *sessionRepository) GetSessionsByIP(ctx context.Context, userID xid.ID, ipAddress string) ([]*ent.Session, error) {
	sessions, err := r.client.Session.Query().
		Where(
			session.UserID(userID),
			session.IPAddress(ipAddress),
		).
		WithUser().
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get sessions by IP: %w", err)
	}
	return sessions, nil
}

func (r *sessionRepository) GetRecentIPs(ctx context.Context, userID xid.ID, since time.Time) ([]string, error) {
	ips, err := r.client.Session.Query().
		Where(
			session.UserID(userID),
			session.CreatedAtGTE(since),
			session.IPAddressNotNil(),
		).
		GroupBy(session.FieldIPAddress).
		Strings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent IPs: %w", err)
	}
	return ips, nil
}

func (r *sessionRepository) GetSessionsByLocation(ctx context.Context, userID xid.ID, location string) ([]*ent.Session, error) {
	sessions, err := r.client.Session.Query().
		Where(
			session.UserID(userID),
			session.Location(location),
		).
		WithUser().
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get sessions by location: %w", err)
	}
	return sessions, nil
}
