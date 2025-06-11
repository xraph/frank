package repository

import (
	"context"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/passkey"
	"github.com/juicycleff/frank/internal/model"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
)

// PasskeyRepository defines the interface for passkey data access
type PasskeyRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input CreatePasskeyInput) (*ent.Passkey, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.Passkey, error)
	GetByCredentialID(ctx context.Context, credentialID string) (*ent.Passkey, error)
	Update(ctx context.Context, id xid.ID, input UpdatePasskeyInput) (*ent.Passkey, error)
	Delete(ctx context.Context, id xid.ID) error

	// List and search operations
	List(ctx context.Context, params ListPasskeysParams) (*model.PaginatedOutput[*ent.Passkey], error)
	ListByUser(ctx context.Context, userID xid.ID, params ListPasskeysParams) (*model.PaginatedOutput[*ent.Passkey], error)
	Search(ctx context.Context, query string, params SearchPasskeysParams) (*model.PaginatedOutput[*ent.Passkey], error)

	// Passkey management
	GetUserPasskeys(ctx context.Context, userID xid.ID, activeOnly bool) ([]*ent.Passkey, error)
	GetActivePasskeys(ctx context.Context, userID xid.ID) ([]*ent.Passkey, error)
	GetPasskeysByDevice(ctx context.Context, userID xid.ID, deviceType string) ([]*ent.Passkey, error)
	GetPasskeysByAAGUID(ctx context.Context, aaguid string) ([]*ent.Passkey, error)

	// Authentication operations
	UpdateSignCount(ctx context.Context, credentialID string, signCount int) error
	UpdateLastUsed(ctx context.Context, credentialID string) error
	IncrementUsage(ctx context.Context, credentialID string, signCount int) error
	ValidateCredentialID(ctx context.Context, credentialID string) (*ent.Passkey, error)

	// Passkey status management
	Activate(ctx context.Context, id xid.ID) error
	Deactivate(ctx context.Context, id xid.ID) error
	DeactivateAllUserPasskeys(ctx context.Context, userID xid.ID) error
	DeactivateByDevice(ctx context.Context, userID xid.ID, deviceType string) error

	// Analytics and reporting
	GetPasskeyStats(ctx context.Context, userID *xid.ID) (*PasskeyStats, error)
	GetDeviceUsageStats(ctx context.Context, userID *xid.ID) (map[string]*DeviceUsageStats, error)
	GetAAGUIDStats(ctx context.Context) (map[string]*AAGUIDStats, error)
	GetUsageAnalytics(ctx context.Context, userID *xid.ID, days int) (*PasskeyUsageAnalytics, error)

	// Device and authenticator management
	GetUserDevices(ctx context.Context, userID xid.ID) ([]string, error)
	GetUniqueAAGUIDs(ctx context.Context, userID *xid.ID) ([]string, error)
	GetAuthenticatorModels(ctx context.Context, userID *xid.ID) (map[string]int, error)
	GetRecentlyUsedPasskeys(ctx context.Context, userID xid.ID, limit int) ([]*ent.Passkey, error)

	// Security and monitoring
	GetSuspiciousActivity(ctx context.Context, userID xid.ID, days int) ([]*PasskeySecurityEvent, error)
	GetUnusedPasskeys(ctx context.Context, userID xid.ID, days int) ([]*ent.Passkey, error)
	GetHighUsagePasskeys(ctx context.Context, userID xid.ID, threshold int) ([]*ent.Passkey, error)

	// Bulk operations
	BulkDeactivate(ctx context.Context, ids []xid.ID) error
	BulkDelete(ctx context.Context, ids []xid.ID) error
	CleanupUnusedPasskeys(ctx context.Context, days int) (int, error)

	// Existence checks
	ExistsByCredentialID(ctx context.Context, credentialID string) (bool, error)
	UserHasPasskeys(ctx context.Context, userID xid.ID) (bool, error)
	UserHasActivePasskeys(ctx context.Context, userID xid.ID) (bool, error)
}

// CreatePasskeyInput represents input for creating a passkey
type CreatePasskeyInput struct {
	UserID         xid.ID                 `json:"user_id"`
	Name           string                 `json:"name"`
	CredentialID   string                 `json:"credential_id"`
	PublicKey      []byte                 `json:"public_key"`
	SignCount      int                    `json:"sign_count"`
	DeviceType     *string                `json:"device_type,omitempty"`
	AAGUID         *string                `json:"aaguid,omitempty"`
	Transports     []string               `json:"transports,omitempty"`
	Attestation    map[string]interface{} `json:"attestation,omitempty"`
	UserAgent      string                 `json:"user_agent,omitempty" example:"Mozilla/5.0..." doc:"User agent"`
	IPAddress      string                 `json:"ip_address,omitempty" example:"192.168.1.1" doc:"IP address"`
	BackupEligible bool                   `json:"backup_eligible" example:"true" doc:"Backup eligible"`
	BackupState    bool                   `json:"backup_state" example:"false" doc:"Backup state"`
	Active         bool                   `json:"active" example:"true" doc:"Active mode"`
}

// UpdatePasskeyInput represents input for updating a passkey
type UpdatePasskeyInput struct {
	Name        *string                `json:"name,omitempty"`
	SignCount   *int                   `json:"sign_count,omitempty"`
	Active      *bool                  `json:"active,omitempty"`
	DeviceType  *string                `json:"device_type,omitempty"`
	LastUsed    *time.Time             `json:"last_used,omitempty"`
	Transports  []string               `json:"transports,omitempty"`
	Attestation map[string]interface{} `json:"attestation,omitempty"`
	BackupState *bool                  `json:"backup_state,omitempty"`
}

// ListPasskeysParams represents parameters for listing passkeys
type ListPasskeysParams struct {
	model.PaginationParams
	UserID     *xid.ID    `json:"user_id"`
	Active     *bool      `json:"active,omitempty"`
	DeviceType string     `json:"device_type,omitempty"`
	AAGUID     *string    `json:"aaguid,omitempty"`
	UsedAfter  *time.Time `json:"used_after,omitempty"`
	UsedBefore *time.Time `json:"used_before,omitempty"`
	Search     string     `json:"search,omitempty"`
}

// SearchPasskeysParams represents parameters for searching passkeys
type SearchPasskeysParams struct {
	model.PaginationParams
	DeviceType *string `json:"device_type,omitempty"`
	ExactMatch bool    `json:"exact_match"`
}

// PasskeyStats represents passkey statistics
type PasskeyStats struct {
	TotalPasskeys      int            `json:"total_passkeys"`
	ActivePasskeys     int            `json:"active_passkeys"`
	InactivePasskeys   int            `json:"inactive_passkeys"`
	UniqueDeviceTypes  int            `json:"unique_device_types"`
	UniqueAAGUIDs      int            `json:"unique_aaguids"`
	DeviceBreakdown    map[string]int `json:"device_breakdown"`
	AAGUIDBreakdown    map[string]int `json:"aaguid_breakdown"`
	TransportBreakdown map[string]int `json:"transport_breakdown"`
	RecentlyUsed       int            `json:"recently_used"` // Last 30 days
	NeverUsed          int            `json:"never_used"`
	AverageSignCount   float64        `json:"average_sign_count"`
}

// DeviceUsageStats represents device usage statistics
type DeviceUsageStats struct {
	DeviceType       string     `json:"device_type"`
	PasskeyCount     int        `json:"passkey_count"`
	ActiveCount      int        `json:"active_count"`
	TotalUsage       int        `json:"total_usage"`
	LastUsed         *time.Time `json:"last_used"`
	AverageSignCount float64    `json:"average_sign_count"`
}

// AAGUIDStats represents AAGUID statistics
type AAGUIDStats struct {
	AAGUID             string     `json:"aaguid"`
	PasskeyCount       int        `json:"passkey_count"`
	UserCount          int        `json:"user_count"`
	TotalUsage         int        `json:"total_usage"`
	LastUsed           *time.Time `json:"last_used"`
	AuthenticatorModel string     `json:"authenticator_model,omitempty"`
}

// PasskeyUsageAnalytics represents usage analytics over time
type PasskeyUsageAnalytics struct {
	Period         int                 `json:"period_days"`
	TotalUsage     int                 `json:"total_usage"`
	UniqueUsers    int                 `json:"unique_users"`
	DailyUsage     []DailyPasskeyUsage `json:"daily_usage"`
	DeviceUsage    map[string]int      `json:"device_usage"`
	TransportUsage map[string]int      `json:"transport_usage"`
	PeakUsageDay   *time.Time          `json:"peak_usage_day"`
	PeakUsageCount int                 `json:"peak_usage_count"`
}

// DailyPasskeyUsage represents daily usage statistics
type DailyPasskeyUsage struct {
	Date        time.Time `json:"date"`
	UsageCount  int       `json:"usage_count"`
	UniqueUsers int       `json:"unique_users"`
}

// PasskeySecurityEvent represents a security-related event
type PasskeySecurityEvent struct {
	PasskeyID      xid.ID                 `json:"passkey_id"`
	CredentialID   string                 `json:"credential_id"`
	EventType      string                 `json:"event_type"`
	EventTime      time.Time              `json:"event_time"`
	Description    string                 `json:"description"`
	RiskLevel      string                 `json:"risk_level"`
	AdditionalData map[string]interface{} `json:"additional_data,omitempty"`
}

// passkeyRepository implements PasskeyRepository
type passkeyRepository struct {
	client *ent.Client
	logger logging.Logger
}

// NewPasskeyRepository creates a new passkey repository
func NewPasskeyRepository(client *ent.Client, logger logging.Logger) PasskeyRepository {
	return &passkeyRepository{
		client: client,
		logger: logger,
	}
}

// Create creates a new passkey
func (r *passkeyRepository) Create(ctx context.Context, input CreatePasskeyInput) (*ent.Passkey, error) {
	create := r.client.Passkey.Create().
		SetUserID(input.UserID).
		SetName(input.Name).
		SetCredentialID(input.CredentialID).
		SetPublicKey(input.PublicKey).
		SetSignCount(input.SignCount)

	// Set optional fields
	if input.DeviceType != nil {
		create.SetDeviceType(*input.DeviceType)
	}
	if input.AAGUID != nil {
		create.SetAaguid(*input.AAGUID)
	}
	if len(input.Transports) > 0 {
		create.SetTransports(input.Transports)
	}
	if input.Attestation != nil {
		create.SetAttestation(input.Attestation)
	}

	passkey, err := create.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, "Passkey with this credential ID already exists")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to create passkey")
	}

	return passkey, nil
}

// GetByID retrieves a passkey by ID
func (r *passkeyRepository) GetByID(ctx context.Context, id xid.ID) (*ent.Passkey, error) {
	passkey, err := r.client.Passkey.Query().
		Where(passkey.ID(id)).
		WithUser().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Passkey not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get passkey by ID")
	}
	return passkey, nil
}

// GetByCredentialID retrieves a passkey by credential ID
func (r *passkeyRepository) GetByCredentialID(ctx context.Context, credentialID string) (*ent.Passkey, error) {
	passkey, err := r.client.Passkey.Query().
		Where(passkey.CredentialID(credentialID)).
		WithUser().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Passkey not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get passkey by credential ID")
	}
	return passkey, nil
}

// Update updates a passkey
func (r *passkeyRepository) Update(ctx context.Context, id xid.ID, input UpdatePasskeyInput) (*ent.Passkey, error) {
	update := r.client.Passkey.UpdateOneID(id)

	if input.Name != nil {
		update.SetName(*input.Name)
	}
	if input.SignCount != nil {
		update.SetSignCount(*input.SignCount)
	}
	if input.Active != nil {
		update.SetActive(*input.Active)
	}
	if input.DeviceType != nil {
		update.SetDeviceType(*input.DeviceType)
	}
	if input.LastUsed != nil {
		update.SetLastUsed(*input.LastUsed)
	}
	if input.Transports != nil {
		update.SetTransports(input.Transports)
	}
	if input.Attestation != nil {
		update.SetAttestation(input.Attestation)
	}

	passkey, err := update.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Passkey not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to update passkey")
	}
	return passkey, nil
}

// Delete deletes a passkey
func (r *passkeyRepository) Delete(ctx context.Context, id xid.ID) error {
	err := r.client.Passkey.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Passkey not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete passkey")
	}
	return nil
}

// List retrieves passkeys with pagination and filtering
func (r *passkeyRepository) List(ctx context.Context, params ListPasskeysParams) (*model.PaginatedOutput[*ent.Passkey], error) {
	query := r.client.Passkey.Query().
		WithUser()

	// Apply filters
	if params.Active != nil {
		query = query.Where(passkey.Active(*params.Active))
	}
	if params.DeviceType != "" {
		query = query.Where(passkey.DeviceType(params.DeviceType))
	}
	if params.AAGUID != nil {
		query = query.Where(passkey.Aaguid(*params.AAGUID))
	}
	if params.UsedAfter != nil {
		query = query.Where(passkey.LastUsedGTE(*params.UsedAfter))
	}
	if params.UsedBefore != nil {
		query = query.Where(passkey.LastUsedLTE(*params.UsedBefore))
	}

	return model.WithPaginationAndOptions[*ent.Passkey, *ent.PasskeyQuery](ctx, query, params.PaginationParams)
}

// ListByUser retrieves passkeys for a specific user
func (r *passkeyRepository) ListByUser(ctx context.Context, userID xid.ID, params ListPasskeysParams) (*model.PaginatedOutput[*ent.Passkey], error) {
	query := r.client.Passkey.Query().
		Where(passkey.UserID(userID)).
		WithUser()

	// Apply same filters as List
	if params.Active != nil {
		query = query.Where(passkey.Active(*params.Active))
	}
	if params.DeviceType != "" {
		query = query.Where(passkey.DeviceType(params.DeviceType))
	}
	if params.AAGUID != nil {
		query = query.Where(passkey.Aaguid(*params.AAGUID))
	}

	return model.WithPaginationAndOptions[*ent.Passkey, *ent.PasskeyQuery](ctx, query, params.PaginationParams)
}

// Search searches for passkeys
func (r *passkeyRepository) Search(ctx context.Context, query string, params SearchPasskeysParams) (*model.PaginatedOutput[*ent.Passkey], error) {
	q := r.client.Passkey.Query().
		WithUser()

	// Apply filters
	if params.DeviceType != nil {
		q = q.Where(passkey.DeviceType(*params.DeviceType))
	}

	// Apply search conditions
	if params.ExactMatch {
		q = q.Where(passkey.Or(
			passkey.Name(query),
			passkey.DeviceType(query),
			passkey.Aaguid(query),
		))
	} else {
		q = q.Where(passkey.Or(
			passkey.NameContains(query),
			passkey.DeviceTypeContains(query),
			passkey.AaguidContains(query),
		))
	}

	return model.WithPaginationAndOptions[*ent.Passkey, *ent.PasskeyQuery](ctx, q, params.PaginationParams)
}

// Passkey management methods

func (r *passkeyRepository) GetUserPasskeys(ctx context.Context, userID xid.ID, activeOnly bool) ([]*ent.Passkey, error) {
	query := r.client.Passkey.Query().
		Where(passkey.UserID(userID)).
		WithUser()

	if activeOnly {
		query = query.Where(passkey.Active(true))
	}

	passkeys, err := query.All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get user passkeys")
	}
	return passkeys, nil
}

func (r *passkeyRepository) GetActivePasskeys(ctx context.Context, userID xid.ID) ([]*ent.Passkey, error) {
	return r.GetUserPasskeys(ctx, userID, true)
}

func (r *passkeyRepository) GetPasskeysByDevice(ctx context.Context, userID xid.ID, deviceType string) ([]*ent.Passkey, error) {
	passkeys, err := r.client.Passkey.Query().
		Where(
			passkey.UserID(userID),
			passkey.DeviceType(deviceType),
		).
		WithUser().
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get passkeys by device")
	}
	return passkeys, nil
}

func (r *passkeyRepository) GetPasskeysByAAGUID(ctx context.Context, aaguid string) ([]*ent.Passkey, error) {
	passkeys, err := r.client.Passkey.Query().
		Where(passkey.Aaguid(aaguid)).
		WithUser().
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get passkeys by AAGUID")
	}
	return passkeys, nil
}

// Authentication operations

func (r *passkeyRepository) UpdateSignCount(ctx context.Context, credentialID string, signCount int) error {
	err := r.client.Passkey.Update().
		Where(passkey.CredentialID(credentialID)).
		SetSignCount(signCount).
		Exec(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update sign count")
	}
	return nil
}

func (r *passkeyRepository) UpdateLastUsed(ctx context.Context, credentialID string) error {
	err := r.client.Passkey.Update().
		Where(passkey.CredentialID(credentialID)).
		SetLastUsed(time.Now()).
		Exec(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update last used")
	}
	return nil
}

func (r *passkeyRepository) IncrementUsage(ctx context.Context, credentialID string, signCount int) error {
	// Update both sign count and last used time
	err := r.client.Passkey.Update().
		Where(passkey.CredentialID(credentialID)).
		SetSignCount(signCount).
		SetLastUsed(time.Now()).
		Exec(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to increment usage")
	}
	return nil
}

func (r *passkeyRepository) ValidateCredentialID(ctx context.Context, credentialID string) (*ent.Passkey, error) {
	passkey, err := r.GetByCredentialID(ctx, credentialID)
	if err != nil {
		return nil, err
	}

	// Check if passkey is active
	if !passkey.Active {
		return nil, errors.New(errors.CodeUnauthorized, "Passkey is inactive")
	}

	return passkey, nil
}

// Passkey status management methods

func (r *passkeyRepository) Activate(ctx context.Context, id xid.ID) error {
	err := r.client.Passkey.UpdateOneID(id).
		SetActive(true).
		Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Passkey not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to activate passkey")
	}
	return nil
}

func (r *passkeyRepository) Deactivate(ctx context.Context, id xid.ID) error {
	err := r.client.Passkey.UpdateOneID(id).
		SetActive(false).
		Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "Passkey not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to deactivate passkey")
	}
	return nil
}

func (r *passkeyRepository) DeactivateAllUserPasskeys(ctx context.Context, userID xid.ID) error {
	err := r.client.Passkey.Update().
		Where(passkey.UserID(userID)).
		SetActive(false).
		Exec(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to deactivate all user passkeys")
	}
	return nil
}

func (r *passkeyRepository) DeactivateByDevice(ctx context.Context, userID xid.ID, deviceType string) error {
	err := r.client.Passkey.Update().
		Where(
			passkey.UserID(userID),
			passkey.DeviceType(deviceType),
		).
		SetActive(false).
		Exec(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to deactivate passkeys by device")
	}
	return nil
}

// Analytics and reporting methods

func (r *passkeyRepository) GetPasskeyStats(ctx context.Context, userID *xid.ID) (*PasskeyStats, error) {
	query := r.client.Passkey.Query()

	if userID != nil {
		query = query.Where(passkey.UserID(*userID))
	}

	// Get total count
	total, err := query.Count(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get total passkeys")
	}

	// Get active count
	active, err := query.Clone().Where(passkey.Active(true)).Count(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get active passkeys")
	}

	// Get unique device types
	deviceTypes, err := query.Clone().
		Where(passkey.DeviceTypeNotNil()).
		GroupBy(passkey.FieldDeviceType).
		Strings(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get unique device types")
	}

	// Get unique AAGUIDs
	aaguids, err := query.Clone().
		Where(passkey.AaguidNotNil()).
		GroupBy(passkey.FieldAaguid).
		Strings(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get unique AAGUIDs")
	}

	// Get recently used (last 30 days)
	thirtyDaysAgo := time.Now().AddDate(0, 0, -30)
	recentlyUsed, err := query.Clone().
		Where(passkey.LastUsedGTE(thirtyDaysAgo)).
		Count(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get recently used passkeys")
	}

	// Get never used
	neverUsed, err := query.Clone().
		Where(passkey.LastUsedIsNil()).
		Count(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get never used passkeys")
	}

	return &PasskeyStats{
		TotalPasskeys:      total,
		ActivePasskeys:     active,
		InactivePasskeys:   total - active,
		UniqueDeviceTypes:  len(deviceTypes),
		UniqueAAGUIDs:      len(aaguids),
		DeviceBreakdown:    make(map[string]int),
		AAGUIDBreakdown:    make(map[string]int),
		TransportBreakdown: make(map[string]int),
		RecentlyUsed:       recentlyUsed,
		NeverUsed:          neverUsed,
	}, nil
}

func (r *passkeyRepository) GetDeviceUsageStats(ctx context.Context, userID *xid.ID) (map[string]*DeviceUsageStats, error) {
	query := r.client.Passkey.Query()

	if userID != nil {
		query = query.Where(passkey.UserID(*userID))
	}

	passkeys, err := query.All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get passkeys for device usage stats")
	}

	stats := make(map[string]*DeviceUsageStats)

	for _, pk := range passkeys {
		deviceType := "unknown"
		if pk.DeviceType != "" {
			deviceType = pk.DeviceType
		}

		if _, exists := stats[deviceType]; !exists {
			stats[deviceType] = &DeviceUsageStats{
				DeviceType: deviceType,
			}
		}

		stat := stats[deviceType]
		stat.PasskeyCount++
		stat.TotalUsage += pk.SignCount

		if pk.Active {
			stat.ActiveCount++
		}

		if pk.LastUsed != nil {
			if stat.LastUsed == nil || pk.LastUsed.After(*stat.LastUsed) {
				stat.LastUsed = pk.LastUsed
			}
		}
	}

	// Calculate averages
	for _, stat := range stats {
		if stat.PasskeyCount > 0 {
			stat.AverageSignCount = float64(stat.TotalUsage) / float64(stat.PasskeyCount)
		}
	}

	return stats, nil
}

func (r *passkeyRepository) GetAAGUIDStats(ctx context.Context) (map[string]*AAGUIDStats, error) {
	passkeys, err := r.client.Passkey.Query().All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get passkeys for AAGUID stats")
	}

	stats := make(map[string]*AAGUIDStats)
	userCounts := make(map[string]map[xid.ID]bool) // Track unique users per AAGUID

	for _, pk := range passkeys {
		aaguid := "unknown"
		if pk.Aaguid != "" {
			aaguid = pk.Aaguid
		}

		if _, exists := stats[aaguid]; !exists {
			stats[aaguid] = &AAGUIDStats{
				AAGUID: aaguid,
			}
			userCounts[aaguid] = make(map[xid.ID]bool)
		}

		stat := stats[aaguid]
		stat.PasskeyCount++
		stat.TotalUsage += pk.SignCount

		// Track unique users
		userCounts[aaguid][pk.UserID] = true

		if pk.LastUsed != nil {
			if stat.LastUsed == nil || pk.LastUsed.After(*stat.LastUsed) {
				stat.LastUsed = pk.LastUsed
			}
		}
	}

	// Set user counts
	for aaguid, stat := range stats {
		stat.UserCount = len(userCounts[aaguid])
	}

	return stats, nil
}

func (r *passkeyRepository) GetUsageAnalytics(ctx context.Context, userID *xid.ID, days int) (*PasskeyUsageAnalytics, error) {
	since := time.Now().AddDate(0, 0, -days)
	query := r.client.Passkey.Query().
		Where(passkey.LastUsedGTE(since))

	if userID != nil {
		query = query.Where(passkey.UserID(*userID))
	}

	passkeys, err := query.All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get passkeys for usage analytics")
	}

	analytics := &PasskeyUsageAnalytics{
		Period:         days,
		DeviceUsage:    make(map[string]int),
		TransportUsage: make(map[string]int),
	}

	uniqueUsers := make(map[xid.ID]bool)
	dailyUsage := make(map[string]int)

	var peakUsageCount int
	var peakUsageDay time.Time

	for _, pk := range passkeys {
		if pk.LastUsed != nil {
			// Count unique users
			uniqueUsers[pk.UserID] = true

			// Track device usage
			if pk.DeviceType != "" {
				analytics.DeviceUsage[pk.DeviceType]++
			}

			// Track transport usage
			for _, transport := range pk.Transports {
				analytics.TransportUsage[transport] += pk.SignCount
			}

			// Daily usage tracking
			day := pk.LastUsed.Format("2006-01-02")
			dailyUsage[day] += pk.SignCount
			analytics.TotalUsage += pk.SignCount

			// Track peak usage
			if dailyUsage[day] > peakUsageCount {
				peakUsageCount = dailyUsage[day]
				peakUsageDay = *pk.LastUsed
			}
		}
	}

	analytics.UniqueUsers = len(uniqueUsers)
	if peakUsageCount > 0 {
		analytics.PeakUsageCount = peakUsageCount
		analytics.PeakUsageDay = &peakUsageDay
	}

	// Convert daily usage to structured format
	for day, count := range dailyUsage {
		if date, err := time.Parse("2006-01-02", day); err == nil {
			analytics.DailyUsage = append(analytics.DailyUsage, DailyPasskeyUsage{
				Date:       date,
				UsageCount: count,
			})
		}
	}

	return analytics, nil
}

// Device and authenticator management methods

func (r *passkeyRepository) GetUserDevices(ctx context.Context, userID xid.ID) ([]string, error) {
	devices, err := r.client.Passkey.Query().
		Where(
			passkey.UserID(userID),
			passkey.DeviceTypeNotNil(),
		).
		GroupBy(passkey.FieldDeviceType).
		Strings(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get user devices")
	}
	return devices, nil
}

func (r *passkeyRepository) GetUniqueAAGUIDs(ctx context.Context, userID *xid.ID) ([]string, error) {
	query := r.client.Passkey.Query().
		Where(passkey.AaguidNotNil())

	if userID != nil {
		query = query.Where(passkey.UserID(*userID))
	}

	aaguids, err := query.GroupBy(passkey.FieldAaguid).Strings(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get unique AAGUIDs")
	}
	return aaguids, nil
}

func (r *passkeyRepository) GetAuthenticatorModels(ctx context.Context, userID *xid.ID) (map[string]int, error) {
	query := r.client.Passkey.Query()

	if userID != nil {
		query = query.Where(passkey.UserID(*userID))
	}

	passkeys, err := query.All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get passkeys for authenticator models")
	}

	models := make(map[string]int)
	for _, pk := range passkeys {
		// This would require AAGUID to authenticator model mapping
		// For now, use AAGUID as the model identifier
		model := "unknown"
		if pk.Aaguid != "" {
			model = pk.Aaguid
		}
		models[model]++
	}

	return models, nil
}

func (r *passkeyRepository) GetRecentlyUsedPasskeys(ctx context.Context, userID xid.ID, limit int) ([]*ent.Passkey, error) {
	passkeys, err := r.client.Passkey.Query().
		Where(
			passkey.UserID(userID),
			passkey.LastUsedNotNil(),
		).
		Order(passkey.ByLastUsed(sql.OrderDesc())).
		Limit(limit).
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get recently used passkeys")
	}
	return passkeys, nil
}

// Security and monitoring methods

func (r *passkeyRepository) GetSuspiciousActivity(ctx context.Context, userID xid.ID, days int) ([]*PasskeySecurityEvent, error) {
	since := time.Now().AddDate(0, 0, -days)

	// Get passkeys with unusual sign count jumps
	passkeys, err := r.client.Passkey.Query().
		Where(
			passkey.UserID(userID),
			passkey.LastUsedGTE(since),
		).
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get passkeys for suspicious activity")
	}

	var events []*PasskeySecurityEvent

	for _, pk := range passkeys {
		// Simple heuristic: large sign count jumps might indicate suspicious activity
		if pk.SignCount > 1000 {
			events = append(events, &PasskeySecurityEvent{
				PasskeyID:    pk.ID,
				CredentialID: pk.CredentialID,
				EventType:    "high_usage",
				EventTime:    time.Now(),
				Description:  fmt.Sprintf("Passkey has unusually high sign count: %d", pk.SignCount),
				RiskLevel:    "medium",
			})
		}

		// Check for passkeys that haven't been used recently but are still active
		if pk.Active && pk.LastUsed != nil && time.Since(*pk.LastUsed) > 30*24*time.Hour {
			events = append(events, &PasskeySecurityEvent{
				PasskeyID:    pk.ID,
				CredentialID: pk.CredentialID,
				EventType:    "dormant_active",
				EventTime:    *pk.LastUsed,
				Description:  "Active passkey hasn't been used in over 30 days",
				RiskLevel:    "low",
			})
		}
	}

	return events, nil
}

func (r *passkeyRepository) GetUnusedPasskeys(ctx context.Context, userID xid.ID, days int) ([]*ent.Passkey, error) {
	cutoff := time.Now().AddDate(0, 0, -days)

	passkeys, err := r.client.Passkey.Query().
		Where(
			passkey.UserID(userID),
			passkey.Or(
				passkey.LastUsedIsNil(),
				passkey.LastUsedLT(cutoff),
			),
		).
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get unused passkeys")
	}
	return passkeys, nil
}

func (r *passkeyRepository) GetHighUsagePasskeys(ctx context.Context, userID xid.ID, threshold int) ([]*ent.Passkey, error) {
	passkeys, err := r.client.Passkey.Query().
		Where(
			passkey.UserID(userID),
			passkey.SignCountGTE(threshold),
		).
		Order(passkey.BySignCount(sql.OrderDesc())).
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get high usage passkeys")
	}
	return passkeys, nil
}

// Bulk operations

func (r *passkeyRepository) BulkDeactivate(ctx context.Context, ids []xid.ID) error {
	err := r.client.Passkey.Update().
		Where(passkey.IDIn(ids...)).
		SetActive(false).
		Exec(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to bulk deactivate passkeys")
	}
	return nil
}

func (r *passkeyRepository) BulkDelete(ctx context.Context, ids []xid.ID) error {
	_, err := r.client.Passkey.Delete().
		Where(passkey.IDIn(ids...)).
		Exec(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to bulk delete passkeys")
	}
	return nil
}

func (r *passkeyRepository) CleanupUnusedPasskeys(ctx context.Context, days int) (int, error) {
	cutoff := time.Now().AddDate(0, 0, -days)

	deleted, err := r.client.Passkey.Delete().
		Where(
			passkey.Active(false),
			passkey.Or(
				passkey.LastUsedIsNil(),
				passkey.LastUsedLT(cutoff),
			),
		).
		Exec(ctx)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to cleanup unused passkeys")
	}
	return deleted, nil
}

// Existence check methods

func (r *passkeyRepository) ExistsByCredentialID(ctx context.Context, credentialID string) (bool, error) {
	exists, err := r.client.Passkey.Query().
		Where(passkey.CredentialID(credentialID)).
		Exist(ctx)
	if err != nil {
		return false, errors.Wrap(err, errors.CodeDatabaseError, "failed to check if passkey exists by credential ID")
	}
	return exists, nil
}

func (r *passkeyRepository) UserHasPasskeys(ctx context.Context, userID xid.ID) (bool, error) {
	exists, err := r.client.Passkey.Query().
		Where(passkey.UserID(userID)).
		Exist(ctx)
	if err != nil {
		return false, errors.Wrap(err, errors.CodeDatabaseError, "failed to check if user has passkeys")
	}
	return exists, nil
}

func (r *passkeyRepository) UserHasActivePasskeys(ctx context.Context, userID xid.ID) (bool, error) {
	exists, err := r.client.Passkey.Query().
		Where(
			passkey.UserID(userID),
			passkey.Active(true),
		).
		Exist(ctx)
	if err != nil {
		return false, errors.Wrap(err, errors.CodeDatabaseError, "failed to check if user has active passkeys")
	}
	return exists, nil
}
