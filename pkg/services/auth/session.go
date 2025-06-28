package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/rs/xid"
	"github.com/samber/lo"
	"github.com/xraph/frank/config"
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/internal/repository"
	"github.com/xraph/frank/pkg/crypto"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
)

// SessionService defines the interface for session operations
type SessionService interface {
	// Session lifecycle
	CreateSession(ctx context.Context, input repository.CreateSessionInput) (*model.Session, error)
	GetSession(ctx context.Context, sessionID xid.ID) (*model.Session, error)
	GetSessionByToken(ctx context.Context, token string) (*model.Session, error)
	UpdateSession(ctx context.Context, sessionID xid.ID, input repository.UpdateSessionInput) (*model.Session, error)
	RefreshSession(ctx context.Context, sessionID xid.ID) (*model.Session, error)
	InvalidateSession(ctx context.Context, sessionID xid.ID) error
	InvalidateSessionByToken(ctx context.Context, token string) error

	// Session validation
	ValidateSession(ctx context.Context, token string) (*model.Session, error)
	IsSessionValid(ctx context.Context, sessionID xid.ID) (bool, error)
	IsSessionActive(ctx context.Context, token string) (bool, error)

	// Session management
	GetUserSessions(ctx context.Context, userID xid.ID, activeOnly bool) ([]*model.Session, error)
	ListSessions(ctx context.Context, params model.ListSessionsParams) (*model.PaginatedOutput[model.Session], error)
	ListUserSessions(ctx context.Context, userID xid.ID, params model.ListSessionsParams) (*model.PaginatedOutput[model.Session], error)
	InvalidateAllUserSessions(ctx context.Context, userID xid.ID) (int, error)
	InvalidateOtherUserSessions(ctx context.Context, userID xid.ID, keepSessionID xid.ID) (int, error)
	GetActiveSessionCount(ctx context.Context, userID xid.ID) (int, error)

	// Session activity tracking
	UpdateLastActivity(ctx context.Context, sessionID xid.ID) error
	UpdateLastActivityByToken(ctx context.Context, token string) error
	ExtendSession(ctx context.Context, sessionID xid.ID, duration time.Duration) error

	// Session cleanup and maintenance
	CleanupExpiredSessions(ctx context.Context) (int, error)
	CleanupOldSessions(ctx context.Context, olderThan time.Duration) (int, error)
	GetExpiredSessions(ctx context.Context, limit int) ([]*model.Session, error)

	// Session analytics
	GetSessionStats(ctx context.Context, userID *xid.ID, organizationID *xid.ID) (*SessionStats, error)
	GetSessionsByDevice(ctx context.Context, userID xid.ID) (map[string][]*model.Session, error)
	GetSessionsByLocation(ctx context.Context, userID xid.ID) (map[string][]*model.Session, error)
	GetSuspiciousSessions(ctx context.Context, userID xid.ID) ([]*model.Session, error)

	// Device management
	GetUserDevices(ctx context.Context, userID xid.ID) ([]*DeviceInfo, error)
	InvalidateDeviceSessions(ctx context.Context, userID xid.ID, deviceID string) (int, error)
	GetDeviceSessionCount(ctx context.Context, userID xid.ID, deviceID string) (int, error)
}

// Session-related types

type DeviceInfo struct {
	DeviceID     string    `json:"device_id"`
	DeviceType   string    `json:"device_type"`
	Platform     string    `json:"platform"`
	Browser      string    `json:"browser"`
	UserAgent    string    `json:"user_agent"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	SessionCount int       `json:"session_count"`
	IsActive     bool      `json:"is_active"`
}

type SessionStats struct {
	TotalSessions      int            `json:"total_sessions"`
	ActiveSessions     int            `json:"active_sessions"`
	ExpiredSessions    int            `json:"expired_sessions"`
	SessionsByDevice   map[string]int `json:"sessions_by_device"`
	SessionsByLocation map[string]int `json:"sessions_by_location"`
	AverageSessionTime time.Duration  `json:"average_session_time"`
	NewSessionsToday   int            `json:"new_sessions_today"`
	UniqueDevices      int            `json:"unique_devices"`
	UniqueLocations    int            `json:"unique_locations"`
}

type SuspiciousActivity struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	RiskLevel   string                 `json:"risk_level"`
	Timestamp   time.Time              `json:"timestamp"`
	Details     map[string]interface{} `json:"details"`
}

// sessionService implements the SessionService interface
type sessionService struct {
	sessionRepo repository.SessionRepository
	userRepo    repository.UserRepository
	auditRepo   repository.AuditRepository
	crypto      crypto.Util
	logger      logging.Logger
	config      *SessionConfig
}

// SessionConfig holds session-related configuration
type SessionConfig struct {
	DefaultDuration             time.Duration
	MaxDuration                 time.Duration
	MaxConcurrentSessions       int
	InactivityTimeout           time.Duration
	RememberMeDuration          time.Duration
	CleanupInterval             time.Duration
	EnableDeviceTracking        bool
	EnableLocationTracking      bool
	SuspiciousActivityDetection bool
	TokenLength                 int
}

// NewSessionService creates a new session service
func NewSessionService(
	repos repository.Repository,
	crypto crypto.Util,
	logger logging.Logger,
	cfg *config.AuthConfig,
) SessionService {

	mcfg := defaultSessionConfig()
	mcfg.DefaultDuration = cfg.SessionDuration
	mcfg.RememberMeDuration = cfg.RememberMeDuration

	return &sessionService{
		sessionRepo: repos.Session(),
		userRepo:    repos.User(),
		auditRepo:   repos.Audit(),
		crypto:      crypto,
		logger:      logger,
		config:      mcfg,
	}
}

// defaultSessionConfig returns default session configuration
func defaultSessionConfig() *SessionConfig {
	return &SessionConfig{
		DefaultDuration:             24 * time.Hour,
		MaxDuration:                 30 * 24 * time.Hour, // 30 days
		MaxConcurrentSessions:       10,
		InactivityTimeout:           2 * time.Hour,
		RememberMeDuration:          30 * 24 * time.Hour, // 30 days
		CleanupInterval:             1 * time.Hour,
		EnableDeviceTracking:        true,
		EnableLocationTracking:      true,
		SuspiciousActivityDetection: true,
		TokenLength:                 32,
	}
}

// CreateSession creates a new user session
func (s *sessionService) CreateSession(ctx context.Context, input repository.CreateSessionInput) (*model.Session, error) {
	// Validate user exists and is active
	user, err := s.userRepo.GetByID(ctx, input.UserID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeBadRequest, "user not found")
	}

	if !user.Active || user.Blocked {
		return nil, errors.New(errors.CodeUnauthorized, "user account is inactive")
	}

	// Check concurrent session limits
	if s.config.MaxConcurrentSessions > 0 {
		activeCount, err := s.sessionRepo.GetActiveSessionsCount(ctx, input.UserID)
		if err != nil {
			s.logger.Error("failed to get active session count", logging.Error(err))
		} else if activeCount >= s.config.MaxConcurrentSessions {
			// Cleanup oldest sessions to make room
			sessions, err := s.sessionRepo.GetActiveSessions(ctx, input.UserID)
			if err == nil && len(sessions) >= s.config.MaxConcurrentSessions {
				// Remove oldest sessions
				for i := 0; i < len(sessions)-s.config.MaxConcurrentSessions+1; i++ {
					_ = s.sessionRepo.Delete(ctx, sessions[i].ID)
				}
			}
		}
	}

	// Generate session token
	sessionToken, err := s.generateSessionToken()
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to generate session token")
	}

	// Set default expiration if not provided
	if input.ExpiresAt.IsZero() {
		input.ExpiresAt = time.Now().Add(s.config.DefaultDuration)
	}

	// Validate expiration doesn't exceed maximum
	maxExpiresAt := time.Now().Add(s.config.MaxDuration)
	if input.ExpiresAt.After(maxExpiresAt) {
		input.ExpiresAt = maxExpiresAt
	}

	// Set session token and defaults
	input.Token = sessionToken
	input.Active = true
	input.LastActiveAt = time.Now()

	if input.Metadata == nil {
		input.Metadata = make(map[string]interface{})
	}

	// Add device information if available
	if s.config.EnableDeviceTracking && input.UserAgent != nil {
		deviceInfo := s.parseUserAgent(*input.UserAgent)
		input.Metadata["device_info"] = deviceInfo
	}

	// Add location information if available
	if s.config.EnableLocationTracking && input.IPAddress != nil {
		locationInfo := s.getLocationFromIP(*input.IPAddress)
		if locationInfo != nil {
			input.Metadata["location_info"] = locationInfo
		}
	}

	// Create session
	session, err := s.sessionRepo.Create(ctx, input)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to create session")
	}

	// Audit log
	s.auditSessionCreated(ctx, session)

	// Check for suspicious activity
	if s.config.SuspiciousActivityDetection {
		go s.detectSuspiciousActivity(context.Background(), session)
	}

	return convertEntSessionToModel(session), nil
}

// GetSession retrieves a session by ID
func (s *sessionService) GetSession(ctx context.Context, sessionID xid.ID) (*model.Session, error) {
	session, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "session not found")
	}

	return convertEntSessionToModel(session), nil
}

// GetSessionByToken retrieves a session by token
func (s *sessionService) GetSessionByToken(ctx context.Context, token string) (*model.Session, error) {
	if token == "" {
		return nil, errors.New(errors.CodeBadRequest, "session token is required")
	}

	session, err := s.sessionRepo.GetByToken(ctx, token)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "session not found")
	}

	return convertEntSessionToModel(session), nil
}

// ValidateSession validates a session token and returns the session if valid
func (s *sessionService) ValidateSession(ctx context.Context, token string) (*model.Session, error) {
	if token == "" {
		return nil, errors.New(errors.CodeUnauthorized, "session token is required")
	}

	session, err := s.sessionRepo.GetByToken(ctx, token)
	if err != nil {
		return nil, errors.New(errors.CodeUnauthorized, "invalid session token")
	}

	// Check if session is active
	if !session.Active {
		return nil, errors.New(errors.CodeUnauthorized, "session is inactive")
	}

	// Check if session has expired
	if time.Now().After(session.ExpiresAt) {
		// Automatically invalidate expired session
		_ = s.sessionRepo.Delete(ctx, session.ID)
		return nil, errors.New(errors.CodeUnauthorized, "session has expired")
	}

	// Check inactivity timeout
	if s.config.InactivityTimeout > 0 {
		inactiveThreshold := time.Now().Add(-s.config.InactivityTimeout)
		if session.LastActiveAt.Before(inactiveThreshold) {
			// Session is inactive, invalidate it
			_ = s.sessionRepo.Delete(ctx, session.ID)
			return nil, errors.New(errors.CodeUnauthorized, "session expired due to inactivity")
		}
	}

	// Update last activity (async to avoid affecting response time)
	go func() {
		if err := s.sessionRepo.UpdateLastActive(ctx, token); err != nil {
			s.logger.Error("failed to update session last activity", logging.Error(err))
		}
	}()

	return convertEntSessionToModel(session), nil
}

// IsSessionValid checks if a session is valid without returning the session
func (s *sessionService) IsSessionValid(ctx context.Context, sessionID xid.ID) (bool, error) {
	session, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		return false, nil
	}

	// Check basic validity
	if !session.Active || time.Now().After(session.ExpiresAt) {
		return false, nil
	}

	// Check inactivity timeout
	if s.config.InactivityTimeout > 0 {
		inactiveThreshold := time.Now().Add(-s.config.InactivityTimeout)
		if session.LastActiveAt.Before(inactiveThreshold) {
			return false, nil
		}
	}

	return true, nil
}

// IsSessionActive checks if a session token is active
func (s *sessionService) IsSessionActive(ctx context.Context, token string) (bool, error) {
	session, err := s.ValidateSession(ctx, token)
	return session != nil, err
}

// RefreshSession refreshes a session's expiration time
func (s *sessionService) RefreshSession(ctx context.Context, sessionID xid.ID) (*model.Session, error) {
	_, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "session not found")
	}

	// Extend session expiration
	newExpiresAt := time.Now().Add(s.config.DefaultDuration)
	maxExpiresAt := time.Now().Add(s.config.MaxDuration)
	if newExpiresAt.After(maxExpiresAt) {
		newExpiresAt = maxExpiresAt
	}

	updateInput := repository.UpdateSessionInput{
		ExpiresAt:    &newExpiresAt,
		LastActiveAt: &[]time.Time{time.Now()}[0],
	}

	updatedSession, err := s.sessionRepo.Update(ctx, sessionID, updateInput)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to refresh session")
	}

	return convertEntSessionToModel(updatedSession), nil
}

// InvalidateSession invalidates a specific session
func (s *sessionService) InvalidateSession(ctx context.Context, sessionID xid.ID) error {
	session, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		return nil // Session doesn't exist, consider it already invalidated
	}

	err = s.sessionRepo.Delete(ctx, sessionID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to invalidate session")
	}

	// Audit log
	s.auditSessionInvalidated(ctx, session)

	return nil
}

// InvalidateSessionByToken invalidates a session by token
func (s *sessionService) InvalidateSessionByToken(ctx context.Context, token string) error {
	if token == "" {
		return errors.New(errors.CodeBadRequest, "session token is required")
	}

	session, err := s.sessionRepo.GetByToken(ctx, token)
	if err != nil {
		return nil // Session doesn't exist, consider it already invalidated
	}

	return s.InvalidateSession(ctx, session.ID)
}

// GetUserSessions retrieves all sessions for a user
func (s *sessionService) GetUserSessions(ctx context.Context, userID xid.ID, activeOnly bool) ([]*model.Session, error) {
	if activeOnly {
		sessions, err := s.sessionRepo.GetActiveSessions(ctx, userID)
		if err != nil {
			return nil, err
		}

		return lo.Map(sessions, func(item *ent.Session, index int) *model.Session {
			return convertEntSessionToModel(item)
		}), nil
	}

	// Get all sessions with pagination
	params := repository.ListSessionsParams{
		UserID: &userID,
	}

	result, err := s.sessionRepo.List(ctx, params)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get user sessions")
	}

	return lo.Map(result.Data, func(item *ent.Session, index int) *model.Session {
		return convertEntSessionToModel(item)
	}), nil
}

func (s *sessionService) ListUserSessions(ctx context.Context, userID xid.ID, params model.ListSessionsParams) (*model.PaginatedOutput[model.Session], error) {
	params.UserID.Value = userID
	params.UserID.IsSet = true

	return s.ListSessions(ctx, params)
}

func (s *sessionService) ListSessions(ctx context.Context, params model.ListSessionsParams) (*model.PaginatedOutput[model.Session], error) {
	// Get all sessions with pagination
	repoParams := repository.ListSessionsParams{
		PaginationParams: params.PaginationParams,
	}

	if params.UserID.IsSet {
		repoParams.UserID = &params.UserID.Value
	}
	if params.Active.IsSet {
		repoParams.Active = &params.Active.Value
	}
	if params.IPAddress.IsSet {
		repoParams.IPAddress = &params.IPAddress.Value
	}
	if params.OrganizationID.IsSet {
		repoParams.OrganizationID = &params.OrganizationID.Value
	}
	if params.DeviceID.IsSet {
		repoParams.DeviceID = &params.DeviceID.Value
	}
	if params.Location.IsSet {
		repoParams.Location = &params.Location.Value
	}

	result, err := s.sessionRepo.List(ctx, repoParams)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get user sessions")
	}

	return &model.PaginatedOutput[model.Session]{
		Data: lo.Map(result.Data, func(item *ent.Session, index int) model.Session {
			return *convertEntSessionToModel(item)
		}),
		Pagination: result.Pagination,
	}, nil
}

// InvalidateAllUserSessions invalidates all sessions for a user
func (s *sessionService) InvalidateAllUserSessions(ctx context.Context, userID xid.ID) (int, error) {
	sessions, err := s.sessionRepo.GetActiveSessions(ctx, userID)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternalServer, "failed to invalidate user sessions")
	}

	err = s.sessionRepo.InvalidateAllUserSessions(ctx, userID)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternalServer, "failed to invalidate user sessions")
	}

	count := len(sessions)

	// Audit log
	s.auditAllUserSessionsInvalidated(ctx, userID, count)

	return count, nil
}

// InvalidateOtherUserSessions invalidates all user sessions except the specified one
func (s *sessionService) InvalidateOtherUserSessions(ctx context.Context, userID xid.ID, keepSessionID xid.ID) (int, error) {
	sessions, err := s.sessionRepo.GetActiveSessions(ctx, userID)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternalServer, "failed to get user sessions")
	}

	count := 0
	for _, session := range sessions {
		if session.ID != keepSessionID {
			if err := s.sessionRepo.Delete(ctx, session.ID); err == nil {
				count++
			}
		}
	}

	return count, nil
}

// GetActiveSessionCount returns the number of active sessions for a user
func (s *sessionService) GetActiveSessionCount(ctx context.Context, userID xid.ID) (int, error) {
	return s.sessionRepo.GetActiveSessionsCount(ctx, userID)
}

// UpdateLastActivity updates the last activity timestamp for a session
func (s *sessionService) UpdateLastActivity(ctx context.Context, sessionID xid.ID) error {
	updateInput := repository.UpdateSessionInput{
		LastActiveAt: &[]time.Time{time.Now()}[0],
	}

	_, err := s.sessionRepo.Update(ctx, sessionID, updateInput)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to update session activity")
	}

	return nil
}

// UpdateLastActivityByToken updates the last activity timestamp by token
func (s *sessionService) UpdateLastActivityByToken(ctx context.Context, token string) error {
	return s.sessionRepo.UpdateLastActive(ctx, token)
}

// ExtendSession extends a session's expiration time
func (s *sessionService) ExtendSession(ctx context.Context, sessionID xid.ID, duration time.Duration) error {
	session, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		return errors.Wrap(err, errors.CodeNotFound, "session not found")
	}

	newExpiresAt := session.ExpiresAt.Add(duration)
	maxExpiresAt := time.Now().Add(s.config.MaxDuration)
	if newExpiresAt.After(maxExpiresAt) {
		newExpiresAt = maxExpiresAt
	}

	updateInput := repository.UpdateSessionInput{
		ExpiresAt: &newExpiresAt,
	}

	_, err = s.sessionRepo.Update(ctx, sessionID, updateInput)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to extend session")
	}

	return nil
}

// CleanupExpiredSessions removes expired sessions
func (s *sessionService) CleanupExpiredSessions(ctx context.Context) (int, error) {
	count, err := s.sessionRepo.InvalidateExpiredSessions(ctx)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternalServer, "failed to cleanup expired sessions")
	}

	s.logger.Info("cleaned up expired sessions", logging.Int("count", count))
	return count, nil
}

// CleanupOldSessions removes sessions older than the specified duration
func (s *sessionService) CleanupOldSessions(ctx context.Context, olderThan time.Duration) (int, error) {
	cutoffTime := time.Now().Add(-olderThan)
	count, err := s.sessionRepo.CleanupOldSessions(ctx, cutoffTime)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternalServer, "failed to cleanup old sessions")
	}

	s.logger.Info("cleaned up old sessions", logging.Int("count", count), logging.Duration("older_than", olderThan))
	return count, nil
}

// GetExpiredSessions returns expired sessions
func (s *sessionService) GetExpiredSessions(ctx context.Context, limit int) ([]*model.Session, error) {
	// This would need to be implemented in the repository
	// For now, return empty slice
	return []*model.Session{}, nil
}

// Helper methods

func (s *sessionService) generateSessionToken() (string, error) {
	bytes := make([]byte, s.config.TokenLength)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (s *sessionService) parseUserAgent(userAgent string) map[string]interface{} {
	// Simple user agent parsing - in production, use a proper library
	deviceInfo := make(map[string]interface{})

	userAgent = strings.ToLower(userAgent)

	// Detect browser
	if strings.Contains(userAgent, "chrome") {
		deviceInfo["browser"] = "Chrome"
	} else if strings.Contains(userAgent, "firefox") {
		deviceInfo["browser"] = "Firefox"
	} else if strings.Contains(userAgent, "safari") {
		deviceInfo["browser"] = "Safari"
	} else if strings.Contains(userAgent, "edge") {
		deviceInfo["browser"] = "Edge"
	} else {
		deviceInfo["browser"] = "Unknown"
	}

	// Detect platform
	if strings.Contains(userAgent, "windows") {
		deviceInfo["platform"] = "Windows"
	} else if strings.Contains(userAgent, "mac") {
		deviceInfo["platform"] = "macOS"
	} else if strings.Contains(userAgent, "linux") {
		deviceInfo["platform"] = "Linux"
	} else if strings.Contains(userAgent, "android") {
		deviceInfo["platform"] = "Android"
	} else if strings.Contains(userAgent, "ios") {
		deviceInfo["platform"] = "iOS"
	} else {
		deviceInfo["platform"] = "Unknown"
	}

	// Detect device type
	if strings.Contains(userAgent, "mobile") {
		deviceInfo["device_type"] = "Mobile"
	} else if strings.Contains(userAgent, "tablet") {
		deviceInfo["device_type"] = "Tablet"
	} else {
		deviceInfo["device_type"] = "Desktop"
	}

	return deviceInfo
}

func (s *sessionService) getLocationFromIP(ipAddress string) map[string]interface{} {
	// Simple IP geolocation - in production, use a proper service
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return nil
	}

	// Check if it's a private IP
	if ip.IsPrivate() || ip.IsLoopback() {
		return map[string]interface{}{
			"type": "private",
			"ip":   ipAddress,
		}
	}

	// For public IPs, you would use a geolocation service
	// For now, just return basic info
	return map[string]interface{}{
		"type":    "public",
		"ip":      ipAddress,
		"country": "Unknown",
		"city":    "Unknown",
	}
}

func (s *sessionService) detectSuspiciousActivity(ctx context.Context, session *ent.Session) {
	// Simple suspicious activity detection
	// In production, this would be more sophisticated

	var activities []SuspiciousActivity

	// Check for unusual location
	if session.Location != "" {
		// Compare with user's usual locations
		// For now, just log if location is present
		activities = append(activities, SuspiciousActivity{
			Type:        "new_location",
			Description: fmt.Sprintf("Login from new location: %s", session.Location),
			RiskLevel:   "low",
			Timestamp:   time.Now(),
			Details: map[string]interface{}{
				"location": session.Location,
				"ip":       session.IPAddress,
			},
		})
	}

	// Check for unusual device
	if session.UserAgent != "" {
		// Compare with user's usual devices
		// For now, just log if user agent is present
		activities = append(activities, SuspiciousActivity{
			Type:        "new_device",
			Description: "Login from new device",
			RiskLevel:   "low",
			Timestamp:   time.Now(),
			Details: map[string]interface{}{
				"user_agent": session.UserAgent,
				"device_id":  session.DeviceID,
			},
		})
	}

	// TODO: Log suspicious activities to audit system
	for _, activity := range activities {
		s.logger.Info("suspicious activity detected",
			logging.String("type", activity.Type),
			logging.String("risk_level", activity.RiskLevel),
			logging.String("user_id", session.UserID.String()),
		)
	}
}

// Analytics methods (stubs for now)

func (s *sessionService) GetSessionStats(ctx context.Context, userID *xid.ID, organizationID *xid.ID) (*SessionStats, error) {
	// TODO: Implement session statistics
	return &SessionStats{}, nil
}

func (s *sessionService) GetSessionsByDevice(ctx context.Context, userID xid.ID) (map[string][]*model.Session, error) {
	sessionsByDevice, err := s.sessionRepo.GetActiveSessionsByDevice(ctx, userID)
	if err != nil {
		return nil, err
	}

	m := make(map[string][]*model.Session)
	for key, session := range sessionsByDevice {
		m[key] = lo.Map(session, func(item *ent.Session, index int) *model.Session {
			return convertEntSessionToModel(item)
		})
	}

	return m, nil
}

func (s *sessionService) GetSessionsByLocation(ctx context.Context, userID xid.ID) (map[string][]*model.Session, error) {
	// TODO: Implement location-based session grouping
	return make(map[string][]*model.Session), nil
}

func (s *sessionService) GetSuspiciousSessions(ctx context.Context, userID xid.ID) ([]*model.Session, error) {
	suspiciousSessions, err := s.sessionRepo.GetSuspiciousSessions(ctx, userID)
	if err != nil {
		return nil, err
	}

	return lo.Map(suspiciousSessions, func(item *ent.Session, index int) *model.Session {
		return convertEntSessionToModel(item)
	}), nil
}

func (s *sessionService) GetUserDevices(ctx context.Context, userID xid.ID) ([]*DeviceInfo, error) {
	// TODO: Implement device information aggregation
	return []*DeviceInfo{}, nil
}

func (s *sessionService) InvalidateDeviceSessions(ctx context.Context, userID xid.ID, deviceID string) (int, error) {
	sessions, err := s.sessionRepo.GetSessionsByDevice(ctx, userID, deviceID)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternalServer, "failed to invalidate user sessions")
	}

	err = s.sessionRepo.InvalidateDeviceSessions(ctx, userID, deviceID)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeInternalServer, "failed to invalidate user sessions")
	}

	return len(sessions), nil
}

func (s *sessionService) GetDeviceSessionCount(ctx context.Context, userID xid.ID, deviceID string) (int, error) {
	sessions, err := s.sessionRepo.GetSessionsByDevice(ctx, userID, deviceID)
	if err != nil {
		return 0, err
	}

	return len(sessions), nil
}

func (s *sessionService) UpdateSession(ctx context.Context, sessionID xid.ID, input repository.UpdateSessionInput) (*model.Session, error) {
	session, err := s.sessionRepo.Update(ctx, sessionID, input)
	if err != nil {
		return nil, err
	}
	return convertEntSessionToModel(session), nil
}

// Audit methods

func (s *sessionService) auditSessionCreated(ctx context.Context, session *ent.Session) {
	// TODO: Implement audit logging
}

func (s *sessionService) auditSessionInvalidated(ctx context.Context, session *ent.Session) {
	// TODO: Implement audit logging
}

func (s *sessionService) auditAllUserSessionsInvalidated(ctx context.Context, userID xid.ID, count int) {
	// TODO: Implement audit logging
}

func (s *sessionService) auditSessionDeleted(ctx context.Context, session *ent.Session) {}

func (s *sessionService) auditSessionUpdated(ctx context.Context, session *ent.Session) {
}

func convertEntSessionToModel(sess *ent.Session) *model.Session {
	m := &model.Session{
		Base: model.Base{
			ID:        sess.ID,
			CreatedAt: sess.CreatedAt,
			UpdatedAt: sess.UpdatedAt,
		},
		UserID:       sess.UserID,
		Token:        sess.Token,
		Location:     sess.Location,
		Active:       sess.Active,
		Metadata:     sess.Metadata,
		DeviceID:     sess.DeviceID,
		IPAddress:    sess.IPAddress,
		UserAgent:    sess.UserAgent,
		ExpiresAt:    sess.ExpiresAt,
		LastActiveAt: sess.LastActiveAt,
	}

	if !sess.OrganizationID.IsNil() {
		m.OrganizationID = &sess.OrganizationID
	}

	return m
}
