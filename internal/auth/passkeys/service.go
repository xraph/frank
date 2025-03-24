package passkeys

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/passkey"
	"github.com/juicycleff/frank/ent/user"
	appErrors "github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// Session represents a WebAuthn session
type Session struct {
	ID        string                `json:"id"`
	UserID    string                `json:"user_id"`
	Type      string                `json:"type"`
	Data      *webauthn.SessionData `json:"data"`
	ExpiresAt time.Time             `json:"expires_at"`
}

// RegistrationOptions contains options for registering a new passkey
type RegistrationOptions struct {
	UserID     string `json:"user_id"`
	DeviceName string `json:"device_name"`
	DeviceType string `json:"device_type"`
}

// AuthenticationOptions contains options for authenticating with a passkey
type AuthenticationOptions struct {
	UserID string `json:"user_id"`
}

// ChallengeResponse contains the challenge response from a client
type ChallengeResponse struct {
	SessionID string          `json:"session_id"`
	Response  json.RawMessage `json:"response"`
}

// RegisteredPasskey contains information about a registered passkey
type RegisteredPasskey struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	DeviceType   string     `json:"device_type"`
	RegisteredAt time.Time  `json:"registered_at"`
	LastUsed     *time.Time `json:"last_used,omitempty"`
}

// Repository provides data access methods for passkeys
type Repository interface {
	GetUserByID(ctx context.Context, userID string) (*ent.User, error)
	GetPasskeysByUserID(ctx context.Context, userID string) ([]*ent.Passkey, error)
	GetPasskeyByCredentialID(ctx context.Context, credentialID string) (*ent.Passkey, error)
	CreatePasskey(ctx context.Context, passkey *ent.PasskeyCreate) (*ent.Passkey, error)
	UpdatePasskey(ctx context.Context, passkeyID string, updates *ent.PasskeyUpdateOne) (*ent.Passkey, error)
	DeletePasskey(ctx context.Context, passkeyID string) error
}

// SessionStore provides methods to store and retrieve WebAuthn sessions
type SessionStore interface {
	StoreSession(ctx context.Context, session *Session) error
	GetSession(ctx context.Context, sessionID string) (*Session, error)
	DeleteSession(ctx context.Context, sessionID string) error
}

// Service provides passkey authentication functionality
type Service interface {
	BeginRegistration(ctx context.Context, opts RegistrationOptions) (map[string]interface{}, error)
	FinishRegistration(ctx context.Context, sessionID string, req *http.Request, opts RegistrationOptions) (*RegisteredPasskey, error)
	BeginAuthentication(ctx context.Context, opts AuthenticationOptions) (map[string]interface{}, error)
	FinishAuthentication(ctx context.Context, sessionID string, req *http.Request) (string, error)
	GetUserPasskeys(ctx context.Context, userID string) ([]*RegisteredPasskey, error)
	UpdatePasskey(ctx context.Context, passkeyID, userID, name string) error
	DeletePasskey(ctx context.Context, passkeyID, userID string) error
}

// serviceImpl is the concrete implementation of the Service interface
type serviceImpl struct {
	config       *config.Config
	client       *ent.Client
	webauthn     *WebAuthnProvider
	logger       logging.Logger
	sessionStore SessionStore
}

// NewService creates a new passkey service
func NewService(
	cfg *config.Config,
	client *ent.Client,
	logger logging.Logger,
	sessionStore SessionStore,
) (Service, error) {
	// Initialize WebAuthn provider
	webauthn, err := NewWebAuthnProvider(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create WebAuthn provider: %w", err)
	}

	return &serviceImpl{
		config:       cfg,
		client:       client,
		webauthn:     webauthn,
		logger:       logger,
		sessionStore: sessionStore,
	}, nil
}

// BeginRegistration starts the passkey registration process
func (s *serviceImpl) BeginRegistration(
	ctx context.Context,
	opts RegistrationOptions,
) (map[string]interface{}, error) {
	// Check if feature is enabled
	if !s.config.Features.EnablePasskeys {
		return nil, appErrors.New(appErrors.CodeFeatureNotEnabled, "passkeys are not enabled")
	}

	// Get user by ID
	user, err := s.client.User.
		Query().
		Where(user.ID(opts.UserID)).
		WithPasskeys().
		Only(ctx)
	if err != nil {
		return nil, handleEntError(err, "failed to get user")
	}

	// Get user's current passkeys
	passkeys := user.Edges.Passkeys

	// Create WebAuthn user
	webAuthnUser := NewWebAuthnUser(user, passkeys)

	// Begin registration
	credentialCreationOptions, sessionData, sessionID, err := s.webauthn.BeginRegistration(ctx, webAuthnUser)
	if err != nil {
		return nil, fmt.Errorf("failed to begin registration: %w", err)
	}

	// Serialize the creation options for the client
	options, err := json.Marshal(credentialCreationOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential creation options: %w", err)
	}

	// Store session data
	session := &Session{
		ID:        sessionID,
		UserID:    opts.UserID,
		Type:      "registration",
		Data:      sessionData,
		ExpiresAt: time.Now().Add(time.Duration(s.config.Passkeys.AttestationTimeout) * time.Millisecond),
	}

	if err := s.sessionStore.StoreSession(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to store session: %w", err)
	}

	// Return response for client
	return map[string]interface{}{
		"options":    json.RawMessage(options),
		"session_id": sessionID,
	}, nil
}

// FinishRegistration completes the passkey registration process
func (s *serviceImpl) FinishRegistration(
	ctx context.Context,
	sessionID string,
	req *http.Request,
	opts RegistrationOptions,
) (*RegisteredPasskey, error) {
	// Check if feature is enabled
	if !s.config.Features.EnablePasskeys {
		return nil, appErrors.New(appErrors.CodeFeatureNotEnabled, "passkeys are not enabled")
	}

	// Get session data
	session, err := s.sessionStore.GetSession(ctx, sessionID)
	if err != nil {
		return nil, appErrors.Wrap(appErrors.CodeInvalidInput, err, "invalid session")
	}

	// Verify session is for registration
	if session.Type != "registration" {
		return nil, appErrors.New(appErrors.CodeInvalidInput, "invalid session type")
	}

	// Verify session belongs to user
	if session.UserID != opts.UserID {
		return nil, appErrors.New(appErrors.CodeForbidden, "session does not belong to user")
	}

	// Verify session has not expired
	if time.Now().After(session.ExpiresAt) {
		return nil, appErrors.New(appErrors.CodeTokenExpired, "session has expired")
	}

	// Get user by ID
	user, err := s.client.User.
		Query().
		Where(user.ID(opts.UserID)).
		WithPasskeys().
		Only(ctx)
	if err != nil {
		return nil, handleEntError(err, "failed to get user")
	}

	// Get user's current passkeys
	passkeys := user.Edges.Passkeys

	// Create WebAuthn user
	webAuthnUser := NewWebAuthnUser(user, passkeys)

	// Finish registration
	credential, err := s.webauthn.FinishRegistration(ctx, webAuthnUser, session.Data, req)
	if err != nil {
		return nil, fmt.Errorf("failed to finish registration: %w", err)
	}

	// Create passkey in database
	deviceType := opts.DeviceType
	if deviceType == "" {
		deviceType = "unknown"
	}

	deviceName := opts.DeviceName
	if deviceName == "" {
		deviceName = "Passkey " + time.Now().Format("Jan 2, 2006")
	}

	// Encode credential ID for storage
	credentialIDStr := base64.RawURLEncoding.EncodeToString(credential.ID)

	// Check if credential ID already exists
	existing, err := s.client.Passkey.
		Query().
		Where(passkey.CredentialID(credentialIDStr)).
		Exist(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check for existing passkey: %w", err)
	}

	if existing {
		return nil, appErrors.New(appErrors.CodeConflict, "passkey already exists")
	}

	// Create transports string array
	transports := make([]string, len(credential.Transport))
	for i, t := range credential.Transport {
		transports[i] = string(t)
	}

	// Create attestation map
	attestation := map[string]interface{}{
		"type": credential.AttestationType,
	}

	// Create new passkey
	newPasskey, err := s.client.Passkey.
		Create().
		SetUserID(opts.UserID).
		SetName(deviceName).
		SetDeviceType(deviceType).
		SetCredentialID(credentialIDStr).
		SetPublicKey(credential.PublicKey).
		SetSignCount(int(credential.Authenticator.SignCount)).
		SetActive(true).
		SetAaguid(string(credential.Authenticator.AAGUID)).
		SetTransports(transports).
		SetAttestation(attestation).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create passkey: %w", err)
	}

	// Delete session
	if err := s.sessionStore.DeleteSession(ctx, sessionID); err != nil {
		s.logger.Warn("Failed to delete session", logging.Error(err))
		// Continue as this is not a critical error
	}

	// Return registered passkey info
	return &RegisteredPasskey{
		ID:           newPasskey.ID,
		Name:         newPasskey.Name,
		DeviceType:   newPasskey.DeviceType,
		RegisteredAt: newPasskey.CreatedAt,
	}, nil
}

// BeginAuthentication starts the passkey authentication process
func (s *serviceImpl) BeginAuthentication(
	ctx context.Context,
	opts AuthenticationOptions,
) (map[string]interface{}, error) {
	// Check if feature is enabled
	if !s.config.Features.EnablePasskeys {
		return nil, appErrors.New(appErrors.CodeFeatureNotEnabled, "passkeys are not enabled")
	}

	// Get user by ID
	user, err := s.client.User.
		Query().
		Where(user.ID(opts.UserID)).
		WithPasskeys(func(q *ent.PasskeyQuery) {
			q.Where(passkey.Active(true))
		}).
		Only(ctx)
	if err != nil {
		return nil, handleEntError(err, "failed to get user")
	}

	// Get user's current passkeys
	passkeys := user.Edges.Passkeys
	if len(passkeys) == 0 {
		return nil, appErrors.New(appErrors.CodeNotFound, "user has no registered passkeys")
	}

	// Create WebAuthn user
	webAuthnUser := NewWebAuthnUser(user, passkeys)

	// Begin authentication
	assertionOptions, sessionData, sessionID, err := s.webauthn.BeginLogin(ctx, webAuthnUser)
	if err != nil {
		return nil, fmt.Errorf("failed to begin authentication: %w", err)
	}

	// Serialize the assertion options for the client
	options, err := json.Marshal(assertionOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal assertion options: %w", err)
	}

	// Store session data
	session := &Session{
		ID:        sessionID,
		UserID:    opts.UserID,
		Type:      "authentication",
		Data:      sessionData,
		ExpiresAt: time.Now().Add(time.Duration(s.config.Passkeys.AssertionTimeout) * time.Millisecond),
	}

	if err := s.sessionStore.StoreSession(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to store session: %w", err)
	}

	// Return response for client
	return map[string]interface{}{
		"options":    json.RawMessage(options),
		"session_id": sessionID,
	}, nil
}

// FinishAuthentication completes the passkey authentication process
func (s *serviceImpl) FinishAuthentication(
	ctx context.Context,
	sessionID string,
	req *http.Request,
) (string, error) {
	// Check if feature is enabled
	if !s.config.Features.EnablePasskeys {
		return "", appErrors.New(appErrors.CodeFeatureNotEnabled, "passkeys are not enabled")
	}

	// Get session data
	session, err := s.sessionStore.GetSession(ctx, sessionID)
	if err != nil {
		return "", appErrors.Wrap(appErrors.CodeInvalidInput, err, "invalid session")
	}

	// Verify session is for authentication
	if session.Type != "authentication" {
		return "", appErrors.New(appErrors.CodeInvalidInput, "invalid session type")
	}

	// Verify session has not expired
	if time.Now().After(session.ExpiresAt) {
		return "", appErrors.New(appErrors.CodeTokenExpired, "session has expired")
	}

	// Get user by ID
	user, err := s.client.User.
		Query().
		Where(user.ID(session.UserID)).
		WithPasskeys(func(q *ent.PasskeyQuery) {
			q.Where(passkey.Active(true))
		}).
		Only(ctx)
	if err != nil {
		return "", handleEntError(err, "failed to get user")
	}

	// Get user's current passkeys
	passkeys := user.Edges.Passkeys
	if len(passkeys) == 0 {
		return "", appErrors.New(appErrors.CodeNotFound, "user has no registered passkeys")
	}

	// Create WebAuthn user
	webAuthnUser := NewWebAuthnUser(user, passkeys)

	// Finish authentication
	credential, err := s.webauthn.FinishLogin(ctx, webAuthnUser, session.Data, req)
	if err != nil {
		return "", fmt.Errorf("failed to finish authentication: %w", err)
	}

	// Find the passkey that was used
	credentialIDStr := base64.RawURLEncoding.EncodeToString(credential.ID)
	var usedPasskey *ent.Passkey
	for _, p := range passkeys {
		if p.CredentialID == credentialIDStr {
			usedPasskey = p
			break
		}
	}

	if usedPasskey == nil {
		return "", appErrors.New(appErrors.CodeNotFound, "passkey not found")
	}

	// Update sign count and last used time
	now := time.Now()
	_, err = s.client.Passkey.
		UpdateOne(usedPasskey).
		SetSignCount(int(credential.Authenticator.SignCount)).
		SetLastUsed(now).
		Save(ctx)
	if err != nil {
		s.logger.Warn("Failed to update passkey",
			logging.String("passkey_id", usedPasskey.ID),
			logging.Error(err),
		)
		// Continue as this is not a critical error
	}

	// Delete session
	if err := s.sessionStore.DeleteSession(ctx, sessionID); err != nil {
		s.logger.Warn("Failed to delete session", logging.Error(err))
		// Continue as this is not a critical error
	}

	// Return the user ID
	return user.ID, nil
}

// GetUserPasskeys retrieves all passkeys for a user
func (s *serviceImpl) GetUserPasskeys(ctx context.Context, userID string) ([]*RegisteredPasskey, error) {
	// Get passkeys for user
	passkeys, err := s.client.Passkey.
		Query().
		Where(
			passkey.UserID(userID),
			passkey.Active(true),
		).
		Order(ent.Desc(passkey.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil, handleEntError(err, "failed to get user passkeys")
	}

	// Convert to response type
	result := make([]*RegisteredPasskey, len(passkeys))
	for i, p := range passkeys {
		result[i] = &RegisteredPasskey{
			ID:           p.ID,
			Name:         p.Name,
			DeviceType:   p.DeviceType,
			RegisteredAt: p.CreatedAt,
		}
		if !p.LastUsed.IsZero() {
			lastUsed := p.LastUsed
			result[i].LastUsed = lastUsed
		}
	}

	return result, nil
}

// UpdatePasskey updates a passkey's name
func (s *serviceImpl) UpdatePasskey(ctx context.Context, passkeyID, userID, name string) error {
	// Verify passkey belongs to user
	passkey, err := s.client.Passkey.
		Query().
		Where(
			passkey.ID(passkeyID),
			passkey.UserID(userID),
		).
		Only(ctx)
	if err != nil {
		return handleEntError(err, "failed to get passkey")
	}

	// Update passkey
	_, err = s.client.Passkey.
		UpdateOne(passkey).
		SetName(name).
		Save(ctx)

	return err
}

// DeletePasskey deletes a passkey
func (s *serviceImpl) DeletePasskey(ctx context.Context, passkeyID, userID string) error {
	// Verify passkey belongs to user
	count, err := s.client.Passkey.
		Query().
		Where(
			passkey.ID(passkeyID),
			passkey.UserID(userID),
		).
		Count(ctx)
	if err != nil {
		return handleEntError(err, "failed to check passkey")
	}

	if count == 0 {
		return appErrors.New(appErrors.CodeNotFound, "passkey not found")
	}

	// Delete passkey
	return s.client.Passkey.
		DeleteOneID(passkeyID).
		Exec(ctx)
}

// handleEntError converts Ent errors to app errors
func handleEntError(err error, message string) error {
	if ent.IsNotFound(err) {
		return appErrors.New(appErrors.CodeNotFound, "resource not found")
	}
	if ent.IsConstraintError(err) {
		return appErrors.New(appErrors.CodeConflict, "resource already exists")
	}
	return appErrors.Wrap(appErrors.CodeInternalServer, err, message)
}
