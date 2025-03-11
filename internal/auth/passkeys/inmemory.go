package passkeys

import (
	"context"
	"sync"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// InMemoryRepository implements the Repository interface with in-memory storage
type InMemoryRepository struct {
	users     map[string]*ent.User
	passkeys  map[string]*ent.Passkey
	idToCred  map[string]string   // Maps passkey ID to credential ID
	credToID  map[string]string   // Maps credential ID to passkey ID
	userToIDs map[string][]string // Maps user ID to passkey IDs
	mutex     sync.RWMutex
	logger    logging.Logger
}

// NewInMemoryRepository creates a new in-memory repository
func NewInMemoryRepository(logger logging.Logger) Repository {
	return &InMemoryRepository{
		users:     make(map[string]*ent.User),
		passkeys:  make(map[string]*ent.Passkey),
		idToCred:  make(map[string]string),
		credToID:  make(map[string]string),
		userToIDs: make(map[string][]string),
		logger:    logger,
	}
}

// GetUserByID retrieves a user by ID
func (r *InMemoryRepository) GetUserByID(ctx context.Context, userID string) (*ent.User, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	user, exists := r.users[userID]
	if !exists {
		return nil, errors.New(errors.CodeUserNotFound, "user not found")
	}

	return user, nil
}

// GetPasskeysByUserID retrieves all passkeys for a user
func (r *InMemoryRepository) GetPasskeysByUserID(ctx context.Context, userID string) ([]*ent.Passkey, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	passkeyIDs, exists := r.userToIDs[userID]
	if !exists {
		return []*ent.Passkey{}, nil
	}

	result := make([]*ent.Passkey, 0, len(passkeyIDs))
	for _, id := range passkeyIDs {
		if passkey, ok := r.passkeys[id]; ok {
			result = append(result, passkey)
		}
	}

	return result, nil
}

// GetPasskeyByCredentialID retrieves a passkey by credential ID
func (r *InMemoryRepository) GetPasskeyByCredentialID(ctx context.Context, credentialID string) (*ent.Passkey, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	passkeyID, exists := r.credToID[credentialID]
	if !exists {
		return nil, errors.New(errors.CodeNotFound, "passkey not found")
	}

	passkey, exists := r.passkeys[passkeyID]
	if !exists {
		return nil, errors.New(errors.CodeNotFound, "passkey not found")
	}

	return passkey, nil
}

// CreatePasskey creates a new passkey
func (r *InMemoryRepository) CreatePasskey(ctx context.Context, create *ent.PasskeyCreate) (*ent.Passkey, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Validate user exists
	userID, _ := create.Mutation().UserID()
	if _, exists := r.users[userID]; !exists {
		return nil, errors.New(errors.CodeUserNotFound, "user not found")
	}

	// Extract values from mutation
	id, _ := create.Mutation().ID()
	name, _ := create.Mutation().Name()
	deviceType, _ := create.Mutation().DeviceType()
	credentialID, _ := create.Mutation().CredentialID()
	publicKey, _ := create.Mutation().PublicKey()
	signCount, _ := create.Mutation().SignCount()
	active, _ := create.Mutation().Active()
	aaguid, _ := create.Mutation().Aaguid()
	transports, _ := create.Mutation().Transports()
	attestation, _ := create.Mutation().Attestation()

	// Check if credential ID already exists
	if _, exists := r.credToID[credentialID]; exists {
		return nil, errors.New(errors.CodeConflict, "passkey with this credential ID already exists")
	}

	// Create passkey
	now := time.Now()
	passkey := &ent.Passkey{
		ID:           id,
		UserID:       userID,
		Name:         name,
		DeviceType:   deviceType,
		CredentialID: credentialID,
		PublicKey:    publicKey,
		SignCount:    signCount,
		Active:       active,
		Aaguid:       aaguid,
		Transports:   transports,
		Attestation:  attestation,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	// Store passkey
	r.passkeys[id] = passkey
	r.idToCred[id] = credentialID
	r.credToID[credentialID] = id
	r.userToIDs[userID] = append(r.userToIDs[userID], id)

	return passkey, nil
}

// UpdatePasskey updates a passkey
func (r *InMemoryRepository) UpdatePasskey(ctx context.Context, passkeyID string, updates *ent.PasskeyUpdateOne) (*ent.Passkey, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	passkey, exists := r.passkeys[passkeyID]
	if !exists {
		return nil, errors.New(errors.CodeNotFound, "passkey not found")
	}

	// Apply updates
	if name, ok := updates.Mutation().Name(); ok {
		passkey.Name = name
	}
	if deviceType, ok := updates.Mutation().DeviceType(); ok {
		passkey.DeviceType = deviceType
	}
	if signCount, ok := updates.Mutation().SignCount(); ok {
		passkey.SignCount = signCount
	}
	if active, ok := updates.Mutation().Active(); ok {
		passkey.Active = active
	}
	if lastUsed, ok := updates.Mutation().LastUsed(); ok {
		passkey.LastUsed = &lastUsed
	}

	// Update timestamp
	passkey.UpdatedAt = time.Now()

	return passkey, nil
}

// DeletePasskey deletes a passkey
func (r *InMemoryRepository) DeletePasskey(ctx context.Context, passkeyID string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	passkey, exists := r.passkeys[passkeyID]
	if !exists {
		return errors.New(errors.CodeNotFound, "passkey not found")
	}

	// Remove from indexes
	delete(r.passkeys, passkeyID)

	credentialID := r.idToCred[passkeyID]
	delete(r.idToCred, passkeyID)
	delete(r.credToID, credentialID)

	// Remove from user's passkeys list
	userID := passkey.UserID
	passkeyIDs := r.userToIDs[userID]
	for i, id := range passkeyIDs {
		if id == passkeyID {
			r.userToIDs[userID] = append(passkeyIDs[:i], passkeyIDs[i+1:]...)
			break
		}
	}

	return nil
}

// AddUser adds a user to the in-memory store (for testing)
func (r *InMemoryRepository) AddUser(user *ent.User) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.users[user.ID] = user
}
