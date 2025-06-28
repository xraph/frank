package repository

import (
	"context"
	"time"

	"github.com/rs/xid"
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/ent/ssostate"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/model"
)

// SSOStateRepository defines the interface for SSO state data operations
type SSOStateRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, input CreateSSOStateInput) (*ent.SSOState, error)
	GetByID(ctx context.Context, id xid.ID) (*ent.SSOState, error)
	GetByState(ctx context.Context, state string) (*ent.SSOState, error)
	Update(ctx context.Context, id xid.ID, input UpdateSSOStateInput) (*ent.SSOState, error)
	Delete(ctx context.Context, id xid.ID) error
	DeleteByState(ctx context.Context, state string) error

	// Query operations
	List(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.SSOState], error)
	ListExpired(ctx context.Context, before time.Time) ([]*ent.SSOState, error)

	// Utility operations
	CleanupExpired(ctx context.Context, before time.Time) (int, error)
	IsValid(ctx context.Context, state string) (bool, error)
	Count(ctx context.Context) (int, error)

	// Advanced queries
	GetValidState(ctx context.Context, state string) (*ent.SSOState, error)
	ListExpiringBefore(ctx context.Context, before time.Time, limit int) ([]*ent.SSOState, error)
}

// ssoStateRepository implements SSOStateRepository interface
type ssoStateRepository struct {
	client *ent.Client
}

// NewSSOStateRepository creates a new SSO state repository
func NewSSOStateRepository(client *ent.Client) SSOStateRepository {
	return &ssoStateRepository{
		client: client,
	}
}

// CreateSSOStateInput defines the input for creating an SSO state
type CreateSSOStateInput struct {
	State       string    `json:"state"`
	Data        string    `json:"data"`
	ExpiresAt   time.Time `json:"expires_at"`
	ProviderID  xid.ID    `json:"provider_id"`
	RedirectURL string    `json:"redirect_url"`
}

// UpdateSSOStateInput defines the input for updating an SSO state
type UpdateSSOStateInput struct {
	Data      *string    `json:"data,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// Create creates a new SSO state
func (r *ssoStateRepository) Create(ctx context.Context, input CreateSSOStateInput) (*ent.SSOState, error) {
	ssoState, err := r.client.SSOState.Create().
		SetState(input.State).
		SetData(input.Data).
		SetExpiresAt(input.ExpiresAt).
		Save(ctx)

	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, errors.New(errors.CodeConflict, "SSO state with this token already exists")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to create SSO state")
	}

	return ssoState, nil
}

// GetByID retrieves an SSO state by its ID
func (r *ssoStateRepository) GetByID(ctx context.Context, id xid.ID) (*ent.SSOState, error) {
	ssoState, err := r.client.SSOState.
		Query().
		Where(ssostate.ID(id)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "SSO state not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get SSO state")
	}

	return ssoState, nil
}

// GetByState retrieves an SSO state by its state token
func (r *ssoStateRepository) GetByState(ctx context.Context, state string) (*ent.SSOState, error) {
	ssoState, err := r.client.SSOState.
		Query().
		Where(ssostate.State(state)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "SSO state not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get SSO state by token")
	}

	return ssoState, nil
}

// Update updates an SSO state
func (r *ssoStateRepository) Update(ctx context.Context, id xid.ID, input UpdateSSOStateInput) (*ent.SSOState, error) {
	builder := r.client.SSOState.UpdateOneID(id)

	if input.Data != nil {
		builder.SetData(*input.Data)
	}

	if input.ExpiresAt != nil {
		builder.SetExpiresAt(*input.ExpiresAt)
	}

	ssoState, err := builder.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "SSO state not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to update SSO state")
	}

	return ssoState, nil
}

// Delete deletes an SSO state
func (r *ssoStateRepository) Delete(ctx context.Context, id xid.ID) error {
	err := r.client.SSOState.DeleteOneID(id).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "SSO state not found")
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to delete SSO state")
	}

	return nil
}

// DeleteByState deletes an SSO state by its state token
func (r *ssoStateRepository) DeleteByState(ctx context.Context, state string) error {
	_, err := r.client.SSOState.
		Delete().
		Where(ssostate.State(state)).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "Failed to delete SSO state by token")
	}

	return nil
}

// List retrieves paginated SSO states
func (r *ssoStateRepository) List(ctx context.Context, opts model.PaginationParams) (*model.PaginatedOutput[*ent.SSOState], error) {
	query := r.client.SSOState.Query()

	// Apply ordering
	query.Order(ent.Desc(ssostate.FieldCreatedAt))

	result, err := model.WithPaginationAndOptions[*ent.SSOState, *ent.SSOStateQuery](ctx, query, opts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list SSO states")
	}

	return result, nil
}

// ListExpired retrieves SSO states that have expired before the given time
func (r *ssoStateRepository) ListExpired(ctx context.Context, before time.Time) ([]*ent.SSOState, error) {
	ssoStates, err := r.client.SSOState.
		Query().
		Where(ssostate.ExpiresAtLT(before)).
		Order(ent.Asc(ssostate.FieldExpiresAt)).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list expired SSO states")
	}

	return ssoStates, nil
}

// CleanupExpired deletes SSO states that have expired before the given time
func (r *ssoStateRepository) CleanupExpired(ctx context.Context, before time.Time) (int, error) {
	count, err := r.client.SSOState.
		Delete().
		Where(ssostate.ExpiresAtLT(before)).
		Exec(ctx)

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to cleanup expired SSO states")
	}

	return count, nil
}

// IsValid checks if an SSO state token is valid (exists and not expired)
func (r *ssoStateRepository) IsValid(ctx context.Context, state string) (bool, error) {
	count, err := r.client.SSOState.
		Query().
		Where(
			ssostate.State(state),
			ssostate.ExpiresAtGT(time.Now()),
		).
		Count(ctx)

	if err != nil {
		return false, errors.Wrap(err, errors.CodeDatabaseError, "Failed to check SSO state validity")
	}

	return count > 0, nil
}

// Count counts the total number of SSO states
func (r *ssoStateRepository) Count(ctx context.Context) (int, error) {
	count, err := r.client.SSOState.Query().Count(ctx)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "Failed to count SSO states")
	}

	return count, nil
}

// GetValidState retrieves a valid (non-expired) SSO state by its token
func (r *ssoStateRepository) GetValidState(ctx context.Context, state string) (*ent.SSOState, error) {
	ssoState, err := r.client.SSOState.
		Query().
		Where(
			ssostate.State(state),
			ssostate.ExpiresAtGT(time.Now()),
		).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "Valid SSO state not found")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to get valid SSO state")
	}

	return ssoState, nil
}

// ListExpiringBefore retrieves SSO states that will expire before the given time
func (r *ssoStateRepository) ListExpiringBefore(ctx context.Context, before time.Time, limit int) ([]*ent.SSOState, error) {
	ssoStates, err := r.client.SSOState.
		Query().
		Where(
			ssostate.ExpiresAtLT(before),
			ssostate.ExpiresAtGT(time.Now()), // Not already expired
		).
		Order(ent.Asc(ssostate.FieldExpiresAt)).
		Limit(limit).
		All(ctx)

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "Failed to list expiring SSO states")
	}

	return ssoStates, nil
}
