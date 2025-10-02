package contexts

import (
	"context"

	"github.com/rs/xid"
	"github.com/xraph/frank/pkg/errors"
)

// WithOrganizationID adds organization ID to context
func WithOrganizationID(ctx context.Context, orgID xid.ID) context.Context {
	return context.WithValue(ctx, OrganizationIDContextKey, orgID)
}

// WithUserID adds user ID to context
func WithUserID(ctx context.Context, userID xid.ID) context.Context {
	return context.WithValue(ctx, UserContextKey, userID)
}

// GetOrganizationIDFromContextSafe safely retrieves organization ID from context
func GetOrganizationIDFromContextSafe(ctx context.Context) (*xid.ID, error) {
	orgID := GetOrganizationIDFromContext(ctx)
	if orgID == nil {
		return nil, errors.New(errors.CodeUnauthorized, "organization ID not found in context")
	}
	return orgID, nil
}

// GetUserIDFromContextSafe safely retrieves user ID from context
func GetUserIDFromContextSafe(ctx context.Context) (*xid.ID, error) {
	userID := GetUserIDFromContext(ctx)
	if userID == nil {
		return nil, errors.New(errors.CodeUnauthorized, "user ID not found in context")
	}
	return userID, nil
}
