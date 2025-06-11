package contexts

import (
	"context"

	"github.com/rs/xid"
)

// GetUserIDFromContext retrieves the user ID from request context
func GetUserIDFromContext(ctx context.Context) *xid.ID {
	if userID, ok := ctx.Value(UserIDContextKey).(xid.ID); ok {
		return &userID
	}
	return nil
}
