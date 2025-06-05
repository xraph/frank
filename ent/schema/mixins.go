package schema

import (
	"context"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
	"github.com/rs/xid"
)

// ModelBaseMixin implements the ent.Mixin for sharing
// time fields with package schemas.
type ModelBaseMixin struct {
	mixin.Schema
}

func (ModelBaseMixin) Fields() []ent.Field {
	return []ent.Field{

		field.String("id").
			GoType(xid.ID{}).
			DefaultFunc(newXID).
			Immutable().
			Unique().
			Comment("ID of the entity"),
	}
}

// Hooks returns the hooks of the ModelBaseMixin.
func (ModelBaseMixin) Hooks() []ent.Hook {
	return []ent.Hook{
		// Hook to set the ID on creation
		// IDHook(),
	}
}

// IDHook ensures XID ID generation for new entities
func IDHook() ent.Hook {
	return func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			// Only run on create operations
			if !m.Op().Is(ent.OpCreate) {
				return next.Mutate(ctx, m)
			}

			// Get ID and check if it's zero value
			id, exists := m.Field("id")
			isZero := false
			if exists {
				if idStr, ok := id.(xid.ID); ok && idStr.IsNil() {
					isZero = true
				}
			} else {
				isZero = true
			}

			// Generate a new ID if needed
			if isZero || !exists {
				if err := m.SetField("id", newXID()); err != nil {
					return nil, err
				}
			}

			return next.Mutate(ctx, m)
		})
	}
}

// newXID generates a new XID
func newXID() xid.ID {
	return xid.New()
}

// TimeMixin implements the ent.Mixin for sharing
// time fields with package schemas.
type TimeMixin struct {
	mixin.Schema
}

// Fields of the TimeMixin.
func (TimeMixin) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}
