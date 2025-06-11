package schema

import (
	"context"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
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

// SoftDeleteMixin implements the soft delete pattern for schemas.
type SoftDeleteMixin struct {
	mixin.Schema
}

// Fields of the SoftDeleteMixin.
func (SoftDeleteMixin) Fields() []ent.Field {
	return []ent.Field{
		field.Time("deleted_at").
			Optional(),
	}
}

type softDeleteKey struct{}

// SkipSoftDelete returns a new context that skips the soft-delete interceptor/mutators.
func SkipSoftDelete(parent context.Context) context.Context {
	return context.WithValue(parent, softDeleteKey{}, true)
}

// Interceptors of the SoftDeleteMixin.
func (d SoftDeleteMixin) Interceptors() []ent.Interceptor {
	return []ent.Interceptor{
		// intercept.TraverseFunc(func(ctx context.Context, q intercept.Query) error {
		// 	// Skip soft-delete, means include soft-deleted entities.
		// 	if skip, _ := ctx.Value(softDeleteKey{}).(bool); skip {
		// 		return nil
		// 	}
		// 	d.P(q)
		// 	return nil
		// }),
	}
}

// Hooks of the SoftDeleteMixin.
func (d SoftDeleteMixin) Hooks() []ent.Hook {
	return []ent.Hook{
		// 	func(next ent.Mutator) ent.Mutator {
		// 		type SoftDeleteEntity interface {
		// 			SetOp(ent.Op)
		// 			Client() *entl.Client
		// 			SetDeletedAt(time.Time)
		// 			WhereP(...func(*sql.Selector))
		// 		}
		// 		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
		// 			// Skip soft-delete, means delete the entity permanently.
		// 			if skip, _ := ctx.Value(softDeleteKey{}).(bool); skip {
		// 				return next.Mutate(ctx, m)
		// 			}
		//
		// 			ml, ok := m.(SoftDeleteEntity)
		// 			if !ok {
		// 				return nil, fmt.Errorf("unexpected mutation type %T", m)
		// 			}
		// 			switch op := m.Op(); {
		// 			case op.Is(ent.OpDeleteOne | ent.OpDelete):
		// 				d.P(ml)
		// 				ml.SetOp(ent.OpUpdate)
		// 				ml.SetDeletedAt(time.Now())
		// 			}
		// 			return next.Mutate(ctx, m)
		// 		})
		// 	},
	}
}

// P adds a storage-level predicate to the queries and mutations.
func (d SoftDeleteMixin) P(w interface{ WhereP(...func(*sql.Selector)) }) {
	w.WhereP(
		sql.FieldIsNull(d.Fields()[0].Descriptor().Name),
	)
}
