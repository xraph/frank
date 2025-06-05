package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/rs/xid"
)

// UserRole represents context-aware role assignments
// Handles roles for all user types in their appropriate contexts
type UserRole struct {
	ent.Schema
}

// Fields of the UserRole.
func (UserRole) Fields() []ent.Field {
	return []ent.Field{
		field.String("user_id").
			GoType(xid.ID{}).
			NotEmpty(),
		field.String("role_id").
			GoType(xid.ID{}).
			NotEmpty(),

		// Context fields - determine the scope of this role assignment
		field.Enum("context_type").
			Values("system", "organization", "application").
			Comment("system = platform-wide, organization = org-specific, application = customer's app"),

		field.String("context_id").
			GoType(xid.ID{}).
			Optional().
			Comment("ID of the context (org_id for org context, app_id for app context, null for system)"),

		// Role assignment metadata
		field.String("assigned_by").
			GoType(xid.ID{}).
			Optional().
			Comment("Who assigned this role (field-only, no edge)"),

		field.Time("assigned_at").
			Default(time.Now),

		field.Time("expires_at").
			Optional().
			Nillable().
			Comment("When this role assignment expires (optional)"),

		field.Bool("active").
			Default(true),

		// Additional metadata
		field.JSON("conditions", map[string]interface{}{}).
			Optional().
			Comment("Optional conditions for when this role applies"),
	}
}

// Edges of the UserRole.
func (UserRole) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("user_roles").
			Field("user_id").
			Unique().
			Required(),

		edge.From("role", Role.Type).
			Ref("user_assignments").
			Field("role_id").
			Unique().
			Required(),

		// Context relationships
		edge.To("organization_context", Organization.Type).
			Field("context_id").
			Unique(),

		// FIXED: assigned_by relationship (references the assigned_user_roles edge in User)
		edge.From("assigned_by_user", User.Type).
			Ref("assigned_user_roles").
			Field("assigned_by").
			Unique(),
	}
}

// Indexes of the UserRole.
func (UserRole) Indexes() []ent.Index {
	return []ent.Index{
		// User can have same role only once per context
		index.Fields("user_id", "role_id", "context_type", "context_id").
			Unique(),

		index.Fields("user_id"),
		index.Fields("role_id"),
		index.Fields("context_type"),
		index.Fields("context_id"),
		index.Fields("active"),
		index.Fields("expires_at"),
		index.Fields("assigned_by"),

		// Query optimization indexes
		index.Fields("user_id", "context_type", "context_id"),
		index.Fields("context_type", "context_id"),
	}
}

// Mixin of the UserRole.
func (UserRole) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
		TimeMixin{},
	}
}
