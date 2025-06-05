package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/rs/xid"
)

// UserPermission represents direct permission assignments to users
// This allows for granular permission control beyond role-based permissions
type UserPermission struct {
	ent.Schema
}

// Fields of the UserPermission.
func (UserPermission) Fields() []ent.Field {
	return []ent.Field{
		field.String("user_id").
			GoType(xid.ID{}).
			NotEmpty(),
		field.String("permission_id").
			GoType(xid.ID{}).
			NotEmpty(),

		// Context and scope (similar to UserRole)
		field.Enum("context_type").
			Values("system", "organization", "application", "resource").
			Comment("Scope where this permission applies"),

		field.String("context_id").
			GoType(xid.ID{}).
			Optional().
			Comment("ID of the context"),

		// Resource-specific permissions
		field.String("resource_type").
			Optional().
			Comment("Specific resource type this permission applies to"),

		field.String("resource_id").
			GoType(xid.ID{}).
			Optional().
			Comment("Specific resource instance this permission applies to"),

		// Permission type
		field.Enum("permission_type").
			Values("grant", "deny").
			Default("grant").
			Comment("Whether this grants or explicitly denies the permission"),

		// Assignment metadata
		field.String("assigned_by").
			GoType(xid.ID{}).
			Optional().
			Comment("Who assigned this permission (field-only, no edge)"),

		field.Time("assigned_at").
			Default(time.Now),

		field.Time("expires_at").
			Optional().
			Nillable().
			Comment("When this permission expires"),

		field.Bool("active").
			Default(true),

		// Conditions for conditional permissions
		field.JSON("conditions", map[string]interface{}{}).
			Optional().
			Comment("Optional conditions for when this permission applies"),

		field.String("reason").
			Optional().
			Comment("Reason for granting/denying this permission"),
	}
}

// Edges of the UserPermission.
func (UserPermission) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("user_permissions").
			Field("user_id").
			Unique().
			Required(),

		edge.From("permission", Permission.Type).
			Ref("user_assignments").
			Field("permission_id").
			Unique().
			Required(),

		// FIXED: assigned_by relationship (references the assigned_user_permissions edge in User)
		edge.From("assigned_by_user", User.Type).
			Ref("assigned_user_permissions").
			Field("assigned_by").
			Unique(),

		// Context relationships
		edge.To("organization_context", Organization.Type).
			Field("context_id").
			Unique(),
	}
}

// Indexes of the UserPermission.
func (UserPermission) Indexes() []ent.Index {
	return []ent.Index{
		// User can have same permission only once per context and resource
		index.Fields("user_id", "permission_id", "context_type", "context_id", "resource_type", "resource_id").
			Unique(),

		index.Fields("user_id"),
		index.Fields("permission_id"),
		index.Fields("context_type"),
		index.Fields("context_id"),
		index.Fields("resource_type"),
		index.Fields("resource_id"),
		index.Fields("permission_type"),
		index.Fields("active"),
		index.Fields("expires_at"),
		index.Fields("assigned_by"),

		// Query optimization
		index.Fields("user_id", "context_type", "context_id"),
		index.Fields("user_id", "resource_type", "resource_id"),
		index.Fields("context_type", "context_id", "active"),
	}
}

// Mixin of the UserPermission.
func (UserPermission) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
		TimeMixin{},
	}
}
