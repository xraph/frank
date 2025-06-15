package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// Role holds enhanced role definition that works across user types
type Role struct {
	ent.Schema
}

// Fields of the Role.
func (Role) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").
			NotEmpty().
			Comment("Role name (system_admin, org_owner, app_user, etc.)"),

		field.String("display_name").
			Optional().
			Comment("Human-readable role name"),

		field.String("description").
			Optional(),

		// Context and scope
		field.Enum("role_type").
			GoType(model.RoleType("")).
			Comment("system = platform roles, organization = org roles, application = customer's app roles"),

		field.String("organization_id").
			GoType(xid.ID{}).
			Optional().
			Comment("If set, role is scoped to this organization"),

		field.String("application_id").
			GoType(xid.ID{}).
			Optional().
			Comment("If set, role is scoped to this application (for customer's app roles)"),

		// Role properties
		field.Bool("system").
			Default(false).
			Comment("System roles cannot be modified"),

		field.Bool("is_default").
			Default(false).
			Comment("Default role assigned to new users in this context"),

		field.Int("priority").
			Default(0).
			Comment("Role priority for hierarchy (higher = more powerful)"),

		field.String("color").
			Optional().
			Comment("Color for UI display"),

		// Target user types
		field.JSON("applicable_user_types", []string{}).
			Comment("Which user types this role can be assigned to: ['internal', 'external', 'end_user']"),

		// Creation context
		field.String("created_by").
			Optional().
			Comment("User who created this role"),

		field.Bool("active").
			Default(true),

		// ADDED: Parent role field for hierarchy
		field.String("parent_id").
			GoType(xid.ID{}).
			Optional().
			Comment("Parent role ID for role hierarchy"),
	}
}

// Edges of the Role.
func (Role) Edges() []ent.Edge {
	return []ent.Edge{
		// Context relationships
		edge.From("organization", Organization.Type).
			Ref("roles").
			Field("organization_id").
			Unique(),

		// User assignments through UserRole
		edge.To("user_assignments", UserRole.Type),

		// Direct system role assignments (legacy compatibility)
		edge.From("system_users", User.Type).
			Ref("system_roles"),

		// Permissions
		edge.To("permissions", Permission.Type),

		// ADDED: Memberships edge (referenced by Membership schema)
		edge.To("memberships", Membership.Type),

		// FIXED: Role hierarchy - both edges needed
		edge.From("parent", Role.Type).
			Ref("children").
			Field("parent_id").
			Unique(),

		edge.To("children", Role.Type),
	}
}

// Indexes of the Role.
func (Role) Indexes() []ent.Index {
	return []ent.Index{
		// Role name unique within context
		index.Fields("name", "role_type", "organization_id", "application_id").
			Unique(),

		index.Fields("organization_id"),
		index.Fields("application_id"),
		index.Fields("role_type"),
		index.Fields("system"),
		index.Fields("is_default"),
		index.Fields("priority"),
		index.Fields("active"),
		index.Fields("created_by"),
		index.Fields("parent_id"), // Added index for parent_id

		// Query optimization
		index.Fields("role_type", "organization_id"),
		index.Fields("role_type", "application_id"),
		index.Fields("organization_id", "is_default"),
		index.Fields("parent_id", "active"),
	}
}

// Mixin of the Role.
func (Role) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
		TimeMixin{},
		SoftDeleteMixin{},
	}
}
