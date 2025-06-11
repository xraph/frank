package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Permission holds enhanced permission definition
type Permission struct {
	ent.Schema
}

// Fields of the Permission.
func (Permission) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").
			Unique().
			NotEmpty().
			Comment("Permission identifier (e.g., 'create:user', 'view:billing')"),

		field.String("display_name").
			Optional().
			Comment("Human-readable permission name"),

		field.String("description").
			NotEmpty(),

		field.String("resource").
			NotEmpty().
			Comment("The resource this permission applies to"),

		field.String("action").
			NotEmpty().
			Comment("The action this permission allows (create, read, update, delete, etc.)"),

		// Permission categorization
		field.Enum("category").
			Values("platform", "organization", "application", "resource").
			Comment("Category helps organize permissions by scope"),

		field.JSON("applicable_user_types", []string{}).
			Comment("Which user types this permission can apply to"),

		field.JSON("applicable_contexts", []string{}).
			Comment("Which contexts this permission can be used in"),

		// Permission properties
		field.String("conditions").
			Optional().
			Comment("JSON expression for conditional access"),

		field.Bool("system").
			Default(false).
			Comment("System permissions cannot be modified"),

		field.Bool("dangerous").
			Default(false).
			Comment("Dangerous permissions require extra confirmation"),

		field.Int("risk_level").
			Default(1).
			Comment("Risk level 1-5 for auditing and approval workflows"),

		// Metadata
		field.String("created_by").
			Optional().
			Comment("User who created this permission"),

		field.Bool("active").
			Default(true),

		// Grouping and organization
		field.String("permission_group").
			Optional().
			Comment("Group permissions by feature (e.g., 'user_management', 'billing')"),
	}
}

// Edges of the Permission.
func (Permission) Edges() []ent.Edge {
	return []ent.Edge{
		// Role assignments
		edge.From("roles", Role.Type).
			Ref("permissions"),

		// Direct user assignments
		edge.To("user_assignments", UserPermission.Type),

		// Permission dependencies through PermissionDependency entity
		edge.To("dependencies", PermissionDependency.Type).
			Comment("Permissions this permission depends on"),

		edge.To("dependents", PermissionDependency.Type).
			Comment("Permissions that depend on this permission"),

		// // Permission dependencies (optional)
		edge.To("required_permissions", Permission.Type).
			From("dependent_permissions"),

		// edge.From("dependent_permissions", Permission.Type).
		// 	Ref("required_permissions"),
	}
}

// Indexes of the Permission.
func (Permission) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("name"),
		index.Fields("resource", "action").
			Unique(),
		index.Fields("category"),
		index.Fields("system"),
		index.Fields("dangerous"),
		index.Fields("risk_level"),
		index.Fields("active"),
		index.Fields("permission_group"),
		index.Fields("created_by"),
	}
}

// Mixin of the Permission.
func (Permission) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
		TimeMixin{},
		SoftDeleteMixin{},
	}
}
