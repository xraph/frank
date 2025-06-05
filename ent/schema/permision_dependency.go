package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/rs/xid"
)

// PermissionDependency represents dependencies between permissions
// If a user has permission A, they might automatically get permission B
type PermissionDependency struct {
	ent.Schema
}

// Fields of the PermissionDependency.
func (PermissionDependency) Fields() []ent.Field {
	return []ent.Field{
		field.String("permission_id").
			GoType(xid.ID{}).
			NotEmpty().
			Comment("The permission that depends on another"),

		field.String("required_permission_id").
			GoType(xid.ID{}).
			NotEmpty().
			Comment("The permission that is required"),

		field.Enum("dependency_type").
			Values("required", "implied", "conditional").
			Default("required").
			Comment("Type of dependency relationship"),

		field.String("condition").
			Optional().
			Comment("Optional condition for when this dependency applies"),

		field.Bool("active").
			Default(true),

		field.String("created_by").
			Optional().
			Comment("Who created this dependency"),
	}
}

// Edges of the PermissionDependency.
func (PermissionDependency) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("permission", Permission.Type).
			Ref("dependencies").
			Field("permission_id").
			Unique().
			Required(),

		edge.From("required_permission", Permission.Type).
			Ref("dependents").
			Field("required_permission_id").
			Unique().
			Required(),
	}
}

// Indexes of the PermissionDependency.
func (PermissionDependency) Indexes() []ent.Index {
	return []ent.Index{
		// Ensure unique dependency relationships
		index.Fields("permission_id", "required_permission_id").
			Unique(),

		index.Fields("permission_id"),
		index.Fields("required_permission_id"),
		index.Fields("dependency_type"),
		index.Fields("active"),
		index.Fields("created_by"),
	}
}

// Mixin of the PermissionDependency.
func (PermissionDependency) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
		TimeMixin{},
	}
}
