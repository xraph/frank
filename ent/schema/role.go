package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Role holds the schema definition for the Role entity.
type Role struct {
	ent.Schema
}

// Fields of the Role.
func (Role) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			Unique(),
		field.String("name").
			NotEmpty(),
		field.String("description").
			Optional(),
		field.String("organization_id").
			Optional(),
		field.Bool("system").
			Default(false).
			Immutable().
			Comment("System roles cannot be modified"),
		field.Bool("is_default").
			Default(false).
			Comment("Default role assigned to new users"),
	}
}

// Edges of the Role.
func (Role) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("users", User.Type).
			Ref("roles"),
		edge.To("permissions", Permission.Type),
	}
}

// Indexes of the Role.
func (Role) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("organization_id"),
		index.Fields("organization_id", "name").
			Unique(),
	}
}

// Mixin of the Role.
func (Role) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
	}
}
