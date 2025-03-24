package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Permission holds the schema definition for the Permission entity.
type Permission struct {
	ent.Schema
}

// Fields of the Permission.
func (Permission) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").
			Unique().
			NotEmpty(),
		field.String("description").
			NotEmpty(),
		field.String("resource").
			NotEmpty().
			Comment("The resource this permission applies to"),
		field.String("action").
			NotEmpty().
			Comment("The action this permission allows (create, read, update, delete, etc.)"),
		field.String("conditions").
			Optional().
			Comment("JSON expression for conditional access"),
		field.Bool("system").
			Default(false).
			Comment("System permissions cannot be modified"),
	}
}

// Edges of the Permission.
func (Permission) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("roles", Role.Type).
			Ref("permissions"),
	}
}

// Indexes of the Permission.
func (Permission) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("name"),
		index.Fields("resource", "action").
			Unique(),
	}
}

// Mixin of the Permission.
func (Permission) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
	}
}
