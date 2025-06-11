package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/juicycleff/frank/pkg/entity"
	"github.com/rs/xid"
)

// ApiKey holds the schema definition for the ApiKey entity.
type ApiKey struct {
	ent.Schema
}

// Fields of the ApiKey.
func (ApiKey) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").
			NotEmpty(),
		field.String("key").
			Unique().
			Sensitive(),
		field.String("hashed_key").
			Unique().
			NotEmpty(),
		field.String("user_id").
			GoType(xid.ID{}).
			Optional(),
		field.String("organization_id").
			GoType(xid.ID{}).
			Optional(),
		field.String("type").
			Default("server"),
		field.Bool("active").
			Default(true),
		field.JSON("permissions", []string{}).
			Optional(),
		field.JSON("scopes", []string{}).
			Optional(),
		entity.JSONMapField("metadata", true),
		field.Time("last_used").
			Optional().
			Nillable(),
		field.Time("expires_at").
			Optional().
			Nillable(),
	}
}

// Edges of the ApiKey.
func (ApiKey) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("api_keys").
			Field("user_id").
			Unique(),
		edge.From("organization", Organization.Type).
			Ref("api_keys").
			Field("organization_id").
			Unique(),
	}
}

// Indexes of the ApiKey.
func (ApiKey) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id"),
		index.Fields("organization_id"),
		index.Fields("hashed_key"),
	}
}

// Mixin of the ApiKey.
func (ApiKey) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
		TimeMixin{},
		SoftDeleteMixin{},
	}
}
