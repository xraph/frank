package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// OAuthScope holds the schema definition for the OAuthScope entity.
type OAuthScope struct {
	ent.Schema
}

// Fields of the OAuthScope.
func (OAuthScope) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").
			Unique().
			NotEmpty(),
		field.String("description").
			NotEmpty(),
		field.Bool("default_scope").
			Default(false).
			Comment("Whether this scope is included by default"),
		field.Bool("public").
			Default(true).
			Comment("Whether this scope can be requested by any client"),
	}
}

// Edges of the OAuthScope.
func (OAuthScope) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("clients", OAuthClient.Type).
			Ref("scopes"),
		edge.From("tokens", OAuthToken.Type).
			Ref("scopes"),
		edge.From("authorizations", OAuthAuthorization.Type).
			Ref("scopes"),
	}
}

// Indexes of the OAuthScope.
func (OAuthScope) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("name"),
	}
}

// Mixin of the OAuthScope.
func (OAuthScope) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
		TimeMixin{},
		SoftDeleteMixin{},
	}
}
