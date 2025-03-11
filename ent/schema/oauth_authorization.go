package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// OAuthAuthorization holds the schema definition for the OAuthAuthorization entity.
type OAuthAuthorization struct {
	ent.Schema
}

// Fields of the OAuthAuthorization.
func (OAuthAuthorization) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			Unique(),
		field.String("client_id").
			NotEmpty(),
		field.String("user_id").
			NotEmpty(),
		field.String("organization_id").
			Optional(),
		field.String("code").
			Unique().
			Optional().
			Sensitive(),
		field.String("code_challenge").
			Optional(),
		field.String("code_challenge_method").
			Optional(),
		field.String("redirect_uri").
			NotEmpty(),
		field.Strings("scope_names").
			Optional().
			Comment("Scope names as strings for quick access"),
		field.Bool("used").
			Default(false),
		field.Time("used_at").Nillable(),
		field.Time("expires_at"),
		field.String("state").
			Optional(),
		field.String("nonce").
			Optional(),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Edges of the OAuthAuthorization.
func (OAuthAuthorization) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("client", OAuthClient.Type).
			Ref("authorizations").
			Field("client_id").
			Unique().
			Required(),
		edge.From("user", User.Type).
			Ref("oauth_authorizations").
			Unique().
			Field("user_id").
			Required(),
		edge.To("scopes", OAuthScope.Type),
	}
}

// Indexes of the OAuthAuthorization.
func (OAuthAuthorization) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("code"),
		index.Fields("client_id"),
		index.Fields("user_id"),
		index.Fields("organization_id"),
		index.Fields("expires_at"),
	}
}
