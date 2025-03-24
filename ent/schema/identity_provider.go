package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/juicycleff/frank/pkg/entity"
)

// IdentityProvider holds the schema definition for the IdentityProvider entity.
type IdentityProvider struct {
	ent.Schema
}

// Fields of the IdentityProvider.
func (IdentityProvider) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").
			NotEmpty(),
		field.String("organization_id").
			NotEmpty(),
		field.String("provider_type").
			NotEmpty().
			Comment("Type of IdP: 'oauth2', 'oidc', 'saml'"),
		field.String("client_id").
			Optional(),
		field.String("client_secret").
			Optional().
			Sensitive(),
		field.String("issuer").
			Optional(),
		field.String("authorization_endpoint").
			Optional(),
		field.String("token_endpoint").
			Optional(),
		field.String("userinfo_endpoint").
			Optional(),
		field.String("jwks_uri").
			Optional(),
		field.String("metadata_url").
			Optional(),
		field.String("redirect_uri").
			Optional(),
		field.String("certificate").
			Optional().
			Sensitive(),
		field.String("private_key").
			Optional().
			Sensitive(),
		field.Bool("active").
			Default(true),
		field.Bool("primary").
			Default(false),
		field.Strings("domains").
			Optional(),
		entity.JSONMapStringField("attributes_mapping", true),
		entity.JSONMapField("metadata", true),
	}
}

// Edges of the IdentityProvider.
func (IdentityProvider) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("organization", Organization.Type).
			Ref("identity_providers").
			Field("organization_id").
			Unique().
			Required(),
	}
}

// Indexes of the IdentityProvider.
func (IdentityProvider) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("organization_id"),
		index.Fields("provider_type"),
	}
}

// Mixin of the IdentityProvider.
func (IdentityProvider) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
	}
}
