package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// OAuthClient holds the schema definition for the OAuthClient entity.
type OAuthClient struct {
	ent.Schema
}

// Fields of the OAuthClient.
func (OAuthClient) Fields() []ent.Field {
	return []ent.Field{
		field.String("client_id").
			Unique().
			NotEmpty(),
		field.String("client_secret").
			NotEmpty().
			Sensitive(),
		field.String("client_name").
			NotEmpty(),
		field.String("client_description").
			Optional(),
		field.String("client_uri").
			Optional(),
		field.String("logo_uri").
			Optional(),
		field.Strings("redirect_uris"),
		field.Strings("post_logout_redirect_uris").
			Optional(),
		field.String("organization_id").
			Optional(),
		field.Bool("public").
			Default(false).
			Comment("Public clients operate without a client secret"),
		field.Bool("active").
			Default(true),
		field.Strings("allowed_cors_origins").
			Optional(),
		field.Strings("allowed_grant_types").
			Default([]string{"authorization_code", "refresh_token"}),
		field.Int("token_expiry_seconds").
			Default(3600),
		field.Int("refresh_token_expiry_seconds").
			Default(86400 * 30), // 30 days
		field.Int("auth_code_expiry_seconds").
			Default(600), // 10 minutes
		field.Bool("requires_pkce").
			Default(true).
			Comment("Enforce PKCE (Proof Key for Code Exchange)"),
		field.Bool("requires_consent").
			Default(true).
			Comment("Require user consent before authorization"),
	}
}

// Edges of the OAuthClient.
func (OAuthClient) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("organization", Organization.Type).
			Ref("oauth_clients").
			Field("organization_id").
			Unique(),
		edge.To("tokens", OAuthToken.Type),
		edge.To("authorizations", OAuthAuthorization.Type),
		edge.To("scopes", OAuthScope.Type),
	}
}

// Indexes of the OAuthClient.
func (OAuthClient) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("client_id"),
		index.Fields("organization_id"),
	}
}

// Mixin of the OAuthClient.
func (OAuthClient) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
	}
}
