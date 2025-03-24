package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/juicycleff/frank/pkg/entity"
)

// User holds the schema definition for the User entity.
type User struct {
	ent.Schema
}

// Fields of the User.
func (User) Fields() []ent.Field {
	return []ent.Field{
		field.String("email").
			NotEmpty().
			Unique(),
		field.String("phone_number").
			Optional(),
		field.String("first_name").
			Optional(),
		field.String("last_name").
			Optional(),
		field.String("password_hash").
			Optional().
			Sensitive(),
		field.Bool("email_verified").
			Default(false),
		field.Bool("phone_verified").
			Default(false),
		field.Bool("active").
			Default(true),
		field.Time("last_login").
			Optional().
			Nillable(),
		field.Time("last_password_change").
			Optional().
			Nillable(),
		entity.JSONMapField("metadata", true),
		field.String("profile_image_url").
			Optional(),
		field.String("primary_organization_id").
			Optional(),
		field.String("locale").
			Default("en"),
	}
}

// Edges of the User.
func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("sessions", Session.Type),
		edge.To("api_keys", ApiKey.Type),
		edge.From("organizations", Organization.Type).
			Ref("users"),
		edge.To("mfa_methods", MFA.Type),
		edge.To("passkeys", Passkey.Type),
		edge.To("oauth_tokens", OAuthToken.Type),
		edge.To("oauth_authorizations", OAuthAuthorization.Type),
		edge.To("verifications", Verification.Type),
		edge.To("roles", Role.Type),
	}
}

// Indexes of the User.
func (User) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("email"),
		index.Fields("phone_number").
			Unique(),
	}
}

// Mixin of the User.
func (User) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
	}
}
