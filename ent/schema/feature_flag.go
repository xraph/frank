package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// FeatureFlag holds the schema definition for the FeatureFlag entity.
type FeatureFlag struct {
	ent.Schema
}

// Fields of the FeatureFlag.
func (FeatureFlag) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").
			Unique().
			NotEmpty(),
		field.String("key").
			Unique().
			NotEmpty(),
		field.String("description").
			Optional(),
		field.Bool("enabled").
			Default(false),
		field.Bool("is_premium").
			Default(false).
			Comment("Whether this feature is only available for premium plans"),
		field.Enum("component").
			Values(
				"oauth2",
				"passwordless",
				"mfa",
				"passkeys",
				"sso",
				"enterprise",
				"webhooks",
				"api_keys",
			).
			Comment("Which component of the auth system this feature belongs to"),
	}
}

// Edges of the FeatureFlag.
func (FeatureFlag) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("organization_features", OrganizationFeature.Type),
	}
}

// Indexes of the FeatureFlag.
func (FeatureFlag) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("key"),
		index.Fields("component"),
	}
}

// Mixin of the FeatureFlag.
func (FeatureFlag) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
		TimeMixin{},
		SoftDeleteMixin{},
	}
}
