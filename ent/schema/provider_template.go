package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/juicycleff/frank/pkg/entity"
)

// ProviderTemplate holds the schema definition for the ProviderTemplate entity.
type ProviderTemplate struct {
	ent.Schema
}

// Fields of the ProviderTemplate.
func (ProviderTemplate) Fields() []ent.Field {
	return []ent.Field{
		field.String("key").
			Unique().
			NotEmpty().
			Comment("Unique template key (e.g., 'google', 'microsoft')"),
		field.String("name").
			NotEmpty().
			Comment("Provider name (e.g., 'Google', 'Microsoft')"),
		field.String("display_name").
			NotEmpty().
			Comment("Display name for UI (e.g., 'Sign in with Google')"),
		field.String("type").
			NotEmpty().
			Comment("Provider type (oidc, oauth2, saml)"),
		field.String("protocol").
			NotEmpty().
			Comment("Authentication protocol"),
		field.String("icon_url").
			Optional().
			Comment("URL to provider icon"),
		field.String("category").
			Default("general").
			Comment("Provider category (social, enterprise, developer, etc.)"),
		field.Bool("popular").
			Default(false).
			Comment("Whether this is a popular provider"),
		field.Bool("active").
			Default(true).
			Comment("Whether template is active"),
		field.Text("description").
			Optional().
			Comment("Provider description"),
		entity.JSONMapField("config_template", false),
		field.JSON("required_fields", []string{}).
			Optional().
			Comment("Required configuration fields"),
		field.JSON("supported_features", []string{}).
			Optional().
			Comment("Supported features list"),
		field.String("documentation_url").
			Optional().
			Comment("Link to provider documentation"),
		field.String("setup_guide_url").
			Optional().
			Comment("Link to setup guide"),
		field.Int("usage_count").
			Default(0).
			Comment("Number of organizations using this template"),
		field.Float("average_setup_time").
			Optional().
			Comment("Average setup time in minutes"),
		field.Float("success_rate").
			Default(0.0).
			Comment("Setup success rate percentage"),
		field.Int("popularity_rank").
			Default(0).
			Comment("Popularity ranking"),
		entity.JSONMapField("metadata", true),
	}
}

// Edges of the ProviderTemplate.
func (ProviderTemplate) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("organization_providers", OrganizationProvider.Type),
	}
}

// Indexes of the ProviderTemplate.
func (ProviderTemplate) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("key").Unique(),
		index.Fields("category"),
		index.Fields("type"),
		index.Fields("popular"),
		index.Fields("active"),
		index.Fields("popularity_rank"),
		index.Fields("category", "popular"),
		index.Fields("type", "active"),
	}
}

// Mixin of the ProviderTemplate.
func (ProviderTemplate) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
		TimeMixin{},
		SoftDeleteMixin{},
	}
}
