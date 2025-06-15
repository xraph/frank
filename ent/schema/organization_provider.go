package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/juicycleff/frank/pkg/entity"
	"github.com/rs/xid"
)

// OrganizationProvider holds the schema definition for the OrganizationProvider entity.
type OrganizationProvider struct {
	ent.Schema
}

// Fields of the OrganizationProvider.
func (OrganizationProvider) Fields() []ent.Field {
	return []ent.Field{
		field.String("organization_id").
			GoType(xid.ID{}).
			NotEmpty().
			Comment("Organization ID"),
		field.String("provider_id").
			GoType(xid.ID{}).
			NotEmpty().
			Comment("Identity Provider ID"),
		field.String("template_id").
			GoType(xid.ID{}).
			NotEmpty().
			Comment("Identity Provider ID"),
		field.String("template_key").
			NotEmpty().
			Comment("Template key used for this provider"),
		entity.JSONMapField("custom_config", true),
		field.Time("enabled_at").
			Default(time.Now).
			Comment("When provider was enabled"),
		field.Time("last_used").
			Optional().
			Nillable().
			Comment("Last time provider was used for authentication"),
		field.Int("usage_count").
			Default(0).
			Comment("Number of times provider has been used"),
		field.Bool("enabled").
			Default(true).
			Comment("Whether provider is currently enabled"),
		field.Float("success_rate").
			Default(0.0).
			Comment("Authentication success rate"),
		field.Int("total_logins").
			Default(0).
			Comment("Total number of login attempts"),
		field.Int("successful_logins").
			Default(0).
			Comment("Number of successful logins"),
		field.Int("failed_logins").
			Default(0).
			Comment("Number of failed login attempts"),
		field.Time("last_success").
			Optional().
			Nillable().
			Comment("Last successful authentication"),
		field.Time("last_failure").
			Optional().
			Nillable().
			Comment("Last failed authentication"),
		field.Int("config_errors").
			Default(0).
			Comment("Number of configuration errors"),
		field.Float("average_response_time").
			Default(0.0).
			Comment("Average response time in milliseconds"),
		entity.JSONMapField("analytics_data", true),
		entity.JSONMapField("metadata", true),
	}
}

// Edges of the OrganizationProvider.
func (OrganizationProvider) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("organization", Organization.Type).
			Ref("organization_providers").
			Field("organization_id").
			Unique().
			Required(),
		edge.From("provider", IdentityProvider.Type).
			Ref("organization_providers").
			Field("provider_id").
			Unique().
			Required(),
		edge.From("template", ProviderTemplate.Type).
			Ref("organization_providers").
			Field("template_id").
			Unique().
			Required(),
	}
}

// Indexes of the OrganizationProvider.
func (OrganizationProvider) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("organization_id"),
		index.Fields("provider_id"),
		index.Fields("template_key"),
		index.Fields("template_id"),
		index.Fields("enabled"),
		index.Fields("organization_id", "provider_id").Unique(),
		index.Fields("organization_id", "template_key"),
		index.Fields("organization_id", "template_id"),
		index.Fields("organization_id", "enabled"),
		index.Fields("template_key", "enabled"),
		index.Fields("template_id", "enabled"),
		index.Fields("last_used"),
		index.Fields("usage_count"),
		index.Fields("success_rate"),
		index.Fields("enabled_at"),
	}
}

// Mixin of the OrganizationProvider.
func (OrganizationProvider) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
		TimeMixin{},
		SoftDeleteMixin{},
	}
}
