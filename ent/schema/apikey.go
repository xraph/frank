package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/juicycleff/frank/pkg/common"
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
			NotEmpty().
			Comment("Human-readable name for the API key"),
		field.String("key").
			Unique().
			Sensitive().
			Comment("The actual API key value (write-only)"),
		field.String("hashed_key").
			Unique().
			NotEmpty().
			Comment("Hashed version of the API key for secure storage"),
		field.String("user_id").
			GoType(xid.ID{}).
			Optional().
			Comment("User ID if this is a user-scoped key"),
		field.String("organization_id").
			GoType(xid.ID{}).
			Optional().
			Comment("Organization ID for multi-tenant isolation"),
		field.String("type").
			Default("server").
			Comment("Type of API key (server, client, admin)"),
		field.Bool("active").
			Default(true).
			Comment("Whether the API key is active"),
		field.JSON("permissions", []string{}).
			Optional().
			Comment("Granted permissions for this key"),
		field.JSON("scopes", []string{}).
			Optional().
			Comment("API scopes for this key"),
		field.Strings("ip_whitelist").
			Optional().
			Comment("Allowed IP addresses/ranges (CIDR notation)"),
		field.JSON("rate_limits", common.APIKeyRateLimits{}).
			Optional().
			Comment("Rate limiting configuration"),
		entity.JSONMapField("metadata", true),
		// Comment("Additional key metadata"),
		field.Time("last_used").
			Optional().
			Nillable().
			Comment("Last time this key was used"),
		field.Time("expires_at").
			Optional().
			Nillable().
			Comment("When this key expires"),
	}
}

// Edges of the ApiKey.
func (ApiKey) Edges() []ent.Edge {
	return []ent.Edge{
		// Parent relationships
		edge.From("user", User.Type).
			Ref("api_keys").
			Field("user_id").
			Unique(),
		edge.From("organization", Organization.Type).
			Ref("api_keys").
			Field("organization_id").
			Unique(),

		// Child relationships
		edge.To("activities", ApiKeyActivity.Type).
			Comment("Activity logs for this API key"),
	}
}

// Indexes of the ApiKey.
func (ApiKey) Indexes() []ent.Index {
	return []ent.Index{
		// Primary lookup indexes
		index.Fields("user_id"),
		index.Fields("organization_id"),
		index.Fields("hashed_key"),

		// Query optimization indexes
		index.Fields("type"),
		index.Fields("active"),
		index.Fields("expires_at"),
		index.Fields("last_used"),

		// Composite indexes for common queries
		index.Fields("user_id", "active"),
		index.Fields("organization_id", "active"),
		index.Fields("user_id", "type"),
		index.Fields("organization_id", "type"),
		index.Fields("active", "expires_at"),

		// Text search indexes
		index.Fields("name"),

		// Performance indexes for filtering
		index.Fields("created_at"),
		index.Fields("updated_at"),
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
