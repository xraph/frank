package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/rs/xid"
	"github.com/xraph/frank/pkg/common"
	"github.com/xraph/frank/pkg/entity"
	"github.com/xraph/frank/pkg/model"
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

		// Public key (safe to display)
		field.String("public_key").
			Unique().
			NotEmpty().
			Comment("Public API key (safe to display, used for identification)"),

		// Secret key (sensitive, used for authentication)
		field.String("secret_key").
			Unique().
			Sensitive().
			Comment("Secret API key value (write-only, used for authentication)"),

		// Hashed secret key for secure storage
		field.String("hashed_secret_key").
			Unique().
			NotEmpty().
			Comment("Hashed version of the secret key for secure storage"),

		// Legacy support - will be deprecated
		field.String("key").
			Unique().
			Sensitive().
			Optional().
			Comment("Legacy API key field (deprecated, use secret_key instead)"),
		field.String("hashed_key").
			Unique().
			Optional().
			Comment("Legacy hashed key field (deprecated, use hashed_secret_key instead)"),

		field.String("user_id").
			GoType(xid.ID{}).
			Optional().
			Comment("User ID if this is a user-scoped key"),
		field.String("organization_id").
			GoType(xid.ID{}).
			Optional().
			Comment("Organization ID for multi-tenant isolation"),
		field.Enum("type").
			GoType(model.APIKeyType("")).
			Default(model.APIKeyTypeServer.String()).
			Comment("Type of API key (server, client, admin)"),
		field.Enum("environment").
			GoType(model.Environment("")).
			Default(model.EnvironmentTest.String()).
			Comment("Environment type (test, live)"),
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
		index.Fields("public_key"),
		index.Fields("hashed_secret_key"),

		// Legacy support indexes
		index.Fields("hashed_key"),

		// Query optimization indexes
		index.Fields("type"),
		index.Fields("environment"),
		index.Fields("active"),
		index.Fields("expires_at"),
		index.Fields("last_used"),

		// Composite indexes for common queries
		index.Fields("user_id", "active"),
		index.Fields("organization_id", "active"),
		index.Fields("user_id", "type"),
		index.Fields("organization_id", "type"),
		index.Fields("user_id", "environment"),
		index.Fields("organization_id", "environment"),
		index.Fields("active", "expires_at"),
		index.Fields("type", "environment"),

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
