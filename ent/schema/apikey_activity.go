package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/juicycleff/frank/pkg/entity"
	"github.com/rs/xid"
)

// ApiKeyActivity holds the schema definition for the ApiKeyActivity entity.
type ApiKeyActivity struct {
	ent.Schema
}

// Fields of the ApiKeyActivity.
func (ApiKeyActivity) Fields() []ent.Field {
	return []ent.Field{
		field.String("key_id").
			GoType(xid.ID{}).
			NotEmpty(),
		field.String("action").
			NotEmpty().
			Comment("Action performed (api_request, key_created, etc.)"),
		field.String("endpoint").
			Optional().
			Comment("API endpoint called"),
		field.String("method").
			Optional().
			Comment("HTTP method (GET, POST, etc.)"),
		field.Int("status_code").
			Optional().
			Comment("HTTP status code"),
		field.Int("response_time").
			Optional().
			Comment("Response time in milliseconds"),
		field.String("ip_address").
			Optional().
			Comment("Client IP address"),
		field.String("user_agent").
			Optional().
			Comment("Client user agent"),
		field.Bool("success").
			Default(true).
			Comment("Whether the request was successful"),
		field.String("error").
			Optional().
			Comment("Error message if failed"),
		field.Time("timestamp").
			Comment("When the activity occurred"),
		entity.JSONMapField("metadata", true),
		// Comment("Additional activity metadata"),
	}
}

// Edges of the ApiKeyActivity.
func (ApiKeyActivity) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("key", ApiKey.Type).
			Ref("activities").
			Field("key_id").
			Required().
			Unique(),
	}
}

// Indexes of the ApiKeyActivity.
func (ApiKeyActivity) Indexes() []ent.Index {
	return []ent.Index{
		// Primary lookup indexes
		index.Fields("key_id"),
		index.Fields("timestamp"),
		index.Fields("key_id", "timestamp"),

		// Query optimization indexes
		index.Fields("action"),
		index.Fields("endpoint"),
		index.Fields("method"),
		index.Fields("status_code"),
		index.Fields("success"),
		index.Fields("ip_address"),

		// Composite indexes for common queries
		index.Fields("key_id", "action"),
		index.Fields("key_id", "success"),
		index.Fields("key_id", "endpoint"),
		index.Fields("action", "timestamp"),
		index.Fields("success", "timestamp"),

		// Time-based queries
		index.Fields("timestamp", "key_id"),
		index.Fields("timestamp", "action"),
		index.Fields("timestamp", "success"),
	}
}

// Mixin of the ApiKeyActivity.
func (ApiKeyActivity) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
	}
}
