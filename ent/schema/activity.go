package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/rs/xid"
	"github.com/xraph/frank/pkg/entity"
	"github.com/xraph/frank/pkg/model"
)

// Activity holds the schema definition for the generic Activity entity.
// This can track activities for ANY resource type (API keys, users, organizations, etc.)
type Activity struct {
	ent.Schema
}

// Fields of the Activity.
func (Activity) Fields() []ent.Field {
	return []ent.Field{
		field.Enum("resource_type").
			GoType(model.ResourceType("")).
			Default(model.ResourceCommon.String()).
			Comment("Type of resource (api_key, user, organization, session, etc.)"),

		field.String("resource_id").
			GoType(xid.ID{}).
			NotEmpty().
			Comment("ID of the specific resource"),

		// WHO/WHERE context
		field.String("user_id").
			GoType(xid.ID{}).
			Optional().
			Comment("User who triggered this activity (if applicable)"),
		field.String("organization_id").
			GoType(xid.ID{}).
			Optional().
			Comment("Organization context"),
		field.String("session_id").
			GoType(xid.ID{}).
			Optional().
			Comment("Session context (if applicable)"),

		// WHAT happened
		field.String("action").
			NotEmpty().
			Comment("Action performed (request, login, create, update, etc.)"),
		field.String("category").
			Default("general").
			Comment("Activity category (api, auth, admin, etc.)"),
		field.String("source").
			Optional().
			Comment("Source of activity (web, api, mobile, system)"),

		// HOW/DETAILS (API-specific fields)
		field.String("endpoint").
			Optional().
			Comment("API endpoint (for API activities)"),
		field.String("method").
			Optional().
			Comment("HTTP method (for API activities)"),
		field.Int("status_code").
			Optional().
			Comment("HTTP status code (for API activities)"),
		field.Int("response_time").
			Optional().
			Comment("Response time in milliseconds"),

		// WHERE from
		field.String("ip_address").
			Optional().
			Comment("Client IP address"),
		field.String("user_agent").
			Optional().
			Comment("Client user agent"),
		field.String("location").
			Optional().
			Comment("Geographic location"),

		// RESULT
		field.Bool("success").
			Default(true).
			Comment("Whether the activity was successful"),
		field.String("error").
			Optional().
			Comment("Error message if failed"),
		field.String("error_code").
			Optional().
			Comment("Error code for categorization"),

		// METRICS
		field.Int("size").
			Optional().
			Comment("Size in bytes (for file operations, etc.)"),
		field.Int("count").
			Optional().
			Comment("Count of items affected"),
		field.Float("value").
			Optional().
			Comment("Numeric value associated with activity"),

		// WHEN
		field.Time("timestamp").
			Comment("When the activity occurred"),
		field.Time("expires_at").
			Optional().
			Comment("When this activity record expires (for cleanup)"),

		// EXTENSIBLE
		entity.JSONMapField("metadata", true),
		// Comment("Additional activity-specific data"),
		field.JSON("tags", []string{}).
			Optional().
			Comment("Tags for categorization and filtering"),
	}
}

// Edges of the ApiKeyActivity.
func (Activity) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("activities").
			Field("user_id").
			Unique(),

		edge.From("organization", Organization.Type).
			Ref("activities").
			Field("organization_id").
			Unique(),

		edge.From("session", Session.Type).
			Ref("activities").
			Field("session_id").
			Unique(),
	}
}

// Indexes of the Activity.
func (Activity) Indexes() []ent.Index {
	return []ent.Index{
		// Primary lookup indexes
		index.Fields("resource_type", "resource_id"),
		index.Fields("resource_type", "resource_id", "timestamp"),

		// User/Organization context
		index.Fields("user_id"),
		index.Fields("organization_id"),
		index.Fields("session_id"),

		// Action-based queries
		index.Fields("action"),
		index.Fields("resource_type", "action"),
		index.Fields("category"),
		index.Fields("source"),

		// Time-based queries (very important for analytics)
		index.Fields("timestamp"),
		index.Fields("timestamp", "resource_type"),
		index.Fields("timestamp", "action"),
		index.Fields("timestamp", "success"),

		// API-specific indexes
		index.Fields("endpoint"),
		index.Fields("method"),
		index.Fields("status_code"),
		index.Fields("success"),

		// Analytics indexes
		index.Fields("resource_type", "timestamp", "success"),
		index.Fields("organization_id", "timestamp"),
		index.Fields("user_id", "timestamp"),

		// Composite indexes for common queries
		index.Fields("resource_type", "action", "timestamp"),
		index.Fields("organization_id", "resource_type", "timestamp"),
		index.Fields("user_id", "resource_type", "timestamp"),

		// IP and security indexes
		index.Fields("ip_address"),
		index.Fields("user_agent"),

		// Cleanup indexes
		index.Fields("expires_at"),
	}
}

// Mixin of the Activity.
func (Activity) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
	}
}
