package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/juicycleff/frank/pkg/entity"
	"github.com/rs/xid"
)

// Audit holds the schema definition for the Audit entity.
type Audit struct {
	ent.Schema
}

// Fields of the Audit.
func (Audit) Fields() []ent.Field {
	return []ent.Field{
		field.String("user_id").
			GoType(xid.ID{}).
			Optional(),
		field.String("organization_id").
			GoType(xid.ID{}).
			Optional(),
		field.String("session_id").
			GoType(xid.ID{}).
			Optional(),
		field.String("action").
			NotEmpty().
			Comment("The action performed: 'login', 'logout', 'create_user', etc."),
		field.String("resource_type").
			NotEmpty().
			Comment("Type of resource acted upon: 'user', 'organization', 'role', etc."),
		field.String("resource_id").
			GoType(xid.ID{}).
			Optional().
			Comment("ID of the specific resource acted upon"),
		field.String("status").
			NotEmpty().
			Comment("Status of the action: 'success', 'failure', 'pending'"),
		field.String("ip_address").
			Optional(),
		field.String("user_agent").
			Optional(),
		field.String("location").
			Optional().
			Comment("Geographic location derived from IP"),
		field.String("device_id").
			Optional(),
		field.String("request_id").
			Optional().
			Comment("Correlation ID for tracing requests"),
		field.String("error_code").
			Optional().
			Comment("Error code if action failed"),
		field.String("error_message").
			Optional().
			Comment("Error message if action failed"),
		field.String("description").
			Optional().
			Comment("Human-readable description of the action"),
		entity.JSONMapField("metadata", true),
		// Comment("Additional context data"),
		entity.JSONMapField("old_values", true),
		// Comment("Previous values for update operations"),
		entity.JSONMapField("current_values", true),
		// Comment("New values for update operations"),
		field.Time("timestamp").
			Immutable().
			Comment("When the action occurred"),
	}
}

// Edges of the Audit.
func (Audit) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("audit_logs").
			Field("user_id").
			Unique(),
		edge.From("organization", Organization.Type).
			Ref("audit_logs").
			Field("organization_id").
			Unique(),
		edge.From("session", Session.Type).
			Ref("audit_logs").
			Field("session_id").
			Unique(),
	}
}

// Indexes of the Audit.
func (Audit) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id"),
		index.Fields("organization_id"),
		index.Fields("session_id"),
		index.Fields("action"),
		index.Fields("resource_type"),
		index.Fields("resource_id"),
		index.Fields("status"),
		index.Fields("timestamp"),
		index.Fields("organization_id", "timestamp"),
		index.Fields("user_id", "timestamp"),
		index.Fields("action", "timestamp"),
		index.Fields("resource_type", "resource_id"),
		index.Fields("ip_address", "timestamp"),
	}
}

// Mixin of the Audit.
func (Audit) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
		SoftDeleteMixin{},
		TimeMixin{},
		// Note: We don't use TimeMixin here because we have our own timestamp field
	}
}
