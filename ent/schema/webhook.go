package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/juicycleff/frank/pkg/entity"
	"github.com/rs/xid"
)

// Webhook holds the schema definition for the Webhook entity.
type Webhook struct {
	ent.Schema
}

// Fields of the Webhook.
func (Webhook) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").
			NotEmpty(),
		field.String("url").
			NotEmpty(),
		field.String("organization_id").
			GoType(xid.ID{}).
			NotEmpty(),
		field.String("secret").
			NotEmpty().
			Sensitive(),
		field.Bool("active").
			Default(true),
		field.Strings("event_types"),
		field.String("version").
			Default("v1"),
		field.Int("retry_count").
			Default(3),
		field.Int("timeout_ms").
			Default(5000),
		field.Enum("format").
			Values("json", "form").
			Default("json"),
		entity.JSONMapField("metadata", true),
		entity.JSONMapStringField("headers", true),
	}
}

// Edges of the Webhook.
func (Webhook) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("organization", Organization.Type).
			Ref("webhooks").
			Unique().
			Field("organization_id").
			Required(),
		edge.To("events", WebhookEvent.Type),
	}
}

// Indexes of the Webhook.
func (Webhook) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("organization_id"),
	}
}

// Mixin of the Webhook.
func (Webhook) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
		TimeMixin{},
		SoftDeleteMixin{},
	}
}
