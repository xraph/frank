package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/rs/xid"
	"github.com/xraph/frank/pkg/entity"
)

// Session holds the schema definition for the Session entity.
type Session struct {
	ent.Schema
}

// Fields of the Session.
func (Session) Fields() []ent.Field {
	return []ent.Field{
		field.String("user_id").
			GoType(xid.ID{}).
			NotEmpty(),
		field.String("token").
			Unique().
			Sensitive(),
		field.String("ip_address").
			Optional(),
		field.String("user_agent").
			Optional(),
		field.String("device_id").
			Optional(),
		field.String("location").
			Optional(),
		field.String("organization_id").
			GoType(xid.ID{}).
			Optional(),
		field.Bool("active").
			Default(true),
		field.Time("expires_at"),
		field.Time("last_active_at").
			Default(time.Now).
			UpdateDefault(time.Now),
		entity.JSONMapField("metadata", true),
	}
}

// Edges of the Session.
func (Session) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("sessions").
			Field("user_id").
			Unique().
			Required(),

		edge.To("audit_logs", Audit.Type),
		edge.To("activities", Activity.Type),
	}
}

// Indexes of the Session.
func (Session) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id"),
		index.Fields("organization_id"),
		index.Fields("token"),
		index.Fields("expires_at"),
	}
}

// Mixin of the Session.
func (Session) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
		TimeMixin{},
	}
}
