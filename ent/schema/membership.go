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

// Membership holds the schema definition for the Membership entity.
type Membership struct {
	ent.Schema
}

// Fields of the Membership.
func (Membership) Fields() []ent.Field {
	return []ent.Field{
		field.String("user_id").
			GoType(xid.ID{}).
			NotEmpty(),
		field.String("organization_id").
			GoType(xid.ID{}).
			NotEmpty(),
		field.String("role_id").
			GoType(xid.ID{}).
			NotEmpty(),
		field.Enum("status").
			Values("pending", "active", "inactive", "suspended").
			Default("pending"),
		field.String("invited_by").
			GoType(xid.ID{}).
			Optional().
			Comment("User ID who sent the invitation"),
		field.Time("invited_at").
			Default(time.Now),
		field.Time("joined_at").
			Optional().
			Nillable().
			Comment("When the user accepted the invitation"),
		field.Time("expires_at").
			Optional().
			Nillable().
			Comment("When the invitation expires"),
		field.String("invitation_token").
			Optional().
			Sensitive().
			Comment("Token for accepting invitations"),
		field.Bool("is_billing_contact").
			Default(false).
			Comment("Whether this member receives billing notifications"),
		field.Bool("is_primary_contact").
			Default(false).
			Comment("Primary contact for the organization"),
		entity.JSONMapField("metadata", true),
	}
}

// Edges of the Membership.
func (Membership) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("memberships").
			Field("user_id").
			Unique().
			Required(),
		edge.From("organization", Organization.Type).
			Ref("memberships").
			Field("organization_id").
			Unique().
			Required(),
		edge.From("role", Role.Type).
			Ref("memberships").
			Field("role_id").
			Unique().
			Required(),
		// Note: We don't create an inverse edge for invited_by to avoid conflicts
		// You can query the inviter using the invited_by field directly
	}
}

// Indexes of the Membership.
func (Membership) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "organization_id").
			Unique(),
		index.Fields("organization_id"),
		index.Fields("user_id"),
		index.Fields("role_id"),
		index.Fields("status"),
		index.Fields("invitation_token"),
		index.Fields("expires_at"),
		index.Fields("invited_by"),
	}
}

// Mixin of the Membership.
func (Membership) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
		TimeMixin{},
	}
}
