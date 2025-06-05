package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/juicycleff/frank/pkg/entity"
	"github.com/rs/xid"
)

// Passkey holds the schema definition for the Passkey entity.
type Passkey struct {
	ent.Schema
}

// Fields of the Passkey.
func (Passkey) Fields() []ent.Field {
	return []ent.Field{
		field.String("user_id").
			GoType(xid.ID{}).
			NotEmpty(),
		field.String("name").
			NotEmpty(),
		field.String("credential_id").
			Unique().
			NotEmpty(),
		field.Bytes("public_key").
			NotEmpty(),
		field.Int("sign_count").
			Default(0),
		field.Bool("active").
			Default(true),
		field.String("device_type").
			Optional(),
		field.String("aaguid").
			Optional(),
		field.Time("last_used").
			Optional().
			Nillable(),
		field.JSON("transports", []string{}).
			Optional(),
		entity.JSONMapField("attestation", true),
	}
}

// Edges of the Passkey.
func (Passkey) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("passkeys").
			Field("user_id").
			Unique().
			Required(),
	}
}

// Indexes of the Passkey.
func (Passkey) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id"),
		index.Fields("credential_id"),
	}
}

// Mixin of the OrganizationFeature.
func (Passkey) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
		TimeMixin{},
	}
}
