package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/juicycleff/frank/pkg/entity"
)

// Passkey holds the schema definition for the Passkey entity.
type Passkey struct {
	ent.Schema
}

// Fields of the Passkey.
func (Passkey) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			Unique(),
		field.String("user_id").
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
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
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
