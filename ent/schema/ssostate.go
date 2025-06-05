package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// SSOState holds the schema definition for the SSOState entity.
// This entity stores temporary state data during SSO authentication flows.
type SSOState struct {
	ent.Schema
}

// Fields of the SSOState.
func (SSOState) Fields() []ent.Field {
	return []ent.Field{
		field.String("state").
			Unique().
			Comment("State token for SSO authentication flow"),

		field.String("data").
			Comment("JSON-encoded state data").
			MaxLen(4096), // Adjust as needed, but consider DB limitations

		field.Time("expires_at").
			Comment("When this state expires"),
	}
}

// Edges of the SSOState.
func (SSOState) Edges() []ent.Edge {
	return nil
}

// Indexes of the SSOState.
func (SSOState) Indexes() []ent.Index {
	return []ent.Index{
		// Index by expiration time to support efficient cleanup
		index.Fields("expires_at"),
	}
}

// Mixin of the SSOState.
func (SSOState) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
		TimeMixin{},
	}
}
