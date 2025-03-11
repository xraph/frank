package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// OrganizationFeature holds the schema definition for the OrganizationFeature entity.
type OrganizationFeature struct {
	ent.Schema
}

// Fields of the OrganizationFeature.
func (OrganizationFeature) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			Unique(),
		field.String("organization_id").
			NotEmpty(),
		field.String("feature_id").
			NotEmpty(),
		field.Bool("enabled").
			Default(true),
		field.JSON("settings", map[string]interface{}{}).
			Optional().
			Comment("Custom settings for this feature in this organization"),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Edges of the OrganizationFeature.
func (OrganizationFeature) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("organization", Organization.Type).
			Ref("feature_flags").
			Field("organization_id").
			Unique().
			Required(),
		edge.To("feature", FeatureFlag.Type).
			Unique().
			Field("feature_id").
			Required(),
	}
}

// Indexes of the OrganizationFeature.
func (OrganizationFeature) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("organization_id"),
		index.Fields("feature_id"),
		index.Fields("organization_id", "feature_id").
			Unique(),
	}
}
