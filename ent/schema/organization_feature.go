package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/rs/xid"
	"github.com/xraph/frank/pkg/entity"
)

// OrganizationFeature holds the schema definition for the OrganizationFeature entity.
type OrganizationFeature struct {
	ent.Schema
}

// Fields of the OrganizationFeature.
func (OrganizationFeature) Fields() []ent.Field {
	return []ent.Field{
		field.String("organization_id").
			GoType(xid.ID{}).
			NotEmpty(),
		field.String("feature_id").
			GoType(xid.ID{}).
			NotEmpty(),
		field.Bool("enabled").
			Default(true),
		entity.JSONMapField("settings", true),
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

		// FIXED: Changed from edge.To() with Field() to edge.From() with Ref()
		// This assumes your FeatureFlag entity has an edge called "organization_features"
		edge.From("feature", FeatureFlag.Type).
			Ref("organization_features").
			Field("feature_id").
			Unique().
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

// Mixin of the OrganizationFeature.
func (OrganizationFeature) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
		TimeMixin{},
		SoftDeleteMixin{},
	}
}
