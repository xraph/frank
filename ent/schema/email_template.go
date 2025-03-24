package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/juicycleff/frank/pkg/entity"
)

// EmailTemplate holds the schema definition for the EmailTemplate entity.
type EmailTemplate struct {
	ent.Schema
}

// Fields of the EmailTemplate.
func (EmailTemplate) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").
			NotEmpty(),
		field.String("subject").
			NotEmpty(),
		field.String("type").
			NotEmpty().
			Comment("Template type: 'verification', 'password_reset', etc."),
		field.String("html_content").
			NotEmpty(),
		field.String("text_content").
			Optional(),
		field.String("organization_id").
			Optional(),
		field.Bool("active").
			Default(true),
		field.Bool("system").
			Default(false).
			Comment("System templates can be overridden but not deleted"),
		field.String("locale").
			Default("en"),
		entity.JSONMapField("metadata", true),
	}
}

// Edges of the EmailTemplate.
func (EmailTemplate) Edges() []ent.Edge {
	return []ent.Edge{}
}

// Indexes of the EmailTemplate.
func (EmailTemplate) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("organization_id"),
		index.Fields("type"),
		index.Fields("organization_id", "type", "locale").
			Unique(),
	}
}

// Mixin of the EmailTemplate.
func (EmailTemplate) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
	}
}
