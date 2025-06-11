package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/juicycleff/frank/pkg/entity"
	"github.com/rs/xid"
)

// SMSTemplate holds the schema definition for the SMSTemplate entity.
type SMSTemplate struct {
	ent.Schema
}

// Fields of the SMSTemplate.
func (SMSTemplate) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").
			NotEmpty().
			Comment("Template name for identification"),
		field.String("content").
			NotEmpty().
			Comment("SMS message content with template variables"),
		field.String("type").
			NotEmpty().
			Comment("Template type: 'verification', 'mfa_code', 'password_reset', etc."),
		field.String("organization_id").
			GoType(xid.ID{}).
			Optional().
			Comment("Organization ID - null for system templates"),
		field.Bool("active").
			Default(true).
			Comment("Whether template is active and available for use"),
		field.Bool("system").
			Default(false).
			Comment("System templates can be overridden but not deleted"),
		field.String("locale").
			Default("en").
			Comment("Template locale/language"),
		field.Int("max_length").
			Default(160).
			Comment("Maximum message length in characters"),
		field.String("message_type").
			Default("transactional").
			Comment("Message type: 'transactional', 'promotional', 'marketing'"),
		field.Int("estimated_segments").
			Default(1).
			Optional().
			Comment("Estimated number of SMS segments"),
		field.Float("estimated_cost").
			Default(0.0).
			Optional().
			Comment("Estimated cost per message"),
		field.String("currency").
			Default("USD").
			Optional().
			Comment("Cost currency"),
		field.JSON("variables", []string{}).
			Optional().
			Comment("List of available template variables"),
		entity.JSONMapField("metadata", true),
		// Comment("Additional template metadata and configuration"),
		field.Time("last_used_at").
			Optional().
			Comment("Last time template was used"),
		field.Int("usage_count").
			Default(0).
			Comment("Number of times template has been used"),
	}
}

// Edges of the SMSTemplate.
func (SMSTemplate) Edges() []ent.Edge {
	return []ent.Edge{
		// Future: Add edge to Organization when needed
		edge.From("organization", Organization.Type).
			Ref("sms_templates").
			Field("organization_id").
			Unique(),
	}
}

// Indexes of the SMSTemplate.
func (SMSTemplate) Indexes() []ent.Index {
	return []ent.Index{
		// Index for filtering by organization
		index.Fields("organization_id"),
		// Index for filtering by template type
		index.Fields("type"),
		// Index for filtering by message type
		index.Fields("message_type"),
		// Index for filtering active templates
		index.Fields("active"),
		// Index for system templates
		index.Fields("system"),
		// Composite index for efficient lookups
		index.Fields("organization_id", "type"),
		// Unique constraint: one template per organization/type/locale combination
		index.Fields("organization_id", "type", "locale").
			Unique(),
		// Index for usage statistics
		index.Fields("usage_count"),
		// Index for recently used templates
		index.Fields("last_used_at"),
	}
}

// Mixin of the SMSTemplate.
func (SMSTemplate) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
		TimeMixin{},
		SoftDeleteMixin{},
	}
}
