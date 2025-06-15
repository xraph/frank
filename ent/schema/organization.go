package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/juicycleff/frank/pkg/entity"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// Organization holds the schema definition for the Organization entity.
type Organization struct {
	ent.Schema
}

// Fields of the Organization.
func (Organization) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").
			NotEmpty(),
		field.String("slug").
			Unique().
			NotEmpty(),
		field.Strings("domains").
			Optional(),
		field.Strings("verified_domains").
			Optional(),
		field.String("domain").
			Optional(),
		field.String("logo_url").
			Optional(),
		field.String("plan").
			Default("free"),
		field.Bool("active").
			Default(true),
		entity.JSONMapField("metadata", true),
		field.Time("trial_ends_at").
			Optional().
			Nillable(),
		field.Bool("trial_used").
			Default(false),
		field.String("owner_id").
			GoType(xid.ID{}).
			Optional().
			Comment("Primary owner of the organization"),

		// Organization type differentiation
		field.Enum("org_type").
			GoType(model.OrgType("")).
			Default(model.OrgTypeCustomer.String()).
			Comment("platform = Your SaaS company, customer = Client organizations"),

		field.Bool("is_platform_organization").
			Default(false).
			Comment("Whether this is the main platform organization"),

		// Member limits and quotas
		field.Int("external_user_limit").
			Default(5).
			Comment("Maximum external users (organization members) allowed"),

		field.Int("end_user_limit").
			Default(100).
			Comment("Maximum end users allowed for auth service"),

		// SSO configuration
		field.Bool("sso_enabled").
			Default(false).
			Comment("Whether SSO is enabled for this org"),
		field.String("sso_domain").
			Optional().
			Comment("Domain for SSO authentication"),

		// Customer-specific fields
		field.String("subscription_id").
			Optional().
			Comment("Stripe/billing subscription ID"),
		field.String("customer_id").
			Optional().
			Comment("Stripe/billing customer ID"),
		field.Enum("subscription_status").
			Values("active", "trialing", "past_due", "canceled", "unpaid").
			Default("trialing").
			Comment("Billing subscription status"),

		// Auth service configuration for customers
		field.Bool("auth_service_enabled").
			Default(false).
			Comment("Whether this org has auth service enabled"),
		field.JSON("auth_config", map[string]interface{}{}).
			Optional().
			Comment("Auth service configuration (allowed domains, providers, etc.)"),
		field.String("auth_domain").
			Optional().
			Comment("Custom domain for auth service (auth.customer.com)"),

		// API limits and usage
		field.Int("api_request_limit").
			Default(10000).
			Comment("Monthly API request limit"),
		field.Int("api_requests_used").
			Default(0).
			Comment("API requests used this month"),

		// Usage tracking
		field.Int("current_external_users").
			Default(0).
			Comment("Current count of active external users"),
		field.Int("current_end_users").
			Default(0).
			Comment("Current count of active end users"),
	}
}

// Edges of the Organization.
func (Organization) Edges() []ent.Edge {
	return []ent.Edge{
		// All users (external users and end users) belong to this organization
		edge.To("users", User.Type),

		// Membership relationships for external users
		edge.To("memberships", Membership.Type),

		// Notification templates
		edge.To("sms_templates", SMSTemplate.Type),
		edge.To("email_templates", EmailTemplate.Type),

		// Organization-scoped resources
		edge.To("api_keys", ApiKey.Type),
		edge.To("webhooks", Webhook.Type),
		edge.To("feature_flags", OrganizationFeature.Type),
		edge.To("identity_providers", IdentityProvider.Type),
		edge.To("oauth_clients", OAuthClient.Type),

		// Organization-scoped roles
		edge.To("roles", Role.Type),

		// REMOVED: The problematic context relationship edges
		// These relationships are already handled by UserRole and UserPermission
		// entities through their organization_context edges. No need to define
		// them here as well.

		// Context relationships for roles and permissions
		edge.From("user_role_contexts", UserRole.Type).
			Ref("organization_context"),

		edge.From("user_permission_contexts", UserPermission.Type).
			Ref("organization_context"),

		edge.To("audit_logs", Audit.Type),
		edge.To("organization_providers", OrganizationProvider.Type),
		edge.To("activities", Activity.Type),
		// edge.To("user_role_contexts", UserRole.Type).
		// 	From("organization_context"),
		// edge.To("user_permission_contexts", UserPermission.Type).
		// 	From("organization_context"),

	}
}

// Indexes of the Organization.
func (Organization) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("domain"),
		index.Fields("slug"),
		index.Fields("owner_id"),
		index.Fields("sso_domain"),
		index.Fields("org_type"),
		index.Fields("is_platform_organization"),
		index.Fields("subscription_status"),
		index.Fields("auth_service_enabled"),
		index.Fields("auth_domain").
			Unique(),
		index.Fields("customer_id"),
		index.Fields("subscription_id"),
		index.Fields("active"),
	}
}

// Mixin of the Organization.
func (Organization) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
		TimeMixin{},
		SoftDeleteMixin{},
	}
}
