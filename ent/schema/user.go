package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/rs/xid"
	"github.com/xraph/frank/pkg/entity"
	"github.com/xraph/frank/pkg/model"
)

// User holds the schema definition for ALL user types
// This includes: internal users, external users, AND end users
type User struct {
	ent.Schema
}

// Fields of the User.
func (User) Fields() []ent.Field {
	return []ent.Field{
		field.String("email").
			NotEmpty(),
		field.String("phone_number").
			Optional(),
		field.String("first_name").
			Optional(),
		field.String("last_name").
			Optional(),
		field.String("username").
			Optional().
			Comment("Used for end users who prefer username over email"),
		field.String("password_hash").
			Optional().
			Sensitive(),
		field.Bool("email_verified").
			Default(false),
		field.Bool("phone_verified").
			Default(false),
		field.Bool("active").
			Default(true),
		field.Bool("blocked").
			Default(false).
			Comment("Can be blocked by organization admin"),
		field.Time("last_login").
			Optional().
			Nillable(),
		field.Time("last_password_change").
			Optional().
			Nillable(),
		entity.JSONMapField("metadata", true),
		field.String("profile_image_url").
			Optional(),
		field.String("locale").
			Default("en"),
		field.String("timezone").
			Optional(),

		// User type and context
		field.Enum("user_type").
			GoType(model.UserType("")).
			Default(model.UserTypeExternal.String()).
			Comment("internal = platform staff, external = customer org members, end_user = auth service users"),

		// Organization context
		field.String("organization_id").
			GoType(xid.ID{}).
			Optional().
			Comment("Which organization this user belongs to"),

		field.String("primary_organization_id").
			GoType(xid.ID{}).
			Optional().
			Comment("Primary organization for external users who belong to multiple orgs"),

		// Platform admin status (for internal users)
		field.Bool("is_platform_admin").
			Default(false).
			Comment("Whether this user can manage the entire SaaS platform"),

		// Authentication context
		field.String("auth_provider").
			Default("internal").
			Comment("Authentication provider: internal, google, github, saml, etc."),

		field.String("external_id").
			Optional().
			Comment("External provider user ID"),

		// Customer/billing integration
		field.String("customer_id").
			Optional().
			Comment("External ID from customer management system (Stripe, etc.)"),

		// End user specific fields
		field.JSON("custom_attributes", map[string]interface{}{}).
			Optional().
			Comment("Custom user attributes defined by organization (for end users)"),

		field.String("created_by").
			Optional().
			Comment("Which user created this user (for end users created by org admins)"),

		// Security fields
		field.Time("password_reset_token_expires").
			Optional().
			Nillable(),
		field.String("password_reset_token").
			Optional().
			Sensitive(),

		field.Int("login_count").
			Default(0),
		field.String("last_login_ip").
			Optional(),
	}
}

// Edges of the User.
func (User) Edges() []ent.Edge {
	return []ent.Edge{
		// Organization relationships
		edge.From("organization", Organization.Type).
			Ref("users").
			Field("organization_id").
			Unique(),

		edge.To("memberships", Membership.Type).
			Comment("For external users - their memberships in organizations"),
		edge.To("sent_invitations", Membership.Type),

		// Shared authentication and security features
		edge.To("sessions", Session.Type),
		edge.To("api_keys", ApiKey.Type),
		edge.To("mfa_methods", MFA.Type),
		edge.To("passkeys", Passkey.Type),
		edge.To("oauth_tokens", OAuthToken.Type),
		edge.To("oauth_authorizations", OAuthAuthorization.Type),
		edge.To("verifications", Verification.Type),

		// Role and permission relationships (context-aware)
		edge.To("user_roles", UserRole.Type),
		edge.To("user_permissions", UserPermission.Type),

		// System roles (for internal users)
		edge.To("system_roles", Role.Type).
			Comment("Direct system-level role assignments for internal users"),

		// ADDED: Assignment tracking edges (for roles/permissions assigned BY this user)
		edge.To("assigned_user_roles", UserRole.Type).
			Comment("Role assignments made by this user"),

		edge.To("assigned_user_permissions", UserPermission.Type).
			Comment("Permission assignments made by this user"),

		edge.To("audit_logs", Audit.Type),
		edge.To("activities", Activity.Type),
	}
}

// Indexes of the User.
func (User) Indexes() []ent.Index {
	return []ent.Index{
		// Composite uniqueness - will need application-level validation
		// index.Fields("user_type", "email").
		// 	Unique(),
		// Comment("Ensures email uniqueness per user type"),

		index.Fields("organization_id", "user_type", "email").
			Unique(),
		// Comment("Ensures email uniqueness within organization per user type"),

		index.Fields("organization_id", "user_type", "username").
			Unique(),
		// Comment("Ensures username uniqueness within organization per user type"),

		// Provider ID unique within organization + provider + user type
		index.Fields("organization_id", "user_type", "auth_provider", "external_id").
			Unique(),

		// Standard indexes for query performance
		index.Fields("organization_id"),
		index.Fields("user_type"),
		index.Fields("email"),
		index.Fields("username"),
		index.Fields("is_platform_admin"),
		index.Fields("auth_provider"),
		index.Fields("active"),
		index.Fields("blocked"),
		index.Fields("last_login"),
		index.Fields("customer_id"),
		index.Fields("created_by"),
		index.Fields("external_id"),

		// Composite indexes for common queries
		index.Fields("organization_id", "user_type"),
		index.Fields("organization_id", "active"),
		index.Fields("user_type", "active"),
		index.Fields("auth_provider", "external_id"),
	}
}

// Mixin of the User.
func (User) Mixin() []ent.Mixin {
	return []ent.Mixin{
		ModelBaseMixin{},
		TimeMixin{},
	}
}
