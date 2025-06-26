package model

import (
	"reflect"

	"github.com/danielgtaylor/huma/v2"
)

// ================================
// PERMISSION CATEGORIES
// ================================

// PermissionCategory defines the type for the "category" enum field.
type PermissionCategory string

// ContextType values.
const (
	PermissionCategoryPlatform           PermissionCategory = "platform"
	PermissionCategoryOrganization       PermissionCategory = "organization"
	PermissionCategoryApplication        PermissionCategory = "application"
	PermissionCategoryResource           PermissionCategory = "resource"
	PermissionCategoryMembership         PermissionCategory = "membership"
	PermissionCategoryUserManagement     PermissionCategory = "user_management"
	PermissionCategorySelfAccess         PermissionCategory = "self_access"
	PermissionCategoryAPIManagement      PermissionCategory = "api_management"
	PermissionCategoryRBAC               PermissionCategory = "rbac"
	PermissionCategorySecurity           PermissionCategory = "security"
	PermissionCategoryIntegration        PermissionCategory = "integration"
	PermissionCategorySystem             PermissionCategory = "system"
	PermissionCategoryPlatformManagement PermissionCategory = "platform_management"
	PermissionCategoryBilling            PermissionCategory = "billing"
	PermissionCategoryAnalytics          PermissionCategory = "analytics"
	PermissionCategoryCompliance         PermissionCategory = "compliance"
	PermissionCategorySupport            PermissionCategory = "support"
)

func (c PermissionCategory) Values() []string {
	return []string{
		string(PermissionCategoryPlatform),
		string(PermissionCategoryOrganization),
		string(PermissionCategoryApplication),
		string(PermissionCategoryResource),
		string(PermissionCategoryMembership),
		string(PermissionCategoryUserManagement),
		string(PermissionCategorySelfAccess),
		string(PermissionCategoryAPIManagement),
		string(PermissionCategoryRBAC),
		string(PermissionCategorySecurity),
		string(PermissionCategoryIntegration),
		string(PermissionCategorySystem),
		string(PermissionCategoryPlatformManagement),
		string(PermissionCategoryBilling),
		string(PermissionCategoryAnalytics),
		string(PermissionCategoryCompliance),
		string(PermissionCategorySupport),
	}
}

func (c PermissionCategory) String() string {
	return string(c)
}

func (c PermissionCategory) Schema(r huma.Registry) *huma.Schema {
	if r.Map()["PermissionCategory"] == nil {
		schemaRef := r.Schema(reflect.TypeOf(""), true, "PermissionCategory")
		schemaRef.Title = "PermissionCategory"
		for _, v := range c.Values() {
			schemaRef.Enum = append(schemaRef.Enum, v)
		}
		r.Map()["PermissionCategory"] = schemaRef
	}
	return &huma.Schema{Ref: "#/components/schemas/PermissionCategory"}
}

// ================================
// PERMISSION GROUPS
// ================================

type PermissionGroup string

const (
	GroupOrganizationManagement PermissionGroup = "organization_management"
	GroupMembershipManagement   PermissionGroup = "membership_management"
	GroupUserManagement         PermissionGroup = "user_management"
	GroupSelfAccess             PermissionGroup = "self_access"
	GroupAPIManagement          PermissionGroup = "api_management"
	GroupRBACManagement         PermissionGroup = "rbac_management"
	GroupSecurityManagement     PermissionGroup = "security_management"
	GroupIntegrationManagement  PermissionGroup = "integration_management"
	GroupSystemAdministration   PermissionGroup = "system_administration"
	GroupPlatformManagement     PermissionGroup = "platform_management"
	GroupBillingManagement      PermissionGroup = "billing_management"
	GroupAnalyticsAccess        PermissionGroup = "analytics_access"
	GroupComplianceManagement   PermissionGroup = "compliance_management"
	GroupSupportAccess          PermissionGroup = "support_access"
)

func (g PermissionGroup) String() string {
	return string(g)
}

func (g PermissionGroup) Values() []string {
	return []string{
		string(GroupOrganizationManagement),
		string(GroupMembershipManagement),
		string(GroupUserManagement),
		string(GroupSelfAccess),
		string(GroupAPIManagement),
		string(GroupRBACManagement),
		string(GroupSecurityManagement),
		string(GroupIntegrationManagement),
		string(GroupSystemAdministration),
		string(GroupPlatformManagement),
		string(GroupBillingManagement),
		string(GroupAnalyticsAccess),
		string(GroupComplianceManagement),
		string(GroupSupportAccess),
	}
}

// ================================
// RESOURCE TYPES
// ================================

// ResourceType represents the type of resource that permissions apply to
type ResourceType string

// Resource Types for context-aware permissions
const (
	ResourceGlobal               ResourceType = "global"
	ResourceSystem               ResourceType = "system"
	ResourceOrganization         ResourceType = "organization"
	ResourceUser                 ResourceType = "user"
	ResourceRole                 ResourceType = "role"
	ResourcePermission           ResourceType = "permission"
	ResourceAPIKey               ResourceType = "api_key"
	ResourceSession              ResourceType = "session"
	ResourceMFA                  ResourceType = "mfa"
	ResourceWebhook              ResourceType = "webhook"
	ResourceAudit                ResourceType = "audit"
	ResourceApplication          ResourceType = "application"
	ResourceEndUser              ResourceType = "end_user"
	ResourceIntegration          ResourceType = "integration"
	ResourceBilling              ResourceType = "billing"
	ResourceAnalytics            ResourceType = "analytics"
	ResourceWebhookEvent         ResourceType = "webhook_event"
	ResourceEmailTemplate        ResourceType = "email_template"
	ResourceVerification         ResourceType = "verification"
	ResourceAuditLog             ResourceType = "audit_log"
	ResourceCommon               ResourceType = "common"
	ResourceOauth                ResourceType = "oauth"
	ResourceMembership           ResourceType = "membership"
	ResourceProvider             ResourceType = "provider"
	ResourcePasskey              ResourceType = "passkey"
	ResourceSSO                  ResourceType = "sso"
	ResourceSelfUser             ResourceType = "self_user"
	ResourcePersonalAPIKey       ResourceType = "personal_api_key"
	ResourcePersonalSession      ResourceType = "personal_session"
	ResourcePersonalMFA          ResourceType = "personal_mfa"
	ResourceInternalUser         ResourceType = "internal_user"
	ResourceEndUserSession       ResourceType = "end_user_session"
	ResourceCustomerOrganization ResourceType = "customer_organization"
	ResourcePlatformAnalytics    ResourceType = "platform_analytics"
	ResourceEndUserAnalytics     ResourceType = "end_user_analytics"
	ResourceAuthServiceAnalytics ResourceType = "auth_service_analytics"
	ResourceAuthService          ResourceType = "auth_service"
	ResourceAuthServiceDomain    ResourceType = "auth_service_domain"
)

func (rt ResourceType) Values() []string {
	return []string{
		string(ResourceGlobal),
		string(ResourceSystem),
		string(ResourceOrganization),
		string(ResourceUser),
		string(ResourceRole),
		string(ResourcePermission),
		string(ResourceAPIKey),
		string(ResourceSession),
		string(ResourceMFA),
		string(ResourceWebhook),
		string(ResourceAudit),
		string(ResourceApplication),
		string(ResourceEndUser),
		string(ResourceIntegration),
		string(ResourceBilling),
		string(ResourceAnalytics),
		string(ResourceWebhookEvent),
		string(ResourceEmailTemplate),
		string(ResourceVerification),
		string(ResourceAuditLog),
		string(ResourceCommon),
		string(ResourceOauth),
		string(ResourceMembership),
		string(ResourceProvider),
		string(ResourcePasskey),
		string(ResourceSSO),
		string(ResourceSelfUser),
		string(ResourcePersonalAPIKey),
		string(ResourcePersonalSession),
		string(ResourcePersonalMFA),
		string(ResourceInternalUser),
		string(ResourceEndUserSession),
		string(ResourceCustomerOrganization),
		string(ResourcePlatformAnalytics),
		string(ResourceEndUserAnalytics),
		string(ResourceAuthServiceAnalytics),
		string(ResourceAuthService),
		string(ResourceAuthServiceDomain),
	}
}

func (rt ResourceType) String() string {
	return string(rt)
}

func (rt ResourceType) Schema(r huma.Registry) *huma.Schema {
	if r.Map()["ResourceType"] == nil {
		schemaRef := r.Schema(reflect.TypeOf(""), true, "ResourceType")
		schemaRef.Title = "ResourceType"
		for _, v := range rt.Values() {
			schemaRef.Enum = append(schemaRef.Enum, v)
		}
		r.Map()["ResourceType"] = schemaRef
	}
	return &huma.Schema{Ref: "#/components/schemas/ResourceType"}
}

// RoleCategory represents the category of a role
type RoleCategory string

const (
	RoleCategorySystem       RoleCategory = "system"
	RoleCategoryOrganization RoleCategory = "organization"
	RoleCategoryApplication  RoleCategory = "application"
)

func (rc RoleCategory) String() string {
	return string(rc)
}

func (rc RoleCategory) Values() []string {
	return []string{
		string(RoleCategorySystem),
		string(RoleCategoryOrganization),
		string(RoleCategoryApplication),
	}
}
