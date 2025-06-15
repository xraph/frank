package model

import (
	"reflect"

	"github.com/danielgtaylor/huma/v2"
)

// UserType defines the type for the "user_type" enum field.
type UserType string

// UserType values.
const (
	UserTypeInternal UserType = "internal"
	UserTypeExternal UserType = "external"
	UserTypeEndUser  UserType = "end_user"
)

func (ut UserType) Values() []string {
	return []string{string(UserTypeInternal), string(UserTypeExternal), string(UserTypeEndUser)}
}

func (ut UserType) String() string {
	return string(ut)
}

// Schema Register enum in OpenAPI specification
func (ut UserType) Schema(r huma.Registry) *huma.Schema {
	if r.Map()["UserType"] == nil {
		schemaRef := r.Schema(reflect.TypeOf(""), true, "UserType")
		schemaRef.Title = "UserType"
		for _, v := range ut.Values() {
			schemaRef.Enum = append(schemaRef.Enum, v)
		}
		r.Map()["UserType"] = schemaRef
	}
	return &huma.Schema{Ref: "#/components/schemas/UserType"}
}

// PermissionType defines the type for the "org_type" enum field.
type PermissionType string

// PermissionTypeGrant values.
const (
	PermissionTypeGrant PermissionType = "grant"
	PermissionTypeDeny  PermissionType = "deny"
)

func (ot PermissionType) Values() []string {
	return []string{string(PermissionTypeGrant), string(PermissionTypeDeny)}
}

func (ot PermissionType) String() string {
	return string(ot)
}

func (ot PermissionType) Schema(r huma.Registry) *huma.Schema {
	if r.Map()["PermissionType"] == nil {
		schemaRef := r.Schema(reflect.TypeOf(""), true, "PermissionType")
		schemaRef.Title = "PermissionType"
		for _, v := range ot.Values() {
			schemaRef.Enum = append(schemaRef.Enum, v)
		}
		r.Map()["PermissionType"] = schemaRef
	}
	return &huma.Schema{Ref: "#/components/schemas/PermissionType"}
}

// OrgType defines the type for the "org_type" enum field.
type OrgType string

// OrgType values.
const (
	OrgTypePlatform OrgType = "platform"
	OrgTypeCustomer OrgType = "customer"
)

func (ot OrgType) Values() []string {
	return []string{string(OrgTypePlatform), string(OrgTypeCustomer)}
}

func (ot OrgType) String() string {
	return string(ot)
}

func (ot OrgType) Schema(r huma.Registry) *huma.Schema {
	if r.Map()["OrgType"] == nil {
		schemaRef := r.Schema(reflect.TypeOf(""), true, "OrgType")
		schemaRef.Title = "OrgType"
		for _, v := range ot.Values() {
			schemaRef.Enum = append(schemaRef.Enum, v)
		}
		r.Map()["OrgType"] = schemaRef
	}
	return &huma.Schema{Ref: "#/components/schemas/OrgType"}
}

// MembershipStatus defines the type for the "status" enum field.
type MembershipStatus string

// MembershipStatus values.
const (
	MembershipStatusPending   MembershipStatus = "pending"
	MembershipStatusActive    MembershipStatus = "active"
	MembershipStatusInactive  MembershipStatus = "inactive"
	MembershipStatusSuspended MembershipStatus = "suspended"
)

func (s MembershipStatus) Values() []string {
	return []string{string(MembershipStatusPending), string(MembershipStatusActive),
		string(MembershipStatusInactive), string(MembershipStatusSuspended)}
}

func (s MembershipStatus) String() string {
	return string(s)
}

func (s MembershipStatus) Schema(r huma.Registry) *huma.Schema {
	if r.Map()["MembershipStatus"] == nil {
		schemaRef := r.Schema(reflect.TypeOf(""), true, "MembershipStatus")
		schemaRef.Title = "MembershipStatus"
		for _, v := range s.Values() {
			schemaRef.Enum = append(schemaRef.Enum, string(v))
		}
		r.Map()["MembershipStatus"] = schemaRef
	}
	return &huma.Schema{Ref: "#/components/schemas/MembershipStatus"}
}

// ContextType defines the type for the "category" enum field.
type ContextType string

// ContextType values.
const (
	ContextTypePlatform     ContextType = "platform"
	ContextTypeOrganization ContextType = "organization"
	ContextTypeApplication  ContextType = "application"
	ContextTypeResource     ContextType = "resource"
)

func (c ContextType) Values() []string {
	return []string{string(ContextTypePlatform), string(ContextTypeOrganization),
		string(ContextTypeApplication), string(ContextTypeResource)}
}

func (c ContextType) String() string {
	return string(c)
}

func (c ContextType) Schema(r huma.Registry) *huma.Schema {
	if r.Map()["ContextType"] == nil {
		schemaRef := r.Schema(reflect.TypeOf(""), true, "ContextType")
		schemaRef.Title = "ContextType"
		for _, v := range c.Values() {
			schemaRef.Enum = append(schemaRef.Enum, v)
		}
		r.Map()["ContextType"] = schemaRef
	}
	return &huma.Schema{Ref: "#/components/schemas/ContextType"}
}

// UserPermissionCategory defines the type for the "category" enum field.
type UserPermissionCategory string

// ContextType values.
const (
	UserPermissionCategoryPlatform     UserPermissionCategory = "platform"
	UserPermissionCategoryOrganization UserPermissionCategory = "organization"
	UserPermissionCategoryApplication  UserPermissionCategory = "application"
	UserPermissionCategoryResource     UserPermissionCategory = "resource"
)

func (c UserPermissionCategory) Values() []string {
	return []string{string(UserPermissionCategoryPlatform), string(UserPermissionCategoryOrganization),
		string(UserPermissionCategoryApplication), string(UserPermissionCategoryResource)}
}

func (c UserPermissionCategory) String() string {
	return string(c)
}

func (c UserPermissionCategory) Schema(r huma.Registry) *huma.Schema {
	if r.Map()["UserPermissionCategory"] == nil {
		schemaRef := r.Schema(reflect.TypeOf(""), true, "UserPermissionCategory")
		schemaRef.Title = "UserPermissionCategory"
		for _, v := range c.Values() {
			schemaRef.Enum = append(schemaRef.Enum, v)
		}
		r.Map()["UserPermissionCategory"] = schemaRef
	}
	return &huma.Schema{Ref: "#/components/schemas/UserPermissionCategory"}
}

// ResourceType defines the type for the "resource_type" enum field.
type ResourceType string

// ResourceType values.
const (
	ResourceTypeAPIKey       ResourceType = "api_key"
	ResourceTypeUser         ResourceType = "user"
	ResourceTypeOrganization ResourceType = "organization"
	ResourceTypeSession      ResourceType = "session"
	ResourceTypeCommon       ResourceType = "common"
	ResourceTypeOauth        ResourceType = "oauth"
	ResourceTypeMembership   ResourceType = "membership"
	ResourceTypeMfa          ResourceType = "mfa"
	ResourceTypeProvider     ResourceType = "provider"
	ResourceTypePasskey      ResourceType = "passkey"
	ResourceTypeSSO          ResourceType = "sso"
	ResourceTypePermission   ResourceType = "permission"
)

func (rt ResourceType) Values() []string {
	return []string{string(ResourceTypeAPIKey), string(ResourceTypeUser), string(ResourceTypeOrganization),
		string(ResourceTypeSession), string(ResourceTypeCommon), string(ResourceTypeOauth),
		string(ResourceTypeMembership), string(ResourceTypeMfa), string(ResourceTypeProvider),
		string(ResourceTypePasskey), string(ResourceTypeSSO), string(ResourceTypePermission)}
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

// RoleType defines the type for the "role_type" enum field.
type RoleType string

// RoleType values.
const (
	RoleTypeSystem       RoleType = "system"
	RoleTypeOrganization RoleType = "organization"
	RoleTypeApplication  RoleType = "application"
)

func (rt RoleType) Values() []string {
	return []string{string(RoleTypeSystem), string(RoleTypeOrganization), string(RoleTypeApplication)}
}

func (rt RoleType) String() string {
	return string(rt)
}

func (rt RoleType) Schema(r huma.Registry) *huma.Schema {
	if r.Map()["RoleType"] == nil {
		schemaRef := r.Schema(reflect.TypeOf(""), true, "RoleType")
		schemaRef.Title = "RoleType"
		for _, v := range rt.Values() {
			schemaRef.Enum = append(schemaRef.Enum, string(v))
		}
		r.Map()["RoleType"] = schemaRef
	}
	return &huma.Schema{Ref: "#/components/schemas/RoleType"}
}

// WebhookFormat defines the type for the "format" enum field.
type WebhookFormat string

// WebhookFormat values.
const (
	WebhookFormatJSON WebhookFormat = "json"
	WebhookFormatForm WebhookFormat = "form"
)

func (f WebhookFormat) Values() []string {
	return []string{string(WebhookFormatJSON), string(WebhookFormatForm)}
}

func (f WebhookFormat) String() string {
	return string(f)
}

func (f WebhookFormat) Schema(r huma.Registry) *huma.Schema {
	if r.Map()["WebhookFormat"] == nil {
		schemaRef := r.Schema(reflect.TypeOf(""), true, "WebhookFormat")
		schemaRef.Title = "WebhookFormat"
		for _, v := range f.Values() {
			schemaRef.Enum = append(schemaRef.Enum, v)
		}
		r.Map()["WebhookFormat"] = schemaRef
	}
	return &huma.Schema{Ref: "#/components/schemas/WebhookFormat"}
}

// InvoiceStatus defines the type for the "format" enum field.
type InvoiceStatus string

// WebhookFormat values.
const (
	InvoicesStatusDraft         InvoiceStatus = "draft"
	InvoicesStatusOpen          InvoiceStatus = "open"
	InvoicesStatusPaid          InvoiceStatus = "paid"
	InvoicesStatusVoid          InvoiceStatus = "void"
	InvoicesStatusUnCollectible InvoiceStatus = "uncollectible"
)

func (f InvoiceStatus) Values() []string {
	return []string{string(InvoicesStatusDraft), string(InvoicesStatusOpen), string(InvoicesStatusPaid), string(InvoicesStatusVoid), string(InvoicesStatusUnCollectible)}
}

func (f InvoiceStatus) String() string {
	return string(f)
}

func (f InvoiceStatus) InvoicesStatus(r huma.Registry) *huma.Schema {
	if r.Map()["InvoiceStatus"] == nil {
		schemaRef := r.Schema(reflect.TypeOf(""), true, "InvoiceStatus")
		schemaRef.Title = "InvoiceStatus"
		for _, v := range f.Values() {
			schemaRef.Enum = append(schemaRef.Enum, v)
		}
		r.Map()["InvoiceStatus"] = schemaRef
	}
	return &huma.Schema{Ref: "#/components/schemas/InvoiceStatus"}
}
