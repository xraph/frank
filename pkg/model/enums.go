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
	ContextPlatform     ContextType = "platform"
	ContextOrganization ContextType = "organization"
	ContextApplication  ContextType = "application"
	ContextResource     ContextType = "resource"
	ContextSelf         ContextType = "self"
	ContextGlobal       ContextType = "global"
)

func (c ContextType) Values() []string {
	return []string{
		string(ContextPlatform),
		string(ContextOrganization),
		string(ContextApplication),
		string(ContextResource),
		string(ContextSelf),
		string(ContextGlobal)}
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

type APIKeyType string

const (
	// APIKeyTypeClient represents client-side API keys
	// These provide organization context but don't act as authenticated users
	// Used by frontend SDKs for public operations like signup/login
	APIKeyTypeClient APIKeyType = "client"

	// APIKeyTypeServer represents server-side API keys
	// These act as authenticated users with full permissions
	// Used for server-to-server communication
	APIKeyTypeServer APIKeyType = "server"

	// APIKeyTypeAdmin represents administrative API keys
	// These act as authenticated users with elevated permissions
	// Used for administrative operations
	APIKeyTypeAdmin APIKeyType = "admin"
)

func (t APIKeyType) String() string {
	return string(t)
}

func (t APIKeyType) Values() []string {
	return []string{string(APIKeyTypeServer), string(APIKeyTypeClient), string(APIKeyTypeAdmin)}
}

func (t APIKeyType) Schema(r huma.Registry) *huma.Schema {
	if r.Map()["APIKeyType"] == nil {
		schemaRef := r.Schema(reflect.TypeOf(""), true, "APIKeyType")
		schemaRef.Title = "APIKeyType"
		for _, v := range t.Values() {
			schemaRef.Enum = append(schemaRef.Enum, v)
		}
		r.Map()["APIKeyType"] = schemaRef
	}
	return &huma.Schema{Ref: "#/components/schemas/APIKeyType"}
}

// IsValid checks if the API key type is valid
func (t APIKeyType) IsValid() bool {
	switch t {
	case APIKeyTypeClient, APIKeyTypeServer, APIKeyTypeAdmin:
		return true
	default:
		return false
	}
}

// IsClientType checks if the API key type is client
func (t APIKeyType) IsClientType() bool {
	return t == APIKeyTypeClient
}

// IsServerType checks if the API key type is server
func (t APIKeyType) IsServerType() bool {
	return t == APIKeyTypeServer
}

// IsAdminType checks if the API key type is admin
func (t APIKeyType) IsAdminType() bool {
	return t == APIKeyTypeAdmin
}

// RequiresUserContext returns true if this API key type should create a user context
func (t APIKeyType) RequiresUserContext() bool {
	return t == APIKeyTypeServer || t == APIKeyTypeAdmin
}

type Environment string

const (
	EnvironmentTest        Environment = "test"
	EnvironmentLive        Environment = "live"
	EnvironmentDevelopment Environment = "development"
	EnvironmentStaging     Environment = "staging"
	EnvironmentProduction  Environment = "production"
)

func (e Environment) String() string {
	return string(e)
}

func (e Environment) Values() []string {
	return []string{string(EnvironmentTest), string(EnvironmentLive), string(EnvironmentDevelopment), string(EnvironmentStaging), string(EnvironmentProduction)}
}

func (e Environment) Schema(r huma.Registry) *huma.Schema {
	if r.Map()["Environment"] == nil {
		schemaRef := r.Schema(reflect.TypeOf(""), true, "Environment")
		schemaRef.Title = "Environment"
		for _, v := range e.Values() {
			schemaRef.Enum = append(schemaRef.Enum, v)
		}
		r.Map()["Environment"] = schemaRef
	}
	return &huma.Schema{Ref: "#/components/schemas/Environment"}
}
