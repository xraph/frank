package contexts

// Context keys for request context
type contextKey string

// Authentication context keys
const (
	UserContextKey        contextKey = "user"
	UserIDContextKey      contextKey = "user_id"
	UserTypeContextKey    contextKey = "user_type"
	SessionContextKey     contextKey = "session"
	SessionIDContextKey   contextKey = "session_id"
	APIKeyContextKey      contextKey = "api_key"
	APIKeyIDContextKey    contextKey = "api_key_id"
	AuthMethodContextKey  contextKey = "auth_method"
	PermissionsContextKey contextKey = "permissions"
	RolesContextKey       contextKey = "roles"
	TokenClaimsContextKey contextKey = "token_claims"
)

// Organization/Tenant context keys
const (
	OrganizationContextKey   contextKey = "organization"
	OrganizationIDContextKey contextKey = "organization_id"
	TenantContextKey         contextKey = "tenant"
	TenantIDContextKey       contextKey = "tenant_id"
	TenantSlugContextKey     contextKey = "tenant_slug"
	TenantPlanContextKey     contextKey = "tenant_plan"
	TenantTypeContextKey     contextKey = "tenant_type"
)

// Detection context keys (for pre-authentication detection)
const (
	DetectedUserTypeKey       contextKey = "detected_user_type"
	DetectedOrganizationIDKey contextKey = "detected_organization_id"
)

// Request context keys
const (
	RequestIDContextKey   contextKey = "request_id"
	IPAddressContextKey   contextKey = "ip_address"
	UserAgentContextKey   contextKey = "user_agent"
	HeadersContextKKey    contextKey = "headers"
	RequestInfoContextKey contextKey = "request_info"
	HTTPRequestContextKey contextKey = "http_request"
	HTTPResponseWriterKey contextKey = "http_response_writer"
	HTTPRequestCookieKey  contextKey = "http_request_cookie"
	HTTPRequestIDKey      contextKey = "http_request_id"
	HTTPRequestMethodKey  contextKey = "http_request_method"
	HTTPRequestPathKey    contextKey = "http_request_path"
	HTTPRequestQueryKey   contextKey = "http_request_query"
	HTTPRequestHostKey    contextKey = "http_request_host"
	HTTPRequestSchemeKey  contextKey = "http_request_scheme"
	HTTPRequestProtoKey   contextKey = "http_request_proto"
)

// RegistrationFlowKey Context keys for registration flows
const (
	RegistrationFlowKey contextKey = "registration_flow"
)
