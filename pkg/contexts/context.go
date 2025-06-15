package contexts

// Context keys for request context
type contextKey string

const (
	// User context keys
	UserContextKey      contextKey = "user"
	UserIDContextKey    contextKey = "user_id"
	UserTypeContextKey  contextKey = "user_type"
	SessionContextKey   contextKey = "session"
	SessionIDContextKey contextKey = "session_id"

	// Organization context keys
	OrganizationContextKey   contextKey = "organization"
	OrganizationIDContextKey contextKey = "organization_id"

	// Authentication context keys
	AuthMethodContextKey  contextKey = "auth_method"
	APIKeyContextKey      contextKey = "api_key"
	APIKeyIDContextKey    contextKey = "api_key_id"
	TokenClaimsContextKey contextKey = "token_claims"

	// Request context keys
	RequestIDContextKey contextKey = "request_id"
	IPAddressContextKey contextKey = "ip_address"
	UserAgentContextKey contextKey = "user_agent"

	// Permission context keys
	PermissionsContextKey contextKey = "permissions"
	RolesContextKey       contextKey = "roles"

	HeadersContextKKey    contextKey = "frank-headers"
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
