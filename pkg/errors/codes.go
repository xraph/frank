package errors

// Error codes for the application
const (
	// Authentication and Authorization error codes
	CodeUnauthorized           = "unauthorized"
	CodeForbidden              = "forbidden"
	CodeInvalidCredentials     = "invalid_credentials"
	CodeInvalidToken           = "invalid_token"
	CodeTokenExpired           = "token_expired"
	CodeInvalidRefreshToken    = "invalid_refresh_token"
	CodeSessionExpired         = "session_expired"
	CodeMFARequired            = "mfa_required"
	CodeMFAFailed              = "mfa_failed"
	CodeEmailNotVerified       = "email_not_verified"
	CodeInvalidAPIKey          = "invalid_api_key"
	CodeInvalidOAuthState      = "invalid_oauth_state"
	CodeOAuthFailed            = "oauth_failed"
	CodeSSOMismatch            = "sso_mismatch"
	CodeInvalidPasskey         = "invalid_passkey"
	CodePasskeyRegistration    = "passkey_registration_error"
	CodePasskeyAuthentication  = "passkey_authentication_error"
	CodePasswordlessLinkFailed = "passwordless_link_failed"

	// Resource error codes
	CodeNotFound              = "not_found"
	CodeAlreadyExists         = "already_exists"
	CodeValidation            = "validation_error"
	CodeConflict              = "conflict"
	CodeUserNotFound          = "user_not_found"
	CodeOrganizationNotFound  = "organization_not_found"
	CodeResourceNotFound      = "resource_not_found"
	CodeRoleNotFound          = "role_not_found"
	CodePermissionNotFound    = "permission_not_found"
	CodeClientNotFound        = "client_not_found"
	CodeWebhookNotFound       = "webhook_not_found"
	CodeFeatureFlagNotFound   = "feature_flag_not_found"
	CodeFeatureNotEnabled     = "feature_not_enabled"
	CodeScopeNotFound         = "scope_not_found"
	CodeTemplateNotFound      = "template_not_found"
	CodeIdentityProviderError = "identity_provider_error"
	CodeLimitExceeded         = "limit_exceeded"

	// Input validation error codes
	CodeBadRequest           = "bad_request"
	CodeUnprocessableEntity  = "unprocessable_entity"
	CodeInvalidInput         = "invalid_input"
	CodeInvalidFormat        = "invalid_format"
	CodeInvalidEmail         = "invalid_email"
	CodeInvalidPhone         = "invalid_phone"
	CodeInvalidPassword      = "invalid_password"
	CodeInvalidOTP           = "invalid_otp"
	CodePasswordTooWeak      = "password_too_weak"
	CodeInvalidRedirectURI   = "invalid_redirect_uri"
	CodeInvalidScope         = "invalid_scope"
	CodeInvalidWebhookURL    = "invalid_webhook_url"
	CodeInvalidCallbackURL   = "invalid_callback_url"
	CodeMissingRequiredField = "missing_required_field"
	CodeInvalidMetadata      = "invalid_metadata"

	// Server error codes
	CodeInternalServer      = "internal_server_error"
	CodeDatabaseError       = "database_error"
	CodeCryptoError         = "crypto_error"
	CodeServiceUnavailable  = "service_unavailable"
	CodeStorageError        = "storage_error"
	CodeNetworkError        = "network_error"
	CodeWebhookDeliveryFail = "webhook_delivery_fail"
	CodeEmailDeliveryFail   = "email_delivery_fail"
	CodeSMSDeliveryFail     = "sms_delivery_fail"
	CodeConfigurationError  = "configuration_error"
	CodeThirdPartyAPIError  = "third_party_api_error"
	CodeUnexpectedError     = "unexpected_error"

	// Request handling error codes
	CodeMethodNotAllowed     = "method_not_allowed"
	CodeTooManyRequests      = "too_many_requests"
	CodeRateLimited          = "rate_limited"
	CodeRequestTimeout       = "request_timeout"
	CodeInvalidHeader        = "invalid_header"
	CodeUnsupportedOperation = "unsupported_operation"
	CodeNotImplemented       = "not_implemented"

	// Error codes specific to SSO

	// CodeProviderNotFound indicates that the requested identity provider was not found
	CodeProviderNotFound = "sso_provider_not_found"
	// CodeProviderDisabled indicates that the identity provider is disabled
	CodeProviderDisabled = "sso_provider_disabled"
	// CodeProviderInitError indicates an error initializing the identity provider
	CodeProviderInitError = "sso_provider_init_error"
	// CodeInvalidCallback indicates an error with the SSO callback
	CodeInvalidCallback = "sso_invalid_callback"
	// CodeUnsupportedProvider indicates that the provider type is not supported
	CodeUnsupportedProvider = "sso_unsupported_provider"
	// CodeDomainNotAllowed indicates that the email domain is not allowed for this provider
	CodeDomainNotAllowed = "sso_domain_not_allowed"
	// CodeProviderCommunicationError indicates an error communicating with the identity provider
	CodeProviderCommunicationError = "sso_provider_communication_error"
	// CodeMissingUserInfo indicates that required user information is missing
	CodeMissingUserInfo = "sso_missing_user_info"
)

// ErrorGroups categorizes error codes for easier handling
var ErrorGroups = map[string][]string{
	"authentication": {
		CodeUnauthorized,
		CodeInvalidCredentials,
		CodeInvalidToken,
		CodeTokenExpired,
		CodeInvalidRefreshToken,
		CodeSessionExpired,
		CodeMFARequired,
		CodeMFAFailed,
		CodeEmailNotVerified,
		CodeInvalidAPIKey,
		CodeInvalidOAuthState,
		CodeOAuthFailed,
		CodeSSOMismatch,
		CodeInvalidPasskey,
		CodePasskeyRegistration,
		CodePasskeyAuthentication,
		CodePasswordlessLinkFailed,
	},
	"authorization": {
		CodeForbidden,
		CodeFeatureNotEnabled,
	},
	"resource": {
		CodeNotFound,
		CodeAlreadyExists,
		CodeConflict,
		CodeUserNotFound,
		CodeOrganizationNotFound,
		CodeResourceNotFound,
		CodeRoleNotFound,
		CodePermissionNotFound,
		CodeClientNotFound,
		CodeWebhookNotFound,
		CodeFeatureFlagNotFound,
		CodeScopeNotFound,
		CodeTemplateNotFound,
		CodeIdentityProviderError,
	},
	"validation": {
		CodeBadRequest,
		CodeUnprocessableEntity,
		CodeInvalidInput,
		CodeInvalidFormat,
		CodeInvalidEmail,
		CodeInvalidPhone,
		CodeInvalidPassword,
		CodeInvalidOTP,
		CodePasswordTooWeak,
		CodeInvalidRedirectURI,
		CodeInvalidScope,
		CodeInvalidWebhookURL,
		CodeInvalidCallbackURL,
		CodeMissingRequiredField,
		CodeInvalidMetadata,
	},
	"server": {
		CodeInternalServer,
		CodeDatabaseError,
		CodeCryptoError,
		CodeServiceUnavailable,
		CodeStorageError,
		CodeNetworkError,
		CodeWebhookDeliveryFail,
		CodeEmailDeliveryFail,
		CodeSMSDeliveryFail,
		CodeConfigurationError,
		CodeThirdPartyAPIError,
		CodeUnexpectedError,
	},
	"request": {
		CodeMethodNotAllowed,
		CodeTooManyRequests,
		CodeRateLimited,
		CodeRequestTimeout,
		CodeInvalidHeader,
		CodeUnsupportedOperation,
		CodeNotImplemented,
	},
	"sso": {
		CodeProviderNotFound,
		CodeProviderDisabled,
		CodeProviderInitError,
		CodeInvalidCallback,
		CodeUnsupportedProvider,
		CodeDomainNotAllowed,
		CodeProviderCommunicationError,
		CodeMissingUserInfo,
	},
}
