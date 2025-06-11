package errors

// Authentication and Authorization Error Codes
const (
	// Authentication Errors
	CodeUnauthorized           = "unauthorized"
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
	CodePasskeyRegistration    = "passkey_registration_failed"
	CodePasskeyAuthentication  = "passkey_authentication_failed"
	CodePasswordlessLinkFailed = "passwordless_link_failed"

	// Authorization Errors
	CodeForbidden         = "forbidden"
	CodeFeatureNotEnabled = "feature_not_enabled"

	// Resource Errors
	CodeNotFound             = "not_found"
	CodeUserNotFound         = "user_not_found"
	CodeOrganizationNotFound = "organization_not_found"
	CodeResourceNotFound     = "resource_not_found"
	CodeRoleNotFound         = "role_not_found"
	CodePermissionNotFound   = "permission_not_found"
	CodeClientNotFound       = "client_not_found"
	CodeWebhookNotFound      = "webhook_not_found"
	CodeFeatureFlagNotFound  = "feature_flag_not_found"
	CodeScopeNotFound        = "scope_not_found"
	CodeTemplateNotFound     = "template_not_found"
	CodeProviderNotFound     = "provider_not_found"
	CodeLimitExceeded        = "limit_exceeded"

	// Conflict Errors
	CodeAlreadyExists = "already_exists"
	CodeConflict      = "conflict"

	// Validation Errors
	CodeBadRequest           = "bad_request"
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
	CodeInvalidHeader        = "invalid_header"
	CodeInvalidCallback      = "invalid_callback"
	CodeUnprocessableEntity  = "unprocessable_entity"

	// Server Errors
	CodeInternalServer             = "internal_server_error"
	CodeDatabaseError              = "database_error"
	CodeCryptoError                = "crypto_error"
	CodeStorageError               = "storage_error"
	CodeNetworkError               = "network_error"
	CodeWebhookDeliveryFail        = "webhook_delivery_failed"
	CodeEmailDeliveryFail          = "email_delivery_failed"
	CodeSMSDeliveryFail            = "sms_delivery_failed"
	CodeConfigurationError         = "configuration_error"
	CodeThirdPartyAPIError         = "third_party_api_error"
	CodeUnexpectedError            = "unexpected_error"
	CodeIdentityProviderError      = "identity_provider_error"
	CodeProviderInitError          = "provider_initialization_error"
	CodeProviderCommunicationError = "provider_communication_error"
	CodeMissingUserInfo            = "missing_user_info"
	CodeServiceUnavailable         = "service_unavailable"
	CodeValidationError            = "validation_error"

	// Request Handling Errors
	CodeMethodNotAllowed     = "method_not_allowed"
	CodeTooManyRequests      = "too_many_requests"
	CodeRateLimited          = "rate_limited"
	CodeRequestTimeout       = "request_timeout"
	CodeUnsupportedOperation = "unsupported_operation"
	CodeNotImplemented       = "not_implemented"
	CodeUnsupportedProvider  = "unsupported_provider"

	// SSO Specific Errors
	CodeProviderDisabled = "provider_disabled"
	CodeDomainNotAllowed = "domain_not_allowed"

	// Organization & Membership Errors
	CodeOrganizationInactive   = "organization_inactive"
	CodeMembershipNotFound     = "membership_not_found"
	CodeInvitationExpired      = "invitation_expired"
	CodeInvitationNotFound     = "invitation_not_found"
	CodeMemberLimitExceeded    = "member_limit_exceeded"
	CodeInsufficientRole       = "insufficient_role"
	CodeCannotRemoveOwner      = "cannot_remove_owner"
	CodeInvalidInvitationToken = "invalid_invitation_token"

	// Billing & Subscription Errors
	CodeSubscriptionRequired = "subscription_required"
	CodeSubscriptionInactive = "subscription_inactive"
	CodePaymentRequired      = "payment_required"
	CodePlanLimitExceeded    = "plan_limit_exceeded"
	CodeBillingError         = "billing_error"
	CodeInvalidPaymentMethod = "invalid_payment_method"

	// MFA Specific Errors
	CodeMFASetupRequired  = "mfa_setup_required"
	CodeInvalidMFACode    = "invalid_mfa_code"
	CodeMFACodeExpired    = "mfa_code_expired"
	CodeMFAMethodNotFound = "mfa_method_not_found"
	CodeMFAAlreadyEnabled = "mfa_already_enabled"
	CodeBackupCodeUsed    = "backup_code_used"
	CodeInvalidBackupCode = "invalid_backup_code"

	// OAuth2 & OIDC Errors
	CodeInvalidGrantType         = "invalid_grant_type"
	CodeInvalidClient            = "invalid_client"
	CodeInvalidClientSecret      = "invalid_client_secret"
	CodeUnsupportedGrantType     = "unsupported_grant_type"
	CodeInvalidAuthorizationCode = "invalid_authorization_code"
	CodeCodeExpired              = "code_expired"
	CodeCodeUsed                 = "code_used"
	CodeInvalidPKCE              = "invalid_pkce"
	CodeMissingCodeChallenge     = "missing_code_challenge"
	CodeInvalidCodeChallenge     = "invalid_code_challenge"

	// Passkey/WebAuthn Errors
	CodePasskeyNotSupported = "passkey_not_supported"
	CodeInvalidChallenge    = "invalid_challenge"
	CodeAttestationFailed   = "attestation_failed"
	CodeAssertionFailed     = "assertion_failed"
	CodeInvalidCredentialID = "invalid_credential_id"
	CodePasskeyExpired      = "passkey_expired"

	// Audit & Compliance Errors
	CodeAuditLogFailed           = "audit_log_failed"
	CodeComplianceViolation      = "compliance_violation"
	CodeRetentionPolicyViolation = "retention_policy_violation"
	CodeDataExportFailed         = "data_export_failed"

	// Webhook Errors
	CodeWebhookValidationFailed = "webhook_validation_failed"
	CodeWebhookSecretMismatch   = "webhook_secret_mismatch"
	CodeWebhookTimeout          = "webhook_timeout"
	CodeWebhookRetryExhausted   = "webhook_retry_exhausted"

	// Template & Notification Errors
	CodeTemplateRenderFailed = "template_render_failed"
	CodeNotificationFailed   = "notification_failed"
	CodeInvalidTemplate      = "invalid_template"
	// CodeTemplateNotFound     = "template_not_found"

	// API Key Errors
	CodeAPIKeyNotFound      = "api_key_not_found"
	CodeAPIKeyExpired       = "api_key_expired"
	CodeAPIKeyRevoked       = "api_key_revoked"
	CodeAPIKeyLimitExceeded = "api_key_limit_exceeded"

	// Session Errors
	CodeSessionNotFound        = "session_not_found"
	CodeSessionLimitExceeded   = "session_limit_exceeded"
	CodeConcurrentSessionLimit = "concurrent_session_limit"

	// Password Policy Errors
	CodePasswordHistoryViolation = "password_history_violation"
	CodePasswordComplexityFailed = "password_complexity_failed"
	CodePasswordExpired          = "password_expired"
	CodePasswordResetRequired    = "password_reset_required"

	// Device & Security Errors
	CodeSuspiciousActivity      = "suspicious_activity"
	CodeDeviceNotRecognized     = "device_not_recognized"
	CodeLocationNotAllowed      = "location_not_allowed"
	CodeSecurityPolicyViolation = "security_policy_violation"
	CodeAccountLocked           = "account_locked"
	CodeAccountSuspended        = "account_suspended"

	// Feature Flag Errors
	CodeFeatureFlagDisabled = "feature_flag_disabled"
	// CodeFeatureFlagNotFound = "feature_flag_not_found"

	// Import/Export Errors
	CodeImportFailed            = "import_failed"
	CodeExportFailed            = "export_failed"
	CodeInvalidImportFormat     = "invalid_import_format"
	CodeImportSizeLimitExceeded = "import_size_limit_exceeded"

	// Custom Attribute Errors
	CodeInvalidCustomAttribute  = "invalid_custom_attribute"
	CodeCustomAttributeRequired = "custom_attribute_required"
	CodeCustomAttributeNotFound = "custom_attribute_not_found"

	// Domain & DNS Errors
	CodeDomainVerificationFailed = "domain_verification_failed"
	CodeDomainNotVerified        = "domain_not_verified"
	CodeInvalidDomain            = "invalid_domain"
	CodeDomainAlreadyExists      = "domain_already_exists"

	// File Upload Errors
	CodeFileTooLarge     = "file_too_large"
	CodeInvalidFileType  = "invalid_file_type"
	CodeFileUploadFailed = "file_upload_failed"
	CodeFileNotFound     = "file_not_found"

	// Integration Errors
	CodeIntegrationFailed        = "integration_failed"
	CodeIntegrationNotConfigured = "integration_not_configured"
	CodeIntegrationTimeout       = "integration_timeout"
	CodeIntegrationRateLimited   = "integration_rate_limited"
)

// Error Categories for grouping and filtering
var ErrorCategories = map[string][]string{
	"authentication": {
		CodeUnauthorized,
		CodeInvalidCredentials,
		CodeInvalidToken,
		CodeTokenExpired,
		CodeInvalidRefreshToken,
		CodeSessionExpired,
		CodeEmailNotVerified,
		CodeInvalidAPIKey,
		CodePasswordlessLinkFailed,
	},
	"authorization": {
		CodeForbidden,
		CodeFeatureNotEnabled,
		CodeInsufficientRole,
	},
	"mfa": {
		CodeMFARequired,
		CodeMFAFailed,
		CodeMFASetupRequired,
		CodeInvalidMFACode,
		CodeMFACodeExpired,
		CodeMFAMethodNotFound,
		CodeMFAAlreadyEnabled,
		CodeBackupCodeUsed,
		CodeInvalidBackupCode,
	},
	"validation": {
		CodeBadRequest,
		CodeInvalidInput,
		CodeInvalidFormat,
		CodeInvalidEmail,
		CodeInvalidPhone,
		CodeInvalidPassword,
		CodePasswordTooWeak,
		CodeMissingRequiredField,
		CodeUnprocessableEntity,
	},
	"resources": {
		CodeNotFound,
		CodeUserNotFound,
		CodeOrganizationNotFound,
		CodeResourceNotFound,
		CodeRoleNotFound,
		CodePermissionNotFound,
		CodeClientNotFound,
		CodeWebhookNotFound,
	},
	"conflicts": {
		CodeAlreadyExists,
		CodeConflict,
	},
	"server": {
		CodeInternalServer,
		CodeDatabaseError,
		CodeCryptoError,
		CodeStorageError,
		CodeNetworkError,
		CodeConfigurationError,
		CodeServiceUnavailable,
	},
	"rate_limiting": {
		CodeTooManyRequests,
		CodeRateLimited,
		CodeRequestTimeout,
	},
	"organizations": {
		CodeOrganizationInactive,
		CodeMembershipNotFound,
		CodeInvitationExpired,
		CodeInvitationNotFound,
		CodeMemberLimitExceeded,
		CodeCannotRemoveOwner,
		CodeInvalidInvitationToken,
	},
	"billing": {
		CodeSubscriptionRequired,
		CodeSubscriptionInactive,
		CodePaymentRequired,
		CodePlanLimitExceeded,
		CodeBillingError,
		CodeInvalidPaymentMethod,
	},
	"oauth": {
		CodeInvalidGrantType,
		CodeInvalidClient,
		CodeInvalidClientSecret,
		CodeUnsupportedGrantType,
		CodeInvalidAuthorizationCode,
		CodeCodeExpired,
		CodeCodeUsed,
		CodeInvalidPKCE,
	},
	"passkeys": {
		CodePasskeyNotSupported,
		CodeInvalidChallenge,
		CodeAttestationFailed,
		CodeAssertionFailed,
		CodeInvalidCredentialID,
		CodePasskeyExpired,
		CodeInvalidPasskey,
		CodePasskeyRegistration,
		CodePasskeyAuthentication,
	},
	"webhooks": {
		CodeWebhookNotFound,
		CodeWebhookValidationFailed,
		CodeWebhookSecretMismatch,
		CodeWebhookTimeout,
		CodeWebhookRetryExhausted,
		CodeWebhookDeliveryFail,
	},
	"notifications": {
		CodeEmailDeliveryFail,
		CodeSMSDeliveryFail,
		CodeNotificationFailed,
		CodeTemplateNotFound,
		CodeTemplateRenderFailed,
		CodeInvalidTemplate,
	},
	"security": {
		CodeSuspiciousActivity,
		CodeDeviceNotRecognized,
		CodeLocationNotAllowed,
		CodeSecurityPolicyViolation,
		CodeAccountLocked,
		CodeAccountSuspended,
	},
	"sso": {
		CodeSSOMismatch,
		CodeOAuthFailed,
		CodeInvalidOAuthState,
		CodeProviderDisabled,
		CodeDomainNotAllowed,
		CodeIdentityProviderError,
		CodeProviderInitError,
		CodeProviderCommunicationError,
		CodeMissingUserInfo,
	},
}

// Error Severity Levels
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Error severity mapping
var ErrorSeverity = map[string]string{
	// Critical errors that affect core functionality
	CodeInternalServer:     SeverityCritical,
	CodeDatabaseError:      SeverityCritical,
	CodeServiceUnavailable: SeverityCritical,
	CodeConfigurationError: SeverityCritical,
	CodeCryptoError:        SeverityCritical,

	// High severity errors that block user actions
	CodeUnauthorized:     SeverityHigh,
	CodeForbidden:        SeverityHigh,
	CodeTokenExpired:     SeverityHigh,
	CodeSessionExpired:   SeverityHigh,
	CodeMFARequired:      SeverityHigh,
	CodeEmailNotVerified: SeverityHigh,
	CodeAccountLocked:    SeverityHigh,
	CodeAccountSuspended: SeverityHigh,

	// Medium severity errors that may impact functionality
	CodeInvalidCredentials: SeverityMedium,
	CodeInvalidToken:       SeverityMedium,
	CodeMFAFailed:          SeverityMedium,
	CodeNotFound:           SeverityMedium,
	CodeConflict:           SeverityMedium,
	CodeRateLimited:        SeverityMedium,
	CodeTooManyRequests:    SeverityMedium,

	// Low severity errors for validation and user input
	CodeBadRequest:           SeverityLow,
	CodeInvalidInput:         SeverityLow,
	CodeInvalidFormat:        SeverityLow,
	CodeInvalidEmail:         SeverityLow,
	CodeInvalidPhone:         SeverityLow,
	CodeMissingRequiredField: SeverityLow,
}

// GetErrorCategory returns the category of an error code
func GetErrorCategory(code string) string {
	for category, codes := range ErrorCategories {
		for _, c := range codes {
			if c == code {
				return category
			}
		}
	}
	return "unknown"
}

// GetErrorSeverity returns the severity level of an error code
func GetErrorSeverity(code string) string {
	if severity, exists := ErrorSeverity[code]; exists {
		return severity
	}
	return SeverityMedium // Default to medium severity
}

// IsClientError checks if error code represents a client error (4xx)
func IsClientError(code string) bool {
	clientErrorCodes := []string{
		CodeBadRequest,
		CodeUnauthorized,
		CodeForbidden,
		CodeNotFound,
		CodeMethodNotAllowed,
		CodeConflict,
		CodeUnprocessableEntity,
		CodeTooManyRequests,
	}

	for _, c := range clientErrorCodes {
		if c == code {
			return true
		}
	}
	return false
}

// IsServerError checks if error code represents a server error (5xx)
func IsServerError(code string) bool {
	serverErrorCodes := []string{
		CodeInternalServer,
		CodeNotImplemented,
		CodeBadRequest,
		CodeServiceUnavailable,
		CodeDatabaseError,
		CodeCryptoError,
		CodeStorageError,
		CodeNetworkError,
		CodeConfigurationError,
		CodeThirdPartyAPIError,
		CodeUnexpectedError,
	}

	for _, c := range serverErrorCodes {
		if c == code {
			return true
		}
	}
	return false
}

// IsRetryable checks if an error should be retried
func IsRetryable(code string) bool {
	retryableErrors := []string{
		CodeNetworkError,
		CodeServiceUnavailable,
		CodeRequestTimeout,
		CodeRateLimited,
		CodeTooManyRequests,
		CodeThirdPartyAPIError,
		CodeWebhookTimeout,
		CodeIntegrationTimeout,
	}

	for _, c := range retryableErrors {
		if c == code {
			return true
		}
	}
	return false
}

// Error Messages - Human readable descriptions
var ErrorMessages = map[string]string{
	// Authentication Errors
	CodeUnauthorized:           "Authentication required",
	CodeInvalidCredentials:     "Invalid email or password",
	CodeInvalidToken:           "Invalid or malformed token",
	CodeTokenExpired:           "Token has expired",
	CodeInvalidRefreshToken:    "Invalid refresh token",
	CodeSessionExpired:         "Session has expired",
	CodeMFARequired:            "Multi-factor authentication required",
	CodeMFAFailed:              "Multi-factor authentication failed",
	CodeEmailNotVerified:       "Email address not verified",
	CodeInvalidAPIKey:          "Invalid API key",
	CodePasswordlessLinkFailed: "Failed to send passwordless login link",

	// Authorization Errors
	CodeForbidden:         "Access denied",
	CodeFeatureNotEnabled: "Feature not enabled for your plan",

	// Resource Errors
	CodeNotFound:             "Resource not found",
	CodeUserNotFound:         "User not found",
	CodeOrganizationNotFound: "Organization not found",
	CodeResourceNotFound:     "Resource not found",
	CodeRoleNotFound:         "Role not found",
	CodePermissionNotFound:   "Permission not found",

	// Validation Errors
	CodeBadRequest:           "Invalid request",
	CodeInvalidInput:         "Invalid input provided",
	CodeInvalidFormat:        "Invalid format",
	CodeInvalidEmail:         "Invalid email address",
	CodeInvalidPhone:         "Invalid phone number",
	CodeInvalidPassword:      "Invalid password",
	CodePasswordTooWeak:      "Password does not meet requirements",
	CodeMissingRequiredField: "Required field is missing",

	// Server Errors
	CodeInternalServer:     "Internal server error",
	CodeDatabaseError:      "Database error occurred",
	CodeServiceUnavailable: "Service temporarily unavailable",
	CodeNotImplemented:     "Feature not implemented",

	// Rate Limiting
	CodeTooManyRequests: "Too many requests",
	CodeRateLimited:     "Rate limit exceeded",

	// Organization Errors
	CodeMemberLimitExceeded: "Organization member limit exceeded",
	CodeInvitationExpired:   "Invitation has expired",
	CodeCannotRemoveOwner:   "Cannot remove organization owner",

	// MFA Errors
	CodeInvalidMFACode:    "Invalid MFA code",
	CodeMFACodeExpired:    "MFA code has expired",
	CodeMFAMethodNotFound: "MFA method not found",

	// OAuth Errors
	CodeInvalidClient:    "Invalid OAuth client",
	CodeInvalidGrantType: "Invalid grant type",
	CodeCodeExpired:      "Authorization code has expired",

	// Passkey Errors
	CodePasskeyNotSupported: "Passkeys not supported",
	CodeAttestationFailed:   "Passkey attestation failed",
	CodeAssertionFailed:     "Passkey assertion failed",

	// Default message for unmapped codes
	"default": "An error occurred",
}
