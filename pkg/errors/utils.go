package errors

// GetErrorMessage returns a human-readable error message for an error code
func GetErrorMessage(code string) string {
	if message, exists := ErrorMessages[code]; exists {
		return message
	}
	return ErrorMessages["default"]
}

// UserFriendlyMessages - More friendly messages for end users
var UserFriendlyMessages = map[string]string{
	CodeUnauthorized:        "Please log in to continue",
	CodeInvalidCredentials:  "The email or password you entered is incorrect",
	CodeTokenExpired:        "Your session has expired. Please log in again",
	CodeSessionExpired:      "Your session has expired. Please log in again",
	CodeMFARequired:         "Please complete two-factor authentication",
	CodeEmailNotVerified:    "Please verify your email address to continue",
	CodePasswordTooWeak:     "Please choose a stronger password",
	CodeMemberLimitExceeded: "You've reached your team member limit. Please upgrade your plan",
	CodeInvitationExpired:   "This invitation has expired. Please request a new one",
	CodeRateLimited:         "You're doing that too often. Please wait a moment and try again",
	CodeServiceUnavailable:  "We're experiencing technical difficulties. Please try again later",
	CodeInternalServer:      "Something went wrong on our end. Please try again later",
}

// GetUserFriendlyMessage returns a user-friendly error message
func GetUserFriendlyMessage(code string) string {
	if message, exists := UserFriendlyMessages[code]; exists {
		return message
	}
	if message, exists := ErrorMessages[code]; exists {
		return message
	}
	return "Something went wrong. Please try again"
}

// Developer-friendly error codes with detailed descriptions
var DeveloperMessages = map[string]string{
	CodeInvalidToken:   "The provided JWT token is invalid, malformed, or has an invalid signature",
	CodeTokenExpired:   "The JWT token has exceeded its expiration time (exp claim)",
	CodeInvalidClient:  "The OAuth client_id is invalid or the client is not authorized",
	CodeDatabaseError:  "Database operation failed. Check connection and query syntax",
	CodeRateLimited:    "API rate limit exceeded. Check rate limiting headers for retry information",
	CodeWebhookTimeout: "Webhook endpoint did not respond within the configured timeout period",
}

// GetDeveloperMessage returns a detailed error message for developers
func GetDeveloperMessage(code string) string {
	if message, exists := DeveloperMessages[code]; exists {
		return message
	}
	return GetErrorMessage(code)
}
