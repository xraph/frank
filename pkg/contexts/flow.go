package contexts

import (
	"context"
)

// Flow Detection Enums and Constants

type RegistrationFlowType string

const (
	RegistrationFlowStandard RegistrationFlowType = "standard"
	// RegistrationFlowOrganization - External user creating organization (no org context required)
	RegistrationFlowOrganization RegistrationFlowType = "organization"
	// RegistrationFlowInvitation - Any user registering via invitation (org context from token)
	RegistrationFlowInvitation  RegistrationFlowType = "invitation"
	RegistrationFlowSelfService RegistrationFlowType = "self_service"
	// RegistrationFlowInternalUser - Internal user registration (no org context required)
	RegistrationFlowInternalUser RegistrationFlowType = "internal_user"
	// RegistrationFlowExternalUser - External user registration (no org context required, joins orgs later)
	RegistrationFlowExternalUser RegistrationFlowType = "external_user"
	// RegistrationFlowEndUser - End user registration (org context REQUIRED)
	RegistrationFlowEndUser RegistrationFlowType = "end_user"
)

const ()

type UserTypeRequirement string

const (
	UserTypeRequirementNone        UserTypeRequirement = "none"         // Internal users
	UserTypeRequirementOptional    UserTypeRequirement = "optional"     // Can be provided via API key/header
	UserTypeRequirementRequired    UserTypeRequirement = "required"     // Must be provided
	UserTypeRequirementFromContext UserTypeRequirement = "from_context" // Derived from invitation/organization
)

// GetRegistrationFlowFromContext Helper functions for getting flow from context
func GetRegistrationFlowFromContext(ctx context.Context) RegistrationFlowType {
	if flow, ok := ctx.Value(RegistrationFlowKey).(RegistrationFlowType); ok {
		return flow
	}
	return RegistrationFlowStandard
}

// IsOrganizationRegistrationFlow checks if current request is organization registration
func IsOrganizationRegistrationFlow(ctx context.Context) bool {
	return GetRegistrationFlowFromContext(ctx) == RegistrationFlowOrganization
}

// IsInvitationRegistrationFlow checks if current request is invitation-based registration
func IsInvitationRegistrationFlow(ctx context.Context) bool {
	return GetRegistrationFlowFromContext(ctx) == RegistrationFlowInvitation
}

// RegistrationFlowDataKey Context keys
const (
	RegistrationFlowDataKey contextKey = "registration_flow_data"
)

// GetRegistrationFlowDataFromContext Helper functions for getting flow data from context
func GetRegistrationFlowDataFromContext(ctx context.Context) map[string]interface{} {
	if data, ok := ctx.Value(RegistrationFlowDataKey).(map[string]interface{}); ok {
		return data
	}
	return nil
}
