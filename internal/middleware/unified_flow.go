package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/xid"
	"github.com/xraph/frank/internal/di"
	"github.com/xraph/frank/internal/repository"
	"github.com/xraph/frank/pkg/contexts"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
	"github.com/xraph/frank/pkg/model"
	"github.com/xraph/frank/pkg/server"
	"github.com/xraph/frank/pkg/services/organization"
)

// UnifiedRegistrationMiddleware handles all registration flows through a single endpoint
type UnifiedRegistrationMiddleware struct {
	config            *OrganizationContextConfig
	orgRepo           repository.OrganizationRepository
	userRepo          repository.UserRepository
	apiKeyRepo        repository.ApiKeyRepository
	invitationService organization.InvitationService
	logger            logging.Logger
	api               huma.API
	mountOpts         *server.MountOptions
}

// NewUnifiedRegistrationMiddleware creates middleware for unified registration flow detection
func NewUnifiedRegistrationMiddleware(api huma.API, di di.Container, mountOpts *server.MountOptions, config *OrganizationContextConfig) *UnifiedRegistrationMiddleware {
	if config == nil {
		config = DefaultOrganizationContextConfig()
	}

	if config.Logger == nil {
		config.Logger = di.Logger().Named("unified-registration-middleware")
	}

	return &UnifiedRegistrationMiddleware{
		config:            config,
		orgRepo:           di.Repo().Organization(),
		userRepo:          di.Repo().User(),
		apiKeyRepo:        di.Repo().APIKey(),
		invitationService: di.InvitationService(),
		logger:            config.Logger,
		api:               api,
		mountOpts:         mountOpts,
	}
}

// UnifiedRegistrationMiddleware detects flow and applies appropriate organization context rules
func (urm *UnifiedRegistrationMiddleware) UnifiedRegistrationMiddleware() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		rctx := ctx.Context()
		r := contexts.GetRequestFromContext(rctx)

		// Skip for non-registration paths
		if !urm.isRegistrationPath(ctx.URL().Path) {
			next(ctx)
			return
		}

		// Detect registration flow from request
		flow, flowData, err := urm.detectRegistrationFlow(rctx, r)
		if err != nil {
			urm.logger.Debug("Failed to detect registration flow", logging.Error(err))
			// Continue with default flow detection
		}

		// Set flow data in context
		ctx = huma.WithValue(ctx, contexts.RegistrationFlowKey, flow)
		if flowData != nil {
			ctx = huma.WithValue(ctx, contexts.RegistrationFlowDataKey, flowData)
		}

		// Apply organization context rules based on detected flow
		if err := urm.applyFlowRules(ctx, flow, flowData); err != nil {
			urm.respondErrorHuma(ctx, err)
			return
		}

		urm.logger.Debug("Registration flow detected and validated",
			logging.String("flow", string(flow)),
			logging.String("path", ctx.URL().Path))

		next(ctx)
	}
}

// detectRegistrationFlow analyzes request to determine the registration flow
func (urm *UnifiedRegistrationMiddleware) detectRegistrationFlow(ctx context.Context, r *http.Request) (contexts.RegistrationFlowType, map[string]interface{}, error) {
	flowData := make(map[string]interface{})

	// Extract flow indicators from multiple sources
	indicators := urm.extractFlowIndicators(r)

	// 1. Check for invitation token (highest priority)
	if invitationToken := urm.getInvitationToken(indicators); invitationToken != "" {
		flowData["invitation_token"] = invitationToken
		return contexts.RegistrationFlowInvitation, flowData, nil
	}

	// 2. Check for organization creation flags
	if urm.isOrganizationCreationRequest(indicators) {
		flowData["organization_creation"] = true
		return contexts.RegistrationFlowOrganization, flowData, nil
	}

	// 3. Detect from user type
	userType := urm.getUserType(indicators)
	flowData["user_type"] = userType

	switch userType {
	case string(model.UserTypeInternal):
		return contexts.RegistrationFlowInternalUser, flowData, nil

	case string(model.UserTypeExternal):
		return contexts.RegistrationFlowExternalUser, flowData, nil

	case string(model.UserTypeEndUser):
		// End users require organization context
		return contexts.RegistrationFlowEndUser, flowData, nil

	default:
		// Default to external user if no type specified
		flowData["user_type"] = string(model.UserTypeExternal)
		return contexts.RegistrationFlowExternalUser, flowData, nil
	}
}

// applyFlowRules applies organization context rules based on the detected flow
func (urm *UnifiedRegistrationMiddleware) applyFlowRules(ctx huma.Context, flow contexts.RegistrationFlowType, flowData map[string]interface{}) error {
	switch flow {
	case contexts.RegistrationFlowOrganization:
		return urm.handleOrganizationCreationFlow(ctx, flowData)

	case contexts.RegistrationFlowInvitation:
		return urm.handleInvitationBasedFlow(ctx, flowData)

	case contexts.RegistrationFlowInternalUser:
		return urm.handleInternalUserFlow(ctx, flowData)

	case contexts.RegistrationFlowExternalUser:
		return urm.handleExternalUserFlow(ctx, flowData)

	case contexts.RegistrationFlowEndUser:
		return urm.handleEndUserFlow(ctx, flowData)

	default:
		return errors.New(errors.CodeInternalServer, "unknown registration flow")
	}
}

func (urm *UnifiedRegistrationMiddleware) handleOrganizationCreationFlow(ctx huma.Context, flowData map[string]interface{}) error {
	// Organization creation: NO organization context required
	urm.logger.Debug("Organization creation flow: no organization context required")
	return nil
}

func (urm *UnifiedRegistrationMiddleware) handleInvitationBasedFlow(ctx huma.Context, flowData map[string]interface{}) error {
	// Invitation-based: Organization context from invitation token
	invitationToken := flowData["invitation_token"].(string)

	// Validate invitation and extract organization context
	invitation, err := urm.invitationService.GetInvitationByToken(ctx.Context(), invitationToken)
	if err != nil {
		return errors.New(errors.CodeBadRequest, "invalid invitation token")
	}

	if err := urm.validateInvitation(invitation); err != nil {
		return err
	}

	// Set organization context from invitation
	ctx = huma.WithValue(ctx, contexts.DetectedOrganizationIDKey, invitation.OrganizationID)
	ctx = huma.WithValue(ctx, contexts.DetectedUserTypeKey, string(model.UserTypeExternal))

	urm.logger.Debug("Invitation-based flow: organization context from invitation",
		logging.String("orgId", invitation.OrganizationID.String()))

	return nil
}

func (urm *UnifiedRegistrationMiddleware) handleInternalUserFlow(ctx huma.Context, flowData map[string]interface{}) error {
	// Internal users: NO organization context required
	urm.logger.Debug("Internal user flow: no organization context required")
	return nil
}

func (urm *UnifiedRegistrationMiddleware) handleExternalUserFlow(ctx huma.Context, flowData map[string]interface{}) error {
	// External users: NO organization context required for registration
	// They can join organizations later via invitations
	urm.logger.Debug("External user flow: no organization context required (can join orgs later)")
	return nil
}

func (urm *UnifiedRegistrationMiddleware) handleEndUserFlow(ctx huma.Context, flowData map[string]interface{}) error {
	// End users: Organization context REQUIRED
	orgID := urm.getDetectedOrganizationID(ctx.Context())

	fmt.Println("orgID ===> ", orgID)
	if orgID == nil {
		return errors.New(errors.CodeBadRequest, "organization context is required for end user registration. Provide organization context via API key (X-Publishable-Key) or headers (X-Org-ID).")
	}

	// Validate organization access
	if err := urm.validateOrganizationAccess(ctx.Context(), *orgID, model.UserTypeEndUser); err != nil {
		return err
	}

	urm.logger.Debug("End user flow: organization context validated",
		logging.String("orgId", orgID.String()))

	return nil
}

// Helper methods for flow detection

func (urm *UnifiedRegistrationMiddleware) extractFlowIndicators(r *http.Request) map[string]interface{} {
	indicators := make(map[string]interface{})

	// Query parameters
	if invitationToken := r.URL.Query().Get("invitation_token"); invitationToken != "" {
		indicators["invitation_token"] = invitationToken
	}
	if createOrg := r.URL.Query().Get("create_organization"); createOrg == "true" {
		indicators["create_organization"] = true
	}
	if userType := r.URL.Query().Get("user_type"); userType != "" {
		indicators["user_type"] = userType
	}
	if regType := r.URL.Query().Get("registration_type"); regType != "" {
		indicators["registration_type"] = regType
	}

	// Headers
	if invitationToken := r.Header.Get("X-Invitation-Token"); invitationToken != "" {
		indicators["invitation_token"] = invitationToken
	}
	if userType := r.Header.Get("X-User-Type"); userType != "" {
		indicators["user_type"] = userType
	}
	if regType := r.Header.Get("X-Registration-Type"); regType != "" {
		indicators["registration_type"] = regType
	}

	// TODO: Parse request body for additional indicators
	// This would require carefully reading the body without consuming it

	return indicators
}

func (urm *UnifiedRegistrationMiddleware) getInvitationToken(indicators map[string]interface{}) string {
	if token, ok := indicators["invitation_token"].(string); ok {
		return token
	}
	return ""
}

func (urm *UnifiedRegistrationMiddleware) isOrganizationCreationRequest(indicators map[string]interface{}) bool {
	// Check for explicit flags
	if createOrg, ok := indicators["create_organization"].(bool); ok && createOrg {
		return true
	}
	if regType, ok := indicators["registration_type"].(string); ok {
		return regType == "organization_owner" || regType == "organization_creator"
	}
	return false
}

func (urm *UnifiedRegistrationMiddleware) getUserType(indicators map[string]interface{}) string {
	if userType, ok := indicators["user_type"].(string); ok {
		return userType
	}
	return "" // Will default to external
}

func (urm *UnifiedRegistrationMiddleware) isRegistrationPath(path string) bool {
	return strings.Contains(path, "/auth/register") &&
		!strings.Contains(path, "/auth/register/") // Only match exact /auth/register
}

func (urm *UnifiedRegistrationMiddleware) validateInvitation(invitation *model.Invitation) error {
	if invitation.Status != model.InvitationStatusPending {
		return errors.New(errors.CodeBadRequest, "invitation is no longer valid")
	}
	if invitation.ExpiresAt != nil && invitation.ExpiresAt.Before(time.Now()) {
		return errors.New(errors.CodeBadRequest, "invitation has expired")
	}
	return nil
}

func (urm *UnifiedRegistrationMiddleware) getDetectedOrganizationID(ctx context.Context) *xid.ID {
	if orgID, ok := ctx.Value(contexts.DetectedOrganizationIDKey).(xid.ID); ok {
		return &orgID
	}
	return nil
}

func (urm *UnifiedRegistrationMiddleware) validateOrganizationAccess(ctx context.Context, orgID xid.ID, userType model.UserType) error {
	org, err := urm.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		if repository.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "organization not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "failed to validate organization")
	}

	if !org.Active {
		return errors.New(errors.CodeForbidden, "organization is inactive")
	}

	// End users cannot access platform organizations
	if org.IsPlatformOrganization && userType == model.UserTypeEndUser {
		return errors.New(errors.CodeForbidden, "access denied to platform organization")
	}

	return nil
}

func (urm *UnifiedRegistrationMiddleware) respondErrorHuma(ctx huma.Context, err error) {
	var errResp *errors.ErrorResponse
	if e, ok := err.(*errors.Error); ok {
		errResp = errors.NewErrorResponse(e)
	} else {
		errResp = errors.NewErrorResponse(errors.New(errors.CodeInternalServer, err.Error()))
	}

	huma.WriteErr(urm.api, ctx, errResp.StatusCode(), errResp.Message)
}
