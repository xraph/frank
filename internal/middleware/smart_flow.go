package middleware

import (
	"context"
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

// RegistrationFlow represents different registration flow types
type RegistrationFlow string

const (
	// FlowOrganizationRegistration - First user creating organization (no org context required)
	FlowOrganizationRegistration RegistrationFlow = "organization_registration"
	// FlowInvitationRegistration - User registering via invitation (org context from token)
	FlowInvitationRegistration RegistrationFlow = "invitation_registration"
	// FlowStandardRegistration - Regular user registration (org context required)
	FlowStandardRegistration RegistrationFlow = "standard_registration"
	// FlowPostRegistrationJoin - User joining organization after registration
	FlowPostRegistrationJoin RegistrationFlow = "post_registration_join"
)

// SmartOrganizationMiddleware handles organization context with registration flows
type SmartOrganizationMiddleware struct {
	config            *OrganizationContextConfig
	orgRepo           repository.OrganizationRepository
	userRepo          repository.UserRepository
	apiKeyRepo        repository.ApiKeyRepository
	invitationService organization.InvitationService
	logger            logging.Logger
	api               huma.API
	mountOpts         *server.MountOptions
}

// NewSmartOrganizationMiddleware creates middleware that handles registration flows intelligently
func NewSmartOrganizationMiddleware(
	api huma.API, di di.Container, mountOpts *server.MountOptions, config *OrganizationContextConfig,
) *SmartOrganizationMiddleware {
	if config == nil {
		config = DefaultOrganizationContextConfig()
	}

	if config.Logger == nil {
		config.Logger = di.Logger().Named("smart-org-middleware")
	}

	return &SmartOrganizationMiddleware{
		config:            config,
		orgRepo:           di.Repo().Organization(),
		userRepo:          di.Repo().User(),
		apiKeyRepo:        di.Repo().APIKey(),
		logger:            config.Logger,
		invitationService: di.InvitationService(),
		api:               api,
		mountOpts:         mountOpts,
	}
}

// SmartOrganizationContextMiddleware intelligently handles organization context based on request type
func (som *SmartOrganizationMiddleware) SmartOrganizationContextMiddleware() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		rctx := ctx.Context()
		r := contexts.GetRequestFromContext(rctx)

		// Skip for certain paths
		if som.shouldSkipPath(ctx.URL().Path) {
			next(ctx)
			return
		}

		// Determine registration flow type
		flow, err := som.determineRegistrationFlow(rctx, r)
		if err != nil {
			som.logger.Debug("Failed to determine registration flow", logging.Error(err))
		}

		// Set flow type in context
		ctx = huma.WithValue(ctx, contexts.RegistrationFlowKey, flow)

		// Apply organization context rules based on flow
		if err := som.applyOrganizationContextRules(ctx, flow); err != nil {
			som.respondErrorHuma(ctx, err)
			return
		}

		next(ctx)
	}
}

// determineRegistrationFlow analyzes the request to determine which flow to use
func (som *SmartOrganizationMiddleware) determineRegistrationFlow(ctx context.Context, r *http.Request) (RegistrationFlow, error) {
	path := r.URL.Path
	method := r.Method

	// Parse request body for additional context
	flowIndicators := som.extractFlowIndicators(r)

	// 1. Organization Registration Flow
	if som.isOrganizationRegistrationFlow(path, method, flowIndicators) {
		return FlowOrganizationRegistration, nil
	}

	// 2. Invitation Registration Flow
	if som.isInvitationRegistrationFlow(path, method, flowIndicators) {
		return FlowInvitationRegistration, nil
	}

	// 3. Post-Registration Organization Join
	if som.isPostRegistrationJoinFlow(path, method, flowIndicators) {
		return FlowPostRegistrationJoin, nil
	}

	// 4. Standard Registration Flow (default)
	return FlowStandardRegistration, nil
}

// Flow detection methods

func (som *SmartOrganizationMiddleware) isOrganizationRegistrationFlow(path, method string, indicators map[string]interface{}) bool {
	// Organization creation endpoints
	if method == "POST" && strings.Contains(path, "/organizations") && !strings.Contains(path, "/organizations/") {
		return true
	}

	// Registration with organization creation flag
	if method == "POST" && strings.Contains(path, "/auth/register") {
		if createOrg, ok := indicators["create_organization"].(bool); ok && createOrg {
			return true
		}
		if registrationType, ok := indicators["registration_type"].(string); ok && registrationType == "organization_owner" {
			return true
		}
	}

	return false
}

func (som *SmartOrganizationMiddleware) isInvitationRegistrationFlow(path, method string, indicators map[string]interface{}) bool {
	// Registration with invitation token
	if method == "POST" && strings.Contains(path, "/auth/register") {
		if invitationToken, ok := indicators["invitation_token"].(string); ok && invitationToken != "" {
			return true
		}
	}

	// Invitation acceptance endpoints
	if method == "POST" && strings.Contains(path, "/invitations/accept") {
		return true
	}

	return false
}

func (som *SmartOrganizationMiddleware) isPostRegistrationJoinFlow(path, method string, indicators map[string]interface{}) bool {
	// User is already authenticated but joining new organization
	if strings.Contains(path, "/invitations/accept") || strings.Contains(path, "/memberships/join") {
		return true
	}

	return false
}

// extractFlowIndicators extracts flow indicators from request
func (som *SmartOrganizationMiddleware) extractFlowIndicators(r *http.Request) map[string]interface{} {
	indicators := make(map[string]interface{})

	// Check query parameters
	if invitationToken := r.URL.Query().Get("invitation_token"); invitationToken != "" {
		indicators["invitation_token"] = invitationToken
	}

	if createOrg := r.URL.Query().Get("create_organization"); createOrg == "true" {
		indicators["create_organization"] = true
	}

	if regType := r.URL.Query().Get("registration_type"); regType != "" {
		indicators["registration_type"] = regType
	}

	// Check headers
	if invitationToken := r.Header.Get("X-Invitation-Token"); invitationToken != "" {
		indicators["invitation_token"] = invitationToken
	}

	if regType := r.Header.Get("X-Registration-Type"); regType != "" {
		indicators["registration_type"] = regType
	}

	// TODO: Parse request body for additional indicators if needed
	// This would require reading the body without consuming it

	return indicators
}

// applyOrganizationContextRules applies context rules based on flow
func (som *SmartOrganizationMiddleware) applyOrganizationContextRules(ctx huma.Context, flow RegistrationFlow) error {
	switch flow {
	case FlowOrganizationRegistration:
		return som.handleOrganizationRegistrationFlow(ctx)
	case FlowInvitationRegistration:
		return som.handleInvitationRegistrationFlow(ctx)
	case FlowPostRegistrationJoin:
		return som.handlePostRegistrationJoinFlow(ctx)
	case FlowStandardRegistration:
		return som.handleStandardRegistrationFlow(ctx)
	default:
		return som.handleStandardRegistrationFlow(ctx)
	}
}

// Flow handlers

func (som *SmartOrganizationMiddleware) handleOrganizationRegistrationFlow(ctx huma.Context) error {
	// Organization registration: NO organization context required
	// This allows the first user to create an organization
	som.logger.Debug("Organization registration flow: skipping organization context requirement")
	return nil
}

func (som *SmartOrganizationMiddleware) handleInvitationRegistrationFlow(ctx huma.Context) error {
	// Invitation registration: Organization context from invitation token
	r := contexts.GetRequestFromContext(ctx.Context())

	// Extract invitation token
	invitationToken := som.extractInvitationToken(r)
	if invitationToken == "" {
		return errors.New(errors.CodeBadRequest, "invitation token is required for invitation registration")
	}

	// Validate invitation and get organization context
	invitation, err := som.invitationService.GetInvitationByToken(ctx.Context(), invitationToken)
	if err != nil {
		return errors.New(errors.CodeBadRequest, "invalid invitation token")
	}

	// Check invitation validity
	if err := som.validateInvitation(invitation); err != nil {
		return err
	}

	// Set organization context from invitation
	ctx = huma.WithValue(ctx, contexts.DetectedOrganizationIDKey, invitation.OrganizationID)
	ctx = huma.WithValue(ctx, contexts.DetectedUserTypeKey, string(model.UserTypeExternal))

	som.logger.Debug("Invitation registration flow: organization context from invitation",
		logging.String("orgId", invitation.OrganizationID.String()),
		logging.String("invitationId", invitation.ID.String()))

	return nil
}

func (som *SmartOrganizationMiddleware) handlePostRegistrationJoinFlow(ctx huma.Context) error {
	// Post-registration join: User is authenticated, joining new organization via invitation
	// Require invitation token for organization context
	r := contexts.GetRequestFromContext(ctx.Context())

	invitationToken := som.extractInvitationToken(r)
	if invitationToken == "" {
		return errors.New(errors.CodeBadRequest, "invitation token is required to join organization")
	}

	// Validate invitation
	invitation, err := som.invitationService.GetInvitationByToken(ctx.Context(), invitationToken)
	if err != nil {
		return errors.New(errors.CodeBadRequest, "invalid invitation token")
	}

	if err := som.validateInvitation(invitation); err != nil {
		return err
	}

	// Set organization context
	ctx = huma.WithValue(ctx, contexts.DetectedOrganizationIDKey, invitation.OrganizationID)

	som.logger.Debug("Post-registration join flow: organization context from invitation",
		logging.String("orgId", invitation.OrganizationID.String()))

	return nil
}

func (som *SmartOrganizationMiddleware) handleStandardRegistrationFlow(ctx huma.Context) error {
	// Standard registration: Require organization context for external/end users
	userType := som.getDetectedUserType(ctx.Context())

	if som.requiresOrganizationContext(model.UserType(userType)) {
		orgID := som.getDetectedOrganizationID(ctx.Context())
		if orgID == nil {
			return errors.New(errors.CodeBadRequest, "organization context is required for this user type")
		}

		// Validate organization
		if err := som.validateOrganizationAccess(ctx.Context(), *orgID, model.UserType(userType)); err != nil {
			return err
		}
	}

	return nil
}

// Helper methods

func (som *SmartOrganizationMiddleware) extractInvitationToken(r *http.Request) string {
	// Try query parameter
	if token := r.URL.Query().Get("invitation_token"); token != "" {
		return token
	}

	// Try header
	if token := r.Header.Get("X-Invitation-Token"); token != "" {
		return token
	}

	// TODO: Try request body if needed
	return ""
}

func (som *SmartOrganizationMiddleware) validateInvitation(invitation *model.Invitation) error {
	// Check invitation status
	if invitation.Status != model.InvitationStatusPending {
		return errors.New(errors.CodeBadRequest, "invitation is no longer valid")
	}

	// Check expiration
	if invitation.ExpiresAt != nil && invitation.ExpiresAt.Before(time.Now()) {
		return errors.New(errors.CodeBadRequest, "invitation has expired")
	}

	return nil
}

func (som *SmartOrganizationMiddleware) getDetectedUserType(ctx context.Context) string {
	if userType, ok := ctx.Value(contexts.DetectedUserTypeKey).(string); ok {
		return userType
	}
	return ""
}

func (som *SmartOrganizationMiddleware) getDetectedOrganizationID(ctx context.Context) *xid.ID {
	if orgID, ok := ctx.Value(contexts.DetectedOrganizationIDKey).(xid.ID); ok {
		return &orgID
	}
	return nil
}

func (som *SmartOrganizationMiddleware) requiresOrganizationContext(userType model.UserType) bool {
	switch userType {
	case model.UserTypeInternal:
		return false
	case model.UserTypeExternal:
		return som.config.EnforceForExternalUsers
	case model.UserTypeEndUser:
		return som.config.EnforceForEndUsers
	default:
		return true
	}
}

func (som *SmartOrganizationMiddleware) validateOrganizationAccess(ctx context.Context, orgID xid.ID, userType model.UserType) error {
	org, err := som.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		if repository.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "organization not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "failed to validate organization")
	}

	if !org.Active {
		return errors.New(errors.CodeForbidden, "organization is inactive")
	}

	// External and end users cannot access platform organizations
	if org.IsPlatformOrganization && (userType == model.UserTypeExternal || userType == model.UserTypeEndUser) {
		return errors.New(errors.CodeForbidden, "access denied to platform organization")
	}

	return nil
}

func (som *SmartOrganizationMiddleware) shouldSkipPath(path string) bool {
	skipPaths := []string{
		"/health",
		"/ready",
		"/metrics",
		"/favicon.ico",
		"/robots.txt",
		"/api/v1/auth/status", // Allow status check without org context
	}

	for _, skipPath := range skipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

func (som *SmartOrganizationMiddleware) respondErrorHuma(ctx huma.Context, err error) {
	var errResp *errors.ErrorResponse
	if e, ok := err.(*errors.Error); ok {
		errResp = errors.NewErrorResponse(e)
	} else {
		errResp = errors.NewErrorResponse(errors.New(errors.CodeInternalServer, err.Error()))
	}

	huma.WriteErr(som.api, ctx, errResp.StatusCode(), errResp.Message)
}
