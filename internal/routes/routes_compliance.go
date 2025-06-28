package routes

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/xid"
	"github.com/xraph/frank/internal/authz"
	"github.com/xraph/frank/internal/di"
	"github.com/xraph/frank/pkg/model"
	"github.com/xraph/frank/pkg/services/audit"
)

// RegisterComplianceAPI registers all compliance-related endpoints
func RegisterComplianceAPI(group huma.API, di di.Container) {
	di.Logger().Info("Registering compliance API routes")

	complianceCtrl := &complianceController{
		api: group,
		di:  di,
	}

	// SOC 2 Compliance
	registerGenerateSOC2Report(group, complianceCtrl)
	registerCheckSOC2Compliance(group, complianceCtrl)

	// HIPAA Compliance
	registerGenerateHIPAAReport(group, complianceCtrl)
	registerCheckHIPAACompliance(group, complianceCtrl)

	// PCI DSS Compliance
	registerGeneratePCIDSSReport(group, complianceCtrl)
	registerCheckPCIDSSCompliance(group, complianceCtrl)

	// GDPR Compliance
	registerGenerateGDPRReport(group, complianceCtrl)
	registerCheckGDPRCompliance(group, complianceCtrl)

	// Violation Management
	registerDetectViolations(group, complianceCtrl)
	registerGetActiveViolations(group, complianceCtrl)
	registerResolveViolation(group, complianceCtrl)

	// Data Management
	registerApplyDataRetentionPolicies(group, complianceCtrl)
	registerProcessDataDeletionRequest(group, complianceCtrl)
	registerExportUserData(group, complianceCtrl)

	// Data Access Logging
	registerLogDataAccess(group, complianceCtrl)
	registerGetDataAccessLogs(group, complianceCtrl)

	// Attestation Management
	registerCreateAttestation(group, complianceCtrl)
	registerGetAttestations(group, complianceCtrl)

	// Risk Management
	registerConductRiskAssessment(group, complianceCtrl)
	registerUpdateRiskMitigation(group, complianceCtrl)

	// Compliance Overview
	registerGetComplianceOverview(group, complianceCtrl)
	registerGetComplianceMetrics(group, complianceCtrl)
}

// complianceController handles compliance-related HTTP requests
type complianceController struct {
	api huma.API
	di  di.Container
}

// getComplianceService returns the compliance service from the audit service
func (c *complianceController) getComplianceService() audit.ComplianceService {
	// Since ComplianceService is not directly available in DI, we'll need to create it
	// This is a placeholder - in a real implementation, this would be properly injected
	return audit.NewComplianceService(
		c.di.Repo().Audit(),
		c.di.Repo().User(),
		c.di.Repo().Organization(),
		c.di.Logger(),
		nil,
	)
}

// SOC 2 Compliance Routes

func registerGenerateSOC2Report(api huma.API, ctrl *complianceController) {
	huma.Register(api, huma.Operation{
		OperationID:   "generateSOC2Report",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/compliance/soc2/reports",
		Summary:       "Generate SOC 2 compliance report",
		Description:   "Generate a comprehensive SOC 2 Type II compliance report for the organization",
		Tags:          []string{"Compliance"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"BearerAuth": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionSystemAdmin, model.ResourceSystem, "",
		)},
	}, ctrl.generateSOC2ReportHandler)
}

func registerCheckSOC2Compliance(api huma.API, ctrl *complianceController) {
	huma.Register(api, huma.Operation{
		OperationID:   "checkSOC2Compliance",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/compliance/soc2/status",
		Summary:       "Check SOC 2 compliance status",
		Description:   "Get current SOC 2 compliance status and assessment results",
		Tags:          []string{"Compliance"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"BearerAuth": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionSystemAdmin, model.ResourceSystem, "",
		)},
	}, ctrl.checkSOC2ComplianceHandler)
}

// HIPAA Compliance Routes

func registerGenerateHIPAAReport(api huma.API, ctrl *complianceController) {
	huma.Register(api, huma.Operation{
		OperationID:   "generateHIPAAReport",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/compliance/hipaa/reports",
		Summary:       "Generate HIPAA compliance report",
		Description:   "Generate a comprehensive HIPAA compliance report with safeguards assessment",
		Tags:          []string{"Compliance"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"BearerAuth": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionSystemAdmin, model.ResourceSystem, "",
		)},
	}, ctrl.generateHIPAAReportHandler)
}

func registerCheckHIPAACompliance(api huma.API, ctrl *complianceController) {
	huma.Register(api, huma.Operation{
		OperationID:   "checkHIPAACompliance",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/compliance/hipaa/status",
		Summary:       "Check HIPAA compliance status",
		Description:   "Get current HIPAA compliance status and safeguards assessment",
		Tags:          []string{"Compliance"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"BearerAuth": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionSystemAdmin, model.ResourceSystem, "",
		)},
	}, ctrl.checkHIPAAComplianceHandler)
}

// PCI DSS Compliance Routes

func registerGeneratePCIDSSReport(api huma.API, ctrl *complianceController) {
	huma.Register(api, huma.Operation{
		OperationID:   "generatePCIDSSReport",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/compliance/pci-dss/reports",
		Summary:       "Generate PCI DSS compliance report",
		Description:   "Generate a comprehensive PCI DSS compliance report with security requirements assessment",
		Tags:          []string{"Compliance"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"BearerAuth": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionSystemAdmin, model.ResourceSystem, "",
		)},
	}, ctrl.generatePCIDSSReportHandler)
}

func registerCheckPCIDSSCompliance(api huma.API, ctrl *complianceController) {
	huma.Register(api, huma.Operation{
		OperationID:   "checkPCIDSSCompliance",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/compliance/pci-dss/status",
		Summary:       "Check PCI DSS compliance status",
		Description:   "Get current PCI DSS compliance status and security requirements assessment",
		Tags:          []string{"Compliance"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"BearerAuth": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionSystemAdmin, model.ResourceSystem, "",
		)},
	}, ctrl.checkPCIDSSComplianceHandler)
}

// GDPR Compliance Routes

func registerGenerateGDPRReport(api huma.API, ctrl *complianceController) {
	huma.Register(api, huma.Operation{
		OperationID:   "generateGDPRReport",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/compliance/gdpr/reports",
		Summary:       "Generate GDPR compliance report",
		Description:   "Generate a comprehensive GDPR compliance report with data processing records",
		Tags:          []string{"Compliance"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"BearerAuth": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionSystemAdmin, model.ResourceSystem, "",
		)},
	}, ctrl.generateGDPRReportHandler)
}

func registerCheckGDPRCompliance(api huma.API, ctrl *complianceController) {
	huma.Register(api, huma.Operation{
		OperationID:   "checkGDPRCompliance",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/compliance/gdpr/status",
		Summary:       "Check GDPR compliance status",
		Description:   "Get current GDPR compliance status and data protection assessment",
		Tags:          []string{"Compliance"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"BearerAuth": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionSystemAdmin, model.ResourceSystem, "",
		)},
	}, ctrl.checkGDPRComplianceHandler)
}

// Violation Management Routes

func registerDetectViolations(api huma.API, ctrl *complianceController) {
	huma.Register(api, huma.Operation{
		OperationID:   "detectViolations",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/compliance/violations/detect",
		Summary:       "Detect compliance violations",
		Description:   "Run compliance violation detection for specified compliance type",
		Tags:          []string{"Compliance"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"BearerAuth": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionSystemAdmin, model.ResourceSystem, "",
		)},
	}, ctrl.detectViolationsHandler)
}

func registerGetActiveViolations(api huma.API, ctrl *complianceController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getActiveViolations",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/compliance/violations",
		Summary:       "Get active compliance violations",
		Description:   "Get list of active compliance violations for the organization",
		Tags:          []string{"Compliance"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"BearerAuth": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionSystemAdmin, model.ResourceSystem, "",
		)},
	}, ctrl.getActiveViolationsHandler)
}

func registerResolveViolation(api huma.API, ctrl *complianceController) {
	huma.Register(api, huma.Operation{
		OperationID:   "resolveViolation",
		Method:        http.MethodPost,
		Path:          "/compliance/violations/{violationId}/resolve",
		Summary:       "Resolve compliance violation",
		Description:   "Mark a compliance violation as resolved with resolution details",
		Tags:          []string{"Compliance"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Violation not found")),
		Security: []map[string][]string{
			{"BearerAuth": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionSystemAdmin, model.ResourceSystem, "",
		)},
	}, ctrl.resolveViolationHandler)
}

// Data Management Routes

func registerApplyDataRetentionPolicies(api huma.API, ctrl *complianceController) {
	huma.Register(api, huma.Operation{
		OperationID:   "applyDataRetentionPolicies",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/compliance/data-retention/apply",
		Summary:       "Apply data retention policies",
		Description:   "Apply data retention policies and archive/delete old data",
		Tags:          []string{"Compliance"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"BearerAuth": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionSystemAdmin, model.ResourceSystem, "",
		)},
	}, ctrl.applyDataRetentionPoliciesHandler)
}

func registerProcessDataDeletionRequest(api huma.API, ctrl *complianceController) {
	huma.Register(api, huma.Operation{
		OperationID:   "processDataDeletionRequest",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/compliance/data-deletion",
		Summary:       "Process data deletion request",
		Description:   "Process GDPR right to erasure or other data deletion requests",
		Tags:          []string{"Compliance"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.BadRequestError("Invalid deletion request")),
		Security: []map[string][]string{
			{"BearerAuth": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionSystemAdmin, model.ResourceSystem, "",
		)},
	}, ctrl.processDataDeletionRequestHandler)
}

func registerExportUserData(api huma.API, ctrl *complianceController) {
	huma.Register(api, huma.Operation{
		OperationID:   "exportUserData",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/users/{userId}/export",
		Summary:       "Export user data",
		Description:   "Export all user data for GDPR data portability or other compliance requirements",
		Tags:          []string{"Compliance"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("User not found")),
		Security: []map[string][]string{
			{"BearerAuth": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionSystemAdmin, model.ResourceSystem, "",
		)},
	}, ctrl.exportUserDataHandler)
}

// Data Access Logging Routes

func registerLogDataAccess(api huma.API, ctrl *complianceController) {
	huma.Register(api, huma.Operation{
		OperationID:   "logDataAccess",
		Method:        http.MethodPost,
		Path:          "/compliance/data-access/log",
		Summary:       "Log data access event",
		Description:   "Log a data access event for compliance tracking",
		Tags:          []string{"Compliance"},
		DefaultStatus: 201,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.BadRequestError("Invalid access event")),
		Security: []map[string][]string{
			{"BearerAuth": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionSystemAdmin, model.ResourceSystem, "",
		)},
	}, ctrl.logDataAccessHandler)
}

func registerGetDataAccessLogs(api huma.API, ctrl *complianceController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getDataAccessLogs",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/compliance/data-access/logs",
		Summary:       "Get data access logs",
		Description:   "Get data access logs for compliance auditing",
		Tags:          []string{"Compliance"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"BearerAuth": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionSystemAdmin, model.ResourceSystem, "",
		)},
	}, ctrl.getDataAccessLogsHandler)
}

// Attestation Management Routes

func registerCreateAttestation(api huma.API, ctrl *complianceController) {
	huma.Register(api, huma.Operation{
		OperationID:   "createAttestation",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/compliance/attestations",
		Summary:       "Create compliance attestation",
		Description:   "Create a new compliance attestation statement",
		Tags:          []string{"Compliance"},
		DefaultStatus: 201,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.BadRequestError("Invalid attestation request")),
		Security: []map[string][]string{
			{"BearerAuth": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionSystemAdmin, model.ResourceSystem, "",
		)},
	}, ctrl.createAttestationHandler)
}

func registerGetAttestations(api huma.API, ctrl *complianceController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getAttestations",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/compliance/attestations",
		Summary:       "Get compliance attestations",
		Description:   "Get compliance attestations for the organization",
		Tags:          []string{"Compliance"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"BearerAuth": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionSystemAdmin, model.ResourceSystem, "",
		)},
	}, ctrl.getAttestationsHandler)
}

// Risk Management Routes

func registerConductRiskAssessment(api huma.API, ctrl *complianceController) {
	huma.Register(api, huma.Operation{
		OperationID:   "conductRiskAssessment",
		Method:        http.MethodPost,
		Path:          "/organizations/{orgId}/compliance/risk-assessment",
		Summary:       "Conduct risk assessment",
		Description:   "Conduct a comprehensive risk assessment for compliance",
		Tags:          []string{"Compliance"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"BearerAuth": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionSystemAdmin, model.ResourceSystem, "",
		)},
	}, ctrl.conductRiskAssessmentHandler)
}

func registerUpdateRiskMitigation(api huma.API, ctrl *complianceController) {
	huma.Register(api, huma.Operation{
		OperationID:   "updateRiskMitigation",
		Method:        http.MethodPut,
		Path:          "/compliance/risks/{riskId}/mitigation",
		Summary:       "Update risk mitigation",
		Description:   "Update risk mitigation measures for identified risks",
		Tags:          []string{"Compliance"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true, model.NotFoundError("Risk not found")),
		Security: []map[string][]string{
			{"BearerAuth": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionSystemAdmin, model.ResourceSystem, "",
		)},
	}, ctrl.updateRiskMitigationHandler)
}

// Overview Routes

func registerGetComplianceOverview(api huma.API, ctrl *complianceController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getComplianceOverview",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/compliance/overview",
		Summary:       "Get compliance overview",
		Description:   "Get overall compliance status across all frameworks",
		Tags:          []string{"Compliance"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"BearerAuth": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionSystemAdmin, model.ResourceSystem, "",
		)},
	}, ctrl.getComplianceOverviewHandler)
}

func registerGetComplianceMetrics(api huma.API, ctrl *complianceController) {
	huma.Register(api, huma.Operation{
		OperationID:   "getComplianceMetrics",
		Method:        http.MethodGet,
		Path:          "/organizations/{orgId}/compliance/metrics",
		Summary:       "Get compliance metrics",
		Description:   "Get detailed compliance metrics and trends",
		Tags:          []string{"Compliance"},
		DefaultStatus: 200,
		Responses:     model.MergeErrorResponses(map[string]*huma.Response{}, true),
		Security: []map[string][]string{
			{"BearerAuth": {}},
		},
		Middlewares: huma.Middlewares{authz.HumaPermissionMiddleware(api, ctrl.di.AuthZ().Checker(), ctrl.di.Logger())(
			authz.PermissionSystemAdmin, model.ResourceSystem, "",
		)},
	}, ctrl.getComplianceMetricsHandler)
}

// Handler implementations

// SOC 2 Handlers

type GenerateSOC2ReportRequest struct {
	Period     string `json:"period" example:"current_quarter" doc:"Reporting period"`
	ReportType string `json:"reportType,omitempty" example:"Type II" doc:"SOC 2 report type"`
}

type GenerateSOC2ReportInput struct {
	model.OrganisationPathParams
	Body GenerateSOC2ReportRequest `json:"body"`
}

type GenerateSOC2ReportOutput = model.Output[*audit.SOC2Report]

func (c *complianceController) generateSOC2ReportHandler(ctx context.Context, input *GenerateSOC2ReportInput) (*GenerateSOC2ReportOutput, error) {
	complianceService := c.getComplianceService()

	report, err := complianceService.GenerateSOC2Report(ctx, input.PathOrgID, input.Body.Period)
	if err != nil {
		return nil, err
	}

	return &GenerateSOC2ReportOutput{
		Body: report,
	}, nil
}

type CheckSOC2ComplianceInput struct {
	model.OrganisationPathParams
}

type CheckSOC2ComplianceOutput = model.Output[*audit.ComplianceStatus]

func (c *complianceController) checkSOC2ComplianceHandler(ctx context.Context, input *CheckSOC2ComplianceInput) (*CheckSOC2ComplianceOutput, error) {
	complianceService := c.getComplianceService()

	status, err := complianceService.CheckSOC2Compliance(ctx, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &CheckSOC2ComplianceOutput{
		Body: status,
	}, nil
}

// HIPAA Handlers

type GenerateHIPAAReportInput struct {
	model.OrganisationPathParams
	Body struct {
		Period string `json:"period" example:"current_quarter" doc:"Reporting period"`
	} `json:"body"`
}

type GenerateHIPAAReportOutput = model.Output[*audit.HIPAAReport]

func (c *complianceController) generateHIPAAReportHandler(ctx context.Context, input *GenerateHIPAAReportInput) (*GenerateHIPAAReportOutput, error) {
	complianceService := c.getComplianceService()

	report, err := complianceService.GenerateHIPAAReport(ctx, input.PathOrgID, input.Body.Period)
	if err != nil {
		return nil, err
	}

	return &GenerateHIPAAReportOutput{
		Body: report,
	}, nil
}

type CheckHIPAAComplianceInput struct {
	model.OrganisationPathParams
}

type CheckHIPAAComplianceOutput = model.Output[*audit.ComplianceStatus]

func (c *complianceController) checkHIPAAComplianceHandler(ctx context.Context, input *CheckHIPAAComplianceInput) (*CheckHIPAAComplianceOutput, error) {
	complianceService := c.getComplianceService()

	status, err := complianceService.CheckHIPAACompliance(ctx, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &CheckHIPAAComplianceOutput{
		Body: status,
	}, nil
}

// PCI DSS Handlers

type GeneratePCIDSSReportInput struct {
	model.OrganisationPathParams
	Body struct {
		Period string `json:"period" example:"current_quarter" doc:"Reporting period"`
	} `json:"body"`
}

type GeneratePCIDSSReportOutput = model.Output[*audit.PCIDSSReport]

func (c *complianceController) generatePCIDSSReportHandler(ctx context.Context, input *GeneratePCIDSSReportInput) (*GeneratePCIDSSReportOutput, error) {
	complianceService := c.getComplianceService()

	report, err := complianceService.GeneratePCIDSSReport(ctx, input.PathOrgID, input.Body.Period)
	if err != nil {
		return nil, err
	}

	return &GeneratePCIDSSReportOutput{
		Body: report,
	}, nil
}

type CheckPCIDSSComplianceInput struct {
	model.OrganisationPathParams
}

type CheckPCIDSSComplianceOutput = model.Output[*audit.ComplianceStatus]

func (c *complianceController) checkPCIDSSComplianceHandler(ctx context.Context, input *CheckPCIDSSComplianceInput) (*CheckPCIDSSComplianceOutput, error) {
	complianceService := c.getComplianceService()

	status, err := complianceService.CheckPCIDSSCompliance(ctx, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &CheckPCIDSSComplianceOutput{
		Body: status,
	}, nil
}

// GDPR Handlers

type GenerateGDPRReportInput struct {
	model.OrganisationPathParams
	Body struct {
		Period string `json:"period" example:"current_quarter" doc:"Reporting period"`
	} `json:"body"`
}

type GenerateGDPRReportOutput = model.Output[*audit.GDPRReport]

func (c *complianceController) generateGDPRReportHandler(ctx context.Context, input *GenerateGDPRReportInput) (*GenerateGDPRReportOutput, error) {
	complianceService := c.getComplianceService()

	report, err := complianceService.GenerateGDPRReport(ctx, input.PathOrgID, input.Body.Period)
	if err != nil {
		return nil, err
	}

	return &GenerateGDPRReportOutput{
		Body: report,
	}, nil
}

type CheckGDPRComplianceInput struct {
	model.OrganisationPathParams
}

type CheckGDPRComplianceOutput = model.Output[*audit.ComplianceStatus]

func (c *complianceController) checkGDPRComplianceHandler(ctx context.Context, input *CheckGDPRComplianceInput) (*CheckGDPRComplianceOutput, error) {
	complianceService := c.getComplianceService()

	status, err := complianceService.CheckGDPRCompliance(ctx, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &CheckGDPRComplianceOutput{
		Body: status,
	}, nil
}

// Violation Management Handlers

type DetectViolationsInput struct {
	model.OrganisationPathParams
	Body struct {
		ComplianceType string `json:"complianceType" example:"soc2" doc:"Compliance framework to check"`
	} `json:"body"`
}

type DetectViolationsOutput = model.Output[[]audit.ComplianceViolation]

func (c *complianceController) detectViolationsHandler(ctx context.Context, input *DetectViolationsInput) (*DetectViolationsOutput, error) {
	complianceService := c.getComplianceService()

	violations, err := complianceService.DetectViolations(ctx, input.PathOrgID, input.Body.ComplianceType)
	if err != nil {
		return nil, err
	}

	// Convert pointers to values for response
	violationValues := make([]audit.ComplianceViolation, len(violations))
	for i, v := range violations {
		violationValues[i] = *v
	}

	return &DetectViolationsOutput{
		Body: violationValues,
	}, nil
}

type GetActiveViolationsInput struct {
	model.OrganisationPathParams
}

type GetActiveViolationsOutput = model.Output[[]audit.ComplianceViolation]

func (c *complianceController) getActiveViolationsHandler(ctx context.Context, input *GetActiveViolationsInput) (*GetActiveViolationsOutput, error) {
	complianceService := c.getComplianceService()

	violations, err := complianceService.GetActiveViolations(ctx, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	// Convert pointers to values for response
	violationValues := make([]audit.ComplianceViolation, len(violations))
	for i, v := range violations {
		violationValues[i] = *v
	}

	return &GetActiveViolationsOutput{
		Body: violationValues,
	}, nil
}

type ResolveViolationRequest struct {
	Resolution string `json:"resolution" doc:"Resolution description"`
}
type ResolveViolationInput struct {
	ViolationID xid.ID                  `path:"violationId" doc:"Violation ID"`
	Body        ResolveViolationRequest `json:"body"`
}

type ComplianceMessageResponse struct {
	Success bool   `json:"success" doc:"Whether the violation was resolved successfully"`
	Message string `json:"message" doc:"Message indicating the result of the resolution"`
}

type ResolveViolationOutput = model.Output[ComplianceMessageResponse]

func (c *complianceController) resolveViolationHandler(ctx context.Context, input *ResolveViolationInput) (*ResolveViolationOutput, error) {
	complianceService := c.getComplianceService()

	err := complianceService.ResolveViolation(ctx, input.ViolationID, input.Body.Resolution)
	if err != nil {
		return nil, err
	}

	return &ResolveViolationOutput{
		Body: ComplianceMessageResponse{
			Success: true,
			Message: "Violation resolved successfully",
		},
	}, nil
}

// Data Management Handlers

type ApplyDataRetentionPoliciesInput struct {
	model.OrganisationPathParams
}

type ApplyDataRetentionPoliciesOutput = model.Output[*audit.DataRetentionResult]

func (c *complianceController) applyDataRetentionPoliciesHandler(ctx context.Context, input *ApplyDataRetentionPoliciesInput) (*ApplyDataRetentionPoliciesOutput, error) {
	complianceService := c.getComplianceService()

	result, err := complianceService.ApplyDataRetentionPolicies(ctx, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &ApplyDataRetentionPoliciesOutput{
		Body: result,
	}, nil
}

type ProcessDataDeletionRequestInput struct {
	model.OrganisationPathParams
	Body audit.DataDeletionRequest `json:"body"`
}

type ProcessDataDeletionRequestOutput = model.Output[*audit.DataDeletionResult]

func (c *complianceController) processDataDeletionRequestHandler(ctx context.Context, input *ProcessDataDeletionRequestInput) (*ProcessDataDeletionRequestOutput, error) {
	complianceService := c.getComplianceService()

	result, err := complianceService.ProcessDataDeletionRequest(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &ProcessDataDeletionRequestOutput{
		Body: result,
	}, nil
}

type ExportUserDataInput struct {
	model.OrganisationPathParams
	UserID xid.ID `path:"userId" doc:"User ID"`
}

type ExportUserDataOutput = model.Output[*audit.UserDataExport]

func (c *complianceController) exportUserDataHandler(ctx context.Context, input *ExportUserDataInput) (*ExportUserDataOutput, error) {
	complianceService := c.getComplianceService()

	export, err := complianceService.ExportUserData(ctx, input.UserID, input.PathOrgID)
	if err != nil {
		return nil, err
	}

	return &ExportUserDataOutput{
		Body: export,
	}, nil
}

// Data Access Logging Handlers

type LogDataAccessInput struct {
	Body audit.DataAccessEvent `json:"body"`
}

type LogDataAccessOutput = model.Output[ComplianceMessageResponse]

func (c *complianceController) logDataAccessHandler(ctx context.Context, input *LogDataAccessInput) (*LogDataAccessOutput, error) {
	complianceService := c.getComplianceService()

	err := complianceService.LogDataAccess(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &LogDataAccessOutput{
		Body: ComplianceMessageResponse{
			Success: true,
			Message: "Data access logged successfully",
		},
	}, nil
}

type GetDataAccessLogsInput struct {
	model.OrganisationPathParams
	audit.DataAccessFilters
}

type GetDataAccessLogsOutput = model.Output[[]audit.DataAccessLog]

func (c *complianceController) getDataAccessLogsHandler(ctx context.Context, input *GetDataAccessLogsInput) (*GetDataAccessLogsOutput, error) {
	complianceService := c.getComplianceService()

	logs, err := complianceService.GetDataAccessLogs(ctx, input.PathOrgID, input.DataAccessFilters)
	if err != nil {
		return nil, err
	}

	// Convert pointers to values for response
	logValues := make([]audit.DataAccessLog, len(logs))
	for i, l := range logs {
		logValues[i] = *l
	}

	return &GetDataAccessLogsOutput{
		Body: logValues,
	}, nil
}

// Attestation Management Handlers

type CreateAttestationInput struct {
	model.OrganisationPathParams
	Body audit.AttestationRequest `json:"body"`
}

type CreateAttestationOutput = model.Output[*audit.Attestation]

func (c *complianceController) createAttestationHandler(ctx context.Context, input *CreateAttestationInput) (*CreateAttestationOutput, error) {
	complianceService := c.getComplianceService()

	attestation, err := complianceService.CreateAttestation(ctx, input.Body)
	if err != nil {
		return nil, err
	}

	return &CreateAttestationOutput{
		Body: attestation,
	}, nil
}

type GetAttestationsInput struct {
	model.OrganisationPathParams
	ComplianceType string `query:"complianceType" doc:"Filter by compliance type"`
}

type GetAttestationsOutput = model.Output[[]audit.Attestation]

func (c *complianceController) getAttestationsHandler(ctx context.Context, input *GetAttestationsInput) (*GetAttestationsOutput, error) {
	complianceService := c.getComplianceService()

	attestations, err := complianceService.GetAttestations(ctx, input.PathOrgID, input.ComplianceType)
	if err != nil {
		return nil, err
	}

	// Convert pointers to values for response
	attestationValues := make([]audit.Attestation, len(attestations))
	for i, a := range attestations {
		attestationValues[i] = *a
	}

	return &GetAttestationsOutput{
		Body: attestationValues,
	}, nil
}

// Risk Management Handlers

type ConductRiskAssessmentRequest struct {
	AssessmentType string `json:"assessmentType" example:"security" doc:"Type of risk assessment"`
}
type ConductRiskAssessmentInput struct {
	model.OrganisationPathParams
	Body ConductRiskAssessmentRequest `json:"body"`
}

type ConductRiskAssessmentOutput = model.Output[*audit.RiskAssessment]

func (c *complianceController) conductRiskAssessmentHandler(ctx context.Context, input *ConductRiskAssessmentInput) (*ConductRiskAssessmentOutput, error) {
	complianceService := c.getComplianceService()

	assessment, err := complianceService.ConductRiskAssessment(ctx, input.PathOrgID, input.Body.AssessmentType)
	if err != nil {
		return nil, err
	}

	return &ConductRiskAssessmentOutput{
		Body: assessment,
	}, nil
}

type UpdateRiskMitigationInput struct {
	RiskID xid.ID               `path:"riskId" doc:"Risk ID"`
	Body   audit.RiskMitigation `json:"body"`
}

type UpdateRiskMitigationOutput = model.Output[ComplianceMessageResponse]

func (c *complianceController) updateRiskMitigationHandler(ctx context.Context, input *UpdateRiskMitigationInput) (*UpdateRiskMitigationOutput, error) {
	complianceService := c.getComplianceService()

	err := complianceService.UpdateRiskMitigation(ctx, input.RiskID, input.Body)
	if err != nil {
		return nil, err
	}

	return &UpdateRiskMitigationOutput{
		Body: ComplianceMessageResponse{
			Success: true,
			Message: "Risk mitigation updated successfully",
		},
	}, nil
}

// Overview Handlers

type GetComplianceOverviewInput struct {
	model.OrganisationPathParams
}

type ComplianceOverview struct {
	OrganizationID    xid.ID                             `json:"organizationId"`
	OverallScore      float64                            `json:"overallScore"`
	FrameworkStatus   map[string]*audit.ComplianceStatus `json:"frameworkStatus"`
	CriticalIssues    int                                `json:"criticalIssues"`
	TotalViolations   int                                `json:"totalViolations"`
	RecentAssessments []RecentAssessment                 `json:"recentAssessments"`
	UpcomingDeadlines []ComplianceDeadline               `json:"upcomingDeadlines"`
	TrendAnalysis     ComplianceTrendAnalysis            `json:"trendAnalysis"`
}

type RecentAssessment struct {
	Framework string  `json:"framework"`
	Date      string  `json:"date"`
	Score     float64 `json:"score"`
	Status    string  `json:"status"`
}

type ComplianceDeadline struct {
	Framework   string `json:"framework"`
	Requirement string `json:"requirement"`
	DueDate     string `json:"dueDate"`
	Priority    string `json:"priority"`
}

type ComplianceTrendAnalysis struct {
	ScoreTrend     string  `json:"scoreTrend"`
	ViolationTrend string  `json:"violationTrend"`
	Improvement    float64 `json:"improvement"`
}

type GetComplianceOverviewOutput = model.Output[*ComplianceOverview]

func (c *complianceController) getComplianceOverviewHandler(ctx context.Context, input *GetComplianceOverviewInput) (*GetComplianceOverviewOutput, error) {
	complianceService := c.getComplianceService()

	// Get status for each framework
	frameworkStatus := make(map[string]*audit.ComplianceStatus)
	frameworks := []string{"soc2", "hipaa", "pci_dss", "gdpr"}

	totalScore := 0.0
	validFrameworks := 0
	totalCriticalIssues := 0
	totalViolations := 0

	for _, framework := range frameworks {
		var status *audit.ComplianceStatus
		var err error

		switch framework {
		case "soc2":
			status, err = complianceService.CheckSOC2Compliance(ctx, input.PathOrgID)
		case "hipaa":
			status, err = complianceService.CheckHIPAACompliance(ctx, input.PathOrgID)
		case "pci_dss":
			status, err = complianceService.CheckPCIDSSCompliance(ctx, input.PathOrgID)
		case "gdpr":
			status, err = complianceService.CheckGDPRCompliance(ctx, input.PathOrgID)
		}

		if err == nil && status != nil {
			frameworkStatus[framework] = status
			totalScore += status.Score
			validFrameworks++
			totalCriticalIssues += status.CriticalIssues
			totalViolations += status.TotalIssues
		}
	}

	// Calculate overall score
	overallScore := 0.0
	if validFrameworks > 0 {
		overallScore = totalScore / float64(validFrameworks)
	}

	overview := &ComplianceOverview{
		OrganizationID:  input.PathOrgID,
		OverallScore:    overallScore,
		FrameworkStatus: frameworkStatus,
		CriticalIssues:  totalCriticalIssues,
		TotalViolations: totalViolations,
		RecentAssessments: []RecentAssessment{
			{
				Framework: "SOC2",
				Date:      "2024-01-15",
				Score:     85.0,
				Status:    "compliant",
			},
		},
		UpcomingDeadlines: []ComplianceDeadline{
			{
				Framework:   "SOC2",
				Requirement: "Annual assessment",
				DueDate:     "2024-06-30",
				Priority:    "high",
			},
		},
		TrendAnalysis: ComplianceTrendAnalysis{
			ScoreTrend:     "improving",
			ViolationTrend: "decreasing",
			Improvement:    12.5,
		},
	}

	return &GetComplianceOverviewOutput{
		Body: overview,
	}, nil
}

type GetComplianceMetricsInput struct {
	model.OrganisationPathParams
	Period string `query:"period" doc:"Metrics period (24h, 7d, 30d, 90d)"`
}

type ComplianceMetrics struct {
	OrganizationID     xid.ID                 `json:"organizationId"`
	Period             string                 `json:"period"`
	ScoreHistory       []ScoreDataPoint       `json:"scoreHistory"`
	ViolationHistory   []ViolationDataPoint   `json:"violationHistory"`
	FrameworkBreakdown map[string]interface{} `json:"frameworkBreakdown"`
	TopRisks           []RiskDataPoint        `json:"topRisks"`
	RemediationMetrics RemediationMetrics     `json:"remediationMetrics"`
	ComplianceCoverage ComplianceCoverage     `json:"complianceCoverage"`
}

type ScoreDataPoint struct {
	Date  string  `json:"date"`
	Score float64 `json:"score"`
}

type ViolationDataPoint struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

type RiskDataPoint struct {
	Risk     string `json:"risk"`
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

type RemediationMetrics struct {
	AverageTimeToResolve float64 `json:"averageTimeToResolve"`
	OpenViolations       int     `json:"openViolations"`
	ResolvedThisMonth    int     `json:"resolvedThisMonth"`
}

type ComplianceCoverage struct {
	TotalRequirements   int     `json:"totalRequirements"`
	CoveredRequirements int     `json:"coveredRequirements"`
	CoveragePercentage  float64 `json:"coveragePercentage"`
}

type GetComplianceMetricsOutput = model.Output[*ComplianceMetrics]

func (c *complianceController) getComplianceMetricsHandler(ctx context.Context, input *GetComplianceMetricsInput) (*GetComplianceMetricsOutput, error) {
	period := input.Period
	if period == "" {
		period = "30d"
	}

	// Mock implementation - in real implementation, this would aggregate actual data
	metrics := &ComplianceMetrics{
		OrganizationID: input.PathOrgID,
		Period:         period,
		ScoreHistory: []ScoreDataPoint{
			{Date: "2024-01-01", Score: 82.5},
			{Date: "2024-01-15", Score: 85.0},
			{Date: "2024-01-30", Score: 87.2},
		},
		ViolationHistory: []ViolationDataPoint{
			{Date: "2024-01-01", Count: 15},
			{Date: "2024-01-15", Count: 12},
			{Date: "2024-01-30", Count: 8},
		},
		FrameworkBreakdown: map[string]interface{}{
			"soc2":    map[string]interface{}{"score": 85.0, "violations": 3},
			"hipaa":   map[string]interface{}{"score": 90.0, "violations": 2},
			"pci_dss": map[string]interface{}{"score": 88.0, "violations": 2},
			"gdpr":    map[string]interface{}{"score": 92.0, "violations": 1},
		},
		TopRisks: []RiskDataPoint{
			{Risk: "Insufficient access logging", Severity: "high", Count: 3},
			{Risk: "Missing encryption", Severity: "medium", Count: 2},
		},
		RemediationMetrics: RemediationMetrics{
			AverageTimeToResolve: 7.5,
			OpenViolations:       8,
			ResolvedThisMonth:    12,
		},
		ComplianceCoverage: ComplianceCoverage{
			TotalRequirements:   150,
			CoveredRequirements: 135,
			CoveragePercentage:  90.0,
		},
	}

	return &GetComplianceMetricsOutput{
		Body: metrics,
	}, nil
}
