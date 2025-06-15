package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
)

// AuditTrailService tracks all RBAC-related changes for compliance and security
type AuditTrailService struct {
	logger logging.Logger
	repo   repository.RoleRepository
}

// AuditEvent represents a single audit trail entry
type AuditEvent struct {
	ID             xid.ID                 `json:"id"`
	EventType      AuditEventType         `json:"event_type"`
	Resource       string                 `json:"resource"` // role, permission, user_role, etc.
	ResourceID     xid.ID                 `json:"resource_id"`
	Action         AuditAction            `json:"action"`       // create, update, delete, assign, revoke
	ActorID        xid.ID                 `json:"actor_id"`     // Who performed the action
	ActorType      string                 `json:"actor_type"`   // user, system, api_key
	SubjectID      *xid.ID                `json:"subject_id"`   // Who was affected (for assignments)
	SubjectType    string                 `json:"subject_type"` // user, role
	OrganizationID *xid.ID                `json:"organization_id"`
	Context        map[string]interface{} `json:"context"`  // Additional context data
	Changes        *ChangeDetails         `json:"changes"`  // What changed
	Metadata       map[string]interface{} `json:"metadata"` // IP, user agent, etc.
	Timestamp      time.Time              `json:"timestamp"`
	Severity       AuditSeverity          `json:"severity"`
	SessionID      string                 `json:"session_id"`
	RequestID      string                 `json:"request_id"`
	Success        bool                   `json:"success"`
	ErrorMessage   string                 `json:"error_message,omitempty"`
}

// AuditEventType categorizes the type of event
type AuditEventType string

const (
	EventTypeRoleManagement       AuditEventType = "role_management"
	EventTypePermissionManagement AuditEventType = "permission_management"
	EventTypeUserRoleAssignment   AuditEventType = "user_role_assignment"
	EventTypeUserPermission       AuditEventType = "user_permission"
	EventTypeAccessAttempt        AuditEventType = "access_attempt"
	EventTypeSystemConfiguration  AuditEventType = "system_configuration"
	EventTypeResourceDiscovery    AuditEventType = "resource_discovery"
	EventTypeTemplateOperation    AuditEventType = "template_operation"
)

// AuditAction specifies what action was performed
type AuditAction string

const (
	ActionCreate   AuditAction = "create"
	ActionUpdate   AuditAction = "update"
	ActionDelete   AuditAction = "delete"
	ActionAssign   AuditAction = "assign"
	ActionRevoke   AuditAction = "revoke"
	ActionAccess   AuditAction = "access"
	ActionDeny     AuditAction = "deny"
	ActionRegister AuditAction = "register"
	ActionApply    AuditAction = "apply"
	ActionValidate AuditAction = "validate"
)

// AuditSeverity indicates the importance of the event
type AuditSeverity string

const (
	SeverityLow      AuditSeverity = "low"
	SeverityMedium   AuditSeverity = "medium"
	SeverityHigh     AuditSeverity = "high"
	SeverityCritical AuditSeverity = "critical"
)

// ChangeDetails captures what specifically changed
type ChangeDetails struct {
	Before map[string]interface{} `json:"before,omitempty"`
	After  map[string]interface{} `json:"after,omitempty"`
	Fields []string               `json:"fields"` // List of fields that changed
}

// AuditQuery parameters for searching audit logs
type AuditQuery struct {
	EventTypes     []AuditEventType `json:"event_types,omitempty"`
	Actions        []AuditAction    `json:"actions,omitempty"`
	ActorID        *xid.ID          `json:"actor_id,omitempty"`
	SubjectID      *xid.ID          `json:"subject_id,omitempty"`
	ResourceID     *xid.ID          `json:"resource_id,omitempty"`
	OrganizationID *xid.ID          `json:"organization_id,omitempty"`
	StartTime      *time.Time       `json:"start_time,omitempty"`
	EndTime        *time.Time       `json:"end_time,omitempty"`
	Severity       []AuditSeverity  `json:"severity,omitempty"`
	Success        *bool            `json:"success,omitempty"`
	Limit          int              `json:"limit"`
	Offset         int              `json:"offset"`
	OrderBy        string           `json:"order_by"` // timestamp, severity
	OrderDesc      bool             `json:"order_desc"`
}

// ComplianceReport represents audit data for compliance reporting
type ComplianceReport struct {
	ReportID          xid.ID                   `json:"report_id"`
	GeneratedAt       time.Time                `json:"generated_at"`
	Period            ReportPeriod             `json:"period"`
	OrganizationID    *xid.ID                  `json:"organization_id"`
	Summary           *ComplianceSummary       `json:"summary"`
	PrivilegedActions []*AuditEvent            `json:"privileged_actions"`
	FailedAttempts    []*AuditEvent            `json:"failed_attempts"`
	UserActivity      map[string]*UserActivity `json:"user_activity"`
	Anomalies         []*AnomalyDetection      `json:"anomalies"`
}

type ReportPeriod struct {
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
}

type ComplianceSummary struct {
	TotalEvents          int                    `json:"total_events"`
	EventsByType         map[AuditEventType]int `json:"events_by_type"`
	EventsBySeverity     map[AuditSeverity]int  `json:"events_by_severity"`
	SuccessRate          float64                `json:"success_rate"`
	UniqueUsers          int                    `json:"unique_users"`
	PrivilegedOperations int                    `json:"privileged_operations"`
	PolicyViolations     int                    `json:"policy_violations"`
}

type UserActivity struct {
	UserID       xid.ID              `json:"user_id"`
	EventCount   int                 `json:"event_count"`
	LastActivity time.Time           `json:"last_activity"`
	Actions      map[AuditAction]int `json:"actions"`
	RiskScore    float64             `json:"risk_score"`
}

type AnomalyDetection struct {
	Type        string        `json:"type"`
	Description string        `json:"description"`
	Severity    string        `json:"severity"`
	DetectedAt  time.Time     `json:"detected_at"`
	Events      []*AuditEvent `json:"events"`
	RiskScore   float64       `json:"risk_score"`
}

// NewAuditTrailService creates a new audit trail service
func NewAuditTrailService(repo repository.RoleRepository, logger logging.Logger) *AuditTrailService {
	return &AuditTrailService{
		logger: logger,
		repo:   repo,
	}
}

// LogEvent records an audit event
func (ats *AuditTrailService) LogEvent(ctx context.Context, event *AuditEvent) error {
	// Set defaults
	if event.ID.IsNil() {
		event.ID = xid.New()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	if event.Success && event.Severity == "" {
		event.Severity = ats.calculateSeverity(event)
	}

	// Extract context information if available
	ats.enrichEventContext(ctx, event)

	// Store the event (you'll need to implement storage)
	err := ats.storeEvent(ctx, event)
	if err != nil {
		ats.logger.Error("Failed to store audit event",
			logging.String("event_type", string(event.EventType)),
			logging.String("action", string(event.Action)),
			logging.Error(err))
		return err
	}

	// Log critical events immediately
	if event.Severity == SeverityCritical {
		ats.logger.Warn("Critical RBAC event",
			logging.String("event_type", string(event.EventType)),
			logging.String("action", string(event.Action)),
			logging.String("actor_id", event.ActorID.String()),
			logging.Any("context", event.Context))
	}

	return nil
}

// Convenience methods for common audit events

func (ats *AuditTrailService) LogRoleCreated(ctx context.Context, roleID xid.ID, actorID xid.ID, roleName string, orgID *xid.ID) error {
	return ats.LogEvent(ctx, &AuditEvent{
		EventType:      EventTypeRoleManagement,
		Resource:       "role",
		ResourceID:     roleID,
		Action:         ActionCreate,
		ActorID:        actorID,
		ActorType:      "user",
		OrganizationID: orgID,
		Context: map[string]interface{}{
			"role_name": roleName,
		},
		Success: true,
	})
}

func (ats *AuditTrailService) LogRoleUpdated(ctx context.Context, roleID xid.ID, actorID xid.ID, changes *ChangeDetails, orgID *xid.ID) error {
	return ats.LogEvent(ctx, &AuditEvent{
		EventType:      EventTypeRoleManagement,
		Resource:       "role",
		ResourceID:     roleID,
		Action:         ActionUpdate,
		ActorID:        actorID,
		ActorType:      "user",
		OrganizationID: orgID,
		Changes:        changes,
		Success:        true,
	})
}

func (ats *AuditTrailService) LogRoleAssigned(ctx context.Context, roleID xid.ID, userID xid.ID, actorID xid.ID, contextType string, orgID *xid.ID) error {
	severity := SeverityMedium
	if contextType == "system" {
		severity = SeverityHigh
	}

	return ats.LogEvent(ctx, &AuditEvent{
		EventType:      EventTypeUserRoleAssignment,
		Resource:       "user_role",
		ResourceID:     roleID,
		Action:         ActionAssign,
		ActorID:        actorID,
		ActorType:      "user",
		SubjectID:      &userID,
		SubjectType:    "user",
		OrganizationID: orgID,
		Context: map[string]interface{}{
			"context_type": contextType,
		},
		Severity: severity,
		Success:  true,
	})
}

func (ats *AuditTrailService) LogPermissionChecked(ctx context.Context, userID xid.ID, resource, action string, granted bool, orgID *xid.ID) error {
	auditAction := ActionAccess
	severity := SeverityLow

	if !granted {
		auditAction = ActionDeny
		severity = SeverityMedium
	}

	return ats.LogEvent(ctx, &AuditEvent{
		EventType:      EventTypeAccessAttempt,
		Resource:       resource,
		Action:         auditAction,
		ActorID:        userID,
		ActorType:      "user",
		OrganizationID: orgID,
		Context: map[string]interface{}{
			"requested_action": action,
			"granted":          granted,
		},
		Severity: severity,
		Success:  granted,
	})
}

func (ats *AuditTrailService) LogResourceRegistered(ctx context.Context, resourceName string, actorID xid.ID, orgID *xid.ID) error {
	return ats.LogEvent(ctx, &AuditEvent{
		EventType:      EventTypeResourceDiscovery,
		Resource:       "resource_definition",
		Action:         ActionRegister,
		ActorID:        actorID,
		ActorType:      "user",
		OrganizationID: orgID,
		Context: map[string]interface{}{
			"resource_name": resourceName,
		},
		Severity: SeverityMedium,
		Success:  true,
	})
}

// Query and reporting methods

func (ats *AuditTrailService) QueryEvents(ctx context.Context, query *AuditQuery) ([]*AuditEvent, error) {
	// Implementation would depend on your storage backend
	// This would query the audit log storage with the given parameters
	return ats.queryEvents(ctx, query)
}

func (ats *AuditTrailService) GenerateComplianceReport(ctx context.Context, period ReportPeriod, orgID *xid.ID) (*ComplianceReport, error) {
	query := &AuditQuery{
		StartTime:      &period.StartTime,
		EndTime:        &period.EndTime,
		OrganizationID: orgID,
		Limit:          10000, // Adjust based on your needs
	}

	events, err := ats.QueryEvents(ctx, query)
	if err != nil {
		return nil, err
	}

	report := &ComplianceReport{
		ReportID:       xid.New(),
		GeneratedAt:    time.Now(),
		Period:         period,
		OrganizationID: orgID,
		Summary:        ats.generateSummary(events),
		UserActivity:   ats.analyzeUserActivity(events),
		Anomalies:      ats.detectAnomalies(events),
	}

	// Filter privileged actions and failed attempts
	for _, event := range events {
		if ats.isPrivilegedAction(event) {
			report.PrivilegedActions = append(report.PrivilegedActions, event)
		}
		if !event.Success {
			report.FailedAttempts = append(report.FailedAttempts, event)
		}
	}

	return report, nil
}

func (ats *AuditTrailService) GetUserAuditTrail(ctx context.Context, userID xid.ID, limit int, orgID *xid.ID) ([]*AuditEvent, error) {
	query := &AuditQuery{
		ActorID:        &userID,
		OrganizationID: orgID,
		Limit:          limit,
		OrderBy:        "timestamp",
		OrderDesc:      true,
	}

	return ats.QueryEvents(ctx, query)
}

func (ats *AuditTrailService) GetResourceAuditTrail(ctx context.Context, resourceID xid.ID, limit int, orgID *xid.ID) ([]*AuditEvent, error) {
	query := &AuditQuery{
		ResourceID:     &resourceID,
		OrganizationID: orgID,
		Limit:          limit,
		OrderBy:        "timestamp",
		OrderDesc:      true,
	}

	return ats.QueryEvents(ctx, query)
}

// Helper methods

func (ats *AuditTrailService) calculateSeverity(event *AuditEvent) AuditSeverity {
	// Calculate severity based on event type and action
	switch event.EventType {
	case EventTypeRoleManagement, EventTypePermissionManagement:
		if event.Action == ActionDelete {
			return SeverityHigh
		}
		if event.Action == ActionCreate || event.Action == ActionUpdate {
			return SeverityMedium
		}
	case EventTypeUserRoleAssignment:
		if event.Action == ActionAssign || event.Action == ActionRevoke {
			// Check if it's a system role or high-privilege role
			if contextType, ok := event.Context["context_type"].(string); ok && contextType == "system" {
				return SeverityHigh
			}
			return SeverityMedium
		}
	case EventTypeAccessAttempt:
		if event.Action == ActionDeny {
			return SeverityMedium
		}
		return SeverityLow
	case EventTypeSystemConfiguration:
		return SeverityHigh
	}

	return SeverityLow
}

func (ats *AuditTrailService) enrichEventContext(ctx context.Context, event *AuditEvent) {
	if event.Metadata == nil {
		event.Metadata = make(map[string]interface{})
	}

	// Extract context information from the request context
	// This would depend on your middleware setup

	// Example extractions:
	// if requestID := ctx.Value("request_id"); requestID != nil {
	//     event.RequestID = requestID.(string)
	// }

	// if sessionID := ctx.Value("session_id"); sessionID != nil {
	//     event.SessionID = sessionID.(string)
	// }

	// if clientIP := ctx.Value("client_ip"); clientIP != nil {
	//     event.Metadata["client_ip"] = clientIP
	// }

	// if userAgent := ctx.Value("user_agent"); userAgent != nil {
	//     event.Metadata["user_agent"] = userAgent
	// }
}

func (ats *AuditTrailService) storeEvent(ctx context.Context, event *AuditEvent) error {
	// Implementation depends on your storage strategy
	// Options include:
	// 1. Database table
	// 2. Time-series database (InfluxDB, TimescaleDB)
	// 3. Log aggregation system (ELK, Fluentd)
	// 4. Cloud logging service (CloudWatch, Stackdriver)

	// For now, just log it
	eventJSON, _ := json.Marshal(event)
	ats.logger.Info("Audit event", logging.String("event", string(eventJSON)))

	return nil
}

func (ats *AuditTrailService) queryEvents(ctx context.Context, query *AuditQuery) ([]*AuditEvent, error) {
	// Implementation would query your storage backend
	// This is a placeholder
	return []*AuditEvent{}, nil
}

func (ats *AuditTrailService) generateSummary(events []*AuditEvent) *ComplianceSummary {
	summary := &ComplianceSummary{
		TotalEvents:      len(events),
		EventsByType:     make(map[AuditEventType]int),
		EventsBySeverity: make(map[AuditSeverity]int),
	}

	successCount := 0
	uniqueUsers := make(map[string]struct{})
	privilegedOps := 0

	for _, event := range events {
		summary.EventsByType[event.EventType]++
		summary.EventsBySeverity[event.Severity]++

		if event.Success {
			successCount++
		}

		uniqueUsers[event.ActorID.String()] = struct{}{}

		if ats.isPrivilegedAction(event) {
			privilegedOps++
		}
	}

	if len(events) > 0 {
		summary.SuccessRate = float64(successCount) / float64(len(events))
	}
	summary.UniqueUsers = len(uniqueUsers)
	summary.PrivilegedOperations = privilegedOps

	return summary
}

func (ats *AuditTrailService) analyzeUserActivity(events []*AuditEvent) map[string]*UserActivity {
	userActivity := make(map[string]*UserActivity)

	for _, event := range events {
		userID := event.ActorID.String()

		if activity, exists := userActivity[userID]; exists {
			activity.EventCount++
			if event.Timestamp.After(activity.LastActivity) {
				activity.LastActivity = event.Timestamp
			}
			activity.Actions[event.Action]++
		} else {
			userActivity[userID] = &UserActivity{
				UserID:       event.ActorID,
				EventCount:   1,
				LastActivity: event.Timestamp,
				Actions:      map[AuditAction]int{event.Action: 1},
				RiskScore:    0, // Would be calculated based on actions
			}
		}
	}

	// Calculate risk scores
	for _, activity := range userActivity {
		activity.RiskScore = ats.calculateUserRiskScore(activity)
	}

	return userActivity
}

func (ats *AuditTrailService) detectAnomalies(events []*AuditEvent) []*AnomalyDetection {
	var anomalies []*AnomalyDetection

	// Simple anomaly detection examples:
	// 1. Multiple failed access attempts
	// 2. Unusual activity patterns
	// 3. Privilege escalation patterns

	failedAttempts := make(map[string][]*AuditEvent)

	for _, event := range events {
		if !event.Success && event.EventType == EventTypeAccessAttempt {
			userID := event.ActorID.String()
			failedAttempts[userID] = append(failedAttempts[userID], event)
		}
	}

	// Detect multiple failed attempts
	for userID, attempts := range failedAttempts {
		if len(attempts) >= 5 { // Threshold for suspicious activity
			anomalies = append(anomalies, &AnomalyDetection{
				Type:        "multiple_failed_attempts",
				Description: fmt.Sprintf("User %s had %d failed access attempts", userID, len(attempts)),
				Severity:    "high",
				DetectedAt:  time.Now(),
				Events:      attempts,
				RiskScore:   0.8,
			})
		}
	}

	return anomalies
}

func (ats *AuditTrailService) isPrivilegedAction(event *AuditEvent) bool {
	privilegedActions := map[AuditEventType]map[AuditAction]bool{
		EventTypeRoleManagement: {
			ActionCreate: true,
			ActionDelete: true,
			ActionUpdate: true,
		},
		EventTypePermissionManagement: {
			ActionCreate: true,
			ActionDelete: true,
			ActionUpdate: true,
		},
		EventTypeUserRoleAssignment: {
			ActionAssign: true,
			ActionRevoke: true,
		},
		EventTypeSystemConfiguration: {
			ActionCreate: true,
			ActionUpdate: true,
			ActionDelete: true,
		},
	}

	if actions, exists := privilegedActions[event.EventType]; exists {
		return actions[event.Action]
	}

	return false
}

func (ats *AuditTrailService) calculateUserRiskScore(activity *UserActivity) float64 {
	score := 0.0

	// Base score on action types
	riskWeights := map[AuditAction]float64{
		ActionDelete: 0.3,
		ActionCreate: 0.2,
		ActionUpdate: 0.1,
		ActionAssign: 0.2,
		ActionRevoke: 0.2,
		ActionAccess: 0.05,
	}

	totalWeight := 0.0
	for action, count := range activity.Actions {
		if weight, exists := riskWeights[action]; exists {
			score += weight * float64(count)
			totalWeight += float64(count)
		}
	}

	if totalWeight > 0 {
		score = score / totalWeight
	}

	// Cap at 1.0
	if score > 1.0 {
		score = 1.0
	}

	return score
}
