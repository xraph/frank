package hooks

import (
	"context"
	"time"

	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
)

// HookType defines the type of hook
type HookType string

const (
	// Authentication hooks
	HookBeforeLogin    HookType = "auth.before_login"
	HookAfterLogin     HookType = "auth.after_login"
	HookBeforeLogout   HookType = "auth.before_logout"
	HookAfterLogout    HookType = "auth.after_logout"
	HookBeforeRegister HookType = "auth.before_register"
	HookAfterRegister  HookType = "auth.after_register"
	HookLoginFailed    HookType = "auth.login_failed"
	HookRegisterFailed HookType = "auth.register_failed"

	// Email verification hooks
	HookBeforeEmailVerification HookType = "email.before_verification"
	HookAfterEmailVerification  HookType = "email.after_verification"
	HookEmailVerificationFailed HookType = "email.verification_failed"

	// Password hooks
	HookBeforePasswordReset  HookType = "password.before_reset"
	HookAfterPasswordReset   HookType = "password.after_reset"
	HookPasswordResetFailed  HookType = "password.reset_failed"
	HookBeforePasswordChange HookType = "password.before_change"
	HookAfterPasswordChange  HookType = "password.after_change"
	HookPasswordChangeFailed HookType = "password.change_failed"

	// User management hooks
	HookBeforeUserCreate      HookType = "user.before_create"
	HookAfterUserCreate       HookType = "user.after_create"
	HookBeforeUserUpdate      HookType = "user.before_update"
	HookAfterUserUpdate       HookType = "user.after_update"
	HookBeforeUserDelete      HookType = "user.before_delete"
	HookAfterUserDelete       HookType = "user.after_delete"
	HookBeforeUserActivated   HookType = "user.before_activated"
	HookUserActivated         HookType = "user.activated"
	HookBeforeUserDeactivated HookType = "user.before_deactivated"
	HookUserDeactivated       HookType = "user.deactivated"
	HookBeforeUserBlocked     HookType = "user.before_blocked"
	HookUserBlocked           HookType = "user.blocked"
	HookBeforeUserUnblocked   HookType = "user.before_unblocked"
	HookUserUnblocked         HookType = "user.unblocked"

	// Session hooks
	HookSessionCreated     HookType = "session.created"
	HookSessionExpired     HookType = "session.expired"
	HookSessionInvalidated HookType = "session.invalidated"

	// Organization hooks
	HookBeforeOrgCreate   HookType = "org.before_create"
	HookAfterOrgCreate    HookType = "org.after_create"
	HookBeforeOrgUpdate   HookType = "org.before_update"
	HookAfterOrgUpdate    HookType = "org.after_update"
	HookBeforeOrgDelete   HookType = "org.before_delete"
	HookAfterOrgDelete    HookType = "org.after_delete"
	HookMemberInvited     HookType = "org.member_invited"
	HookMemberJoined      HookType = "org.member_joined"
	HookMemberLeft        HookType = "org.member_left"
	HookMemberRoleChanged HookType = "org.member_role_changed"

	// MFA hooks
	HookMFAEnabled  HookType = "mfa.enabled"
	HookMFADisabled HookType = "mfa.disabled"
	HookMFARequired HookType = "mfa.required"
	HookMFAVerified HookType = "mfa.verified"
	HookMFAFailed   HookType = "mfa.failed"

	// Audit hooks
	HookAuditLogCreated    HookType = "audit.log_created"
	HookSuspiciousActivity HookType = "audit.suspicious_activity"

	// Webhook hooks
	HookWebhookSent     HookType = "webhook.sent"
	HookWebhookFailed   HookType = "webhook.failed"
	HookWebhookReceived HookType = "webhook.received"

	// API hooks
	HookAPIKeyCreated     HookType = "api.key_created"
	HookAPIKeyRevoked     HookType = "api.key_revoked"
	HookAPIRequestMade    HookType = "api.request_made"
	HookRateLimitExceeded HookType = "api.rate_limit_exceeded"

	// System hooks
	HookSystemStartup     HookType = "system.startup"
	HookSystemShutdown    HookType = "system.shutdown"
	HookHealthCheck       HookType = "system.health_check"
	HookConfigChanged     HookType = "system.config_changed"
	HookDatabaseMigration HookType = "system.database_migration"
)

// HookPriority defines execution priority for hooks
type HookPriority int

const (
	PriorityLow      HookPriority = 100
	PriorityNormal   HookPriority = 50
	PriorityHigh     HookPriority = 10
	PriorityCritical HookPriority = 1
)

// HookExecutionMode defines how hooks should be executed
type HookExecutionMode int

const (
	ExecutionModeSync       HookExecutionMode = iota // Execute synchronously
	ExecutionModeAsync                               // Execute asynchronously
	ExecutionModeParallel                            // Execute in parallel
	ExecutionModeBackground                          // Execute in background
)

// HookContext provides context for hook execution
type HookContext struct {
	ctx            context.Context
	HookType       HookType
	ExecutionID    xid.ID
	Timestamp      time.Time
	UserID         *xid.ID
	OrganizationID *xid.ID
	SessionID      *xid.ID
	IPAddress      string
	UserAgent      string
	RequestID      string
	Metadata       map[string]interface{}
	Data           interface{}
	Error          error
	logger         logging.Logger

	// Execution tracking
	StartTime  time.Time
	Duration   time.Duration
	RetryCount int
	MaxRetries int

	// Data transformation
	transformations []HookTransformation

	// Cancellation
	cancel context.CancelFunc
}

// HookTransformation defines a data transformation
type HookTransformation struct {
	Field     string
	Transform func(interface{}) interface{}
	Validate  func(interface{}) error
}

// HookResult represents the result of hook execution
type HookResult struct {
	Success     bool
	Data        interface{}
	Error       error
	Duration    time.Duration
	RetryCount  int
	Metadata    map[string]interface{}
	Modified    bool
	ShouldStop  bool // If true, stops executing subsequent hooks
	ShouldRetry bool // If true, retries the hook
}

// HookHandler defines the interface for hook handlers
type HookHandler interface {
	Execute(ctx *HookContext) *HookResult
	Name() string
	Priority() HookPriority
	Timeout() time.Duration
	RetryPolicy() *RetryPolicy
	ShouldExecute(ctx *HookContext) bool
}

// RetryPolicy defines retry behavior for hooks
type RetryPolicy struct {
	MaxRetries      int
	InitialDelay    time.Duration
	MaxDelay        time.Duration
	BackoffFactor   float64
	RetryableErrors []string
}

// DefaultRetryPolicy returns a default retry policy
func DefaultRetryPolicy() *RetryPolicy {
	return &RetryPolicy{
		MaxRetries:    3,
		InitialDelay:  100 * time.Millisecond,
		MaxDelay:      5 * time.Second,
		BackoffFactor: 2.0,
		RetryableErrors: []string{
			"connection_error",
			"timeout_error",
			"rate_limit_error",
		},
	}
}

// HookExecutionResult represents the result of hook execution
type HookExecutionResult struct {
	Success    bool
	Data       interface{}
	Error      error
	HooksCount int
	Results    []*HookResult
	StartTime  time.Time
	Duration   time.Duration
}

type HookStats struct {
	HookType             HookType
	ExecutionCount       int64
	SuccessCount         int64
	FailureCount         int64
	SuccessRate          float64
	AverageExecutionTime time.Duration
	LastExecution        time.Time
}
