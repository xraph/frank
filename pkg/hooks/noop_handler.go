package hooks

import (
	"time"

	"github.com/xraph/frank/pkg/logging"
)

// NoOpHookHandler is a hook handler that does nothing (no operation)
// Useful for testing, placeholders, or temporarily disabling hooks
type NoOpHookHandler struct {
	name              string
	priority          HookPriority
	timeout           time.Duration
	retryPolicy       *RetryPolicy
	logger            logging.Logger
	logExecution      bool // Whether to log when the hook executes
	shouldExecuteFunc func(ctx *HookContext) bool
}

// NewNoOpHook creates a new no-operation hook handler
func NewNoOpHook(name string) *NoOpHookHandler {
	return &NoOpHookHandler{
		name:              name,
		priority:          PriorityNormal,
		timeout:           1 * time.Second,             // Short timeout since it does nothing
		retryPolicy:       &RetryPolicy{MaxRetries: 0}, // No retries needed
		logExecution:      false,
		shouldExecuteFunc: func(ctx *HookContext) bool { return true },
	}
}

// NewNoOpHookWithLogging creates a no-op hook that logs its execution
func NewNoOpHookWithLogging(name string, logger logging.Logger) *NoOpHookHandler {
	return &NoOpHookHandler{
		name:              name,
		priority:          PriorityNormal,
		timeout:           1 * time.Second,
		retryPolicy:       &RetryPolicy{MaxRetries: 0},
		logger:            logger,
		logExecution:      true,
		shouldExecuteFunc: func(ctx *HookContext) bool { return true },
	}
}

// Execute implements the HookHandler interface - does nothing and returns success
func (h *NoOpHookHandler) Execute(ctx *HookContext) *HookResult {
	if h.logExecution && h.logger != nil {
		h.logger.Debug("NoOp hook executed",
			logging.String("hook_name", h.name),
			logging.String("hook_type", string(ctx.HookType)),
			logging.String("execution_id", ctx.ExecutionID.String()),
		)
	}

	return &HookResult{
		Success:    true,
		Data:       ctx.Data, // Pass through data unchanged
		Duration:   0,        // No actual processing time
		RetryCount: 0,
		Modified:   false, // Data not modified
		ShouldStop: false, // Continue with other hooks
		Metadata: map[string]interface{}{
			"handler_type": "noop",
			"executed_at":  time.Now(),
		},
	}
}

func (h *NoOpHookHandler) Name() string { return h.name }

func (h *NoOpHookHandler) Priority() HookPriority { return h.priority }

func (h *NoOpHookHandler) Timeout() time.Duration { return h.timeout }

func (h *NoOpHookHandler) RetryPolicy() *RetryPolicy { return h.retryPolicy }

func (h *NoOpHookHandler) ShouldExecute(ctx *HookContext) bool {
	return h.shouldExecuteFunc(ctx)
}

func (h *NoOpHookHandler) WithPriority(priority HookPriority) *NoOpHookHandler {
	h.priority = priority
	return h
}

func (h *NoOpHookHandler) WithTimeout(timeout time.Duration) *NoOpHookHandler {
	h.timeout = timeout
	return h
}

func (h *NoOpHookHandler) WithLogger(logger logging.Logger) *NoOpHookHandler {
	h.logger = logger
	return h
}

func (h *NoOpHookHandler) WithLogging(enabled bool) *NoOpHookHandler {
	h.logExecution = enabled
	return h
}

func (h *NoOpHookHandler) WithShouldExecuteFunc(fn func(ctx *HookContext) bool) *NoOpHookHandler {
	h.shouldExecuteFunc = fn
	return h
}

// DisabledHook creates a no-op hook that never executes (always returns false for ShouldExecute)
func DisabledHook(name string) *NoOpHookHandler {
	return NewNoOpHook(name).WithShouldExecuteFunc(func(ctx *HookContext) bool {
		return false
	})
}

// ConditionalNoOpHook creates a no-op hook that only executes under certain conditions
func ConditionalNoOpHook(name string, condition func(ctx *HookContext) bool) *NoOpHookHandler {
	return NewNoOpHook(name).WithShouldExecuteFunc(condition)
}
