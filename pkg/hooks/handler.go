package hooks

import (
	"fmt"
	"time"
)

// BaseHookHandler provides a base implementation for hook handlers
type BaseHookHandler struct {
	name              string
	priority          HookPriority
	timeout           time.Duration
	retryPolicy       *RetryPolicy
	executeFunc       func(ctx *HookContext) *HookResult
	shouldExecuteFunc func(ctx *HookContext) bool
}

func NewBaseHookHandler(name string) *BaseHookHandler {
	return &BaseHookHandler{
		name:              name,
		priority:          PriorityNormal,
		timeout:           30 * time.Second,
		retryPolicy:       DefaultRetryPolicy(),
		shouldExecuteFunc: func(ctx *HookContext) bool { return true },
	}
}

func (h *BaseHookHandler) Execute(ctx *HookContext) *HookResult {
	if h.executeFunc == nil {
		return &HookResult{
			Success: false,
			Error:   fmt.Errorf("no execute function defined for hook %s", h.name),
		}
	}
	return h.executeFunc(ctx)
}

func (h *BaseHookHandler) Name() string                        { return h.name }
func (h *BaseHookHandler) Priority() HookPriority              { return h.priority }
func (h *BaseHookHandler) Timeout() time.Duration              { return h.timeout }
func (h *BaseHookHandler) RetryPolicy() *RetryPolicy           { return h.retryPolicy }
func (h *BaseHookHandler) ShouldExecute(ctx *HookContext) bool { return h.shouldExecuteFunc(ctx) }

func (h *BaseHookHandler) WithPriority(priority HookPriority) *BaseHookHandler {
	h.priority = priority
	return h
}

func (h *BaseHookHandler) WithTimeout(timeout time.Duration) *BaseHookHandler {
	h.timeout = timeout
	return h
}

func (h *BaseHookHandler) WithRetryPolicy(policy *RetryPolicy) *BaseHookHandler {
	h.retryPolicy = policy
	return h
}

func (h *BaseHookHandler) WithExecuteFunc(fn func(ctx *HookContext) *HookResult) *BaseHookHandler {
	h.executeFunc = fn
	return h
}

func (h *BaseHookHandler) WithShouldExecuteFunc(fn func(ctx *HookContext) bool) *BaseHookHandler {
	h.shouldExecuteFunc = fn
	return h
}
