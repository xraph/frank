package hooks

import (
	"time"

	"github.com/xraph/frank/pkg/logging"
)

// =============================================================================
// Utility Functions
// =============================================================================

// NoOpHookBuilder provides a fluent interface for building no-op hooks
type NoOpHookBuilder struct {
	handler *NoOpHookHandler
}

// NewNoOpBuilder creates a new no-op hook builder
func NewNoOpBuilder(name string) *NoOpHookBuilder {
	return &NoOpHookBuilder{
		handler: NewNoOpHook(name),
	}
}

func (b *NoOpHookBuilder) WithPriority(priority HookPriority) *NoOpHookBuilder {
	b.handler.WithPriority(priority)
	return b
}

func (b *NoOpHookBuilder) WithTimeout(timeout time.Duration) *NoOpHookBuilder {
	b.handler.WithTimeout(timeout)
	return b
}

func (b *NoOpHookBuilder) WithLogging(logger logging.Logger) *NoOpHookBuilder {
	b.handler.WithLogger(logger).WithLogging(true)
	return b
}

func (b *NoOpHookBuilder) OnlyIf(condition func(ctx *HookContext) bool) *NoOpHookBuilder {
	b.handler.WithShouldExecuteFunc(condition)
	return b
}

func (b *NoOpHookBuilder) Disabled() *NoOpHookBuilder {
	b.handler.WithShouldExecuteFunc(func(ctx *HookContext) bool { return false })
	return b
}

func (b *NoOpHookBuilder) Build() *NoOpHookHandler {
	return b.handler
}
