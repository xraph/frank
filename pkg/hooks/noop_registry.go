package hooks

import (
	"github.com/xraph/frank/pkg/logging"
)

// NoOpHookRegistry extends HookRegistry with noop-specific functionality
type NoOpHookRegistry struct {
	HookRegistry
	logger logging.Logger
}

// NewNoOpHookRegistry creates a hook registry with noop helper methods
func NewNoOpHookRegistry(logger logging.Logger) *NoOpHookRegistry {
	return &NoOpHookRegistry{
		HookRegistry: NewHookRegistry(logger),
		logger:       logger,
	}
}

// RegisterNoOp registers a no-operation hook for the specified hook type
func (nr *NoOpHookRegistry) RegisterNoOp(hookType HookType, name string) error {
	handler := NewNoOpHook(name)
	return nr.Register(hookType, handler)
}

// RegisterNoOpWithLogging registers a no-op hook that logs its execution
func (nr *NoOpHookRegistry) RegisterNoOpWithLogging(hookType HookType, name string) error {
	handler := NewNoOpHookWithLogging(name, nr.logger)
	return nr.Register(hookType, handler)
}

// DisableHook replaces an existing hook with a disabled no-op hook
func (nr *NoOpHookRegistry) DisableHook(hookType HookType, handlerName string) error {
	// First unregister the existing hook
	if err := nr.Unregister(hookType, handlerName); err != nil {
		// If hook doesn't exist, that's fine - just register the disabled hook
	}

	// Register a disabled hook with the same name
	disabledHandler := DisabledHook(handlerName)
	return nr.Register(hookType, disabledHandler)
}

// ReplaceWithNoOp replaces an existing hook with a no-op version
func (nr *NoOpHookRegistry) ReplaceWithNoOp(hookType HookType, handlerName string, logExecution bool) error {
	// Unregister existing hook
	if err := nr.Unregister(hookType, handlerName); err != nil {
		// Continue even if hook doesn't exist
	}

	// Register no-op replacement
	var handler *NoOpHookHandler
	if logExecution {
		handler = NewNoOpHookWithLogging(handlerName, nr.logger)
	} else {
		handler = NewNoOpHook(handlerName)
	}

	return nr.Register(hookType, handler)
}
