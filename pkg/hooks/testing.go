package hooks

import (
	"github.com/xraph/frank/pkg/logging"
)

// MockHookRegistry is a registry that replaces all hooks with no-ops for testing
type MockHookRegistry struct {
	HookRegistry
	originalHooks map[HookType][]HookHandler
	mocked        bool
}

// NewMockHookRegistry creates a registry for testing purposes
func NewMockHookRegistry(logger logging.Logger) *MockHookRegistry {
	return &MockHookRegistry{
		HookRegistry:  NewHookRegistry(logger),
		originalHooks: make(map[HookType][]HookHandler),
		mocked:        false,
	}
}

// EnableMockMode replaces all registered hooks with no-ops
func (mr *MockHookRegistry) EnableMockMode() {
	if mr.mocked {
		return
	}

	// mr.mutex.Lock()
	// defer mr.mutex.Unlock()
	//
	// // Save original hooks
	// for hookType, handlers := range mr.hooks {
	// 	mr.originalHooks[hookType] = make([]HookHandler, len(handlers))
	// 	copy(mr.originalHooks[hookType], handlers)
	//
	// 	// Replace with no-ops
	// 	mr.hooks[hookType] = make([]HookHandler, 0, len(handlers))
	// 	for _, handler := range handlers {
	// 		noopHandler := NewNoOpHookWithLogging(
	// 			fmt.Sprintf("mock_%s", handler.Name()),
	// 			mr.logger,
	// 		)
	// 		mr.hooks[hookType] = append(mr.hooks[hookType], noopHandler)
	// 	}
	// }
	//
	// mr.mocked = true
	// mr.logger.Info("Mock mode enabled - all hooks replaced with no-ops")
}

// DisableMockMode restores original hooks
func (mr *MockHookRegistry) DisableMockMode() {
	if !mr.mocked {
		return
	}

	// mr.mutex.Lock()
	// defer mr.mutex.Unlock()
	//
	// // Restore original hooks
	// for hookType, handlers := range mr.originalHooks {
	// 	mr.hooks[hookType] = make([]HookHandler, len(handlers))
	// 	copy(mr.hooks[hookType], handlers)
	// }
	//
	// // Clear saved hooks
	// mr.originalHooks = make(map[HookType][]HookHandler)
	// mr.mocked = false
	//
	// mr.logger.Info("Mock mode disabled - original hooks restored")
}
