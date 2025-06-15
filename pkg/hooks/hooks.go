package hooks

import (
	"context"
	"fmt"

	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/model"
)

// Hooks defines the interface for hook management and execution
type Hooks interface {
	// Registry access
	Registry() HookRegistry

	// Hook registration convenience methods
	OnLogin(handler func(ctx *HookContext) *HookResult) error
	BeforeLogin(handler func(ctx *HookContext) *HookResult) error
	OnLogout(handler func(ctx *HookContext) *HookResult) error
	BeforeLogout(handler func(ctx *HookContext) *HookResult) error
	OnRegister(handler func(ctx *HookContext) *HookResult) error
	BeforeRegister(handler func(ctx *HookContext) *HookResult) error
	OnUserCreate(handler func(ctx *HookContext) *HookResult) error
	BeforeUserCreate(handler func(ctx *HookContext) *HookResult) error
	OnUserUpdate(handler func(ctx *HookContext) *HookResult) error
	BeforeUserUpdate(handler func(ctx *HookContext) *HookResult) error
	OnUserDelete(handler func(ctx *HookContext) *HookResult) error
	BeforeUserDelete(handler func(ctx *HookContext) *HookResult) error
	OnEmailVerification(handler func(ctx *HookContext) *HookResult) error
	BeforeEmailVerification(handler func(ctx *HookContext) *HookResult) error
	OnPasswordReset(handler func(ctx *HookContext) *HookResult) error
	BeforePasswordReset(handler func(ctx *HookContext) *HookResult) error
	OnPasswordChange(handler func(ctx *HookContext) *HookResult) error
	BeforePasswordChange(handler func(ctx *HookContext) *HookResult) error
	OnOrgCreate(handler func(ctx *HookContext) *HookResult) error
	BeforeOrgCreate(handler func(ctx *HookContext) *HookResult) error
	OnMemberJoin(handler func(ctx *HookContext) *HookResult) error
	OnMemberLeave(handler func(ctx *HookContext) *HookResult) error
	OnSessionCreate(handler func(ctx *HookContext) *HookResult) error
	OnSessionExpire(handler func(ctx *HookContext) *HookResult) error
	OnMFAEnable(handler func(ctx *HookContext) *HookResult) error
	OnMFADisable(handler func(ctx *HookContext) *HookResult) error
	OnSuspiciousActivity(handler func(ctx *HookContext) *HookResult) error
	OnSystemStartup(handler func(ctx *HookContext) *HookResult) error
	OnSystemShutdown(handler func(ctx *HookContext) *HookResult) error

	// Generic hook registration
	RegisterHook(hookType HookType, handler HookHandler) error
	RegisterHookFunc(hookType HookType, name string, handlerFunc func(ctx *HookContext) *HookResult) error
	UnregisterHook(hookType HookType, handlerName string) error

	// NoOp hook management
	RegisterNoOp(hookType HookType, name string) error
	RegisterNoOpWithLogging(hookType HookType, name string) error
	DisableHook(hookType HookType, handlerName string) error
	ReplaceWithNoOp(hookType HookType, handlerName string, logExecution bool) error

	// Conditional hooks
	RegisterConditionalHook(hookType HookType, name string, condition func(ctx *HookContext) bool, handler func(ctx *HookContext) *HookResult) error
	RegisterConditionalNoOp(hookType HookType, name string, condition func(ctx *HookContext) bool) error

	// Hook execution convenience methods
	ExecuteLoginHooks(ctx context.Context, loginResponse *model.LoginResponse) error
	ExecuteLogoutHooks(ctx context.Context, user *model.User) error
	ExecuteRegisterHooks(ctx context.Context, registerResponse *model.RegisterResponse) error
	ExecuteUserCreateHooks(ctx context.Context, user *model.User) error
	ExecuteUserUpdateHooks(ctx context.Context, user *model.User) error
	ExecuteUserDeleteHooks(ctx context.Context, userID interface{}) error
	ExecuteEmailVerificationHooks(ctx context.Context, verificationResponse *model.VerificationResponse) error
	ExecutePasswordResetHooks(ctx context.Context, resetRequest *model.PasswordResetRequest) error
	ExecutePasswordChangeHooks(ctx context.Context, user *model.User) error
	ExecuteOrgCreateHooks(ctx context.Context, org *model.Organization) error
	ExecuteMemberJoinHooks(ctx context.Context, membership *model.Membership) error
	ExecuteMemberLeaveHooks(ctx context.Context, membership *model.Membership) error
	ExecuteSessionCreateHooks(ctx context.Context, session *model.Session) error
	ExecuteSessionExpireHooks(ctx context.Context, session *model.Session) error
	ExecuteMFAEnableHooks(ctx context.Context, userID interface{}, method string) error
	ExecuteMFADisableHooks(ctx context.Context, userID interface{}, method string) error
	ExecuteSuspiciousActivityHooks(ctx context.Context, activity interface{}) error
	ExecuteSystemStartupHooks(ctx context.Context) error
	ExecuteSystemShutdownHooks(ctx context.Context) error

	// Generic execution methods
	Execute(ctx context.Context, hookType HookType, data interface{}) error
	ExecuteWithContext(ctx context.Context, hookType HookType, data interface{}, metadata map[string]interface{}) error
	ExecuteAsync(ctx context.Context, hookType HookType, data interface{}) <-chan error
	ExecuteParallel(ctx context.Context, hookType HookType, data interface{}) error

	// Hook management
	ListHooks(hookType HookType) []string
	GetHookStats(hookType HookType) HookStats
	EnableHook(hookType HookType, handlerName string) error
	IsHookEnabled(hookType HookType, handlerName string) bool

	// Lifecycle management
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Health(ctx context.Context) error
}

// hooksImpl interface with new functionality
type hooksImpl struct {
	registry HookRegistry
	logger   logging.Logger
	started  bool
}

func NewHooks(logger logging.Logger) Hooks {
	return &hooksImpl{
		registry: NewHookRegistry(logger),
		logger:   logger,
	}
}

// NewHooksServiceWithRegistry creates a hooks service with an existing registry
func NewHooksServiceWithRegistry(registry HookRegistry, logger logging.Logger) Hooks {
	return &hooksImpl{
		registry: registry,
		logger:   logger,
	}
}

func (h *hooksImpl) Registry() HookRegistry {
	return h.registry
}

// =============================================================================
// Hook Registration Convenience Methods
// =============================================================================

func (h *hooksImpl) OnLogin(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("on_login").WithExecuteFunc(handler)
	return h.registry.Register(HookAfterLogin, hookHandler)
}

func (h *hooksImpl) BeforeLogin(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("before_login").WithExecuteFunc(handler)
	return h.registry.Register(HookBeforeLogin, hookHandler)
}

func (h *hooksImpl) OnLogout(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("on_logout").WithExecuteFunc(handler)
	return h.registry.Register(HookAfterLogout, hookHandler)
}

func (h *hooksImpl) BeforeLogout(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("before_logout").WithExecuteFunc(handler)
	return h.registry.Register(HookBeforeLogout, hookHandler)
}

func (h *hooksImpl) OnRegister(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("on_register").WithExecuteFunc(handler)
	return h.registry.Register(HookAfterRegister, hookHandler)
}

func (h *hooksImpl) BeforeRegister(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("before_register").WithExecuteFunc(handler)
	return h.registry.Register(HookBeforeRegister, hookHandler)
}

func (h *hooksImpl) OnUserCreate(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("on_user_create").WithExecuteFunc(handler)
	return h.registry.Register(HookAfterUserCreate, hookHandler)
}

func (h *hooksImpl) BeforeUserCreate(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("before_user_create").WithExecuteFunc(handler)
	return h.registry.Register(HookBeforeUserCreate, hookHandler)
}

func (h *hooksImpl) OnUserUpdate(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("on_user_update").WithExecuteFunc(handler)
	return h.registry.Register(HookAfterUserUpdate, hookHandler)
}

func (h *hooksImpl) BeforeUserUpdate(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("before_user_update").WithExecuteFunc(handler)
	return h.registry.Register(HookBeforeUserUpdate, hookHandler)
}

func (h *hooksImpl) OnUserDelete(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("on_user_delete").WithExecuteFunc(handler)
	return h.registry.Register(HookAfterUserDelete, hookHandler)
}

func (h *hooksImpl) BeforeUserDelete(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("before_user_delete").WithExecuteFunc(handler)
	return h.registry.Register(HookBeforeUserDelete, hookHandler)
}

func (h *hooksImpl) OnEmailVerification(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("on_email_verification").WithExecuteFunc(handler)
	return h.registry.Register(HookAfterEmailVerification, hookHandler)
}

func (h *hooksImpl) BeforeEmailVerification(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("before_email_verification").WithExecuteFunc(handler)
	return h.registry.Register(HookBeforeEmailVerification, hookHandler)
}

func (h *hooksImpl) OnPasswordReset(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("on_password_reset").WithExecuteFunc(handler)
	return h.registry.Register(HookAfterPasswordReset, hookHandler)
}

func (h *hooksImpl) BeforePasswordReset(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("before_password_reset").WithExecuteFunc(handler)
	return h.registry.Register(HookBeforePasswordReset, hookHandler)
}

func (h *hooksImpl) OnPasswordChange(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("on_password_change").WithExecuteFunc(handler)
	return h.registry.Register(HookAfterPasswordChange, hookHandler)
}

func (h *hooksImpl) BeforePasswordChange(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("before_password_change").WithExecuteFunc(handler)
	return h.registry.Register(HookBeforePasswordChange, hookHandler)
}

func (h *hooksImpl) OnOrgCreate(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("on_org_create").WithExecuteFunc(handler)
	return h.registry.Register(HookAfterOrgCreate, hookHandler)
}

func (h *hooksImpl) BeforeOrgCreate(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("before_org_create").WithExecuteFunc(handler)
	return h.registry.Register(HookBeforeOrgCreate, hookHandler)
}

func (h *hooksImpl) OnMemberJoin(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("on_member_join").WithExecuteFunc(handler)
	return h.registry.Register(HookMemberJoined, hookHandler)
}

func (h *hooksImpl) OnMemberLeave(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("on_member_leave").WithExecuteFunc(handler)
	return h.registry.Register(HookMemberLeft, hookHandler)
}

func (h *hooksImpl) OnSessionCreate(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("on_session_create").WithExecuteFunc(handler)
	return h.registry.Register(HookSessionCreated, hookHandler)
}

func (h *hooksImpl) OnSessionExpire(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("on_session_expire").WithExecuteFunc(handler)
	return h.registry.Register(HookSessionExpired, hookHandler)
}

func (h *hooksImpl) OnMFAEnable(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("on_mfa_enable").WithExecuteFunc(handler)
	return h.registry.Register(HookMFAEnabled, hookHandler)
}

func (h *hooksImpl) OnMFADisable(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("on_mfa_disable").WithExecuteFunc(handler)
	return h.registry.Register(HookMFADisabled, hookHandler)
}

func (h *hooksImpl) OnSuspiciousActivity(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("on_suspicious_activity").WithExecuteFunc(handler)
	return h.registry.Register(HookSuspiciousActivity, hookHandler)
}

func (h *hooksImpl) OnSystemStartup(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("on_system_startup").WithExecuteFunc(handler)
	return h.registry.Register(HookSystemStartup, hookHandler)
}

func (h *hooksImpl) OnSystemShutdown(handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler("on_system_shutdown").WithExecuteFunc(handler)
	return h.registry.Register(HookSystemShutdown, hookHandler)
}

// =============================================================================
// Generic Hook Registration Methods
// =============================================================================

func (h *hooksImpl) RegisterHook(hookType HookType, handler HookHandler) error {
	return h.registry.Register(hookType, handler)
}

func (h *hooksImpl) RegisterHookFunc(hookType HookType, name string, handlerFunc func(ctx *HookContext) *HookResult) error {
	handler := NewBaseHookHandler(name).WithExecuteFunc(handlerFunc)
	return h.registry.Register(hookType, handler)
}

func (h *hooksImpl) UnregisterHook(hookType HookType, handlerName string) error {
	return h.registry.Unregister(hookType, handlerName)
}

// =============================================================================
// NoOp Hook Management Methods
// =============================================================================

func (h *hooksImpl) RegisterNoOp(hookType HookType, name string) error {
	handler := NewNoOpHook(name)
	return h.registry.Register(hookType, handler)
}

func (h *hooksImpl) RegisterNoOpWithLogging(hookType HookType, name string) error {
	handler := NewNoOpHookWithLogging(name, h.logger)
	return h.registry.Register(hookType, handler)
}

func (h *hooksImpl) DisableHook(hookType HookType, handlerName string) error {
	// Unregister existing hook
	_ = h.registry.Unregister(hookType, handlerName)

	// Register disabled hook
	handler := DisabledHook(handlerName)
	return h.registry.Register(hookType, handler)
}

func (h *hooksImpl) ReplaceWithNoOp(hookType HookType, handlerName string, logExecution bool) error {
	// Unregister existing hook
	_ = h.registry.Unregister(hookType, handlerName)

	// Register NoOp replacement
	var handler *NoOpHookHandler
	if logExecution {
		handler = NewNoOpHookWithLogging(handlerName, h.logger)
	} else {
		handler = NewNoOpHook(handlerName)
	}

	return h.registry.Register(hookType, handler)
}

// =============================================================================
// Conditional Hook Methods
// =============================================================================

func (h *hooksImpl) RegisterConditionalHook(hookType HookType, name string, condition func(ctx *HookContext) bool, handler func(ctx *HookContext) *HookResult) error {
	hookHandler := NewBaseHookHandler(name).
		WithExecuteFunc(handler).
		WithShouldExecuteFunc(condition)
	return h.registry.Register(hookType, hookHandler)
}

func (h *hooksImpl) RegisterConditionalNoOp(hookType HookType, name string, condition func(ctx *HookContext) bool) error {
	handler := ConditionalNoOpHook(name, condition)
	return h.registry.Register(hookType, handler)
}

// =============================================================================
// Hook Execution Convenience Methods
// =============================================================================

func (h *hooksImpl) ExecuteLoginHooks(ctx context.Context, loginResponse *model.LoginResponse) error {
	result := h.registry.Execute(ctx, HookAfterLogin, loginResponse)
	if !result.Success {
		return result.Error
	}
	return nil
}

func (h *hooksImpl) ExecuteLogoutHooks(ctx context.Context, user *model.User) error {
	result := h.registry.Execute(ctx, HookAfterLogout, user)
	if !result.Success {
		return result.Error
	}
	return nil
}

func (h *hooksImpl) ExecuteRegisterHooks(ctx context.Context, registerResponse *model.RegisterResponse) error {
	result := h.registry.Execute(ctx, HookAfterRegister, registerResponse)
	if !result.Success {
		return result.Error
	}
	return nil
}

func (h *hooksImpl) ExecuteUserCreateHooks(ctx context.Context, user *model.User) error {
	result := h.registry.Execute(ctx, HookAfterUserCreate, user)
	if !result.Success {
		return result.Error
	}
	return nil
}

func (h *hooksImpl) ExecuteUserUpdateHooks(ctx context.Context, user *model.User) error {
	result := h.registry.Execute(ctx, HookAfterUserUpdate, user)
	if !result.Success {
		return result.Error
	}
	return nil
}

func (h *hooksImpl) ExecuteUserDeleteHooks(ctx context.Context, userID interface{}) error {
	result := h.registry.Execute(ctx, HookAfterUserDelete, userID)
	if !result.Success {
		return result.Error
	}
	return nil
}

func (h *hooksImpl) ExecuteEmailVerificationHooks(ctx context.Context, verificationResponse *model.VerificationResponse) error {
	result := h.registry.Execute(ctx, HookAfterEmailVerification, verificationResponse)
	if !result.Success {
		return result.Error
	}
	return nil
}

func (h *hooksImpl) ExecutePasswordResetHooks(ctx context.Context, resetRequest *model.PasswordResetRequest) error {
	result := h.registry.Execute(ctx, HookAfterPasswordReset, resetRequest)
	if !result.Success {
		return result.Error
	}
	return nil
}

func (h *hooksImpl) ExecutePasswordChangeHooks(ctx context.Context, user *model.User) error {
	result := h.registry.Execute(ctx, HookAfterPasswordChange, user)
	if !result.Success {
		return result.Error
	}
	return nil
}

func (h *hooksImpl) ExecuteOrgCreateHooks(ctx context.Context, org *model.Organization) error {
	result := h.registry.Execute(ctx, HookAfterOrgCreate, org)
	if !result.Success {
		return result.Error
	}
	return nil
}

func (h *hooksImpl) ExecuteMemberJoinHooks(ctx context.Context, membership *model.Membership) error {
	result := h.registry.Execute(ctx, HookMemberJoined, membership)
	if !result.Success {
		return result.Error
	}
	return nil
}

func (h *hooksImpl) ExecuteMemberLeaveHooks(ctx context.Context, membership *model.Membership) error {
	result := h.registry.Execute(ctx, HookMemberLeft, membership)
	if !result.Success {
		return result.Error
	}
	return nil
}

func (h *hooksImpl) ExecuteSessionCreateHooks(ctx context.Context, session *model.Session) error {
	result := h.registry.Execute(ctx, HookSessionCreated, session)
	if !result.Success {
		return result.Error
	}
	return nil
}

func (h *hooksImpl) ExecuteSessionExpireHooks(ctx context.Context, session *model.Session) error {
	result := h.registry.Execute(ctx, HookSessionExpired, session)
	if !result.Success {
		return result.Error
	}
	return nil
}

func (h *hooksImpl) ExecuteMFAEnableHooks(ctx context.Context, userID interface{}, method string) error {
	data := map[string]interface{}{
		"user_id": userID,
		"method":  method,
	}
	result := h.registry.Execute(ctx, HookMFAEnabled, data)
	if !result.Success {
		return result.Error
	}
	return nil
}

func (h *hooksImpl) ExecuteMFADisableHooks(ctx context.Context, userID interface{}, method string) error {
	data := map[string]interface{}{
		"user_id": userID,
		"method":  method,
	}
	result := h.registry.Execute(ctx, HookMFADisabled, data)
	if !result.Success {
		return result.Error
	}
	return nil
}

func (h *hooksImpl) ExecuteSuspiciousActivityHooks(ctx context.Context, activity interface{}) error {
	result := h.registry.Execute(ctx, HookSuspiciousActivity, activity)
	if !result.Success {
		return result.Error
	}
	return nil
}

func (h *hooksImpl) ExecuteSystemStartupHooks(ctx context.Context) error {
	result := h.registry.Execute(ctx, HookSystemStartup, nil)
	if !result.Success {
		return result.Error
	}
	return nil
}

func (h *hooksImpl) ExecuteSystemShutdownHooks(ctx context.Context) error {
	result := h.registry.Execute(ctx, HookSystemShutdown, nil)
	if !result.Success {
		return result.Error
	}
	return nil
}

// =============================================================================
// Generic Execution Methods
// =============================================================================

func (h *hooksImpl) Execute(ctx context.Context, hookType HookType, data interface{}) error {
	result := h.registry.Execute(ctx, hookType, data)
	if !result.Success {
		return result.Error
	}
	return nil
}

func (h *hooksImpl) ExecuteWithContext(ctx context.Context, hookType HookType, data interface{}, metadata map[string]interface{}) error {
	result := h.registry.ExecuteWithContext(ctx, hookType, data, metadata)
	if !result.Success {
		return result.Error
	}
	return nil
}

func (h *hooksImpl) ExecuteAsync(ctx context.Context, hookType HookType, data interface{}) <-chan error {
	resultChan := make(chan error, 1)

	go func() {
		defer close(resultChan)
		result := h.registry.Execute(ctx, hookType, data)
		if !result.Success {
			resultChan <- result.Error
		} else {
			resultChan <- nil
		}
	}()

	return resultChan
}

func (h *hooksImpl) ExecuteParallel(ctx context.Context, hookType HookType, data interface{}) error {
	result := h.registry.ExecuteParallel(ctx, hookType, data)
	if !result.Success {
		return result.Error
	}
	return nil
}

// =============================================================================
// Hook Management Methods
// =============================================================================

func (h *hooksImpl) ListHooks(hookType HookType) []string {
	h.registry.(*hookRegistry).mutex.RLock()
	defer h.registry.(*hookRegistry).mutex.RUnlock()

	handlers, exists := h.registry.(*hookRegistry).hooks[hookType]
	if !exists {
		return []string{}
	}

	names := make([]string, len(handlers))
	for i, handler := range handlers {
		names[i] = handler.Name()
	}

	return names
}

func (h *hooksImpl) GetHookStats(hookType HookType) HookStats {
	return h.registry.(*hookRegistry).metrics.GetStats(hookType)
}

func (h *hooksImpl) EnableHook(hookType HookType, handlerName string) error {
	// This would typically involve re-registering a disabled hook
	// For now, we'll just log the action
	h.logger.Info("Hook enabled",
		logging.String("hook_type", string(hookType)),
		logging.String("handler", handlerName),
	)
	return nil
}

func (h *hooksImpl) IsHookEnabled(hookType HookType, handlerName string) bool {
	hooks := h.ListHooks(hookType)
	for _, hookName := range hooks {
		if hookName == handlerName {
			return true
		}
	}
	return false
}

// =============================================================================
// Lifecycle Management
// =============================================================================

func (h *hooksImpl) Start(ctx context.Context) error {
	if h.started {
		return nil
	}

	h.logger.Info("Starting hooks service")

	// Execute startup hooks
	if err := h.ExecuteSystemStartupHooks(ctx); err != nil {
		h.logger.Error("Startup hooks failed", logging.Error(err))
	}

	h.started = true
	return nil
}

func (h *hooksImpl) Stop(ctx context.Context) error {
	if !h.started {
		return nil
	}

	h.logger.Info("Stopping hooks service")

	// Execute shutdown hooks
	if err := h.ExecuteSystemShutdownHooks(ctx); err != nil {
		h.logger.Error("Shutdown hooks failed", logging.Error(err))
	}

	h.started = false
	return nil
}

func (h *hooksImpl) Health(ctx context.Context) error {
	// Basic health check - could be extended to check hook health
	if !h.started {
		return fmt.Errorf("hooks service not started")
	}

	// Execute health check hooks
	result := h.registry.Execute(ctx, HookHealthCheck, nil)
	if !result.Success {
		return result.Error
	}

	return nil
}
