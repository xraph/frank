package hooks

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
)

// HookRegistryInterface defines the contract for hook registry implementations
type HookRegistry interface {
	// Register registers a hook handler
	Register(hookType HookType, handler HookHandler) error

	// Unregister removes a hook handler
	Unregister(hookType HookType, handlerName string) error

	// Execute executes all hooks for a given type
	Execute(ctx context.Context, hookType HookType, data interface{}) *HookExecutionResult

	// ExecuteWithContext executes hooks with additional context
	ExecuteWithContext(ctx context.Context, hookType HookType, data interface{}, metadata map[string]interface{}) *HookExecutionResult

	// ExecuteAsync executes hooks asynchronously
	ExecuteAsync(ctx context.Context, hookType HookType, data interface{}) <-chan *HookExecutionResult

	// ExecuteParallel executes hooks in parallel
	ExecuteParallel(ctx context.Context, hookType HookType, data interface{}) *HookExecutionResult
}

// HookRegistry manages hook registration and execution
type hookRegistry struct {
	hooks   map[HookType][]HookHandler
	mutex   sync.RWMutex
	logger  logging.Logger
	metrics *HookMetrics

	// Configuration
	defaultTimeout     time.Duration
	defaultRetryPolicy *RetryPolicy
	maxConcurrency     int
	enableMetrics      bool
	enableTracing      bool
}

// NewHookRegistry creates a new hook registry
func NewHookRegistry(logger logging.Logger) HookRegistry {
	return &hookRegistry{
		hooks:              make(map[HookType][]HookHandler),
		logger:             logger,
		metrics:            NewHookMetrics(),
		defaultTimeout:     30 * time.Second,
		defaultRetryPolicy: DefaultRetryPolicy(),
		maxConcurrency:     10,
		enableMetrics:      true,
		enableTracing:      true,
	}
}

// Register registers a hook handler
func (hr *hookRegistry) Register(hookType HookType, handler HookHandler) error {
	hr.mutex.Lock()
	defer hr.mutex.Unlock()

	if handler == nil {
		return fmt.Errorf("handler cannot be nil")
	}

	if _, exists := hr.hooks[hookType]; !exists {
		hr.hooks[hookType] = make([]HookHandler, 0)
	}

	hr.hooks[hookType] = append(hr.hooks[hookType], handler)

	// Sort by priority (lower number = higher priority)
	handlers := hr.hooks[hookType]
	for i := len(handlers) - 1; i > 0; i-- {
		if handlers[i].Priority() < handlers[i-1].Priority() {
			handlers[i], handlers[i-1] = handlers[i-1], handlers[i]
		} else {
			break
		}
	}

	hr.logger.Info("Hook registered",
		logging.String("type", string(hookType)),
		logging.String("handler", handler.Name()),
		logging.Int("priority", int(handler.Priority())),
	)

	return nil
}

// Unregister removes a hook handler
func (hr *hookRegistry) Unregister(hookType HookType, handlerName string) error {
	hr.mutex.Lock()
	defer hr.mutex.Unlock()

	handlers, exists := hr.hooks[hookType]
	if !exists {
		return fmt.Errorf("no handlers registered for hook type %s", hookType)
	}

	for i, handler := range handlers {
		if handler.Name() == handlerName {
			hr.hooks[hookType] = append(handlers[:i], handlers[i+1:]...)
			hr.logger.Info("Hook unregistered",
				logging.String("type", string(hookType)),
				logging.String("handler", handlerName),
			)
			return nil
		}
	}

	return fmt.Errorf("handler %s not found for hook type %s", handlerName, hookType)
}

// Execute executes all hooks for a given type
func (hr *hookRegistry) Execute(ctx context.Context, hookType HookType, data interface{}) *HookExecutionResult {
	return hr.ExecuteWithContext(ctx, hookType, data, nil)
}

// ExecuteWithContext executes hooks with additional context
func (hr *hookRegistry) ExecuteWithContext(ctx context.Context, hookType HookType, data interface{}, metadata map[string]interface{}) *HookExecutionResult {
	hr.mutex.RLock()
	handlers, exists := hr.hooks[hookType]
	hr.mutex.RUnlock()

	if !exists || len(handlers) == 0 {
		return &HookExecutionResult{
			Success:    true,
			Data:       data,
			HooksCount: 0,
		}
	}

	// Create hook context
	hookCtx := &HookContext{
		ctx:         ctx,
		HookType:    hookType,
		ExecutionID: xid.New(),
		Timestamp:   time.Now(),
		Data:        data,
		Metadata:    metadata,
		logger:      hr.logger,
		StartTime:   time.Now(),
		MaxRetries:  hr.defaultRetryPolicy.MaxRetries,
	}

	// Extract context values if available
	if userID := ctx.Value("user_id"); userID != nil {
		if uid, ok := userID.(xid.ID); ok {
			hookCtx.UserID = &uid
		}
	}

	if orgID := ctx.Value("organization_id"); orgID != nil {
		if oid, ok := orgID.(xid.ID); ok {
			hookCtx.OrganizationID = &oid
		}
	}

	if sessionID := ctx.Value("session_id"); sessionID != nil {
		if sid, ok := sessionID.(xid.ID); ok {
			hookCtx.SessionID = &sid
		}
	}

	if ip := ctx.Value("ip_address"); ip != nil {
		if ipStr, ok := ip.(string); ok {
			hookCtx.IPAddress = ipStr
		}
	}

	if ua := ctx.Value("user_agent"); ua != nil {
		if uaStr, ok := ua.(string); ok {
			hookCtx.UserAgent = uaStr
		}
	}

	if reqID := ctx.Value("request_id"); reqID != nil {
		if reqIDStr, ok := reqID.(string); ok {
			hookCtx.RequestID = reqIDStr
		}
	}

	// Execute hooks
	result := &HookExecutionResult{
		Success:    true,
		Data:       data,
		HooksCount: len(handlers),
		Results:    make([]*HookResult, 0, len(handlers)),
		StartTime:  time.Now(),
	}

	for _, handler := range handlers {
		if !handler.ShouldExecute(hookCtx) {
			hr.logger.Debug("Skipping hook execution",
				logging.String("type", string(hookType)),
				logging.String("handler", handler.Name()),
			)
			continue
		}

		hookResult := hr.executeHook(hookCtx, handler)
		result.Results = append(result.Results, hookResult)

		if !hookResult.Success {
			result.Success = false
			result.Error = hookResult.Error
		}

		// Update data if modified
		if hookResult.Modified && hookResult.Data != nil {
			result.Data = hookResult.Data
			hookCtx.Data = hookResult.Data
		}

		// Stop execution if requested
		if hookResult.ShouldStop {
			break
		}
	}

	result.Duration = time.Since(result.StartTime)

	// Update metrics
	if hr.enableMetrics {
		hr.metrics.RecordExecution(hookType, result.Success, result.Duration, len(result.Results))
	}

	return result
}

// executeHook executes a single hook with retry logic
func (hr *hookRegistry) executeHook(ctx *HookContext, handler HookHandler) *HookResult {
	var result *HookResult
	var lastError error

	retryPolicy := handler.RetryPolicy()
	if retryPolicy == nil {
		retryPolicy = hr.defaultRetryPolicy
	}

	timeout := handler.Timeout()
	if timeout == 0 {
		timeout = hr.defaultTimeout
	}

	for attempt := 0; attempt <= retryPolicy.MaxRetries; attempt++ {
		ctx.RetryCount = attempt

		// Create timeout context
		_, cancel := context.WithTimeout(ctx.ctx, timeout)
		ctx.cancel = cancel

		// Execute hook
		start := time.Now()
		result = handler.Execute(ctx)
		result.Duration = time.Since(start)
		result.RetryCount = attempt

		cancel()

		if result.Success || !result.ShouldRetry {
			break
		}

		lastError = result.Error

		// Check if error is retryable
		if !hr.isRetryableError(result.Error, retryPolicy) {
			break
		}

		// Calculate delay for next attempt
		if attempt < retryPolicy.MaxRetries {
			delay := hr.calculateDelay(attempt, retryPolicy)
			hr.logger.Warn("Hook execution failed, retrying",
				logging.String("hook", handler.Name()),
				logging.String("type", string(ctx.HookType)),
				logging.Int("attempt", attempt+1),
				logging.Duration("delay", delay),
				logging.Error(result.Error),
			)

			select {
			case <-time.After(delay):
				// Continue to next attempt
			case <-ctx.ctx.Done():
				result.Error = ctx.ctx.Err()
				return result
			}
		}
	}

	if !result.Success && lastError != nil {
		hr.logger.Error("Hook execution failed after all retries",
			logging.String("hook", handler.Name()),
			logging.String("type", string(ctx.HookType)),
			logging.Int("attempts", ctx.RetryCount+1),
			logging.Error(lastError),
		)
	}

	return result
}

// isRetryableError checks if an error is retryable
func (hr *hookRegistry) isRetryableError(err error, policy *RetryPolicy) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	for _, retryableErr := range policy.RetryableErrors {
		if errStr == retryableErr {
			return true
		}
	}

	return false
}

// calculateDelay calculates the delay for the next retry attempt
func (hr *hookRegistry) calculateDelay(attempt int, policy *RetryPolicy) time.Duration {
	delay := policy.InitialDelay
	for i := 0; i < attempt; i++ {
		delay = time.Duration(float64(delay) * policy.BackoffFactor)
		if delay > policy.MaxDelay {
			delay = policy.MaxDelay
			break
		}
	}
	return delay
}

// ExecuteAsync executes hooks asynchronously
func (hr *hookRegistry) ExecuteAsync(ctx context.Context, hookType HookType, data interface{}) <-chan *HookExecutionResult {
	resultChan := make(chan *HookExecutionResult, 1)

	go func() {
		defer close(resultChan)
		result := hr.Execute(ctx, hookType, data)
		resultChan <- result
	}()

	return resultChan
}

// ExecuteParallel executes hooks in parallel
func (hr *hookRegistry) ExecuteParallel(ctx context.Context, hookType HookType, data interface{}) *HookExecutionResult {
	hr.mutex.RLock()
	handlers, exists := hr.hooks[hookType]
	hr.mutex.RUnlock()

	if !exists || len(handlers) == 0 {
		return &HookExecutionResult{
			Success:    true,
			Data:       data,
			HooksCount: 0,
		}
	}

	// Create hook context
	hookCtx := &HookContext{
		ctx:         ctx,
		HookType:    hookType,
		ExecutionID: xid.New(),
		Timestamp:   time.Now(),
		Data:        data,
		logger:      hr.logger,
		StartTime:   time.Now(),
		MaxRetries:  hr.defaultRetryPolicy.MaxRetries,
	}

	// Execute hooks in parallel
	results := make([]*HookResult, len(handlers))
	var wg sync.WaitGroup

	for i, handler := range handlers {
		if !handler.ShouldExecute(hookCtx) {
			continue
		}

		wg.Add(1)
		go func(index int, h HookHandler) {
			defer wg.Done()
			results[index] = hr.executeHook(hookCtx, h)
		}(i, handler)
	}

	wg.Wait()

	// Combine results
	result := &HookExecutionResult{
		Success:    true,
		Data:       data,
		HooksCount: len(handlers),
		Results:    results,
		StartTime:  hookCtx.StartTime,
		Duration:   time.Since(hookCtx.StartTime),
	}

	for _, hookResult := range results {
		if hookResult != nil && !hookResult.Success {
			result.Success = false
			if result.Error == nil {
				result.Error = hookResult.Error
			}
		}
	}

	return result
}
