package workers

import (
	"context"
	"time"

	"github.com/juicycleff/frank/internal/auth/sso"
	"github.com/juicycleff/frank/pkg/logging"
)

// SSOStateCleanupWorker periodically cleans up expired SSO states
type SSOStateCleanupWorker struct {
	stateStore *sso.EntStateStore
	interval   time.Duration
	logger     logging.Logger
	stopCh     chan struct{}
}

// NewSSOStateCleanupWorker creates a new SSO state cleanup worker
func NewSSOStateCleanupWorker(
	stateStore *sso.EntStateStore,
	interval time.Duration,
	logger logging.Logger,
) *SSOStateCleanupWorker {
	if interval <= 0 {
		interval = 1 * time.Hour // Default to hourly cleanup
	}

	return &SSOStateCleanupWorker{
		stateStore: stateStore,
		interval:   interval,
		logger:     logger,
		stopCh:     make(chan struct{}),
	}
}

// Start begins the cleanup worker
func (w *SSOStateCleanupWorker) Start() {
	go w.run()
}

// Stop stops the cleanup worker
func (w *SSOStateCleanupWorker) Stop() {
	close(w.stopCh)
}

// run executes the cleanup job at regular intervals
func (w *SSOStateCleanupWorker) run() {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	// Run cleanup immediately on start
	w.cleanup()

	for {
		select {
		case <-ticker.C:
			w.cleanup()
		case <-w.stopCh:
			w.logger.Info("SSO state cleanup worker stopped")
			return
		}
	}
}

// cleanup performs the actual cleanup operation
func (w *SSOStateCleanupWorker) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	w.logger.Debug("Starting SSO state cleanup")

	count, err := w.stateStore.CleanupExpiredStates(ctx)
	if err != nil {
		w.logger.Error("Failed to clean up expired SSO states",
			logging.Error(err),
		)
		return
	}

	if count > 0 {
		w.logger.Info("Cleaned up expired SSO states",
			logging.Int("count", count),
		)
	} else {
		w.logger.Debug("No expired SSO states to clean up")
	}
}
