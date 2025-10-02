package data

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
	"github.com/uptrace/bun/extra/bundebug"
	"github.com/uptrace/bun/extra/bunotel"
	"github.com/xraph/forge"
	"github.com/xraph/forge/pkg/cli/output"
	"github.com/xraph/frank/config"
)

type Tx = bun.Tx
type IDB interface {
	bun.IDB
	AddQueryHook(hook bun.QueryHook)
	PingContext(ctx context.Context) error
}

type DB struct {
	*bun.DB
	rootconfig *config.Config
	config     *config.DatabaseConfig
	healthMu   sync.RWMutex
	isHealthy  bool
	lastCheck  time.Time
	metrics    *ConnectionMetrics
	log        forge.Logger
	sqldb      *sql.DB
}

// ConnectionMetrics holds connection statistics
type ConnectionMetrics struct {
	mu                  sync.RWMutex
	TotalConnections    int64
	ActiveConnections   int64
	FailedConnections   int64
	HealthCheckFailures int64
	LastHealthCheck     time.Time
	HealthCheckDuration time.Duration
	ConnectionsCreated  int64
	ConnectionsClosed   int64
	QueriesExecuted     int64
	QueryErrors         int64
	AvgQueryDuration    time.Duration
}

// HealthStatus represents the health status of the database
type HealthStatus struct {
	Healthy         bool          `json:"healthy"`
	LastCheck       time.Time     `json:"last_check"`
	ResponseTime    time.Duration `json:"response_time"`
	Error           string        `json:"error,omitempty"`
	DatabaseVersion string        `json:"database_version,omitempty"`
	ConnectionStats sql.DBStats   `json:"connection_stats"`
}

// New creates a new database connection with the given config
func New(config *config.Config, sqldb *sql.DB, log forge.Logger) (*DB, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if log == nil {
		log = output.NewConsoleLogger(output.ConsoleLoggerConfig{
			EnableTrueColor: true,
		})
	}

	db := &DB{
		rootconfig: config,
		config:     &config.Database,
		isHealthy:  false,
		metrics:    &ConnectionMetrics{},
		log:        log,
		sqldb:      sqldb,
	}

	if err := db.connect(); err != nil {
		return nil, fmt.Errorf("failed to establish database connection: %w", err)
	}

	// Start health check monitoring
	go db.startHealthCheckMonitoring()

	return db, nil
}

// connect establishes the database connection with retry logic
func (db *DB) connect() error {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s&connect_timeout=%d",
		db.config.User,
		db.config.Password,
		db.config.Host,
		db.config.Port,
		db.config.Database,
		db.config.SSLMode,
		int(db.config.ConnectTimeout.Seconds()),
	)
	if db.config.DSN != "" {
		dsn = db.config.DSN
	}

	sqldb := db.sqldb
	var err error

	if sqldb == nil {
		// Retry connection with exponential backoff
		for attempt := 1; attempt <= db.config.MaxRetries; attempt++ {
			connector := pgdriver.NewConnector(pgdriver.WithDSN(dsn))
			sqldb = sql.OpenDB(connector)

			// Configure connection pool
			sqldb.SetMaxOpenConns(db.config.MaxOpenConns)
			sqldb.SetMaxIdleConns(db.config.MaxIdleConns)
			sqldb.SetConnMaxLifetime(db.config.ConnMaxLife)
			sqldb.SetConnMaxIdleTime(db.config.ConnMaxIdle)

			// Test connection with timeout
			ctx, cancel := context.WithTimeout(context.Background(), db.config.ConnectTimeout)
			err = sqldb.PingContext(ctx)
			cancel()

			if err == nil {
				break
			}

			log.Printf("Database connection attempt %d failed: %v", attempt, err)
			if attempt < db.config.MaxRetries {
				time.Sleep(db.config.RetryDelay * time.Duration(attempt))
			}
		}
		if err != nil {
			return fmt.Errorf("failed to connect after %d attempts: %w", db.config.MaxRetries, err)
		}
	}

	// Create bun.DB instance
	db.DB = bun.NewDB(sqldb, pgdialect.New())

	// Add query hooks
	db.setupHooks()

	// Update metrics
	if db.config.EnableMetrics {
		db.metrics.mu.Lock()
		db.metrics.TotalConnections++
		db.metrics.ConnectionsCreated++
		db.metrics.mu.Unlock()
	}

	// Mark as healthy after successful connection
	db.setHealthStatus(true, "")

	log.Printf("Database connected successfully to %s:%s/%s", db.config.Host, db.config.Port, db.config.Database)
	return nil
}

// setupHooks configures debugging and monitoring hooks
func (db *DB) setupHooks() {
	// Debug hook for development
	if config.IsDevelopment() {
		db.AddQueryHook(bundebug.NewQueryHook(
			bundebug.WithVerbose(true),
			bundebug.FromEnv("BUNDEBUG"),
		))
	}

	// OpenTelemetry tracing hook
	if db.config.EnableTracing {
		db.AddQueryHook(bunotel.NewQueryHook(
			bunotel.WithDBName(db.config.Database),
		))
	}

	// Metrics hook
	if db.config.EnableMetrics {
		db.AddQueryHook(&metricsHook{metrics: db.metrics})
	}
}

// startHealthCheckMonitoring runs periodic health checks
func (db *DB) startHealthCheckMonitoring() {
	ticker := time.NewTicker(db.config.HealthCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		db.performHealthCheck()
	}
}

// performHealthCheck checks database health
func (db *DB) performHealthCheck() {
	ctx, cancel := context.WithTimeout(context.Background(), db.config.PingTimeout)
	defer cancel()

	start := time.Now()
	err := db.PingContext(ctx)
	duration := time.Since(start)

	if db.config.EnableMetrics {
		db.metrics.mu.Lock()
		db.metrics.LastHealthCheck = start
		db.metrics.HealthCheckDuration = duration
		if err != nil {
			db.metrics.HealthCheckFailures++
		}
		db.metrics.mu.Unlock()
	}

	if err != nil {
		log.Printf("Health check failed: %v", err)
		db.setHealthStatus(false, err.Error())
		// Attempt to reconnect on health check failure
		go db.handleReconnection()
	} else {
		db.setHealthStatus(true, "")
	}
}

// handleReconnection attempts to reconnect on connection failure
func (db *DB) handleReconnection() {
	log.Println("Attempting to reconnect to database...")

	if err := db.DB.Close(); err != nil {
		log.Printf("Error closing existing connection: %v", err)
	}

	if err := db.connect(); err != nil {
		log.Printf("Reconnection failed: %v", err)
		db.setHealthStatus(false, err.Error())
	} else {
		log.Println("Successfully reconnected to database")
		db.setHealthStatus(true, "")
	}
}

// setHealthStatus updates the health status thread-safely
func (db *DB) setHealthStatus(healthy bool, errorMsg string) {
	db.healthMu.Lock()
	defer db.healthMu.Unlock()

	db.isHealthy = healthy
	db.lastCheck = time.Now()

	if !healthy {
		log.Printf("Database health status: UNHEALTHY - %s", errorMsg)
	}
}

// IsHealthy returns the current health status
func (db *DB) IsHealthy() bool {
	db.healthMu.RLock()
	defer db.healthMu.RUnlock()
	return db.isHealthy
}

// HealthCheck performs a comprehensive health check and returns detailed status
func (db *DB) HealthCheck(ctx context.Context) *HealthStatus {
	start := time.Now()

	status := &HealthStatus{
		LastCheck: start,
	}

	// Test basic connectivity
	if err := db.PingContext(ctx); err != nil {
		status.Healthy = false
		status.Error = err.Error()
		status.ResponseTime = time.Since(start)
		return status
	}

	// Test with a simple query
	var version string
	if err := db.NewSelect().ColumnExpr("version()").Scan(ctx, &version); err != nil {
		status.Healthy = false
		status.Error = fmt.Sprintf("query test failed: %v", err)
		status.ResponseTime = time.Since(start)
		return status
	}

	// Get connection statistics
	stats := db.DB.DB.Stats()

	status.Healthy = true
	status.ResponseTime = time.Since(start)
	status.DatabaseVersion = version
	status.ConnectionStats = stats

	return status
}

// GetMetrics returns current connection metrics
func (db *DB) GetMetrics() *ConnectionMetrics {
	if !db.config.EnableMetrics {
		return nil
	}

	db.metrics.mu.RLock()
	defer db.metrics.mu.RUnlock()

	// Create a copy to avoid race conditions
	metrics := *db.metrics
	return &metrics
}

// Close gracefully closes the database connection
func (db *DB) Close() error {
	log.Println("Closing database connection...")

	if db.config.EnableMetrics {
		db.metrics.mu.Lock()
		db.metrics.ConnectionsClosed++
		db.metrics.mu.Unlock()
	}

	if db.DB != nil {
		return db.DB.Close()
	}
	return nil
}

// WaitForConnection blocks until database is healthy or context is cancelled
func (db *DB) WaitForConnection(ctx context.Context) error {
	if db.IsHealthy() {
		return nil
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if db.IsHealthy() {
				return nil
			}
		}
	}
}

// metricsHook implements bun.QueryHook for metrics collection
type metricsHook struct {
	metrics *ConnectionMetrics
}

func (h *metricsHook) BeforeQuery(ctx context.Context, event *bun.QueryEvent) context.Context {
	event.StartTime = time.Now()
	return ctx
}

func (h *metricsHook) AfterQuery(ctx context.Context, event *bun.QueryEvent) {
	duration := time.Since(event.StartTime)

	h.metrics.mu.Lock()
	defer h.metrics.mu.Unlock()

	h.metrics.QueriesExecuted++
	if event.Err != nil {
		h.metrics.QueryErrors++
	}

	// Simple moving average for query duration
	if h.metrics.QueriesExecuted == 1 {
		h.metrics.AvgQueryDuration = duration
	} else {
		h.metrics.AvgQueryDuration = time.Duration(
			(int64(h.metrics.AvgQueryDuration)*9 + int64(duration)) / 10,
		)
	}
}
