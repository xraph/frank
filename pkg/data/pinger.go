package data

import (
	"context"
	"time"

	entsql "entgo.io/ent/dialect/sql"
	"github.com/xraph/frank/ent"
)

// Configuration values
const (
	dbConnectionTimeout = 5 * time.Second
)

type DatabasePinger struct {
	db  *ent.Client
	drv *entsql.Driver
}

func NewDatabasePinger(db *ent.Client, drv *entsql.Driver) *DatabasePinger {
	return &DatabasePinger{db: db, drv: drv}
}

// Ping implements the `health.Pinger` interface.
func (c *DatabasePinger) Ping(ctx context.Context) error {
	// Create context with timeout for health check
	checkCtx, cancel := context.WithTimeout(ctx, dbConnectionTimeout)
	defer cancel()

	// Execute a simple query to check database health
	// startTime := time.Now()
	// err := c.drv.PingContext(checkCtx)
	// responseTime := time.Since(startTime)
	//
	// if err != nil {
	// 	// Database check failed
	// 	status.Status = health.StatusDown
	// 	status.Error = err.Error()
	// 	return status
	// }

	_, err := c.drv.ExecContext(checkCtx, "SELECT 1")
	if err != nil {
		return err
	}

	return nil
}

// Name implements the `health.Pinger` interface.
func (c *DatabasePinger) Name() string {
	return "Database"
}
