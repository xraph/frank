package data

import (
	"context"

	"entgo.io/ent/dialect/sql/schema"
	"github.com/go-redis/redis/v8"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/migrate"
	"github.com/juicycleff/frank/pkg/logging"
)

type Clients struct {
	DB    *ent.Client
	Redis redis.UniversalClient
	cfg   *config.Config
	log   logging.Logger
}

func NewClients(
	db *ent.Client,
	redis redis.UniversalClient,
	cfg *config.Config,
	log logging.Logger,
) *Clients {
	return &Clients{DB: db, Redis: redis, cfg: cfg, log: log}
}

func (c *Clients) Close() error {
	if err := c.DB.Close(); err != nil {
		return err
	}

	if !c.cfg.Redis.Enabled || c.Redis == nil {
		return nil
	}

	if err := c.Redis.Close(); err != nil {
		return err
	}

	return nil
}

func (c *Clients) Ping() error {
	return nil
}

func (c *Clients) DBName() string {
	return "frank"
}

func (c *Clients) IsClosed() bool {
	return false
}

func (c *Clients) IsReplica() bool {
	return false
}

// RunAutoMigration Run the auto migration tool.
func (c *Clients) RunAutoMigration() error {
	if !c.cfg.Database.AutoMigrate {
		return nil
	}

	ctx := context.Background()
	if err := c.DB.Schema.Create(
		ctx,
		migrate.WithDropIndex(true),
		migrate.WithDropColumn(true),
		migrate.WithForeignKeys(true),
		migrate.WithGlobalUniqueID(true),
		schema.WithHooks(func(next schema.Creator) schema.Creator {
			return schema.CreateFunc(func(ctx context.Context, tables ...*schema.Table) error {
				return next.Create(ctx, tables...)
			})
		}),
	); err != nil {
		c.log.Errorf("failed creating schema resources: %v", err)
		return err
	}

	return nil
}
