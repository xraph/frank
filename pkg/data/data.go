package data

import (
	"context"

	entsql "entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/schema"
	"github.com/redis/go-redis/v9"

	// _ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/lib/pq"           // PostgreSQL driver
	_ "github.com/mattn/go-sqlite3" // SQLite driver
	"github.com/xraph/frank/config"
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/ent/migrate"
	"github.com/xraph/frank/pkg/logging"
)

type Clients struct {
	dbDriver *entsql.Driver
	DB       *ent.Client
	Redis    redis.UniversalClient
	cfg      *config.Config
	log      logging.Logger

	DBPinger *DatabasePinger
}

func NewClients(
	cfg *config.Config,
	log logging.Logger,
	drv *entsql.Driver,
	redis redis.UniversalClient,
) *Clients {
	db, drv := newSqlServer(drv, cfg)

	return &Clients{
		DB:       db,
		Redis:    redis,
		cfg:      cfg,
		log:      log,
		dbDriver: drv,
		DBPinger: NewDatabasePinger(db, drv),
	}
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

func (c *Clients) PingDB() error {
	return c.DBPinger.Ping(context.Background())
}

func (c *Clients) Driver() *entsql.Driver {
	return c.dbDriver
}

func (c *Clients) Dialect() string {
	return c.cfg.Database.Driver
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
		c.log.Infof("Auto migration is disabled. Skipping.")
		return nil
	}

	c.log.Infof("Running auto migration")

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

	c.log.Infof("Completed running auto migration")
	return nil
}

// RunMigration Run the auto migration tool.
func (c *Clients) RunMigration() error {
	c.log.Infof("Running migration")

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

	c.log.Infof("Completed running auto migration")
	return nil
}
