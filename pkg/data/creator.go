package data

import (
	"database/sql"
	"fmt"
	"log"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"

	// Database drivers
	_ "github.com/go-sql-driver/mysql" // MySQL
	// _ "github.com/lib/pq"              // PostgreSQL
	// _ "github.com/mattn/go-sqlite3"    // SQLite

	_ "github.com/jackc/pgx/v5/stdlib"
	// _ "github.com/lib/pq"           // PostgreSQL driver
	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

func newSqlServer(drv *entsql.Driver, cfg *config.Config) (*ent.Client, *entsql.Driver) {
	if drv != nil {
		return ent.NewClient(ent.Driver(drv)), drv
	}

	var db *sql.DB
	var entClient *ent.Client
	var dbDriver *entsql.Driver
	var err error

	switch cfg.Database.Driver {
	case "postgres", "postgresql":
		dsn := cfg.Database.DSN
		if dsn == "" {
			dsn = fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
				cfg.Database.Host, cfg.Database.Port, cfg.Database.User,
				cfg.Database.Password, cfg.Database.Database, cfg.Database.SSLMode)
		}
		db, err = sql.Open("pgx", dsn)
		if err != nil {
			log.Fatalf("Failed to connect to database: %v", err)
		}

		dbDriver = entsql.OpenDB(dialect.Postgres, db)
		entClient = ent.NewClient(ent.Driver(dbDriver))
	case "sqlite3":
		entClient, err = ent.Open("sqlite3", cfg.Database.Database)
	default:
		log.Fatalf("Unsupported database driver: %s", cfg.Database.Driver)
	}

	return entClient, dbDriver
}
