//go:build ignore

package main

import (
	"context"
	"log"
	"os"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent/migrate"

	"ariga.io/atlas/sql/sqltool"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql/schema"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	ctx := context.Background()

	// Load configuration to get database settings
	cfg, err := config.Load("")
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}

	// Create a local migration directory able to understand golang-migrate migration file format for replay.
	dir, err := sqltool.NewGolangMigrateDir("migrations")
	if err != nil {
		log.Fatalf("failed creating atlas migration directory: %v", err)
	}

	// Determine dialect based on configuration
	var dialectType string
	var databaseURL string

	switch cfg.Database.Driver {
	case "postgres":
		dialectType = dialect.Postgres
		if cfg.Database.DSN != "" {
			databaseURL = cfg.Database.DSN
		} else {
			databaseURL = cfg.Database.GetFullAddress()
		}
	case "mysql":
		dialectType = dialect.MySQL
		if cfg.Database.DSN != "" {
			databaseURL = cfg.Database.DSN
		} else {
			databaseURL = cfg.Database.GetFullAddress()
		}
	case "sqlite", "sqlite3":
		dialectType = dialect.SQLite
		databaseURL = "sqlite://" + cfg.Database.Database
	default:
		log.Fatalf("unsupported database driver: %s", cfg.Database.Driver)
	}

	// Migrate diff options.
	opts := []schema.MigrateOption{
		schema.WithDir(dir),                                  // provide migration directory
		schema.WithMigrationMode(schema.ModeReplay),          // provide migration mode
		schema.WithDialect(dialectType),                      // Ent dialect to use
		schema.WithFormatter(sqltool.GolangMigrateFormatter), // Use golang-migrate format
	}

	// Check if we have a migration name
	if len(os.Args) != 2 {
		log.Fatalln("migration name is required. Use: 'go run -mod=mod ent/migrate/main.go <name>'")
	}

	migrationName := os.Args[1]

	log.Printf("Generating migration '%s' for %s database", migrationName, cfg.Database.Driver)
	log.Printf("Database URL: %s", maskPassword(databaseURL))

	// Generate migrations using Atlas support
	err = migrate.NamedDiff(ctx, databaseURL, migrationName, opts...)
	if err != nil {
		log.Fatalf("failed generating migration file: %v", err)
	}

	log.Printf("Migration '%s' generated successfully in migrations/", migrationName)
	log.Println("Review the generated files before applying them to your database.")
}

// maskPassword masks the password in database URL for logging
func maskPassword(url string) string {
	// Simple password masking - in production you might want more sophisticated masking
	if len(url) > 50 {
		return url[:20] + "***" + url[len(url)-10:]
	}
	return "***"
}
