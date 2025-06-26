//go:build ignore

package main

import (
	"context"
	"log"
	"os"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
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

	// Check if we have a migration name
	if len(os.Args) < 2 {
		log.Fatalln("migration name is required. Use: 'go run -mod=mod ent/migrate/main.go <name> [--force]'")
	}

	migrationName := os.Args[1]
	// forceMode := len(os.Args) > 2 && os.Args[2] == "--force"
	forceMode := true

	if forceMode {
		log.Println("WARNING: Force mode enabled. This will generate migration against existing database state.")

		// Option 1: Use schema inspection approach
		opts := []schema.MigrateOption{
			schema.WithDir(dir),
			schema.WithMigrationMode(schema.ModeInspect), // Use inspect mode instead of replay
			schema.WithDialect(dialectType),
			schema.WithFormatter(sqltool.GolangMigrateFormatter),
		}

		log.Printf("Generating migration '%s' for %s database (force mode)", migrationName, cfg.Database.Driver)

		err = migrate.NamedDiff(ctx, databaseURL, migrationName, opts...)
		if err != nil {
			log.Fatalf("failed generating migration file: %v", err)
		}
	} else {
		// Option 2: Create client and apply schema directly first
		client, err := ent.Open(cfg.Database.Driver, databaseURL)
		if err != nil {
			log.Fatalf("failed opening database: %v", err)
		}
		defer client.Close()

		// Check if this is the first migration
		if isFirstMigration(dir) {
			log.Println("No existing migrations found. Creating baseline migration...")

			// Apply current schema to get to known state
			err = client.Schema.Create(ctx,
				schema.WithDropIndex(true),
				schema.WithDropColumn(true),
				schema.WithGlobalUniqueID(true),
			)
			if err != nil {
				log.Fatalf("failed creating baseline schema: %v", err)
			}

			log.Println("Baseline schema applied. Now generating migration...")
		}

		// Now generate the migration
		opts := []schema.MigrateOption{
			schema.WithDir(dir),
			schema.WithMigrationMode(schema.ModeReplay),
			schema.WithDialect(dialectType),
			schema.WithFormatter(sqltool.GolangMigrateFormatter),
		}

		log.Printf("Generating migration '%s' for %s database", migrationName, cfg.Database.Driver)
		log.Printf("Database URL: %s", maskPassword(databaseURL))

		err = migrate.NamedDiff(ctx, databaseURL, migrationName, opts...)
		if err != nil {
			log.Fatalf("failed generating migration file: %v", err)
		}
	}

	log.Printf("Migration '%s' generated successfully in migrations/", migrationName)
	log.Println("Review the generated files before applying them to your database.")
}

// isFirstMigration checks if there are any existing migration files
func isFirstMigration(dir *sqltool.GolangMigrateDir) bool {
	files, err := dir.Files()
	if err != nil {
		return true
	}
	return len(files) == 0
}

// maskPassword masks the password in database URL for logging
func maskPassword(url string) string {
	// Simple password masking - in production you might want more sophisticated masking
	if len(url) > 50 {
		return url[:20] + "***" + url[len(url)-10:]
	}
	return "***"
}
