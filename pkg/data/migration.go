package data

import "github.com/uptrace/bun/migrate"

var Migrations = migrate.NewMigrations(
	migrate.WithMigrationsDirectory("./migrations"),
)

func init() {
	if err := Migrations.DiscoverCaller(); err != nil {
		panic(err)
	}
}
