package main

import (
	"os"
	"os/exec"
	"path/filepath"

	"github.com/danielgtaylor/huma/v2/humacli"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/juicycleff/frank"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/server"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/spf13/cobra"
)

func main() {
	banner := server.DefaultBanner()

	var apiServer *server.Server
	var app *frank.Frank

	cli := humacli.New(func(hooks humacli.Hooks, opts *server.ConfigFlags) {
		var err error
		banner.Title = "Wakflo Identity Server is starting"

		// Setup api router
		app, err = frank.New(
			opts,
			frank.WithServerEnabled(),
		)
		apiServer = app.Server()

		// Build web client if in development mode and --skip-client-build is not specified
		if config.IsDevelopment() && !opts.EnableWebBuild {
			buildWebClient(app.DI().Logger())
		}

		hooks.OnStart(func() {
			// Start your server here
			err = apiServer.StartWithOutChan()
			if err != nil {
				app.DI().Logger().Fatalf("Failed to start api server: %v", err)
				return
			}
		})

		hooks.OnStop(func() {
			err := app.DI().Close()
			if err != nil {
				app.DI().Logger().Fatalf("Failed to close api server: %v", err)
			}

			_ = apiServer.Stop()
		})
	})

	cmd := cli.Root()
	cmd.Use = "Frank Identity Server"
	cmd.Version = "1.0.0"

	cli.Root().AddCommand(&cobra.Command{
		Use:   "start",
		Short: "Start the server",
		Run:   server.StartCMD(apiServer),
	})

	cli.Root().AddCommand(&cobra.Command{
		Use:   "migrate",
		Short: "Run database migration",
		Run: func(cmd *cobra.Command, args []string) {
			app.DI().Logger().Info("Running database migrations")
			app.DI().Logger().Info("Running database migrations for Frank")
			err := app.DI().Data().RunAutoMigration()
			if err != nil {
				app.DI().Logger().Error(err.Error())
			}

			app.DI().Logger().Info("Running database migrations for Wakflo")
			err = app.DI().Data().RunAutoMigration()
			if err != nil {
				app.DI().Logger().Error(err.Error())
			}
		},
	})

	cli.Run()
}

// buildWebClient builds the web client
func buildWebClient(logger logging.Logger) {
	logger.Info("Building web client...")

	// Get the directory of the current executable
	execPath, err := os.Executable()
	if err != nil {
		logger.Error("Failed to get executable path", logging.Error(err))
		return
	}

	execDir := filepath.Dir(execPath)
	scriptPath := filepath.Join(execDir, "..", "web", "build.sh")

	// Make sure the script exists
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		logger.Error("Web client build script not found", logging.String("path", scriptPath))
		return
	}

	// Make the script executable
	if err := os.Chmod(scriptPath, 0755); err != nil {
		logger.Error("Failed to make build script executable", logging.Error(err))
		return
	}

	// Run the build script
	cmd := exec.Command(scriptPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		logger.Error("Failed to build web client", logging.Error(err))
		return
	}

	logger.Info("Web client built successfully")
}
