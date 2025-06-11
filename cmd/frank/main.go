package main

import (
	"context"
	"fmt"

	"github.com/danielgtaylor/huma/v2/humacli"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/juicycleff/frank"
	commands2 "github.com/juicycleff/frank/commands"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/di"
	"github.com/juicycleff/frank/internal/server"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// CLI holds the application state
type FrankCLI struct {
	humacli.CLI
	app       *frank.Frank
	container di.Container
	logger    logging.Logger
	config    *config.Config
	ctx       context.Context
	base      *commands2.BaseCommand
	allCmds   *commands2.AllCommands
}

func main() {
	cli := &FrankCLI{
		ctx: context.Background(),
	}

	banner := server.DefaultBanner()

	var apiServer *server.Server

	cli.CLI = humacli.New(func(hooks humacli.Hooks, opts *server.ConfigFlags) {
		var err error
		banner.Title = "Wakflo Identity Server is starting"

		// Setup api router
		cli.app, err = frank.New(
			opts,
			frank.WithServerEnabled(),
		)
		apiServer = cli.app.Server()
		// Check for initialization errors
		if err != nil {
			// Create a fallback logger if app failed to initialize
			logger := logging.NewDefaultLogger()
			logger.Fatalf("Failed to initialize Frank: %v", err)
			return
		}

		// Verify the app is properly initialized
		if !cli.app.IsReady() {
			cli.app.DI().Logger().Fatal("Frank instance is not ready - missing critical dependencies")
			return
		}

		hooks.OnStart(func() {
			// Start your server here
			err = apiServer.StartWithOutChan()
			if err != nil {
				cli.app.DI().Logger().Fatalf("Failed to start api server: %v", err)
				return
			}
		})

		hooks.OnStop(func() {
			err := cli.app.DI().Stop(context.Background())
			if err != nil {
				cli.app.DI().Logger().Fatalf("Failed to close api server: %v", err)
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
			cli.app.DI().Logger().Info("Running database migrations")
			cli.app.DI().Logger().Info("Running database migrations for Frank")
			err := cli.app.DI().Data().RunAutoMigration()
			if err != nil {
				cli.app.DI().Logger().Error(err.Error())
			}

			cli.app.DI().Logger().Info("Running database migrations for Wakflo")
			err = cli.app.DI().Data().RunAutoMigration()
			if err != nil {
				cli.app.DI().Logger().Error(err.Error())
			}
		},
	})

	cli.initialize(cli.Root(), cmd.ArgAliases)

	cli.Run()
}

// registerCommands sets up the commands without full initialization
func (cli *FrankCLI) registerCommands(rootCmd *cobra.Command) {
	// We need to do a basic initialization to register commands
	// but keep it lightweight for command discovery

	// Initialize basic logger for command registration
	cli.logger = logging.NewLogger(&logging.LoggerConfig{
		Level: "error", // Minimal logging during registration
	})

	// Load basic config for command registration
	cli.config = &config.Config{
		Database: config.DatabaseConfig{
			Driver:   "postgres",
			Host:     "localhost",
			Port:     5432,
			User:     "postgres",
			Password: "postgres",
			Database: "frank",
			SSLMode:  "disable",
		},
	}

	// Create base command with minimal setup for registration
	cli.base = commands2.NewBaseCommand(cli.config, nil, cli.logger, cli.ctx)
	cli.allCmds = commands2.NewAllCommands(cli.base)

	// Register all commands
	cli.allCmds.RegisterAllCommands(rootCmd)
}

// initialize sets up the CLI with full configuration and dependency injection container
func (cli *FrankCLI) initialize(cmd *cobra.Command, args []string) error {
	// Re-initialize logger with proper verbosity for actual command execution
	verbose, _ := cmd.Flags().GetBool("verbose")
	logLevel := "info"
	if verbose {
		logLevel = "debug"
	}

	// Replace the minimal logger with a properly configured one
	cli.logger = logging.NewLogger(&logging.LoggerConfig{
		Level: logLevel,
	})

	cli.logger.Debug("Initializing CLI for command execution",
		zap.String("logLevel", logLevel),
		zap.Bool("verbose", verbose),
	)

	// Load full configuration
	configPath, _ := cmd.Flags().GetString("config")
	var err error

	if configPath != "" {
		cli.config, err = config.Load(configPath)
		cli.logger.Debug("Loading config from path", zap.String("configPath", configPath))
	} else {
		cli.config, err = config.Load()
		cli.logger.Debug("Loading default config")
	}

	if err != nil {
		cli.logger.Warn("Failed to load config, using defaults", zap.Error(err))
		// Keep the existing default config that was set during registration
	}

	// Override database URL if provided via flag
	if databaseURL, _ := cmd.Flags().GetString("database-url"); databaseURL != "" {
		cli.config.Database.DSN = databaseURL
		cli.logger.Debug("Database URL overridden via flag", zap.String("databaseURL", "[REDACTED]"))
	}

	// Initialize dependency injection container
	cli.container, err = di.NewContainer(cli.config, cli.logger)
	if err != nil {
		cli.logger.Error("Failed to initialize container", zap.Error(err))
		return fmt.Errorf("failed to initialize container: %w", err)
	}

	// Start the container
	if err := cli.container.Start(cli.ctx); err != nil {
		cli.logger.Error("Failed to start container", zap.Error(err))
		return fmt.Errorf("failed to start container: %w", err)
	}

	// Update the base command with full dependencies
	cli.base = commands2.NewBaseCommand(cli.config, cli.container, cli.logger, cli.ctx)
	cli.allCmds = commands2.NewAllCommands(cli.base)
	cli.allCmds.RegisterAllCommands(cmd)

	cli.logger.Debug("CLI initialized successfully")
	return nil
}

// cleanup shuts down the container
func (cli *FrankCLI) cleanup(cmd *cobra.Command, args []string) error {
	if cli.container != nil {
		cli.logger.Debug("Shutting down container")
		if err := cli.container.Stop(cli.ctx); err != nil {
			cli.logger.Error("Failed to stop container", zap.Error(err))
			return err
		}
		cli.logger.Debug("Container shut down successfully")
	}
	return nil
}
