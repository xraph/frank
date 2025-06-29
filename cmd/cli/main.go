package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/xraph/frank/config"
	"github.com/xraph/frank/internal/commands"
	"github.com/xraph/frank/internal/di"
	"github.com/xraph/frank/pkg/logging"
	"go.uber.org/zap"
)

// CLI holds the application state
type CLI struct {
	config    *config.Config
	container di.Container
	logger    logging.Logger
	ctx       context.Context
	base      *commands.BaseCommand
	allCmds   *commands.AllCommands
}

func main() {
	cli := &CLI{
		ctx: context.Background(),
	}

	rootCmd := &cobra.Command{
		Use:   "frank-cli",
		Short: "Frank Auth CLI - Administrative tool for Frank Auth SaaS platform",
		Long: `Frank Auth CLI provides administrative commands for managing users, 
organizations, and system configuration in the Frank Auth SaaS platform.`,
		PersistentPreRunE:  cli.initialize,
		PersistentPostRunE: cli.cleanup,
	}

	// Global flags
	rootCmd.PersistentFlags().String("config", "", "config file path")
	rootCmd.PersistentFlags().String("database-url", "", "database connection URL")
	rootCmd.PersistentFlags().Bool("verbose", false, "enable verbose logging")
	rootCmd.PersistentFlags().Bool("debug", false, "enable debug mode")

	// // Register commands before executing
	// cli.registerCommands(rootCmd)
	cli.initialize(rootCmd, rootCmd.ArgAliases)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// registerCommands sets up the commands without full initialization
func (cli *CLI) registerCommands(rootCmd *cobra.Command) {
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
	cli.base = commands.NewBaseCommand(cli.config, nil, cli.logger, cli.ctx)
	cli.allCmds = commands.NewAllCommands(cli.base)

	// Register all commands
	cli.allCmds.RegisterAllCommands(rootCmd)
}

// initialize sets up the CLI with full configuration and dependency injection container
func (cli *CLI) initialize(cmd *cobra.Command, args []string) error {
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
	cli.base = commands.NewBaseCommand(cli.config, cli.container, cli.logger, cli.ctx)
	cli.allCmds = commands.NewAllCommands(cli.base)
	cli.allCmds.RegisterAllCommands(cmd.Root())

	cli.logger.Debug("CLI initialized successfully")
	return nil
}

// cleanup shuts down the container
func (cli *CLI) cleanup(cmd *cobra.Command, args []string) error {
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
