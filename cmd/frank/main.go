package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/go-redis/redis/v8"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/juicycleff/frank"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/pkg/data"
	"github.com/juicycleff/frank/pkg/logging"
)

var (
	buildDate string
	gitCommit string
)

// @title       Frank API with Swagger
// @version      1.0
// @description  This is a sample server using Chi router with Swagger documentation.
// @host         localhost:8080
// @BasePath     /
// @output       docs
// @schemes      http
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
// @openapi 3.0.0
func main() {
	// Parse command line flags
	configPath := flag.String("config", "config.yaml", "path to config file")

	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	fmt.Println(gitCommit, buildDate)

	cfg.GitCommit = gitCommit
	cfg.BuildDate = buildDate

	// Initialize logger
	logging.Init(cfg.Logging.Level, cfg.Environment)
	logger := logging.GetLogger()
	logger.Info("Starting Frank Authentication Server",
		logging.String("version", cfg.Version),
		logging.String("environment", cfg.Environment),
	)

	// Connect to database
	logger.Info("Connecting to database",
		logging.String("driver", cfg.Database.Driver),
		logging.String("database", cfg.Database.Database),
	)

	dataClients := data.NewClients(cfg, logger, nil, nil)

	if cfg.Redis.Enabled {
		redisClient := redis.NewUniversalClient(&redis.UniversalOptions{
			Addrs:           strings.Split(cfg.Redis.Host, ","),
			Password:        cfg.Redis.Password,
			DB:              cfg.Redis.Database,
			MaxRetries:      cfg.Redis.MaxRetries,
			MinRetryBackoff: cfg.Redis.MinRetryBackoff,
			MaxRetryBackoff: cfg.Redis.MaxRetryBackoff,
			DialTimeout:     cfg.Redis.DialTimeout,
			ReadTimeout:     cfg.Redis.ReadTimeout,
			WriteTimeout:    cfg.Redis.WriteTimeout,
		})
		dataClients.Redis = redisClient
	}

	defer dataClients.Close()

	// // Run auto migrations in development mode
	// if cfg.Environment == "development" {
	// 	if err := entClient.Schema.Create(context.Background()); err != nil {
	// 		log.Fatalf("Failed to run schema migration: %v", err)
	// 	}
	// 	logger.Info("Database schema migrations completed")
	// }

	// Build web client if in development mode and --skip-client-build is not specified
	skipClientBuild := flag.Lookup("skip-client-build") != nil && flag.Lookup("skip-client-build").Value.(flag.Getter).Get().(bool)
	if os.Getenv("APP_ENV") == "development" && !skipClientBuild {
		buildWebClient(logger)
	}

	frankServer := frank.NewServer(dataClients, cfg, logger)

	// Start server in a goroutine
	serverErrors := frankServer.Start()

	// Listen for shutdown signals
	frankServer.WaitForSignal(serverErrors)
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
