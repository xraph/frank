package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/go-redis/redis/v8"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/internal/auth/session"
	"github.com/juicycleff/frank/internal/data"
	"github.com/juicycleff/frank/internal/handlers"
	"github.com/juicycleff/frank/internal/middleware"
	"github.com/juicycleff/frank/internal/repo"
	"github.com/juicycleff/frank/internal/services"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"

	_ "github.com/jackc/pgx/v4/stdlib" // PostgreSQL driver (alternative)
	_ "github.com/lib/pq"              // PostgreSQL driver
	_ "github.com/mattn/go-sqlite3"    // SQLite driver
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

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

	var entClient *ent.Client
	switch cfg.Database.Driver {
	case "postgres", "postgresql":
		dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			cfg.Database.Host, cfg.Database.Port, cfg.Database.User,
			cfg.Database.Password, cfg.Database.Database, cfg.Database.SSLMode)
		entClient, err = ent.Open("postgres", dsn)
	case "sqlite3":
		entClient, err = ent.Open("sqlite3", cfg.Database.Database)
	default:
		log.Fatalf("Unsupported database driver: %s", cfg.Database.Driver)
	}

	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer entClient.Close()

	dataClients := &data.Clients{
		DB: entClient,
	}

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
		defer redisClient.Close()
	}

	// Run auto migrations in development mode
	if cfg.Environment == "development" {
		if err := entClient.Schema.Create(context.Background()); err != nil {
			log.Fatalf("Failed to run schema migration: %v", err)
		}
		logger.Info("Database schema migrations completed")
	}

	// Initialize session store
	utils.InitSessionStore(cfg)

	// Auth related services
	sessionManager := session.NewManager(entClient, cfg, logger, nil)

	// Init repos
	repos := repo.New(cfg, entClient, logger)

	// Initialize services
	svcs, err := services.New(repos, cfg, dataClients, logger)
	if err != nil {
		log.Fatalf("Failed to initialize user service: %v", err)
	}

	// Initialize handlers
	routeHandlers := handlers.New(svcs, dataClients, cfg, logger)

	// Initialize middleware
	authMiddleware := middleware.Auth(cfg, logger, sessionManager, svcs.APIKey)
	corsMiddleware := middleware.CORS(cfg)
	recoveryMiddleware := middleware.Recovery(logger)
	loggingMiddleware := middleware.Logging(logger)
	rateLimiterMiddleware := middleware.RateLimiter(cfg.Security.RateLimitPerSecond, cfg.Security.RateLimitBurst)
	errorMiddleware := middleware.ErrorHandler(logger)

	// Create router
	router := http.NewServeMux()

	// Register routes
	routeHandlers.RegisterRoutes(router)

	// Create global middleware chain
	handler := errorMiddleware(
		loggingMiddleware(
			recoveryMiddleware(
				corsMiddleware(
					rateLimiterMiddleware(
						authMiddleware(router),
					),
				),
			),
		),
	)

	// Create and start server
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      handler,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start server in a goroutine
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("Starting server",
			logging.String("address", server.Addr),
		)
		serverErrors <- server.ListenAndServe()
	}()

	// Listen for shutdown signals
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Block until a signal is received or server fails
	select {
	case err := <-serverErrors:
		log.Fatalf("Server error: %v", err)
	case sig := <-shutdown:
		logger.Info("Shutdown signal received",
			logging.String("signal", sig.String()),
		)

		// Create context with timeout for graceful shutdown
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
		defer cancel()

		// Attempt graceful shutdown
		if cfg.Server.GracefulShutdown {
			logger.Info("Attempting graceful shutdown")
			if err := server.Shutdown(ctx); err != nil {
				logger.Error("Server shutdown failed", logging.Error(err))
				if err := server.Close(); err != nil {
					logger.Error("Server close failed", logging.Error(err))
				}
			}
		}

		logger.Info("Server shutdown complete")
	}
}
