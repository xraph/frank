package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/frank"
	"github.com/juicycleff/frank/internal/router"
	"github.com/juicycleff/frank/pkg/astro_fs"
	"github.com/juicycleff/frank/pkg/data"
	"github.com/juicycleff/frank/pkg/logging"
)

// Server represents an HTTP server
type Server struct {
	server *http.Server
	config *config.Config
	logger logging.Logger
	router router.FrankRouter
}

// NewServer creates a new HTTP server
func NewServer(clients *data.Clients, cfg *config.Config, logger logging.Logger) *Server {
	// Init routes
	frk, err := frank.New(clients, cfg, logger)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// Create HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      frk.Router.Handler(),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	if cfg.Server.EnableHTTP2 {
		astro_fs.EnableHTTP2(server)
	}

	return &Server{
		server: server,
		config: cfg,
		logger: logger,
		router: frk.Router,
	}
}

// Start starts the HTTP server
func (s *Server) Start() chan error {
	// Register routes
	s.router.RegisterRoutes()

	serverErrors := make(chan error, 1)

	// Start server in a goroutine
	go func() {
		s.logger.Info("Starting HTTP server",
			logging.String("address", s.server.Addr),
			logging.Bool("tls", s.config.Server.TLS.Enabled),
		)

		var err error
		if s.config.Server.TLS.Enabled {
			err = s.server.ListenAndServeTLS(
				s.config.Server.TLS.CertFile,
				s.config.Server.TLS.KeyFile,
			)
		} else {
			err = s.server.ListenAndServe()
		}

		if !errors.Is(err, http.ErrServerClosed) {
			s.logger.Fatal("HTTP server error", logging.Error(err))
		}

		serverErrors <- err
	}()

	return serverErrors
}

// Stop gracefully stops the HTTP server
func (s *Server) Stop() error {
	s.logger.Info("Stopping HTTP server")

	// Create context with timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), s.config.Server.ShutdownTimeout)
	defer cancel()

	// Attempt graceful shutdown
	if s.config.Server.GracefulShutdown {
		s.logger.Info("Attempting graceful shutdown")
		if err := s.server.Shutdown(ctx); err != nil {
			s.logger.Error("Server shutdown failed", logging.Error(err))
			if err := s.server.Close(); err != nil {
				s.logger.Error("Server close failed", logging.Error(err))
			}
		}
	}

	s.logger.Info("HTTP server stopped")
	return nil
}

// WaitForSignal waits for termination signals
func (s *Server) WaitForSignal(serverErrors chan error) {
	// Create signal channel
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for signal
	sig := <-sigChan

	// Block until a signal is received or server fails
	select {
	case err := <-serverErrors:
		log.Fatalf("Server error: %v", err)
	case sig = <-sigChan:
		s.logger.Info("Received signal", logging.String("signal", sig.String()))
		// Stop server
		if err := s.Stop(); err != nil {
			s.logger.Error("Error stopping server", logging.Error(err))
		}
	}
}

// Router returns the router
func (s *Server) Router() router.FrankRouter {
	return s.router
}
