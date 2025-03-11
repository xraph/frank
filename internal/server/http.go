package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/utils"
)

// Server represents an HTTP server
type Server struct {
	server *http.Server
	config *config.Config
	logger logging.Logger
	router *Router
}

// NewServer creates a new HTTP server
func NewServer(cfg *config.Config, logger logging.Logger) *Server {
	router := NewRouter(cfg, logger)

	// Create HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      router.Handler(),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	return &Server{
		server: server,
		config: cfg,
		logger: logger,
		router: router,
	}
}

// Start starts the HTTP server
func (s *Server) Start() error {
	// Initialize session store
	utils.InitSessionStore(s.config)

	// Register routes
	s.router.RegisterRoutes()

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

		if err != http.ErrServerClosed {
			s.logger.Fatal("HTTP server error", logging.Error(err))
		}
	}()

	return nil
}

// Stop gracefully stops the HTTP server
func (s *Server) Stop() error {
	s.logger.Info("Stopping HTTP server")

	// Create context with timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), s.config.Server.ShutdownTimeout)
	defer cancel()

	// Shutdown server
	if err := s.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown error: %w", err)
	}

	s.logger.Info("HTTP server stopped")
	return nil
}

// WaitForSignal waits for termination signals
func (s *Server) WaitForSignal() {
	// Create signal channel
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for signal
	sig := <-sigChan
	s.logger.Info("Received signal", logging.String("signal", sig.String()))

	// Stop server
	if err := s.Stop(); err != nil {
		s.logger.Error("Error stopping server", logging.Error(err))
	}
}

// Router returns the router
func (s *Server) Router() *Router {
	return s.router
}
