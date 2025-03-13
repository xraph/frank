package logging

import (
	"context"
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger is the interface for logging
type Logger interface {
	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, fields ...Field)
	Errorf(msg string, fields ...any)
	Fatal(msg string, fields ...Field)
	With(fields ...Field) Logger
	WithContext(ctx context.Context) Logger
}

// Field is a log field
type Field = zapcore.Field

// logger implements the Logger interface
type logger struct {
	zap *zap.Logger
}

var (
	// global logger instance
	globalLogger *logger

	// log field constructors
	String   = zap.String
	Int      = zap.Int
	Int64    = zap.Int64
	Float64  = zap.Float64
	Bool     = zap.Bool
	Error    = zap.Error
	Time     = zap.Time
	Duration = zap.Duration
	Stringer = zap.Stringer
	Any      = zap.Any
)

// contextKey is a private type for context keys
type contextKey int

const (
	// loggerKey is the key for logger values in contexts
	loggerKey contextKey = iota

	// requestIDKey is the key for request ID values in contexts
	requestIDKey
)

// Init initializes the global logger
func Init(level string, environment string) {
	var zapLogger *zap.Logger

	// Determine log level
	logLevel := zapcore.InfoLevel
	switch level {
	case "debug":
		logLevel = zapcore.DebugLevel
	case "info":
		logLevel = zapcore.InfoLevel
	case "warn":
		logLevel = zapcore.WarnLevel
	case "error":
		logLevel = zapcore.ErrorLevel
	}

	// Configure logger based on environment
	if environment == "production" {
		config := zap.NewProductionConfig()
		config.Level = zap.NewAtomicLevelAt(logLevel)
		zapLogger, _ = config.Build(zap.AddCallerSkip(1))
	} else {
		// config := zap.NewDevelopmentConfig()
		// config.Level = zap.NewAtomicLevelAt(logLevel)
		// config.EncoderConfig.EncodeLevel = CustomColorLevelEncoder
		// config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		// zapLogger, _ = config.Build(zap.AddCallerSkip(1))
		zapLogger = devTheme(logLevel)
	}

	globalLogger = &logger{zap: zapLogger}
}

// CustomColorLevelEncoder defines custom colors for log levels
func CustomColorLevelEncoder(l zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	var levelColor string

	switch l {
	case zapcore.DebugLevel:
		levelColor = "\033[36m" // Cyan
	case zapcore.InfoLevel:
		levelColor = "\033[32m" // Green
	case zapcore.WarnLevel:
		levelColor = "\033[33m" // Yellow
	case zapcore.ErrorLevel:
		levelColor = "\033[31m" // Red
	case zapcore.DPanicLevel, zapcore.PanicLevel, zapcore.FatalLevel:
		levelColor = "\033[35m" // Magenta
	default:
		levelColor = "\033[37m" // White
	}

	reset := "\033[0m"
	levelStr := l.CapitalString() // Get capitalized level name like "DEBUG", "INFO", etc.
	coloredLevel := levelColor + levelStr + reset

	enc.AppendString(coloredLevel)
}

// GetLogger returns the global logger
func GetLogger() Logger {
	if globalLogger == nil {
		// Provide a default logger if not initialized
		config := zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		zapLogger, _ := config.Build(zap.AddCallerSkip(1))
		globalLogger = &logger{zap: zapLogger}
	}
	return globalLogger
}

// FromContext extracts a logger from the context
func FromContext(ctx context.Context) Logger {
	if ctx == nil {
		return GetLogger()
	}
	if l, ok := ctx.Value(loggerKey).(Logger); ok {
		return l
	}
	return GetLogger()
}

// WithContext adds the logger to a context
func WithContext(ctx context.Context, l Logger) context.Context {
	return context.WithValue(ctx, loggerKey, l)
}

// WithRequestID adds a request ID to the context
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

// RequestIDFromContext extracts the request ID from the context
func RequestIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

// Debug logs a debug message
func (l *logger) Debug(msg string, fields ...Field) {
	l.zap.Debug(msg, fields...)
}

// Info logs an info message
func (l *logger) Info(msg string, fields ...Field) {
	l.zap.Info(msg, fields...)
}

// Warn logs a warning message
func (l *logger) Warn(msg string, fields ...Field) {
	l.zap.Warn(msg, fields...)
}

// Error logs an error message
func (l *logger) Error(msg string, fields ...Field) {
	l.zap.Error(msg, fields...)
}

// Errorf logs an error message
func (l *logger) Errorf(msg string, fields ...any) {
	l.zap.Error(fmt.Sprintf(msg, fields...))
}

// Fatal logs a fatal message then calls os.Exit(1)
func (l *logger) Fatal(msg string, fields ...Field) {
	l.zap.Fatal(msg, fields...)
	os.Exit(1)
}

// With creates a new logger with additional fields
func (l *logger) With(fields ...Field) Logger {
	return &logger{zap: l.zap.With(fields...)}
}

// WithContext creates a logger with context-specific fields
func (l *logger) WithContext(ctx context.Context) Logger {
	if ctx == nil {
		return l
	}

	// Add request ID if available
	if requestID := RequestIDFromContext(ctx); requestID != "" {
		return l.With(String("request_id", requestID))
	}

	return l
}

// LoggerConfig contains configuration for the logger
type LoggerConfig struct {
	Level       string `json:"level" yaml:"level" env:"LOG_LEVEL" envDefault:"info"`
	Environment string `json:"environment" yaml:"environment" env:"ENVIRONMENT" envDefault:"development"`
}

// Track logs the execution time of a function
func Track(ctx context.Context, name string) func() {
	startTime := time.Now()
	return func() {
		logger := FromContext(ctx)
		logger.Debug("Function execution time",
			String("function", name),
			Duration("duration", time.Since(startTime)),
		)
	}
}
