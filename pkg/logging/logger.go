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
	Infof(msg string, fields ...any)
	Warnf(msg string, fields ...any)
	Debugf(msg string, fields ...any)
	Fatalf(msg string, fields ...any)
	Fatal(msg string, fields ...Field)
	With(fields ...Field) Logger
	WithContext(ctx context.Context) Logger

	// New methods for Zap-like interface
	Named(name string) Logger
	Sugar() SugaredLogger
	Sync() error
}

// SugaredLogger provides a more flexible API compared to the Logger
type SugaredLogger interface {
	Debugf(template string, args ...interface{})
	Infof(template string, args ...interface{})
	Warnf(template string, args ...interface{})
	Errorf(template string, args ...interface{})
	Fatalf(template string, args ...interface{})
	Debugw(msg string, keysAndValues ...interface{})
	Infow(msg string, keysAndValues ...interface{})
	Warnw(msg string, keysAndValues ...interface{})
	Errorw(msg string, keysAndValues ...interface{})
	Fatalw(msg string, keysAndValues ...interface{})
	With(args ...interface{}) SugaredLogger
}

// Field is a log field
type Field = zapcore.Field

// logger implements the Logger interface
type logger struct {
	zap *zap.Logger
}

// sugaredLogger implements the SugaredLogger interface
type sugaredLogger struct {
	sugar *zap.SugaredLogger
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

	// Additional field constructors
	Namespace  = zap.Namespace
	Binary     = zap.Binary
	ByteString = zap.ByteString
	Uint       = zap.Uint
	Uint32     = zap.Uint32
	Uint64     = zap.Uint64
	Float32    = zap.Float32
	Reflect    = zap.Reflect
	Complex64  = zap.Complex64
	Complex128 = zap.Complex128
	Object     = zap.Object
	Array      = zap.Array
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

// NewLogger creates a new logger with the given configuration
func NewLogger(cfg *LoggerConfig) Logger {
	var zapLogger *zap.Logger

	if cfg == nil {
		cfg = &LoggerConfig{
			Level:       "info",
			Environment: "development",
		}
	}

	// Determine log level
	logLevel := zapcore.InfoLevel
	switch cfg.Level {
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
	if cfg.Environment == "production" {
		config := zap.NewProductionConfig()
		config.Level = zap.NewAtomicLevelAt(logLevel)
		zapLogger, _ = config.Build(zap.AddCallerSkip(1))
	} else {
		zapLogger = devTheme(logLevel)
	}

	return &logger{zap: zapLogger}
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

// Debugf logs a debug message
func (l *logger) Debugf(msg string, fields ...any) {
	l.zap.Debug(fmt.Sprintf(msg, fields...))
}

// Info logs an info message
func (l *logger) Info(msg string, fields ...Field) {
	l.zap.Info(msg, fields...)
}

// Infof logs an info message
func (l *logger) Infof(msg string, fields ...any) {
	l.zap.Info(fmt.Sprintf(msg, fields...))
}

// Warn logs a warning message
func (l *logger) Warn(msg string, fields ...Field) {
	l.zap.Warn(msg, fields...)
}

// Warnf logs a warning message
func (l *logger) Warnf(msg string, fields ...any) {
	l.zap.Warn(fmt.Sprintf(msg, fields...))
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

func (l *logger) Fatalf(msg string, fields ...any) {
	l.zap.Fatal(fmt.Sprintf(msg, fields...))
	os.Exit(1)
}

// With creates a new logger with additional fields
func (l *logger) With(fields ...Field) Logger {
	return &logger{zap: l.zap.With(fields...)}
}

// Named adds a sub-scope to the logger's name
func (l *logger) Named(name string) Logger {
	return &logger{zap: l.zap.Named(name)}
}

// Sugar converts the logger to a SugaredLogger
func (l *logger) Sugar() SugaredLogger {
	return &sugaredLogger{sugar: l.zap.Sugar()}
}

// Sync flushes any buffered log entries
func (l *logger) Sync() error {
	return l.zap.Sync()
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

// SugaredLogger implementation

// Debugf logs a debug message with formatting
func (s *sugaredLogger) Debugf(template string, args ...interface{}) {
	s.sugar.Debugf(template, args...)
}

// Infof logs an info message with formatting
func (s *sugaredLogger) Infof(template string, args ...interface{}) {
	s.sugar.Infof(template, args...)
}

// Warnf logs a warning message with formatting
func (s *sugaredLogger) Warnf(template string, args ...interface{}) {
	s.sugar.Warnf(template, args...)
}

// Errorf logs an error message with formatting
func (s *sugaredLogger) Errorf(template string, args ...interface{}) {
	s.sugar.Errorf(template, args...)
}

// Fatalf logs a fatal message with formatting
func (s *sugaredLogger) Fatalf(template string, args ...interface{}) {
	s.sugar.Fatalf(template, args...)
}

// Debugw logs a debug message with key-value pairs
func (s *sugaredLogger) Debugw(msg string, keysAndValues ...interface{}) {
	s.sugar.Debugw(msg, keysAndValues...)
}

// Infow logs an info message with key-value pairs
func (s *sugaredLogger) Infow(msg string, keysAndValues ...interface{}) {
	s.sugar.Infow(msg, keysAndValues...)
}

// Warnw logs a warning message with key-value pairs
func (s *sugaredLogger) Warnw(msg string, keysAndValues ...interface{}) {
	s.sugar.Warnw(msg, keysAndValues...)
}

// Errorw logs an error message with key-value pairs
func (s *sugaredLogger) Errorw(msg string, keysAndValues ...interface{}) {
	s.sugar.Errorw(msg, keysAndValues...)
}

// Fatalw logs a fatal message with key-value pairs
func (s *sugaredLogger) Fatalw(msg string, keysAndValues ...interface{}) {
	s.sugar.Fatalw(msg, keysAndValues...)
}

// With creates a new sugared logger with additional fields
func (s *sugaredLogger) With(args ...interface{}) SugaredLogger {
	return &sugaredLogger{sugar: s.sugar.With(args...)}
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
