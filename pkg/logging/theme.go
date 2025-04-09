package logging

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ANSI color codes
const (
	Reset      = "\033[0m"
	DebugColor = "\033[36m" // Cyan
	InfoColor  = "\033[32m" // Green
	WarnColor  = "\033[33m" // Yellow
	ErrorColor = "\033[31m" // Red
	FatalColor = "\033[35m" // Magenta
)

// createEncoder creates a console encoder with proper spacing
func createEncoder(encoderConfig zapcore.EncoderConfig) zapcore.Encoder {
	// Override the EncodeLevel to add color and fix spacing
	originalLevelEncoder := encoderConfig.EncodeLevel

	encoderConfig.EncodeLevel = func(level zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
		// Prepend the color code
		enc.AppendString(colorForLevel(level))

		// Use original encoder or default to capital letters
		if originalLevelEncoder != nil {
			originalLevelEncoder(level, enc)
		} else {
			enc.AppendString(level.CapitalString())
		}

		// Append reset code
		enc.AppendString(Reset)
	}

	return zapcore.NewConsoleEncoder(encoderConfig)
}

// colorForLevel returns the appropriate color for a log level
func colorForLevel(level zapcore.Level) string {
	switch level {
	case zapcore.DebugLevel:
		return DebugColor
	case zapcore.InfoLevel:
		return InfoColor
	case zapcore.WarnLevel:
		return WarnColor
	case zapcore.ErrorLevel:
		return ErrorColor
	case zapcore.DPanicLevel, zapcore.PanicLevel, zapcore.FatalLevel:
		return FatalColor
	default:
		return Reset
	}
}

// Custom WriteSyncer that adds color to the entire line
type ColoredWriteSyncer struct {
	zapcore.WriteSyncer
}

// Write implements io.Writer with line coloring and fixed spacing
func (w *ColoredWriteSyncer) Write(p []byte) (n int, err error) {
	// If the log is empty, just return
	if len(p) == 0 {
		return 0, nil
	}

	// Look for excess tab characters and replace with single spaces
	var fixedLog []byte
	var lastWasTab bool

	for i := 0; i < len(p); i++ {
		// Fix double tabs
		if p[i] == '\t' {
			if !lastWasTab {
				fixedLog = append(fixedLog, ' ')
				lastWasTab = true
			}
		} else {
			fixedLog = append(fixedLog, p[i])
			lastWasTab = false
		}
	}

	// Try to determine the log level from the content
	var colorCode string

	// Look for common level strings in the content
	for i := 0; i < len(fixedLog)-6; i++ {
		if fixedLog[i] == '[' || (i > 0 && fixedLog[i-1] == ' ') {
			if i+5 < len(fixedLog) && string(fixedLog[i:i+5]) == "DEBUG" {
				colorCode = DebugColor
				break
			} else if i+4 < len(fixedLog) && string(fixedLog[i:i+4]) == "INFO" {
				colorCode = InfoColor
				break
			} else if i+4 < len(fixedLog) && string(fixedLog[i:i+4]) == "WARN" {
				colorCode = WarnColor
				break
			} else if i+5 < len(fixedLog) && string(fixedLog[i:i+5]) == "ERROR" {
				colorCode = ErrorColor
				break
			} else if i+5 < len(fixedLog) && string(fixedLog[i:i+5]) == "FATAL" {
				colorCode = FatalColor
				break
			}
		}
	}

	// If we couldn't determine the level, just write without coloring
	if colorCode == "" {
		return w.WriteSyncer.Write(fixedLog)
	}

	// Write with color
	colorPrefix := []byte(colorCode)
	colorSuffix := []byte(Reset)

	// Write color prefix
	_, err = w.WriteSyncer.Write(colorPrefix)
	if err != nil {
		return 0, err
	}

	// Write the content
	n, err = w.WriteSyncer.Write(fixedLog)
	if err != nil {
		return n, err
	}

	// Write color suffix (reset)
	_, err = w.WriteSyncer.Write(colorSuffix)
	if err != nil {
		return n, err
	}

	return n, nil
}

func devTheme(logLevel zapcore.Level) *zap.Logger {
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalLevelEncoder, // Will be overridden
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	// Create our colored write syncer
	writeSyncer := &ColoredWriteSyncer{
		WriteSyncer: zapcore.AddSync(os.Stdout),
	}

	// Create the core with the encoder
	core := zapcore.NewCore(
		createEncoder(encoderConfig),
		writeSyncer,
		zap.NewAtomicLevelAt(logLevel),
	)

	// Create the logger
	return zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))
}

// // Logger returns the global logger
// func Logger() Logger {
// 	if globalLogger == nil {
// 		// Provide a default colored logger if not initialized
// 		// Create the encoder config
// 		encoderConfig := zapcore.EncoderConfig{
// 			TimeKey:        "ts",
// 			LevelKey:       "level",
// 			NameKey:        "logger",
// 			CallerKey:      "caller",
// 			FunctionKey:    zapcore.OmitKey,
// 			MessageKey:     "msg",
// 			StacktraceKey:  "stacktrace",
// 			LineEnding:     zapcore.DefaultLineEnding,
// 			EncodeLevel:    zapcore.CapitalLevelEncoder,  // Will be overridden
// 			EncodeTime:     zapcore.ISO8601TimeEncoder,
// 			EncodeDuration: zapcore.StringDurationEncoder,
// 			EncodeCaller:   zapcore.ShortCallerEncoder,
// 		}
//
// 		// Create our colored write syncer
// 		writeSyncer := &ColoredWriteSyncer{
// 			WriteSyncer: zapcore.AddSync(os.Stdout),
// 		}
//
// 		// Create the core with the encoder
// 		core := zapcore.NewCore(
// 			createEncoder(encoderConfig),
// 			writeSyncer,
// 			zap.NewAtomicLevelAt(zapcore.InfoLevel),
// 		)
//
// 		// Create the logger
// 		zapLogger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))
// 		globalLogger = &logger{zap: zapLogger}
// 	}
// 	return globalLogger
// }
