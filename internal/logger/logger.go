// Package logger provides structured logging initialization using the Go standard log/slog package.
package logger

import (
	"io"
	"log/slog"
	"strings"
)

// New initializes a configured *slog.Logger based on environment and log level.
// It outputs JSON for production and staging, and human-readable text for development.
func New(env, level string, out io.Writer) *slog.Logger {
	var logLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: logLevel,
	}

	var handler slog.Handler
	if env == "production" || env == "staging" {
		handler = slog.NewJSONHandler(out, opts)
	} else {
		handler = slog.NewTextHandler(out, opts)
	}

	return slog.New(handler)
}
