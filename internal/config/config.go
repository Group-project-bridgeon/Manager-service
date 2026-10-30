// Package config provides application configuration loading and validation.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all validated application configuration.
// It is immutable once loaded; pass it by reference.
type Config struct {
	AppEnv          string
	Port            int
	LogLevel        string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
}

// Load reads configuration from the environment and an optional .env file,
// applies sensible defaults, and validates all values.
func Load() (*Config, error) {
	// Attempt to load .env file if it exists (development convenience)
	_ = loadDotEnv(".env")

	cfg := &Config{
		AppEnv:          getEnv("APP_ENV", "development"),
		LogLevel:        strings.ToLower(getEnv("LOG_LEVEL", "info")),
		ReadTimeout:     getDurationEnv("READ_TIMEOUT", 5*time.Second),
		WriteTimeout:    getDurationEnv("WRITE_TIMEOUT", 10*time.Second),
		IdleTimeout:     getDurationEnv("IDLE_TIMEOUT", 120*time.Second),
		ShutdownTimeout: getDurationEnv("SHUTDOWN_TIMEOUT", 5*time.Second),
	}

	portStr := getEnv("PORT", "8080")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid PORT %q: must be an integer", portStr)
	}
	cfg.Port = port

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

func (c *Config) validate() error {
	switch c.AppEnv {
	case "development", "staging", "production":
	default:
		return fmt.Errorf("invalid APP_ENV %q: must be one of [development, staging, production]", c.AppEnv)
	}

	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid PORT %d: must be between 1 and 65535", c.Port)
	}

	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("invalid LOG_LEVEL %q: must be one of [debug, info, warn, error]", c.LogLevel)
	}

	// Docker default stop timeout is 10s. If our shutdown timeout is >= 10s,
	// Docker will send SIGKILL before our graceful cleanup completes.
	if c.ShutdownTimeout >= 10*time.Second {
		return errors.New("SHUTDOWN_TIMEOUT must be less than 10s to allow graceful exit before Docker SIGKILL")
	}

	return nil
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok && strings.TrimSpace(val) != "" {
		return strings.TrimSpace(val)
	}
	return fallback
}

func getDurationEnv(key string, fallback time.Duration) time.Duration {
	valStr := getEnv(key, "")
	if valStr == "" {
		return fallback
	}
	d, err := time.ParseDuration(valStr)
	if err != nil {
		return fallback
	}
	return d
}

// loadDotEnv parses a simple KEY=VALUE file into the process environment.
// It will not overwrite existing environment variables.
func loadDotEnv(filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return err // file does not exist, ignore
	}
	defer func() {
		_ = file.Close()
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		// Preserve environment variables already explicitly set
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, val)
		}
	}
	return scanner.Err()
}
