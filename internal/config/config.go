// Package config provides application configuration loading and validation.
package config

import (
	"bufio"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/group-project-bridgeon/manager-service/internal/auth"
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

	// Database Configuration
	DBHost            string
	DBPort            int
	DBUser            string
	DBPassword        string
	DBName            string
	DBSSLMode         string
	DBMaxConns        int32
	DBMinConns        int32
	DBMaxConnLifetime time.Duration
	DBMaxConnIdleTime time.Duration

	// JWT Configuration
	JWTPublicKeyPath string
	JWTIssuer        string
	JWTAudience      string
	JWTPublicKey     *rsa.PublicKey
}

// Load reads configuration from the environment and an optional .env file,
// applies sensible defaults, and validates all values.
func Load() (*Config, error) {
	// Attempt to load .env file if it exists (development convenience)
	_ = loadDotEnv(".env")

	cfg := &Config{
		AppEnv:            getEnv("APP_ENV", "development"),
		LogLevel:          strings.ToLower(getEnv("LOG_LEVEL", "info")),
		ReadTimeout:       getDurationEnv("READ_TIMEOUT", 5*time.Second),
		WriteTimeout:      getDurationEnv("WRITE_TIMEOUT", 10*time.Second),
		IdleTimeout:       getDurationEnv("IDLE_TIMEOUT", 120*time.Second),
		ShutdownTimeout:   getDurationEnv("SHUTDOWN_TIMEOUT", 5*time.Second),
		DBHost:            getEnv("DB_HOST", "localhost"),
		DBUser:            getEnv("DB_USER", "postgres"),
		DBPassword:        getEnv("DB_PASSWORD", ""),
		DBName:            getEnv("DB_NAME", "erp_manager"),
		DBSSLMode:         getEnv("DB_SSLMODE", "disable"),
		DBMaxConns:        getInt32Env("DB_MAX_CONNS", 25),
		DBMinConns:        getInt32Env("DB_MIN_CONNS", 5),
		DBMaxConnLifetime: getDurationEnv("DB_MAX_CONN_LIFETIME", 1*time.Hour),
		DBMaxConnIdleTime: getDurationEnv("DB_MAX_CONN_IDLE_TIME", 30*time.Minute),
		JWTPublicKeyPath:  getEnv("JWT_PUBLIC_KEY_PATH", ""),
		JWTIssuer:         getEnv("JWT_ISSUER", "erp-auth"),
		JWTAudience:       getEnv("JWT_AUDIENCE", "erp-api"),
	}

	portStr := getEnv("PORT", "8080")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid PORT %q: must be an integer", portStr)
	}
	cfg.Port = port

	dbPortStr := getEnv("DB_PORT", "5432")
	dbPort, err := strconv.Atoi(dbPortStr)
	if err != nil {
		return nil, fmt.Errorf("invalid DB_PORT %q: must be an integer", dbPortStr)
	}
	cfg.DBPort = dbPort

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

// DSN returns the formatted PostgreSQL connection URL.
func (c *Config) DSN() string {
	userInfo := url.User(c.DBUser)
	if c.DBPassword != "" {
		userInfo = url.UserPassword(c.DBUser, c.DBPassword)
	}

	u := url.URL{
		Scheme:   "postgres",
		User:     userInfo,
		Host:     fmt.Sprintf("%s:%d", c.DBHost, c.DBPort),
		Path:     c.DBName,
		RawQuery: fmt.Sprintf("sslmode=%s", c.DBSSLMode),
	}

	return u.String()
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

	if c.ShutdownTimeout >= 10*time.Second {
		return errors.New("SHUTDOWN_TIMEOUT must be less than 10s to allow graceful exit before Docker SIGKILL")
	}

	// Database validations
	if strings.TrimSpace(c.DBHost) == "" {
		return errors.New("DB_HOST cannot be empty")
	}
	if c.DBPort < 1 || c.DBPort > 65535 {
		return fmt.Errorf("invalid DB_PORT %d: must be between 1 and 65535", c.DBPort)
	}
	if strings.TrimSpace(c.DBUser) == "" {
		return errors.New("DB_USER cannot be empty")
	}
	if strings.TrimSpace(c.DBName) == "" {
		return errors.New("DB_NAME cannot be empty")
	}
	switch c.DBSSLMode {
	case "disable", "require", "verify-ca", "verify-full":
	default:
		return fmt.Errorf("invalid DB_SSLMODE %q: must be one of [disable, require, verify-ca, verify-full]", c.DBSSLMode)
	}
	if c.DBMinConns < 0 {
		return errors.New("DB_MIN_CONNS cannot be negative")
	}
	if c.DBMaxConns <= 0 {
		return errors.New("DB_MAX_CONNS must be greater than 0")
	}
	if c.DBMinConns > c.DBMaxConns {
		return fmt.Errorf("DB_MIN_CONNS (%d) cannot be greater than DB_MAX_CONNS (%d)", c.DBMinConns, c.DBMaxConns)
	}

	// JWT Validations
	if strings.TrimSpace(c.JWTPublicKeyPath) == "" {
		return errors.New("JWT_PUBLIC_KEY_PATH is required")
	}
	if strings.TrimSpace(c.JWTIssuer) == "" {
		return errors.New("JWT_ISSUER cannot be empty")
	}
	if strings.TrimSpace(c.JWTAudience) == "" {
		return errors.New("JWT_AUDIENCE cannot be empty")
	}
	keyBytes, err := os.ReadFile(c.JWTPublicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read JWT public key file from %q: %w", c.JWTPublicKeyPath, err)
	}
	pubKey, err := auth.ParseRSAPublicKeyPEM(keyBytes)
	if err != nil {
		return fmt.Errorf("invalid JWT public key: %w", err)
	}
	c.JWTPublicKey = pubKey

	return nil
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok && strings.TrimSpace(val) != "" {
		return strings.TrimSpace(val)
	}
	return fallback
}

func getInt32Env(key string, fallback int32) int32 {
	valStr := getEnv(key, "")
	if valStr == "" {
		return fallback
	}
	v, err := strconv.ParseInt(valStr, 10, 32)
	if err != nil {
		return fallback
	}
	return int32(v)
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
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, val)
		}
	}
	return scanner.Err()
}
