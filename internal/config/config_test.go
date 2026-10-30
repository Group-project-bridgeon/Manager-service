package config_test

import (
	"os"
	"testing"

	"github.com/group-project-bridgeon/manager-service/internal/config"
)

func TestConfigLoadDefaults(t *testing.T) {
	os.Clearenv()

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("expected valid default config, got error: %v", err)
	}

	if cfg.Port != 8080 {
		t.Errorf("expected default Port 8080, got %d", cfg.Port)
	}
	if cfg.AppEnv != "development" {
		t.Errorf("expected default AppEnv 'development', got %s", cfg.AppEnv)
	}
	if cfg.DBHost != "localhost" {
		t.Errorf("expected default DBHost 'localhost', got %s", cfg.DBHost)
	}
	if cfg.DBPort != 5432 {
		t.Errorf("expected default DBPort 5432, got %d", cfg.DBPort)
	}
	if cfg.DBName != "erp_manager" {
		t.Errorf("expected default DBName 'erp_manager', got %s", cfg.DBName)
	}
}

func TestConfigDSN(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("DB_HOST", "db.internal")
	_ = os.Setenv("DB_PORT", "5433")
	_ = os.Setenv("DB_USER", "erp_user")
	_ = os.Setenv("DB_PASSWORD", "secret123")
	_ = os.Setenv("DB_NAME", "production_db")
	_ = os.Setenv("DB_SSLMODE", "require")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}

	dsn := cfg.DSN()
	expectedPrefix := "postgres://erp_user:secret123@db.internal:5433/production_db?sslmode=require"
	if dsn != expectedPrefix {
		t.Errorf("expected DSN %q, got %q", expectedPrefix, dsn)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		envKey  string
		envVal  string
		wantErr bool
	}{
		{"invalid environment", "APP_ENV", "invalid_env", true},
		{"invalid port", "PORT", "99999", true},
		{"invalid log level", "LOG_LEVEL", "verbose", true},
		{"shutdown timeout too high", "SHUTDOWN_TIMEOUT", "12s", true},
		{"invalid db port", "DB_PORT", "70000", true},
		{"invalid ssl mode", "DB_SSLMODE", "unsupported_mode", true},
		{"min conns greater than max conns", "DB_MIN_CONNS", "50", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Clearenv()
			_ = os.Setenv(tt.envKey, tt.envVal)
			if tt.name == "min conns greater than max conns" {
				_ = os.Setenv("DB_MAX_CONNS", "20")
			}

			_, err := config.Load()
			if (err != nil) != tt.wantErr {
				t.Errorf("config.Load() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
