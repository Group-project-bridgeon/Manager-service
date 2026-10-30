package config_test

import (
	"os"
	"testing"

	"github.com/group-project-bridgeon/manager-service/internal/config"
)

func TestConfigLoadDefaults(t *testing.T) {
	// Clear any environment variables that might interfere
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Clearenv()
			_ = os.Setenv(tt.envKey, tt.envVal)

			_, err := config.Load()
			if (err != nil) != tt.wantErr {
				t.Errorf("config.Load() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
