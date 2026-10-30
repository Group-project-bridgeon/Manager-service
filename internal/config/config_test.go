package config_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/group-project-bridgeon/manager-service/internal/config"
)

func writeTempRSAPublicKey(t *testing.T, bits int) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	pubASN1, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal RSA public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "jwt_public.pem")
	if err := os.WriteFile(keyPath, pubPEM, 0600); err != nil {
		t.Fatalf("failed to write temp public key: %v", err)
	}
	return keyPath
}

func TestConfigLoadDefaults(t *testing.T) {
	keyPath := writeTempRSAPublicKey(t, 2048)
	os.Clearenv()
	_ = os.Setenv("JWT_PUBLIC_KEY_PATH", keyPath)

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
	if cfg.JWTIssuer != "erp-auth" {
		t.Errorf("expected default JWTIssuer 'erp-auth', got %s", cfg.JWTIssuer)
	}
	if cfg.JWTAudience != "erp-api" {
		t.Errorf("expected default JWTAudience 'erp-api', got %s", cfg.JWTAudience)
	}
	if cfg.JWTPublicKey == nil {
		t.Fatal("expected parsed JWTPublicKey, got nil")
	}
}

func TestConfigDSN(t *testing.T) {
	keyPath := writeTempRSAPublicKey(t, 2048)
	os.Clearenv()
	_ = os.Setenv("JWT_PUBLIC_KEY_PATH", keyPath)
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
	validKeyPath := writeTempRSAPublicKey(t, 2048)
	smallKeyPath := writeTempRSAPublicKey(t, 1024)

	invalidPEMPath := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(invalidPEMPath, []byte("NOT A PEM"), 0600); err != nil {
		t.Fatalf("failed to write invalid pem file: %v", err)
	}

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
		{"missing jwt public key path", "JWT_PUBLIC_KEY_PATH", "", true},
		{"non-existent jwt public key file", "JWT_PUBLIC_KEY_PATH", "/non/existent/path.pem", true},
		{"rsa public key under 2048 bits", "JWT_PUBLIC_KEY_PATH", smallKeyPath, true},
		{"invalid pem file content", "JWT_PUBLIC_KEY_PATH", invalidPEMPath, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Clearenv()
			_ = os.Setenv("JWT_PUBLIC_KEY_PATH", validKeyPath)
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
