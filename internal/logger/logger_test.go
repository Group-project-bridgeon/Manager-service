package logger_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/group-project-bridgeon/manager-service/internal/logger"
)

func TestLoggerProductionJSON(t *testing.T) {
	var buf bytes.Buffer
	log := logger.New("production", "info", &buf)

	log.Info("test message", "key", "value")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("expected JSON log output, failed to parse: %v", err)
	}

	if entry["msg"] != "test message" {
		t.Errorf("expected msg 'test message', got %v", entry["msg"])
	}
	if entry["key"] != "value" {
		t.Errorf("expected key 'value', got %v", entry["key"])
	}
}

func TestLoggerDevelopmentText(t *testing.T) {
	var buf bytes.Buffer
	log := logger.New("development", "debug", &buf)

	log.Debug("dev message")

	output := buf.String()
	if !strings.Contains(output, "level=DEBUG") {
		t.Errorf("expected level=DEBUG in text output, got: %s", output)
	}
	if !strings.Contains(output, "msg=\"dev message\"") {
		t.Errorf("expected msg=\"dev message\" in text output, got: %s", output)
	}
}
