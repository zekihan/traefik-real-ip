package traefik_real_ip

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestNewPluginLogger(t *testing.T) {
	logger := NewPluginLogger(t.Context(), "test-plugin", LogLevelDebug)
	if logger.pluginName != "test-plugin" {
		t.Errorf("Expected pluginName to be 'test-plugin', got '%s'", logger.pluginName)
	}
}

func TestPluginLogger_LogMethods(t *testing.T) {
	level := &slog.LevelVar{}
	level.Set(slog.LevelDebug)

	var buf bytes.Buffer

	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: level})

	// Create PluginLogger with custom logger writing to buf
	logger := &PluginLogger{
		logger:     slog.New(handler),
		pluginName: "unit-test",
	}

	logger.Debug("debug message", slog.String("key", "value"))
	logger.Info("info message", slog.Int("num", 42))
	logger.Warn("warn message")
	logger.Error("error message", errTest)

	logs := buf.String()
	if !strings.Contains(logs, "debug message") ||
		!strings.Contains(logs, "info message") ||
		!strings.Contains(logs, "warn message") ||
		!strings.Contains(logs, "error message") {
		t.Errorf("Log output missing expected messages: %s", logs)
	}

	if !strings.Contains(logs, "plugin=unit-test") {
		t.Errorf("Log output missing plugin name: %s", logs)
	}
}

var errTest = errors.New("test error")

func TestErrorAttr(t *testing.T) {
	attr := ErrorAttr(errTest)
	if attr.Key != "error" {
		t.Errorf("Expected key 'error', got '%s'", attr.Key)
	}

	group := attr.Value.Group()
	foundMsg := false
	foundStack := false

	for _, a := range group {
		if a.Key == "exception.message" && a.Value.String() == "test error" {
			foundMsg = true
		}

		if a.Key == "exception.stacktrace" && a.Value.String() != "" {
			foundStack = true
		}
	}

	if !foundMsg || !foundStack {
		t.Errorf("ErrorAttr missing expected fields: %+v", group)
	}
}

func TestErrorAttrWithoutStack(t *testing.T) {
	attr := ErrorAttrWithoutStack(errTest)
	if attr.Key != "error" {
		t.Errorf("Expected key 'error', got '%s'", attr.Key)
	}

	group := attr.Value.Group()
	foundMsg := false

	for _, a := range group {
		if a.Key == "exception.message" && a.Value.String() == "test error" {
			foundMsg = true
		}
	}

	if !foundMsg {
		t.Errorf("ErrorAttrWithoutStack missing exception.message: %+v", group)
	}
}

var errReplace = errors.New("replace error")

func TestReplaceAttr(t *testing.T) {
	attr := slog.Any("err", errReplace)

	replaced := replaceAttr([]string{}, attr)
	if replaced.Key != "err" && replaced.Key != "error" {
		t.Errorf("replaceAttr did not replace error attr as expected: %+v", replaced)
	}
}
