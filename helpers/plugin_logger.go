package helpers

import (
	"context"
	"log/slog"
	"os"
)

type PluginLogger struct {
	logger     *slog.Logger
	pluginName string
}

func NewPluginLogger(pluginName string, logLevel *slog.LevelVar) *PluginLogger {
	opts := &slog.HandlerOptions{
		AddSource:   false,
		Level:       logLevel,
		ReplaceAttr: nil,
	}

	handler := slog.NewTextHandler(os.Stdout, opts)
	slog.SetDefault(slog.New(handler))
	return &PluginLogger{
		logger:     slog.Default(),
		pluginName: pluginName,
	}
}

func (l *PluginLogger) Log(ctx context.Context, level slog.Level, msg string, args ...any) {
	args = append(args, slog.String("plugin", l.pluginName))
	l.logger.Log(ctx, level, msg, args...)
}

func (l *PluginLogger) Debug(msg string, attrs ...any) {
	l.Log(context.Background(), slog.LevelDebug, msg, attrs...)
}

func (l *PluginLogger) Info(msg string, attrs ...any) {
	l.Log(context.Background(), slog.LevelInfo, msg, attrs...)
}

func (l *PluginLogger) Warn(msg string, attrs ...any) {
	l.Log(context.Background(), slog.LevelWarn, msg, attrs...)
}

func (l *PluginLogger) Error(msg string, attrs ...any) {
	l.Log(context.Background(), slog.LevelError, msg, attrs...)
}
