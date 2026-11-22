package traefik_real_ip

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime/debug"
	"strings"
)

// PluginLogger writes this middleware's logs and tags each record with the plugin name.
type PluginLogger struct {
	logger     *slog.Logger
	pluginName string
}

// NewPluginLogger writes text logs to stdout. An empty level is info. An unknown
// level is also info, and that choice is reported at warn.
func NewPluginLogger(ctx context.Context, pluginName, logLevelStr string) *PluginLogger {
	logLevel := slog.LevelInfo
	invalidLevel := false

	switch strings.ToLower(logLevelStr) {
	case LogLevelDebug:
		logLevel = slog.LevelDebug
	case LogLevelInfo, "":
	case LogLevelWarn:
		logLevel = slog.LevelWarn
	case LogLevelError:
		logLevel = slog.LevelError
	default:
		invalidLevel = true
	}

	opts := &slog.HandlerOptions{
		AddSource:   false,
		Level:       logLevel,
		ReplaceAttr: replaceAttr,
	}

	logger := &PluginLogger{
		logger:     slog.New(slog.NewTextHandler(os.Stdout, opts)),
		pluginName: pluginName,
	}
	if invalidLevel {
		logger.WarnContext(ctx, "Invalid log level, using info", slog.String("level", logLevelStr))
	}

	return logger
}

func replaceAttr(_ []string, attr slog.Attr) slog.Attr {
	switch attr.Value.Kind() {
	case slog.KindAny:
		if v, ok := attr.Value.Any().(error); ok {
			return ErrorAttr(v)
		}
	case slog.KindBool,
		slog.KindDuration,
		slog.KindFloat64,
		slog.KindInt64,
		slog.KindString,
		slog.KindTime,
		slog.KindUint64,
		slog.KindGroup,
		slog.KindLogValuer:
		return attr
	default:
		return attr
	}

	return attr
}

func ErrorAttr(val any) slog.Attr {
	errMsg := fmt.Sprintf("%v", val)
	if err, ok := val.(error); ok {
		errMsg = err.Error()
	}

	stack := debug.Stack()

	return slog.Group("error",
		slog.String("exceptionMessage", errMsg),
		slog.String("exceptionStacktrace", string(stack)),
	)
}

func ErrorAttrWithoutStack(val any) slog.Attr {
	errMsg := fmt.Sprintf("%v", val)
	if err, ok := val.(error); ok {
		errMsg = err.Error()
	}

	return slog.Group("error",
		slog.String("exceptionMessage", errMsg),
	)
}

// Log writes msg at level and appends a plugin attribute. Attribute arguments are
// passed through to slog.
func (l *PluginLogger) Log(ctx context.Context, level slog.Level, msg string, args ...any) {
	args = append(args, slog.String("plugin", l.pluginName))
	l.logger.Log(ctx, level, msg, args...)
}

// DebugContext logs at [LevelDebug].
func (l *PluginLogger) DebugContext(ctx context.Context, msg string, attrs ...any) {
	l.Log(ctx, slog.LevelDebug, msg, attrs...)
}

// Debug logs at [LevelDebug].
func (l *PluginLogger) Debug(msg string, attrs ...any) {
	l.DebugContext(context.Background(), msg, attrs...)
}

// InfoContext logs at [LevelInfo].
func (l *PluginLogger) InfoContext(ctx context.Context, msg string, attrs ...any) {
	l.Log(ctx, slog.LevelInfo, msg, attrs...)
}

// Info logs at [LevelInfo].
func (l *PluginLogger) Info(msg string, attrs ...any) {
	l.InfoContext(context.Background(), msg, attrs...)
}

// WarnContext logs at [LevelWarn].
func (l *PluginLogger) WarnContext(ctx context.Context, msg string, attrs ...any) {
	l.Log(ctx, slog.LevelWarn, msg, attrs...)
}

// Warn logs at [LevelWarn].
func (l *PluginLogger) Warn(msg string, attrs ...any) {
	l.WarnContext(context.Background(), msg, attrs...)
}

// ErrorContext logs at [LevelError].
func (l *PluginLogger) ErrorContext(ctx context.Context, msg string, attrs ...any) {
	l.Log(ctx, slog.LevelError, msg, attrs...)
}

// Error logs at [LevelError].
func (l *PluginLogger) Error(msg string, attrs ...any) {
	l.ErrorContext(context.Background(), msg, attrs...)
}
