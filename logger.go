package traefik_real_ip

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"runtime/debug"
)

func init() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource:   false,
		Level:       slog.LevelDebug,
		ReplaceAttr: replaceAttr,
	}))
	slog.SetDefault(logger)
}

type PluginLogger struct {
	logger     *slog.Logger
	pluginName string
}

func NewPluginLogger(pluginName string, logLevel *slog.LevelVar) *PluginLogger {
	opts := &slog.HandlerOptions{
		AddSource:   false,
		Level:       logLevel,
		ReplaceAttr: replaceAttr,
	}

	handler := slog.NewTextHandler(os.Stdout, opts)
	slog.SetDefault(slog.New(handler))

	return &PluginLogger{
		logger:     slog.Default(),
		pluginName: pluginName,
	}
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
	n := runtime.Stack(stack, false)

	return slog.Group("error",
		slog.String("exception.message", errMsg),
		slog.String("exception.stacktrace", string(stack[:n])),
	)
}

func ErrorAttrWithoutStack(val any) slog.Attr {
	errMsg := fmt.Sprintf("%v", val)
	if err, ok := val.(error); ok {
		errMsg = err.Error()
	}

	return slog.Group("error",
		slog.String("exception.message", errMsg),
	)
}

// Log emits a log record with the current time and the given level and message.
// The Record's Attrs consist of the Logger's attributes followed by
// the Attrs specified by args.
//
// The attribute arguments are processed as follows:
//   - If an argument is an Attr, it is used as is.
//   - If an argument is a string and this is not the last argument,
//     the following argument is treated as the value and the two are combined
//     into an Attr.
//   - Otherwise, the argument is treated as a value with key "!BADKEY".
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
