package traefik_real_ip

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
)

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

func replaceAttr(_ []string, a slog.Attr) slog.Attr {
	switch a.Value.Kind() {
	case slog.KindAny:
		switch v := a.Value.Any().(type) {
		case error:
			return ErrorAttr(v)
		}
	default:
		return a
	}

	return a
}

func ErrorAttr(val any) slog.Attr {
	errMsg := fmt.Sprintf("%v", val)
	if err, ok := val.(error); ok {
		errMsg = err.Error()
	}

	stack := make([]byte, 4096)
	n := runtime.Stack(stack, false)

	return slog.Group("error",
		slog.String("exception.message", errMsg),
		slog.String("exception.stacktrace", fmt.Sprintf("%s", stack[:n])),
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

// Debug logs at [LevelDebug].
func (l *PluginLogger) Debug(msg string, attrs ...any) {
	l.Log(context.Background(), slog.LevelDebug, msg, attrs...)
}

// Info logs at [LevelInfo].
func (l *PluginLogger) Info(msg string, attrs ...any) {
	l.Log(context.Background(), slog.LevelInfo, msg, attrs...)
}

// Warn logs at [LevelWarn].
func (l *PluginLogger) Warn(msg string, attrs ...any) {
	l.Log(context.Background(), slog.LevelWarn, msg, attrs...)
}

// Error logs at [LevelError].
func (l *PluginLogger) Error(msg string, attrs ...any) {
	l.Log(context.Background(), slog.LevelError, msg, attrs...)
}
