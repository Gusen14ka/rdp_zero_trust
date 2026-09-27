package logging

import (
	"fmt"
	"log/slog"
	"os"
)

func Configure(level string) error {
	logLevel, err := parseLevel(level)
	if err != nil {
		return err
	}

	handler := slog.NewTextHandler(
		os.Stderr,
		&slog.HandlerOptions{
			Level: logLevel,
		},
	)

	slog.SetDefault(slog.New(handler))

	return nil
}

func parseLevel(level string) (slog.Level, error) {
	switch level {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level: %s", level)
	}
}

func Fatalf(message string, args ...any) {
	slog.Error(message, args...)
	os.Exit(1)
}
