package common

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func WatchExit(ctx context.Context, exitFunc func()) {
	exit := make(chan os.Signal, 1)
	// SIGHUP: terminal closed
	// SIGINT: Ctrl+C
	// SIGTERM: program exit
	// SIGQUIT: Ctrl+/
	signal.Notify(exit, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	select {
	case <-exit:
		exitFunc()
	case <-ctx.Done():
	}
	Logger.Info("👋🏻Goodbye~")
}
