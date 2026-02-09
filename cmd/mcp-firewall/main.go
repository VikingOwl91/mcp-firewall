package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/VikingOwl91/mcp-firewall/internal/config"
	"github.com/VikingOwl91/mcp-firewall/internal/proxy"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		slog.Error("failed to determine home directory", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defaultConfig := filepath.Join(home, ".mcp-firewall", "config.yaml")

	configPath := flag.String("config", defaultConfig, "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", slog.String("error", err.Error()))
		os.Exit(1)
	}

	level := parseLogLevel(cfg.LogLevel)
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	p := proxy.New(cfg, logger)

	if err := p.Run(ctx, &mcp.StdioTransport{}); err != nil {
		logger.Error("proxy exited with error", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func parseLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
